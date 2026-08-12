from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import TYPE_CHECKING, Any, Final, NoReturn

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, PlainTextResponse
from filelock import FileLock, Timeout
from prometheus_fastapi_instrumentator import Instrumentator
from starlette.concurrency import run_in_threadpool

import slowapi_compat  # noqa: F401  (triggers RateLimitItem patch on import)

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from storage import (
    DomainError,
    StorageError,
    StorageCursorError,
    StorageFullError,
    StorageBusyError,
    read_tail,
    read_last_line,
    scan_domain,
    list_domains,
    sanitize_domain,
    write_payload,
    write_payload_unique,
)
from provenance import ProvenanceError
from validation import (
    parse_iso_ts,
    prewarm_validators,
)
from integrity import IntegrityManager
from canonical_ingest import (
    apply_retention_policy,
    build_quality_envelope,
    payload_event_type,
)
from ingest_validation import validate_and_normalize_item
from http_adapter import (
    HttpPayloadShapeError,
    adapt_ingest_http_items,
    ingest_request_body_openapi,
)
from audit_log import AuditAction, emit_audit_event
from settings import Settings

# --- Runtime constants & logging ---
_STARTUP_SETTINGS = Settings()
MAX_PAYLOAD_SIZE: Final[int] = _STARTUP_SETTINGS.max_payload_size
MAX_RID_LENGTH: Final[int] = 128
RATE_LIMIT: Final[str] = _STARTUP_SETTINGS.rate_limit

# Provenance enforcement: set to "1" to require provenance fields
# Quality markers: set to "0" to disable quality marker computation
# Note: These are read at runtime, not frozen at import time


def _is_provenance_enforced() -> bool:
    """Check if provenance enforcement is enabled at runtime."""
    return Settings.provenance_enforced_now()


def _is_quality_enabled() -> bool:
    """Check if quality markers are enabled at runtime."""
    return Settings.quality_enabled_now()

LOG_LEVEL = _STARTUP_SETTINGS.log_level
DEBUG_MODE: Final[bool] = _STARTUP_SETTINGS.debug_mode
logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger("chronik")

class ExtraFormatter(logging.Formatter):
    """Formatter that adds 'extra' fields to the log message."""

    def format(self, record):
        s = super().format(record)
        if hasattr(record, "request_id"):
            extras = [
                f'{k}="{v}"'
                for k, v in record.__dict__.items()
                if k
                in {
                    "request_id",
                    "method",
                    "path",
                    "status",
                    "duration_ms",
                    "domain",
                    "file",
                }
            ]
            if extras:
                s = f"{s} {' '.join(extras)}"
        return s


# Re-configure root logger with our custom formatter
_handler = logging.StreamHandler()
_handler.setFormatter(ExtraFormatter(fmt="%(levelname)s:%(name)s:%(message)s"))
logging.getLogger().handlers = [_handler]
logging.getLogger().setLevel(LOG_LEVEL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm validators to avoid latency on first request
    await run_in_threadpool(prewarm_validators)

    # Initialize IntegrityManager per-app instance
    app.state.integrity_manager = IntegrityManager()

    # Start integrity sync loop if enabled
    if Settings.integrity_enabled_now():
        app.state.integrity_task = asyncio.create_task(app.state.integrity_manager.loop())
    else:
        app.state.integrity_task = None

    yield

    # Clean shutdown of integrity loop
    if app.state.integrity_task:
        app.state.integrity_manager.stop()
        app.state.integrity_task.cancel()
        try:
            # Wait for task to finish with timeout to prevent hanging
            await asyncio.wait_for(app.state.integrity_task, timeout=5.0)
        except asyncio.CancelledError:
            # Normal shutdown path
            logger.debug("Integrity loop shutdown gracefully")
        except asyncio.TimeoutError:
            logger.warning("Integrity loop shutdown timed out")
        except Exception as exc:
            logger.error(f"Integrity loop shutdown error: {exc}")


app = FastAPI(title="chronik-ingest", debug=DEBUG_MODE, lifespan=lifespan)

VERSION: Final[str] = _STARTUP_SETTINGS.version

_METRIC_LABEL_SANITIZER = re.compile(r'[^a-zA-Z0-9._-]')
_TOKEN_SPLITTER = re.compile(r'[,\r\n]')

# Cache for parsed tokens to avoid regex splitting on every request.
_VALID_TOKENS_CACHE: tuple[str, ...] | None = None
_RAW_TOKEN_ENV_CACHE: str | None = None
_TOKEN_CACHE_LOCK = Lock()


def _get_valid_tokens() -> tuple[str, ...]:
    """Retrieves a deterministic tuple of valid tokens from the environment.
    Supports multiple tokens separated by commas, newlines, or carriage returns.
    Duplicates are removed while preserving original order.
    Results are cached to minimize per-request overhead.
    """
    global _VALID_TOKENS_CACHE, _RAW_TOKEN_ENV_CACHE
    raw = Settings.current_token()

    # Fast path: Return cached version if environment hasn't changed.
    if _VALID_TOKENS_CACHE is not None and raw == _RAW_TOKEN_ENV_CACHE:
        return _VALID_TOKENS_CACHE

    with _TOKEN_CACHE_LOCK:
        # Re-check inside lock to avoid race conditions.
        if _VALID_TOKENS_CACHE is not None and raw == _RAW_TOKEN_ENV_CACHE:
            return _VALID_TOKENS_CACHE

        if not raw:
            _VALID_TOKENS_CACHE = ()
            _RAW_TOKEN_ENV_CACHE = raw
            return _VALID_TOKENS_CACHE

        seen: set[str] = set()
        valid: list[str] = []
        for t in _TOKEN_SPLITTER.split(raw):
            tok = t.strip()
            if tok and tok not in seen:
                valid.append(tok)
                seen.add(tok)

        _VALID_TOKENS_CACHE = tuple(valid)
        _RAW_TOKEN_ENV_CACHE = raw
        return _VALID_TOKENS_CACHE


@app.middleware("http")
async def request_id_logging(request: Request, call_next):
    raw_rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    # Sanitize to prevent log injection and limit length
    rid = _METRIC_LABEL_SANITIZER.sub("_", raw_rid)[:MAX_RID_LENGTH]
    request.state.request_id = rid
    start = time.perf_counter()
    # Falls im Handler ein Fehler hochgeht, loggen wir konservativ 500
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        dur_ms = int((time.perf_counter() - start) * 1000)
        logger.info(
            "access",
            extra={
                "request_id": rid,
                "method": request.method,
                "path": request.url.path,
                "status": status,
                "duration_ms": dur_ms,
            },
        )


def _is_ingest_request(request: Request) -> bool:
    path = str(request.scope.get("path", ""))
    return path == "/v1/ingest" or path.startswith("/ingest/")


def _request_audit_domain(request: Request) -> str | None:
    remembered = getattr(request.state, "audit_domain", None)
    if remembered is not None:
        return str(remembered)
    path_domain = request.path_params.get("domain")
    if path_domain is not None:
        return str(path_domain)
    query_domain = request.query_params.get("domain")
    if query_domain is not None:
        return str(query_domain)
    return None


def _audit_ingest_decision(
    request: Request,
    action: AuditAction,
    reason: str,
    *,
    domain: str | None = None,
) -> None:
    if not _is_ingest_request(request):
        return
    if domain is not None:
        request.state.audit_domain = domain
    client_ip = request.client.host if request.client is not None else None
    emit_audit_event(
        request_id=getattr(request.state, "request_id", None),
        domain=_request_audit_domain(request),
        action=action,
        reason=reason,
        client_ip=client_ip,
    )


@app.exception_handler(HTTPException)
async def _on_http_exception(request: Request, exc: HTTPException):
    _audit_ingest_decision(request, "REJECTED", str(exc.detail))
    return await http_exception_handler(request, exc)


limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
async def _on_rate_limited(request: Request, exc: RateLimitExceeded):
    _audit_ingest_decision(request, "REJECTED", "rate_limited")
    response = PlainTextResponse("too many requests", status_code=429)
    # Defaulting to 60s which matches our window size.
    # A more precise calculation would require querying the limiter storage.
    response.headers["Retry-After"] = "60"
    return response


Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# Custom metrics for event quality and provenance
from prometheus_client import Counter, Histogram

# Event ingestion metrics
events_ingested_total = Counter(
    "chronik_events_ingested_total",
    "Validated events presented for ingestion; not proof of durable persistence",
    ["domain", "event_type"],
)

events_persisted_total = Counter(
    "chronik_events_persisted_total",
    "Events durably appended to authoritative Chronik storage",
    ["domain"],
)

agent_ledger_delivery_total = Counter(
    "chronik_agent_ledger_delivery_total",
    "Agent ledger ingest requests by bounded delivery outcome",
    ["result"],
)
AGENT_LEDGER_DELIVERY_RESULTS: Final[frozenset[str]] = frozenset(
    {"accepted", "replayed", "mixed", "conflict", "invalid_identity"}
)

events_rejected_total = Counter(
    "chronik_events_rejected_total",
    "Total number of events rejected",
    ["domain", "reason"],
)

events_signal_strength = Counter(
    "chronik_events_signal_strength_total",
    "Validated delivery attempts by signal strength level; not durable writes",
    ["domain", "signal_strength"],
)

provenance_validation_failures = Counter(
    "chronik_provenance_validation_failures_total",
    "Events rejected due to missing provenance",
    ["domain"],
)


def _sanitize_metric_label(value: str, max_length: int = 80) -> str:
    """Sanitize a value for use as a Prometheus metric label.
    
    Protects against label cardinality explosion by:
    - Limiting length
    - Replacing problematic characters
    - Providing a fallback for empty/invalid values
    
    Args:
        value: The value to sanitize
        max_length: Maximum allowed length (default: 80)
    
    Returns:
        Sanitized label value safe for Prometheus
    """
    if not value or not isinstance(value, str):
        return "unknown"
    
    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length]
    
    # Replace problematic characters (keep alphanumeric, dots, dashes, underscores)
    sanitized = _METRIC_LABEL_SANITIZER.sub('_', value)
    
    # Ensure it's not empty after sanitization
    if not sanitized or sanitized == '_' * len(sanitized):
        return "unknown"
    
    return sanitized


def _sanitize_domain(domain: str) -> str:
    try:
        return sanitize_domain(domain)
    except DomainError as exc:
        raise HTTPException(status_code=400, detail="invalid domain") from exc


def _require_auth(x_auth: str) -> None:
    valid_tokens = _get_valid_tokens()
    if not valid_tokens:
        # Misconfigured server: auth is required but no secret is configured.
        # Use 500 to avoid leaking auth behavior details.
        raise HTTPException(status_code=500, detail="server misconfigured")

    if not x_auth:
        raise HTTPException(status_code=401, detail="unauthorized")

    # Check all configured tokens without early exit to reduce trivial timing differences.
    match_found = False
    for token in valid_tokens:
        if secrets.compare_digest(x_auth, token):
            match_found = True

    if not match_found:
        raise HTTPException(status_code=401, detail="unauthorized")


def _require_auth_dep(x_auth: str = Header(default="")) -> None:
    """
    FastAPI dependency that enforces authentication.
    Using a dedicated dep allows us to control execution order at the route decorator.
    """
    _require_auth(x_auth)


def _validate_body_size(req: Request) -> None:
    """
    Validate Content-Length before reading the body. Limited by MAX_PAYLOAD_SIZE.
    Must run *after* auth to avoid leaking details to unauthenticated callers.
    """
    cl_raw = req.headers.get("content-length")
    if cl_raw:
        try:
            cl = int(cl_raw)
        except (ValueError, TypeError):  # defensive
            raise HTTPException(status_code=400, detail="invalid content-length")
        if cl < 0:
            raise HTTPException(status_code=400, detail="invalid content-length")
        if cl > MAX_PAYLOAD_SIZE:
            raise HTTPException(status_code=413, detail="payload too large")
        return

    # No content-length. Check transfer-encoding.
    te = req.headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        return  # Body size will be checked during read

    raise HTTPException(status_code=411, detail="length required")


async def _read_body_as_utf8(request: Request, limit: int) -> str:
    """
    Reads the request body, respecting the limit, and decodes it as UTF-8.
    Chronik treats request bodies as UTF-8 regardless of Content-Type charset.

    Raises HTTPException(413) if limit is exceeded.
    Raises UnicodeError if body is not valid UTF-8.
    """
    data = bytearray()
    # Starlette's request.stream() yields chunks
    async for chunk in request.stream():
        if len(data) + len(chunk) > limit:
            raise HTTPException(status_code=413, detail="payload too large")
        data.extend(chunk)
    return data.decode("utf-8")


def _adapt_http_items(value: Any) -> list[dict[str, Any]]:
    """Apply only the permissive Pydantic HTTP-shape adapter."""
    try:
        return adapt_ingest_http_items(value)
    except HttpPayloadShapeError as exc:
        raise HTTPException(status_code=400, detail="invalid payload") from exc


def _process_items(items: list[Any], dom: str) -> list[str]:
    lines: list[str] = []
    # Leeres Array: nichts zu tun
    if not items:
        logger.warning("empty payload array received", extra={"domain": dom})
        return lines

    # Hoist invariants out of loop
    # We assume these flags are request-invariant (env vars/settings)
    # If they ever become dynamic per-item, this hoisting must be reverted.
    is_provenance_enforced = _is_provenance_enforced()
    is_quality_enabled = _is_quality_enabled()

    # Pre-compute label to prevent label pollution/entropy
    domain_label = _sanitize_metric_label(dom)

    for entry in items:
        try:
            normalized = validate_and_normalize_item(
                entry,
                dom,
                provenance_enforced=is_provenance_enforced,
            )
        except ProvenanceError as exc:
            provenance_validation_failures.labels(domain=domain_label).inc()
            events_rejected_total.labels(domain=domain_label, reason="provenance").inc()
            logger.warning(
                f"Provenance validation failed: {exc}", extra={"domain": dom}
            )
            raise HTTPException(
                status_code=400,
                detail=f"provenance validation failed: {str(exc)}",
            ) from exc

        event_type = payload_event_type(normalized)
        metrics_event_type = event_type if event_type else f"domain.{dom}"
        event_type_for_metrics = _sanitize_metric_label(metrics_event_type)
        received_dt = datetime.now(timezone.utc)

        quality_envelope = build_quality_envelope(
            dom,
            normalized,
            received_at=received_dt,
            quality_enabled=is_quality_enabled,
        )
        wrapper = apply_retention_policy(
            quality_envelope,
            received_at=received_dt,
        )

        if is_quality_enabled:
            events_signal_strength.labels(
                domain=domain_label,
                signal_strength=wrapper["quality"]["signal_strength"],
            ).inc()
        # Track metrics with sanitized labels (both domain and event_type)
        events_ingested_total.labels(domain=domain_label, event_type=event_type_for_metrics).inc()

        lines.append(json.dumps(wrapper, ensure_ascii=False, separators=(",", ":")))
    return lines


def _record_persisted_events(dom: str, count: int) -> None:
    """Record confirmed durable events without changing the ingest outcome."""
    if count <= 0:
        return
    try:
        events_persisted_total.labels(domain=_sanitize_metric_label(dom)).inc(count)
    except Exception:
        logger.exception("failed to record durable event metric", extra={"domain": dom})


def _record_agent_ledger_outcome(result: str) -> None:
    """Record one fixed agent.ledger result without affecting ledger semantics."""
    if result not in AGENT_LEDGER_DELIVERY_RESULTS:
        logger.error("unsupported agent.ledger delivery result")
        return
    try:
        agent_ledger_delivery_total.labels(result=result).inc()
    except Exception:
        logger.exception("failed to record agent.ledger delivery metric")


def _raise_storage_http_exception(
    exc: StorageError, *, domain: str | None = None
) -> NoReturn:
    """Map storage errors to HTTP exceptions without claiming persistence."""
    if isinstance(exc, StorageFullError):
        raise HTTPException(status_code=507, detail="insufficient storage") from exc
    if isinstance(exc, StorageBusyError):
        raise HTTPException(status_code=429, detail="busy, try again") from exc

    # Fallback for other storage errors (e.g. symlinks, invalid paths).
    msg = str(exc).lower()
    if msg.startswith("conflicting event_id:"):
        if domain == "agent.ledger":
            _record_agent_ledger_outcome("conflict")
        raise HTTPException(status_code=409, detail="conflicting event_id") from exc
    if msg == "missing event_id":
        if domain == "agent.ledger":
            _record_agent_ledger_outcome("invalid_identity")
        raise HTTPException(status_code=400, detail="missing event_id") from exc
    if "invalid target" in msg:
        raise HTTPException(status_code=400, detail="invalid target") from exc
    raise HTTPException(status_code=500, detail="storage error") from exc


def _agent_ledger_result(*, requested: int, written: int, skipped: int) -> dict[str, Any]:
    if written == requested:
        result = "accepted"
    elif skipped == requested:
        result = "replayed"
    else:
        result = "mixed"
    return {
        "domain": "agent.ledger",
        "result": result,
        "requested": requested,
        "written": written,
        "skipped_existing": skipped,
    }


def _process_and_write_combined(dom: str, items: list[Any]) -> dict[str, Any] | None:
    """Process one request and preserve existing semantics outside agent.ledger."""
    lines_to_write = _process_items(items, dom)
    if not lines_to_write:
        return None
    if dom == "agent.ledger":
        written, skipped = write_payload_unique(dom, lines_to_write, identity_key="event_id")
        result = _agent_ledger_result(
            requested=len(lines_to_write),
            written=written,
            skipped=skipped,
        )
        _record_persisted_events(dom, written)
        _record_agent_ledger_outcome(str(result["result"]))
        return result
    write_payload(dom, lines_to_write)
    _record_persisted_events(dom, len(lines_to_write))
    return None


@app.post(
    "/v1/ingest",
    # Dependency order matters: auth FIRST, then size check.
    dependencies=[Depends(_require_auth_dep), Depends(_validate_body_size)],
    status_code=202,
    openapi_extra=ingest_request_body_openapi(include_ndjson=True),
)
@limiter.limit(RATE_LIMIT)
async def ingest_v1(
    request: Request,
    domain: str | None = None,
):
    # Determine domain from query param or payload
    if domain:
        request.state.audit_domain = domain
        dom = _sanitize_domain(domain)
    else:
        dom = None

    content_type = request.headers.get("content-type", "").lower()

    try:
        body = await _read_body_as_utf8(request, MAX_PAYLOAD_SIZE)
    except UnicodeError as exc:
        raise HTTPException(status_code=400, detail="invalid encoding") from exc

    if "application/json" in content_type:
        try:
            obj = json.loads(body)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="invalid json") from exc
        items = _adapt_http_items(obj)
    elif "application/x-ndjson" in content_type:
        decoded_items: list[Any] = []
        lines = body.strip().split("\n")
        for line in lines:
            if not line:
                continue
            try:
                decoded_items.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail="invalid ndjson") from exc
        items = _adapt_http_items(decoded_items)
    else:
        raise HTTPException(status_code=415, detail="unsupported content-type")

    if not items:
        logger.warning("empty payload received")
        _audit_ingest_decision(request, "ACCEPTED", "empty", domain=dom)
        return PlainTextResponse("ok", status_code=202)

    # If domain was not in query, try to get it from the first item.
    if not dom:
        first_item = items[0]
        if not isinstance(first_item, dict):
            raise HTTPException(status_code=400, detail="invalid payload")

        first_item_domain = first_item.get("domain")
        if not first_item_domain or not isinstance(first_item_domain, str):
            raise HTTPException(
                status_code=400,
                detail="domain must be specified via query or payload",
            )
        request.state.audit_domain = first_item_domain
        dom = _sanitize_domain(first_item_domain)

    try:
        result = await run_in_threadpool(_process_and_write_combined, dom, items)
    except StorageError as exc:
        _raise_storage_http_exception(exc, domain=dom)

    if result is not None:
        _audit_ingest_decision(request, "ACCEPTED", str(result["result"]), domain=dom)
        return JSONResponse(result, status_code=202)
    _audit_ingest_decision(request, "ACCEPTED", "accepted", domain=dom)
    return PlainTextResponse("ok", status_code=202)


@app.post(
    "/ingest/{domain}",
    # Dependency order matters: auth FIRST, then size check.
    dependencies=[Depends(_require_auth_dep), Depends(_validate_body_size)],
    deprecated=True,
    openapi_extra=ingest_request_body_openapi(include_ndjson=False),
)
@limiter.limit(RATE_LIMIT)
async def ingest(
    domain: str,
    request: Request,
):
    request.state.audit_domain = domain
    dom = _sanitize_domain(domain)

    # JSON parsen
    try:
        body = await _read_body_as_utf8(request, MAX_PAYLOAD_SIZE)
    except UnicodeError as exc:
        raise HTTPException(status_code=400, detail="invalid encoding") from exc

    try:
        obj = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid json") from exc

    # Pydantic adapts only the HTTP object shape; canonical validation follows.
    items = _adapt_http_items(obj)
    try:
        result = await run_in_threadpool(_process_and_write_combined, dom, items)
    except StorageError as exc:
        _raise_storage_http_exception(exc, domain=dom)

    if result is not None:
        _audit_ingest_decision(request, "ACCEPTED", str(result["result"]), domain=dom)
        return JSONResponse(result, status_code=202)
    _audit_ingest_decision(
        request, "ACCEPTED", "empty" if not items else "accepted", domain=dom
    )
    return PlainTextResponse("ok", status_code=202)


def _fetch_events_helper(d: str, start: int, lim: int):
    """Synchronous helper to fetch events from storage.

    This function isolates the file I/O and iteration logic from the async
    FastAPI endpoint handler. It is designed to be run in a threadpool.
    """
    results = []
    next_off = start
    has_more = False

    iterator = scan_domain(d, start_offset=start)

    count = 0

    # Use strict unpacking: scan_domain now yields (start, next, line)
    for item_start, item_next, line in iterator:
        # Default: we consume this line (valid or not), so next_cursor advances past it
        next_off = item_next

        try:
            stored_item = json.loads(line)
        except json.JSONDecodeError:
            # Skip corrupt lines but we already advanced next_off
            continue

        count += 1

        if count > lim:
            # We found a valid item BEYOND the limit.
            has_more = True
            # The client should fetch THIS item next time.
            # So next_cursor should be the START of this extra item.
            next_off = item_start
            break

        results.append(stored_item)

    return results, next_off, has_more


@app.get("/v1/events", dependencies=[Depends(_require_auth_dep)])
async def events_v1(
    domain: str,
    limit: int = 100,
    cursor: int = 0,
):
    """
    Consumer pull endpoint.
    - cursor: Byte offset pointing to the start of the next line to read. 0 = start of file.
    - limit: Max events to return.

    Returns:
    - events: List of event objects.
    - next_cursor: The cursor to use for the NEXT batch.
    - has_more: True if there is at least one more valid event after this batch. False if EOF reached.
    """
    if limit < 1:
        raise HTTPException(status_code=400, detail="limit must be >= 1")
    if limit > 2000:
        raise HTTPException(status_code=400, detail="limit must be <= 2000")
    if cursor < 0:
        raise HTTPException(status_code=400, detail="cursor must be >= 0")

    try:
        dom = _sanitize_domain(domain)
    except HTTPException as exc:
        # Re-raise with original detail
        raise HTTPException(status_code=400, detail=exc.detail) from exc

    try:
        events, next_cursor, has_more = await run_in_threadpool(_fetch_events_helper, dom, cursor, limit)
    except StorageCursorError as exc:
        raise HTTPException(
            status_code=400, detail="cursor must point to a record boundary"
        ) from exc
    except StorageBusyError as exc:
        raise HTTPException(status_code=429, detail="busy, try again") from exc
    except StorageError as exc:
        if "invalid target" in str(exc):
            raise HTTPException(status_code=400, detail="invalid domain") from exc
        raise HTTPException(status_code=500, detail="storage error") from exc

    return {
        "events": events,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "limit": limit,
        "meta": {
            "count": len(events),
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }
    }


@app.get("/v1/latest", dependencies=[Depends(_require_auth_dep)], deprecated=True)
async def latest_v1(domain: str, unwrap: int = 0):
    try:
        dom = _sanitize_domain(domain)
    except HTTPException:
        raise

    try:
        # Use storage.read_last_line to get exactly one line efficiently
        line = await run_in_threadpool(read_last_line, dom)
    except StorageBusyError as exc:
        raise HTTPException(status_code=429, detail="busy, try again") from exc
    except StorageError as exc:
        raise HTTPException(status_code=500, detail="storage error") from exc

    if line is None:
        raise HTTPException(status_code=404, detail="no data")

    try:
        item = json.loads(line)
        if unwrap == 1:
            return item.get("payload", item)
        return item
    except json.JSONDecodeError as exc:
        logger.error("corrupt line encountered in latest", extra={"domain": dom})
        raise HTTPException(status_code=500, detail="data corruption") from exc


def _process_tail_lines(
    lines: list[str], since_dt: datetime | None, dom: str
) -> tuple[list[Any], int, datetime | None]:
    """CPU-bound parsing; run in threadpool."""
    results: list[Any] = []
    dropped = 0
    last_seen_dt: datetime | None = None

    for line in lines:
        try:
            item = json.loads(line)

            ts_str = None
            if isinstance(item, dict):
                ts_str = (
                    item.get("received_at")
                    or item.get("ts")
                    or item.get("timestamp")
                )

            dt = None
            if isinstance(ts_str, str):
                dt = parse_iso_ts(ts_str)

            if since_dt and (dt is None or dt <= since_dt):
                continue

            results.append(item)

            if dt is not None:
                if last_seen_dt is None or dt > last_seen_dt:
                    last_seen_dt = dt
        except json.JSONDecodeError:
            dropped += 1

    if dropped > 0:
        logger.warning(
            "dropped corrupt lines: %d",
            dropped,
            extra={"domain": dom, "dropped": dropped},
        )

    return results, dropped, last_seen_dt


@app.get("/v1/tail", dependencies=[Depends(_require_auth_dep)], deprecated=True)
async def tail_v1(
    domain: str,
    limit: int = 200,
    since: str | None = None,
):
    if limit < 1:
        raise HTTPException(status_code=400, detail="limit must be >= 1")
    if limit > 2000:
        raise HTTPException(status_code=400, detail="limit must be <= 2000")

    since_dt: datetime | None = None
    if since:
        since_dt = parse_iso_ts(since)
        if since_dt is None:
            raise HTTPException(status_code=400, detail="invalid since format")

    try:
        dom = _sanitize_domain(domain)
    except HTTPException:
        # If domain invalid, _sanitize_domain raises 400
        raise

    try:
        lines = await run_in_threadpool(read_tail, dom, limit)
    except StorageBusyError as exc:
        raise HTTPException(status_code=429, detail="busy, try again") from exc
    except StorageError as exc:
        # read_tail returns [] on ENOENT, so StorageError means something else
        raise HTTPException(status_code=500, detail="storage error") from exc

    results, dropped, last_seen_dt = await run_in_threadpool(
        _process_tail_lines, lines, since_dt, dom
    )

    headers = {
        "X-Chronik-Lines-Returned": str(len(results)),
        "X-Chronik-Lines-Dropped": str(dropped),
        "X-Chronik-Last-Seen-TS": last_seen_dt.isoformat() if last_seen_dt else "",
    }
    return JSONResponse(content=results, headers=headers)


@app.get("/v1/integrity", dependencies=[Depends(_require_auth_dep)])
async def integrity_view(request: Request):
    """
    Optional view: returns the latest integrity status for all known repos.
    Returns aggregated status object.
    """
    im = getattr(request.app.state, "integrity_manager", None)
    if im is None:
        return {
            "as_of": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_status": "MISSING",
            "repos": [],
        }
    return await im.get_aggregate_view()


@app.get("/health")
async def health(x_auth: str = Header(default="")) -> dict[str, str]:
    _require_auth(x_auth)
    return {"status": "ok"}


@app.get("/version")
async def version(x_auth: str = Header(default="")) -> dict[str, Any]:
    _require_auth(x_auth)
    return {"version": VERSION}
