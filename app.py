from __future__ import annotations

import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Final

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
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
    StorageFullError,
    StorageBusyError,
    read_tail,
    read_last_line,
    list_domains,
    sanitize_domain,
    write_payload,
)
from provenance import ProvenanceError, validate_provenance, has_provenance
from retention import get_ttl_for_event, compute_expiry_date
from validation import (
    normalize_heimgeist_item,
    parse_iso_ts,
    prewarm_validators,
    validate_insights_daily_payload,
)

# --- Runtime constants & logging ---
MAX_PAYLOAD_SIZE: Final[int] = int(
    os.getenv("CHRONIK_MAX_BODY") or str(1024 * 1024)
)
RATE_LIMIT: Final[str] = os.getenv("CHRONIK_RATE_LIMIT") or "60/minute"

# Provenance enforcement: set to "1" to require provenance fields
# Quality markers: set to "0" to disable quality marker computation
# Note: These are read at runtime, not frozen at import time


def _is_provenance_enforced() -> bool:
    """Check if provenance enforcement is enabled at runtime."""
    return os.getenv("CHRONIK_ENFORCE_PROVENANCE", "0") == "1"


def _is_quality_enabled() -> bool:
    """Check if quality markers are enabled at runtime."""
    return os.getenv("CHRONIK_ENABLE_QUALITY", "1") == "1"

LOG_LEVEL = (
    os.getenv("CHRONIK_LOG_LEVEL") or os.getenv("LOG_LEVEL", "INFO")
).upper()

_debug_val = (os.getenv("CHRONIK_DEBUG") or "").lower()
DEBUG_MODE: Final[bool] = _debug_val in {
    "1",
    "true",
    "yes",
    "on",
}
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
    prewarm_validators()
    yield


app = FastAPI(title="chronik-ingest", debug=DEBUG_MODE, lifespan=lifespan)

VERSION: Final[str] = os.environ.get("CHRONIK_VERSION") or "1.0.0"


def _get_secret() -> str | None:
    # Runtime lookup (no import-time hard dependency)
    return os.environ.get("CHRONIK_TOKEN")


@app.middleware("http")
async def request_id_logging(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
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


limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
async def _on_rate_limited(request: Request, exc: RateLimitExceeded):
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
    "Total number of events ingested",
    ["domain", "event_type"],
)

events_rejected_total = Counter(
    "chronik_events_rejected_total",
    "Total number of events rejected",
    ["domain", "reason"],
)

events_signal_strength = Counter(
    "chronik_events_signal_strength_total",
    "Events by signal strength level",
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
    import re
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', value)
    
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
    secret = _get_secret()
    if not secret:
        # Misconfigured server: auth is required but no secret is configured.
        # Use 500 to avoid leaking auth behavior details.
        raise HTTPException(status_code=500, detail="server misconfigured")
    if not x_auth or not secrets.compare_digest(x_auth, secret):
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


async def _read_body_with_limit(request: Request, limit: int) -> bytes:
    """
    Reads the request body, respecting the limit.
    Raises HTTPException(413) if limit is exceeded.
    """
    data = bytearray()
    # Starlette's request.stream() yields chunks
    async for chunk in request.stream():
        if len(data) + len(chunk) > limit:
            raise HTTPException(status_code=413, detail="payload too large")
        data.extend(chunk)
    return bytes(data)


def _process_items(items: list[Any], dom: str) -> list[str]:
    lines: list[str] = []
    # Leeres Array: nichts zu tun
    if not items:
        logger.warning("empty payload array received", extra={"domain": dom})
        return lines

    # Normalisieren & validieren
    for entry in items:
        if not isinstance(entry, dict):
            raise HTTPException(status_code=400, detail="invalid payload")

        normalized = dict(entry)

        # 1. Validation & Normalization logic per domain
        if dom == "insights.daily":
            validate_insights_daily_payload(normalized)
        elif dom == "heimgeist":
            normalized = normalize_heimgeist_item(normalized)
        else:
            # Generic domain checks
            summary_val = normalized.get("summary")
            if isinstance(summary_val, str) and len(summary_val) > 500:
                raise HTTPException(status_code=422, detail="summary too long (max 500)")

            if "domain" in normalized:
                entry_domain = normalized["domain"]
                if not isinstance(entry_domain, str):
                    raise HTTPException(status_code=400, detail="invalid payload")

                try:
                    sanitized_entry_domain = sanitize_domain(entry_domain)
                except DomainError as exc:
                    raise HTTPException(status_code=400, detail="invalid payload") from exc
                if sanitized_entry_domain != dom:
                    raise HTTPException(status_code=400, detail="domain mismatch")
        
        # 1b. Provenance validation (if enabled)
        if _is_provenance_enforced():
            try:
                validate_provenance(normalized, strict=True)
            except ProvenanceError as exc:
                # Sanitize domain for metrics to prevent label cardinality explosion
                domain_label = _sanitize_metric_label(dom)
                provenance_validation_failures.labels(domain=domain_label).inc()
                events_rejected_total.labels(domain=domain_label, reason="provenance").inc()
                logger.warning(
                    f"Provenance validation failed: {exc}",
                    extra={"domain": dom}
                )
                raise HTTPException(
                    status_code=400,
                    detail=f"provenance validation failed: {str(exc)}"
                ) from exc
        else:
            # Non-strict validation: just log warnings
            validate_provenance(normalized, strict=False)
        
        # 1c. Compute quality markers (if enabled) - but don't mutate payload
        quality_meta = None
        if _is_quality_enabled():
            from quality import compute_signal_strength, compute_completeness
            signal_strength = compute_signal_strength(normalized)
            completeness = compute_completeness(normalized)
            quality_meta = {
                "signal_strength": signal_strength.value if hasattr(signal_strength, 'value') else signal_strength,
                "completeness": completeness,
            }
            # Sanitize domain for metrics to prevent label cardinality explosion
            domain_label = _sanitize_metric_label(dom)
            events_signal_strength.labels(domain=domain_label, signal_strength=quality_meta["signal_strength"]).inc()
        
        # 1d. Compute retention metadata
        # Extract event_type from event itself (not from domain)
        # Priority: kind > type > event
        event_type = normalized.get("kind") or normalized.get("type") or normalized.get("event")
        
        # For retention: use event_type if available, otherwise apply default policy
        # Note: We do NOT use domain as event_type - they serve different purposes
        retention_event_type = event_type if event_type else "unknown"
        
        # For metrics: use domain as fallback to preserve observability
        # This allows us to see which domains produce events without type fields
        metrics_event_type = event_type if event_type else f"domain.{dom}"
        
        # Sanitize for metrics to prevent label cardinality explosion
        event_type_for_metrics = _sanitize_metric_label(metrics_event_type)
        domain_label = _sanitize_metric_label(dom)
        
        ttl_days = get_ttl_for_event(retention_event_type)
        received_dt = datetime.now(timezone.utc)
        expiry_dt = compute_expiry_date(retention_event_type, received_dt)
        
        retention_meta = {
            "ttl_days": ttl_days,
            "expires_at": expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if expiry_dt else None,
        }

        # 2. Canonical Wrapping (All domains)
        # Payload remains unmodified; quality and retention are envelope metadata
        wrapper = {
            "domain": dom,
            "received_at": received_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "payload": normalized,
            "retention": retention_meta,
        }
        
        # Add quality to wrapper (not payload) if enabled
        if quality_meta:
            wrapper["quality"] = quality_meta
        
        # Track metrics with sanitized labels (both domain and event_type)
        events_ingested_total.labels(domain=domain_label, event_type=event_type_for_metrics).inc()
        
        lines.append(json.dumps(wrapper, ensure_ascii=False, separators=(",", ":")))
    return lines


def _write_lines_to_storage_wrapper(dom: str, lines: list[str]) -> None:
    try:
        write_payload(dom, lines)
    except StorageFullError as exc:
        raise HTTPException(status_code=507, detail="insufficient storage") from exc
    except StorageBusyError as exc:
        raise HTTPException(status_code=429, detail="busy, try again") from exc
    except StorageError as exc:
        # Fallback for other storage errors (e.g. symlinks, invalid paths)
        # We assume most are client errors (bad domain/path), but some might be internal
        if "invalid target" in str(exc) or "invalid target path" in str(exc):
             raise HTTPException(status_code=400, detail="invalid target") from exc
        raise HTTPException(status_code=500, detail="storage error") from exc


@app.post(
    "/v1/ingest",
    # Dependency order matters: auth FIRST, then size check.
    dependencies=[Depends(_require_auth_dep), Depends(_validate_body_size)],
    status_code=202,
)
@limiter.limit(RATE_LIMIT)
async def ingest_v1(
    request: Request,
    domain: str | None = None,
):
    # Determine domain from query param or payload
    if domain:
        dom = _sanitize_domain(domain)
    else:
        dom = None

    content_type = request.headers.get("content-type", "").lower()

    try:
        raw = await _read_body_with_limit(request, MAX_PAYLOAD_SIZE)
        body = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid encoding") from exc

    items = []
    if "application/json" in content_type:
        try:
            obj = json.loads(body)
            items = obj if isinstance(obj, list) else [obj]
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="invalid json") from exc
    elif "application/x-ndjson" in content_type:
        lines = body.strip().split("\n")
        for line in lines:
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=400, detail="invalid ndjson") from exc
    else:
        raise HTTPException(status_code=415, detail="unsupported content-type")

    if not items:
        logger.warning("empty payload received")
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
        dom = _sanitize_domain(first_item_domain)

    lines_to_write = _process_items(items, dom)
    await run_in_threadpool(_write_lines_to_storage_wrapper, dom, lines_to_write)
    return PlainTextResponse("ok", status_code=202)


@app.post(
    "/ingest/{domain}",
    # Dependency order matters: auth FIRST, then size check.
    dependencies=[Depends(_require_auth_dep), Depends(_validate_body_size)],
    deprecated=True,
)
@limiter.limit(RATE_LIMIT)
async def ingest(
    domain: str,
    request: Request,
):
    dom = _sanitize_domain(domain)

    # JSON parsen
    try:
        raw = await _read_body_with_limit(request, MAX_PAYLOAD_SIZE)
        obj = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid json") from exc

    # Objekt oder Array → JSONL: eine kompakte Zeile pro Eintrag
    items = obj if isinstance(obj, list) else [obj]
    lines = _process_items(items, dom)
    await run_in_threadpool(_write_lines_to_storage_wrapper, dom, lines)

    return PlainTextResponse("ok", status_code=202)


@app.get("/v1/latest", dependencies=[Depends(_require_auth_dep)])
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


@app.get("/v1/tail", dependencies=[Depends(_require_auth_dep)])
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

    results = []
    dropped = 0
    last_seen_dt: datetime | None = None

    for line in lines:
        try:
            item = json.loads(line)

            ts_str = None
            if isinstance(item, dict):
                ts_str = item.get("ts") or item.get("timestamp")

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
            logger.warning("dropped corrupt line", extra={"domain": dom})

    headers = {
        "X-Chronik-Lines-Returned": str(len(results)),
        "X-Chronik-Lines-Dropped": str(dropped),
        "X-Chronik-Last-Seen-TS": last_seen_dt.isoformat() if last_seen_dt else "",
    }
    return JSONResponse(content=results, headers=headers)


@app.get("/v1/integrity", dependencies=[Depends(_require_auth_dep)])
async def integrity_view():
    """
    Optional view: returns the latest integrity status for all known repos
    (domains starting with 'integrity.').
    """
    # 1. List all domains starting with "integrity"
    # Note: we use "integrity" prefix, which matches "integrity.jsonl" and "integrity.*.jsonl"
    domains = await run_in_threadpool(list_domains, "integrity")

    results = {}

    for dom in domains:
        try:
            # 2. Read last line for each domain
            line = await run_in_threadpool(read_last_line, dom)
            if line:
                item = json.loads(line)
                # The generic ingest wrapper structure is:
                # { "domain": ..., "received_at": ..., "payload": ... }

                # Filter by kind/type to avoid "integrity junk"
                payload = item.get("payload", {}) or {}
                kind = payload.get("kind") or payload.get("type") or item.get("type")

                if kind != "integrity.summary.published.v1":
                    continue

                # We use the domain stored in the event if possible, else the filename key.
                real_domain = item.get("domain", dom)
                results[real_domain] = item
        except (StorageError, json.JSONDecodeError):
            # Ignore errors for individual files in the aggregate view
            continue

    return results


@app.get("/health")
async def health(x_auth: str = Header(default="")) -> dict[str, str]:
    _require_auth(x_auth)
    return {"status": "ok"}


@app.get("/version")
async def version(x_auth: str = Header(default="")) -> dict[str, Any]:
    _require_auth(x_auth)
    return {"version": VERSION}
