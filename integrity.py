import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
from starlette.concurrency import run_in_threadpool

from storage import (
    write_payload,
    list_domains,
    read_last_line,
    sanitize_domain,
)

from validation import parse_iso_ts

logger = logging.getLogger(__name__)

# Ranking: lower index = better status.
# But we want "worst of". So we map status to severity, higher is worse.
STATUS_SEVERITY = {
    "OK": 0,
    "UNCLEAR": 10,
    "WARN": 20,
    "MISSING": 30,
    "FAIL": 40,
}

ALLOWED_STATUS = set(STATUS_SEVERITY.keys())

def normalize_status(value: Any) -> str:
    """Normalize status to contract-allowed values. Unknown -> UNCLEAR."""
    if not isinstance(value, str):
        return "UNCLEAR"
    v = value.strip().upper()
    return v if v in ALLOWED_STATUS else "UNCLEAR"

DEFAULT_SOURCES_URL = "https://github.com/heimgewebe/metarepo/releases/download/integrity/sources.v1.json"

# Concurrency limit for integrity aggregation to prevent threadpool starvation.
# Default is 20, which is safe for standard Starlette/AnyIO threadpools.
try:
    INTEGRITY_CONCURRENCY_LIMIT = int(os.getenv("CHRONIK_INTEGRITY_CONCURRENCY", "20"))
except ValueError:
    INTEGRITY_CONCURRENCY_LIMIT = 20

def get_current_utc_str() -> str:
    """Return current UTC time in strict ISO8601 format (Z-suffix)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class IntegrityManager:
    def __init__(self):
        self.sources_url = os.getenv("INTEGRITY_SOURCES_URL", DEFAULT_SOURCES_URL)
        self.override = os.getenv("INTEGRITY_SOURCES_OVERRIDE")
        self.fetch_interval = int(os.getenv("INTEGRITY_FETCH_INTERVAL_SEC", "300"))
        # Default 10 min tolerance for future timestamps
        self.future_tolerance_min = int(os.getenv("INTEGRITY_FUTURE_TOLERANCE_MIN", "10"))
        self._running = False

    async def loop(self):
        """Background loop to sync integrity data."""
        self._running = True
        logger.info("Integrity sync loop started")
        while self._running:
            try:
                await self.sync_all()
            except asyncio.CancelledError:
                logger.info("Integrity sync loop cancelled")
                break
            except Exception as exc:
                logger.error(f"Integrity sync failed: {exc}")

            try:
                await asyncio.sleep(self.fetch_interval)
            except asyncio.CancelledError:
                logger.info("Integrity sync loop cancelled during sleep")
                break

    def stop(self):
        """Signal the loop to stop."""
        self._running = False

    async def sync_all(self):
        """Fetch sources and update state for each."""
        # Reuse client for both sources fetch and individual reports
        async with httpx.AsyncClient(timeout=10.0) as client:
            sources = await self.fetch_sources(client)
            if not sources:
                logger.warning("No integrity sources found or invalid source data")
                return

            sem = asyncio.Semaphore(INTEGRITY_CONCURRENCY_LIMIT)

            async def _bounded_fetch(repo, url):
                async with sem:
                    await self._fetch_and_update(client, repo, url)

            tasks = []
            for source in sources.get("sources", []):
                if not source.get("enabled", True):
                    continue

                repo = source.get("repo")
                url = source.get("summary_url")
                if not repo or not url:
                    continue

                tasks.append(_bounded_fetch(repo, url))

            if tasks:
                await asyncio.gather(*tasks)

    async def fetch_sources(self, client: httpx.AsyncClient = None) -> dict[str, Any] | None:
        """Load sources from override or URL."""
        # 1. Override
        if self.override:
            # Check if it's a file path
            if os.path.exists(self.override):
                try:
                    with open(self.override, "r") as f:
                        data = json.load(f)
                    logger.info(f"Loaded integrity sources from file: {self.override}")
                    return self._validate_sources_data(data)
                except Exception as exc:
                    logger.error(f"Failed to load override file: {exc}")
                    return None
            else:
                # Try parsing as JSON string
                try:
                    data = json.loads(self.override)
                    logger.info("Loaded integrity sources from ENV JSON")
                    return self._validate_sources_data(data)
                except json.JSONDecodeError:
                    logger.warning("INTEGRITY_SOURCES_OVERRIDE is neither file nor valid JSON")
                    return None

        # 2. URL
        if not self.sources_url:
            return None

        # If no client provided, use a transient one (e.g. tests calling this directly)
        if client:
            return await self._fetch_sources_http(client)
        else:
            async with httpx.AsyncClient(timeout=10.0) as temp_client:
                return await self._fetch_sources_http(temp_client)

    async def _fetch_sources_http(self, client: httpx.AsyncClient) -> dict[str, Any] | None:
        try:
            resp = await client.get(self.sources_url)
            resp.raise_for_status()
            data = resp.json()
            return self._validate_sources_data(data)
        except Exception as exc:
            logger.error(f"Failed to fetch integrity sources from {self.sources_url}: {exc}")
            return None

    def _validate_sources_data(self, data: Any) -> dict[str, Any] | None:
        """Validate the sources data structure."""
        if not isinstance(data, dict):
            logger.error("Integrity sources data must be a dictionary")
            return None

        api_version = data.get("apiVersion")
        if api_version != "integrity.sources.v1":
            logger.error(f"Unsupported integrity apiVersion: {api_version}")
            return None

        # Validate generated_at (required by schema)
        generated_at = data.get("generated_at")
        if not generated_at or not isinstance(generated_at, str) or parse_iso_ts(generated_at) is None:
            logger.error(f"Integrity sources invalid/missing generated_at: {generated_at}")
            return None

        raw_sources = data.get("sources", [])
        if not isinstance(raw_sources, list):
            logger.error("Integrity sources 'sources' field must be a list")
            return None

        valid_sources = []
        for item in raw_sources:
            if not isinstance(item, dict):
                logger.warning(f"Skipping invalid source item (not a dict): {item}")
                continue

            # Use copy to avoid mutating input dict
            new_item = dict(item)
            repo = new_item.get("repo")
            url = new_item.get("summary_url")
            enabled = new_item.get("enabled")

            if not isinstance(repo, str) or not repo:
                logger.warning(f"Skipping invalid source item (missing/invalid repo): {item}")
                continue

            if not isinstance(url, str) or not url:
                logger.warning(f"Skipping invalid source item (missing/invalid summary_url): {item}")
                continue

            if enabled is not None and not isinstance(enabled, bool):
                logger.warning(f"Skipping invalid source item (enabled not bool): {item}")
                continue

            # Default enabled to True if missing (Contract: optional, default True)
            if enabled is None:
                new_item["enabled"] = True

            valid_sources.append(new_item)

        if not valid_sources and raw_sources:
            logger.warning("No valid sources found after filtering")
            return None

        data["sources"] = valid_sources
        return data

    async def _fetch_and_update(self, client: httpx.AsyncClient, repo: str, url: str):
        received_at = get_current_utc_str()
        domain = self._repo_to_domain(repo)

        payload_data = {}
        invalid_new_generated_at = False
        error_reason = None

        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                try:
                    report = resp.json()
                    status = normalize_status(report.get("status", "UNCLEAR"))
                    # Create copy to avoid mutating cache
                    payload_data = dict(report)

                    # Ensure minimal fields in payload (report contract)
                    if "generated_at" not in payload_data:
                        # Missing timestamp -> FAIL and sanitize
                        invalid_new_generated_at = True
                        status = "FAIL"
                        error_reason = "Missing generated_at"
                    else:
                        # Validate generated_at is parseable ISO
                        parsed_dt = parse_iso_ts(payload_data.get("generated_at"))
                        if parsed_dt is None:
                            invalid_new_generated_at = True
                            status = "FAIL"
                            error_reason = "Invalid timestamp format"
                        else:
                            # Sanity check: Future timestamps (> tolerance) are invalid
                            # This prevents frozen state if a producer clock is wrong
                            future_limit = datetime.now(timezone.utc) + timedelta(minutes=self.future_tolerance_min)
                            if parsed_dt > future_limit:
                                logger.warning(f"Future timestamp detected for {repo}: {parsed_dt}")
                                invalid_new_generated_at = True
                                status = "FAIL"
                                error_reason = "Future timestamp detected"

                    if "url" not in payload_data:
                        payload_data["url"] = url

                    if "repo" not in payload_data or not payload_data["repo"]:
                        # Missing or empty repo in report is a contract violation
                        status = "FAIL"
                        error_reason = "Missing or empty repo in report"
                        payload_data["repo"] = repo # Fallback to source repo

                except ValueError as exc:
                    status = "FAIL" # Schema/Parse fail
                    error_reason = f"Invalid JSON: {str(exc)}"
                    logger.warning(f"Integrity JSON parse failed for {repo} ({url}): {exc}")
            else:
                logger.warning(f"Integrity fetch failed for {repo}: {resp.status_code}")
                status = "MISSING"
                error_reason = f"HTTP {resp.status_code}"
        except Exception as exc:
            logger.warning(f"Integrity fetch exception for {repo}: {exc}")
            status = "MISSING"
            error_reason = f"Network Error: {str(exc)}"

        # Check Latest Semantics (Optimistic concurrency control manually)
        new_generated_at = payload_data.get("generated_at")
        current_line = await run_in_threadpool(read_last_line, domain)

        current_payload = {}
        curr_dt = None
        has_current_state = False

        if current_line:
            try:
                current_item = json.loads(current_line)
                current_payload = current_item.get("payload", {})
                current_generated_at = current_payload.get("generated_at")
                curr_dt = parse_iso_ts(current_generated_at) if current_generated_at else None
                has_current_state = True
            except (json.JSONDecodeError, ValueError):
                # Corrupt current state, treat as no state
                pass

        # Stability Logic:
        # If fetch failed (MISSING) and we have a valid current state, preserve it.
        # Don't overwrite known truth with transient network failure.
        if status == "MISSING" and has_current_state:
            logger.debug(f"Preserving existing state for {repo} despite fetch failure")
            return

        if has_current_state:
            # If new generated_at invalid, preserve valid current state
            if invalid_new_generated_at and curr_dt:
                logger.warning(
                    f"Skipping overwrite for {repo}: invalid generated_at in fetched report "
                    f"({new_generated_at!r}); keeping current ({current_payload.get('generated_at')!r})"
                )
                return

            new_dt = parse_iso_ts(new_generated_at) if new_generated_at else None

            # Update logic:
            # - Skip if older or equal (<=) to prevent redundant writes/churn.
            if new_dt and curr_dt and new_dt <= curr_dt:
                # New report is older or same, skip update
                logger.debug(f"Skipping update for {repo}: {new_generated_at} <= {current_payload.get('generated_at')}")
                return

        # If we failed fetch/parse (and didn't return early), we synthesize a minimal payload
        if not payload_data:
            payload_data = {
                "repo": repo,
                "url": url,
                "status": normalize_status(status),
                "generated_at": received_at
            }
        else:
            # Ensure status is updated in payload if we overrode it (e.g. FAIL/UNCLEAR logic)
            payload_data["status"] = normalize_status(status)

            # Sanitization Strategy (Path B):
            # If generated_at was invalid/missing and we are allowed to write,
            # normalize it to received_at AND mark it explicitly.
            if invalid_new_generated_at:
                payload_data["generated_at"] = received_at
                payload_data["generated_at_sanitized"] = True
            else:
                # Ensure flag is absent if valid
                payload_data.pop("generated_at_sanitized", None)

        # Create Envelope
        # Strict Schema: kind is in wrapper, not payload
        wrapper = {
            "domain": domain,
            "kind": "integrity.summary.published.v1",
            "received_at": received_at,
            "payload": payload_data,
        }

        # Add meta with error reason if available
        if error_reason:
            wrapper["meta"] = {"error_reason": error_reason}

        # Write to storage
        try:
            lines = [json.dumps(wrapper)]
            await run_in_threadpool(write_payload, domain, lines)
        except Exception as exc:
            logger.error(f"Failed to save integrity state for {repo}: {exc}")

    def _repo_to_domain(self, repo: str) -> str:
        # Canonicalize using sanitize_domain
        # Strategy: integrity.owner.repo
        # We replace '/' with '.' and let sanitize_domain handle the rest
        base = "integrity." + repo.replace("/", ".")
        try:
            return sanitize_domain(base)
        except Exception:
            # Fallback for very weird characters: purely alphanumeric + dots
            safe_repo = re.sub(r"[^a-z0-9-]", ".", repo.lower())
            safe_repo = re.sub(r"\.+", ".", safe_repo)
            return f"integrity.{safe_repo}"

    async def get_aggregate_view(self) -> dict[str, Any]:
        """Return the aggregated view of all integrity states."""
        domains = await run_in_threadpool(list_domains, "integrity")
        repos = []
        worst_severity = 0
        total_status = "MISSING" # Default to MISSING if no repos found

        found_any = False

        # Use bounded task creation to prevent memory overhead for large N
        async def _bounded_process(dom):
            return await run_in_threadpool(self._process_domain_state_sync, dom)

        pending = set()
        it = iter(domains)

        def _fill_tasks():
            while len(pending) < INTEGRITY_CONCURRENCY_LIMIT:
                try:
                    dom = next(it)
                except StopIteration:
                    return
                task = asyncio.create_task(_bounded_process(dom))
                pending.add(task)

        _fill_tasks()

        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                try:
                    payload = t.result()
                    if not payload:
                        continue

                    status = payload["status"]
                    # Update total status
                    severity = STATUS_SEVERITY.get(status, 100) # Unknown = super bad
                    if not found_any:
                        # First item initializes status
                        worst_severity = severity
                        total_status = status
                        found_any = True
                    else:
                        if severity > worst_severity:
                            worst_severity = severity
                            total_status = status

                    repos.append(payload)
                except Exception as exc:
                    logger.debug("Aggregate task failed: %s", exc)

            _fill_tasks()

        # Sort repos by name for deterministic output
        repos.sort(key=lambda x: x.get("repo", ""))

        return {
            "as_of": get_current_utc_str(),
            "total_status": total_status,
            "repos": repos
        }

    def _process_domain_state_sync(self, dom: str) -> dict[str, Any] | None:
        """Process a single domain synchronously."""
        try:
            line = read_last_line(dom)
            if not line:
                return None

            item = json.loads(line)

            payload = item.get("payload", {})
            # Make a copy to avoid side-effects on the stored dict if reused
            payload = payload.copy()

            # Check kind in wrapper (Canonical)
            if item.get("kind") == "integrity.summary.published.v1":
                pass # Canonical path
            # Backward compatibility: check payload.kind/type if wrapper.kind missing
            elif payload.get("kind") == "integrity.summary.published.v1":
                payload["legacy"] = True
            elif payload.get("type") == "integrity.summary.published.v1":
                payload["legacy"] = True
            # Optional: wrapper type fallback
            elif item.get("type") == "integrity.summary.published.v1":
                payload["legacy"] = True
            else:
                # Junk or unrelated event
                return None

            status = normalize_status(payload.get("status", "UNCLEAR"))
            payload["status"] = status
            return payload
        except Exception as exc:
            # Log at debug level to avoid spamming, but allow inspection
            logger.debug("Failed to process integrity domain %s: %s", dom, exc)
            return None
