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

DEFAULT_SOURCES_URL = "https://raw.githubusercontent.com/heimgewebe/metarepo/main/reports/integrity/sources.v1.json"


class IntegrityManager:
    def __init__(self):
        self.sources_url = os.getenv("INTEGRITY_SOURCES_URL", DEFAULT_SOURCES_URL)
        self.override = os.getenv("INTEGRITY_SOURCES_OVERRIDE")
        self.fetch_interval = int(os.getenv("INTEGRITY_FETCH_INTERVAL_SEC", "300"))
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
        sources = await self.fetch_sources()
        if not sources:
            logger.warning("No integrity sources found or invalid source data")
            return

        async with httpx.AsyncClient() as client:
            for source in sources.get("sources", []):
                if not source.get("enabled", True):
                    continue

                repo = source.get("repo")
                url = source.get("summary_url")
                if not repo or not url:
                    continue

                await self._fetch_and_update(client, repo, url)

    async def fetch_sources(self) -> dict[str, Any] | None:
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
                    # If override fails, do we fallback? Strict behavior suggests failing or returning None.
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

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(self.sources_url, timeout=10.0)
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

        return data

    async def _fetch_and_update(self, client: httpx.AsyncClient, repo: str, url: str):
        received_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        domain = self._repo_to_domain(repo)

        status = "MISSING"
        payload_data = {}
        invalid_new_generated_at = False

        try:
            resp = await client.get(url, timeout=10.0)
            if resp.status_code == 200:
                try:
                    report = resp.json()
                    status = normalize_status(report.get("status", "UNCLEAR"))
                    payload_data = report

                    # Ensure minimal fields in payload (report contract)
                    if "generated_at" not in payload_data:
                         payload_data["generated_at"] = received_at # Fallback
                    else:
                        # Validate generated_at is parseable ISO
                        parsed_dt = parse_iso_ts(payload_data.get("generated_at"))
                        if parsed_dt is None:
                            invalid_new_generated_at = True
                            status = "FAIL"
                        else:
                             # Sanity check: Future timestamps (> 10 mins) are invalid
                             # This prevents frozen state if a producer clock is wrong
                             future_limit = datetime.now(timezone.utc) + timedelta(minutes=10)
                             if parsed_dt > future_limit:
                                 logger.warning(f"Future timestamp detected for {repo}: {parsed_dt}")
                                 invalid_new_generated_at = True
                                 status = "FAIL"

                    if "url" not in payload_data:
                        payload_data["url"] = url

                    if "repo" not in payload_data:
                        payload_data["repo"] = repo

                except json.JSONDecodeError:
                    status = "FAIL" # Schema/Parse fail
            else:
                logger.warning(f"Integrity fetch failed for {repo}: {resp.status_code}")
                status = "MISSING"
        except Exception as exc:
            logger.warning(f"Integrity fetch exception for {repo}: {exc}")
            status = "MISSING"

        # Check Latest Semantics (Optimistic concurrency control manually)
        new_generated_at = payload_data.get("generated_at")
        current_line = await run_in_threadpool(read_last_line, domain)
        if current_line:
            try:
                current_item = json.loads(current_line)
                current_payload = current_item.get("payload", {})
                current_generated_at = current_payload.get("generated_at")

                curr_dt = parse_iso_ts(current_generated_at) if current_generated_at else None
                new_dt = parse_iso_ts(new_generated_at) if new_generated_at else None

                if invalid_new_generated_at and curr_dt:
                    logger.warning(
                        f"Skipping overwrite for {repo}: invalid generated_at in fetched report "
                        f"({new_generated_at!r}); keeping current ({current_generated_at!r})"
                    )
                    return

                # Update logic:
                # - Skip only if STRICTLY older (<).
                # - If equal (==), we overwrite (last-writer-wins / idempotency).
                if new_dt and curr_dt and new_dt < curr_dt:
                        # New report is older, skip update
                        logger.debug(f"Skipping update for {repo}: {new_generated_at} < {current_generated_at}")
                        return
            except (json.JSONDecodeError, ValueError):
                pass # corrupt current state, overwrite safe

        # If we failed fetch/parse, we synthesize a minimal payload to report status
        if not payload_data:
            payload_data = {
                "repo": repo,
                "url": url,
                "status": normalize_status(status),
                "generated_at": received_at
            }
        else:
            # Ensure status is updated in payload if we overrode it (e.g. FAIL/UNCLEAR logic)
            # But normally we trust the report's status unless fetch failed.
            if status in ["MISSING", "FAIL", "UNCLEAR"] and payload_data.get("status") != status:
                 payload_data["status"] = normalize_status(status)
            else:
                 payload_data["status"] = normalize_status(payload_data.get("status", status))

            # If generated_at was invalid and we are allowed to write (no current valid state),
            # normalize it to received_at so the stored state is parseable downstream.
            if invalid_new_generated_at:
                payload_data["generated_at"] = received_at

        # Create Envelope
        # Strict Schema: kind is in wrapper, not payload
        wrapper = {
            "domain": domain,
            "kind": "integrity.summary.published.v1",
            "received_at": received_at,
            "payload": payload_data,
        }

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

        for dom in domains:
            try:
                line = await run_in_threadpool(read_last_line, dom)
                if not line:
                    continue

                item = json.loads(line)

                # Check kind in wrapper
                if item.get("kind") != "integrity.summary.published.v1":
                    # Backward compatibility or junk filtering
                    # If kind not in wrapper, check payload (old way) just in case
                    payload = item.get("payload", {})
                    if payload.get("kind") != "integrity.summary.published.v1":
                        continue

                payload = item.get("payload", {})
                # Make a copy to avoid side-effects on the stored dict if reused
                payload = payload.copy()

                status = normalize_status(payload.get("status", "UNCLEAR"))
                payload["status"] = status

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

            except Exception:
                continue

        # Sort repos by name for deterministic output
        repos.sort(key=lambda x: x.get("repo", ""))

        return {
            "total_status": total_status,
            "repos": repos
        }

# Global singleton instance
manager = IntegrityManager()
