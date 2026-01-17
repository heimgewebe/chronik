import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from starlette.concurrency import run_in_threadpool

from storage import (
    write_payload,
    list_domains,
    read_last_line,
    sanitize_domain,
)

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
            except Exception as exc:
                logger.error(f"Integrity sync failed: {exc}")

            await asyncio.sleep(self.fetch_interval)

    async def sync_all(self):
        """Fetch sources and update state for each."""
        sources = await self.fetch_sources()
        if not sources:
            logger.warning("No integrity sources found")
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
                    return data
                except Exception as exc:
                    logger.error(f"Failed to load override file: {exc}")
            else:
                # Try parsing as JSON string
                try:
                    data = json.loads(self.override)
                    logger.info("Loaded integrity sources from ENV JSON")
                    return data
                except json.JSONDecodeError:
                    logger.warning("INTEGRITY_SOURCES_OVERRIDE is neither file nor valid JSON")

        # 2. URL
        if not self.sources_url:
            return None

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(self.sources_url, timeout=10.0)
                resp.raise_for_status()
                data = resp.json()

                if data.get("apiVersion") != "integrity.sources.v1":
                    logger.warning(f"Unknown integrity apiVersion: {data.get('apiVersion')}")

                return data
        except Exception as exc:
            logger.error(f"Failed to fetch integrity sources from {self.sources_url}: {exc}")
            return None

    async def _fetch_and_update(self, client: httpx.AsyncClient, repo: str, url: str):
        received_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        domain = self._repo_to_domain(repo)

        status = "MISSING"
        payload_data = {}

        try:
            resp = await client.get(url, timeout=10.0)
            if resp.status_code == 200:
                try:
                    report = resp.json()
                    # Validate/Normalize
                    # "kind" must be in payload to be identified later if we used the generic storage
                    # but here we are constructing the envelope ourselves.

                    status = report.get("status", "UNCLEAR")
                    payload_data = report
                    # Ensure minimal fields
                    if "generated_at" not in payload_data:
                         payload_data["generated_at"] = received_at # Fallback

                    # Ensure url is present in payload (as requested)
                    if "url" not in payload_data:
                        payload_data["url"] = url

                    # Ensure repo is present
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

        # Create Envelope
        # Note: 'kind' inside payload is crucial for integrity_view filtering in app.py logic
        # (though we might replace that view logic with get_aggregate_view here)

        # We enforce strict schema for the stored event
        payload_data["kind"] = "integrity.summary.published.v1"
        payload_data["status"] = status
        # If we failed, we might not have a full payload, so fill essentials
        if "repo" not in payload_data: payload_data["repo"] = repo
        if "url" not in payload_data: payload_data["url"] = url
        if "generated_at" not in payload_data: payload_data["generated_at"] = received_at

        wrapper = {
            "domain": domain,
            "received_at": received_at,
            "payload": payload_data,
            # No retention needed (unlimited? or standard?)
        }

        # Write to storage
        try:
            lines = [json.dumps(wrapper)]
            await run_in_threadpool(write_payload, domain, lines)
        except Exception as exc:
            logger.error(f"Failed to save integrity state for {repo}: {exc}")

    def _repo_to_domain(self, repo: str) -> str:
        # "owner/name" -> "integrity.owner.name"
        # Sanitize slashes and other unsafe chars
        safe_repo = re.sub(r"[^a-z0-9-]", ".", repo.lower())
        # Remove duplicate dots
        safe_repo = re.sub(r"\.+", ".", safe_repo)
        return f"integrity.{safe_repo}"

    async def get_aggregate_view(self) -> dict[str, Any]:
        """Return the aggregated view of all integrity states."""
        domains = await run_in_threadpool(list_domains, "integrity")
        repos = []
        worst_severity = 0
        total_status = "OK"

        for dom in domains:
            try:
                line = await run_in_threadpool(read_last_line, dom)
                if not line:
                    continue

                item = json.loads(line)
                payload = item.get("payload", {})

                # Check kind
                if payload.get("kind") != "integrity.summary.published.v1":
                    continue

                status = payload.get("status", "UNCLEAR")

                # Update total status
                severity = STATUS_SEVERITY.get(status, 100) # Unknown = super bad
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
