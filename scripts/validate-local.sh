#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

./scripts/setup-venv.sh

TMP_DATA_DIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMP_DATA_DIR"
}
trap cleanup EXIT

export CHRONIK_TOKEN="${CHRONIK_TOKEN:-dev}"
export CHRONIK_DATA_DIR="$TMP_DATA_DIR"

./.venv/bin/python -m pytest -q

./.venv/bin/python - <<'PY'
import os
import re
from fastapi.testclient import TestClient
from app import app

TOKENS = [token.strip() for token in re.split(r"[,\n]+", os.environ["CHRONIK_TOKEN"]) if token.strip()]
assert TOKENS, "CHRONIK_TOKEN produced no usable token"
headers = {"X-Auth": TOKENS[0]}
client = TestClient(app)

health = client.get("/health", headers=headers)
assert health.status_code == 200, health.text

version = client.get("/version", headers=headers)
assert version.status_code == 200, version.text

event = {
    "schema_version": "agent-ledger.v0",
    "event_id": "01JZ0000000000000000000000",
    "kind": "agent.run.completed",
    "ts": "2026-07-02T12:00:00Z",
    "source": {
        "repo": "heimgewebe/grabowski",
        "component": "grabowski",
        "run_id": "local-validation-smoke",
    },
    "subject": {
        "repo": "heimgewebe/chronik",
        "branch": "local-validation",
        "head": "local",
    },
    "trust_tier": "declared",
    "status": "active",
    "caused_by": [],
    "evidence_refs": ["local-validation"],
    "data": {"result": "completed"},
}

ingest = client.post(
    "/v1/ingest?domain=agent.ledger",
    json=event,
    headers=headers,
)
assert ingest.status_code == 202, ingest.text

events = client.get(
    "/v1/events?domain=agent.ledger&limit=10",
    headers=headers,
)
assert events.status_code == 200, events.text
body = events.json()
assert body["meta"]["count"] == 1, body
assert body["events"][0]["payload"]["kind"] == "agent.run.completed", body

print("local validation smoke ok")
PY
