#!/usr/bin/env bash
set -euo pipefail

if [ -z "${CHRONIK_TOKEN:-}" ]; then
  echo "ERROR: CHRONIK_TOKEN is required in ~/.config/chronik/chronik.env" >&2
  exit 78
fi

CHRONIK_ROOT="${CHRONIK_ROOT:-$HOME/repos/chronik}"
CHRONIK_HOST="${CHRONIK_HOST:-127.0.0.1}"
CHRONIK_PORT="${CHRONIK_PORT:-8788}"
CHRONIK_DATA_DIR="${CHRONIK_DATA_DIR:-$HOME/.local/state/chronik/data}"

mkdir -p "$CHRONIK_DATA_DIR"
cd "$CHRONIK_ROOT"
exec .venv/bin/uvicorn app:app --host "$CHRONIK_HOST" --port "$CHRONIK_PORT"
