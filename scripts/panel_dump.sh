#!/usr/bin/env bash
set -euo pipefail
domain="${1:-pc}"
file="data/${domain}.jsonl"
[ -f "$file" ] && cat "$file" || true
