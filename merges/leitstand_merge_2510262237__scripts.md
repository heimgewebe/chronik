### 📄 scripts/ingest_append.py

**Größe:** 1 KB | **md5:** `c6565895a7fe668ad36f0d4a40d7834e`

```python
#!/usr/bin/env python3
"""CLI helper to append JSON payloads in the same format as the API."""

from __future__ import annotations

import json
import sys

from storage import DATA_DIR, DomainError, safe_target_path, sanitize_domain


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: ingest_append.py <domain> <json-payload>", file=sys.stderr)
        return 2

    _, domain, raw_payload = argv

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as exc:
        print(f"invalid json payload: {exc}", file=sys.stderr)
        return 1

    try:
        dom = sanitize_domain(domain)
        target_path = safe_target_path(dom, data_dir=DATA_DIR)
    except DomainError:
        print("invalid domain", file=sys.stderr)
        return 1

    if not isinstance(payload, dict):
        print("payload must be a JSON object", file=sys.stderr)
        return 1

    payload = dict(payload)
    payload["domain"] = dom

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    with target_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    print(str(target_path))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
```

### 📄 scripts/panel_dump.sh

**Größe:** 122 B | **md5:** `c4c2f56243882b4edaaa010ccaa39d76`

```bash
#!/usr/bin/env bash
set -euo pipefail
domain="${1:-pc}"
file="data/${domain}.jsonl"
[ -f "$file" ] && cat "$file" || true
```

### 📄 scripts/push_leitstand.sh

**Größe:** 1 KB | **md5:** `c8f2929cb7e635a5facf735d0568b14a`

```bash
#!/usr/bin/env bash
# Push die letzten N Meldungen aus einer JSONL/JSON-Stream-Datei sicher zum Leitstand.
# Multiline/pretty-printed Einträge werden vorab zu 1-Zeilen-Objekten verdichtet.
set -euo pipefail

# Eingaben
: "${FILE:?Pfad zur JSONL/JSON-Stream-Datei fehlt (FILE)}"
: "${URL:?Basis-URL vom Leitstand fehlt (URL)}"
: "${DOMAIN:?Domain fehlt (DOMAIN)}"
: "${N:?Anzahl letzter Events fehlt (N)}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Fehlt: $1" >&2; exit 127; }; }
need jq
need curl

# 1) Kompakter JSON-Stream: Jede Zeile = ein vollständiges JSON-Objekt.
#    jq liest robuste JSON-Streams (mehrere JSON-Werte hintereinander, auch pretty-printed).
#    Danach nehmen wir die letzten N Objekte.
jq -c . "$FILE" | tail -n "$N" | while IFS= read -r line; do
  # Skip leere Zeilen (sollte mit jq -c nicht vorkommen, aber sicher ist sicher)
  [ -z "$line" ] && continue
  # 2) POST an /ingest/<domain>
  if [ -n "${LEITSTAND_TOKEN:-}" ]; then
    curl -fsS \
      -H 'content-type: application/json' \
      -H "x-auth: ${LEITSTAND_TOKEN}" \
      --data-binary "$line" \
      "${URL%/}/ingest/$DOMAIN"
  else
    curl -fsS \
      -H 'content-type: application/json' \
      --data-binary "$line" \
      "${URL%/}/ingest/$DOMAIN"
  fi
done

echo "✓ Gesendet: letzte ${N} Events aus $(basename "$FILE") → ${URL%/}/ingest/$DOMAIN" >&2
```

