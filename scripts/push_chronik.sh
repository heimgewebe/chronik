#!/usr/bin/env bash
# Push die letzten N Meldungen aus einer JSONL/JSON-Stream-Datei sicher zum Chronik.
# Multiline/pretty-printed Einträge werden vorab zu 1-Zeilen-Objekten verdichtet.
set -euo pipefail

# Eingaben
: "${FILE:?Pfad zur JSONL/JSON-Stream-Datei fehlt (FILE)}"
: "${URL:?Basis-URL vom Chronik fehlt (URL)}"
: "${DOMAIN:?Domain fehlt (DOMAIN)}"
: "${N:?Anzahl letzter Events fehlt (N)}"

need() { command -v "$1" >/dev/null 2>&1 || {
  echo "Fehlt: $1" >&2
  exit 127
}; }
need jq
need curl

TOKEN="${CHRONIK_TOKEN:-}"
: "${TOKEN:?CHRONIK_TOKEN fehlt}"

# 1) Kompakter JSON-Stream: Jede Zeile = ein vollständiges JSON-Objekt.
#    jq liest robuste JSON-Streams (mehrere JSON-Werte hintereinander, auch pretty-printed).
#    Danach nehmen wir die letzten N Objekte.
jq -c . "$FILE" | tail -n "$N" | while IFS= read -r line; do
  # Skip leere Zeilen (sollte mit jq -c nicht vorkommen, aber sicher ist sicher)
  [ -z "$line" ] && continue
  # 2) POST an /ingest/<domain>
  curl -fsS \
    -H 'content-type: application/json' \
    -H "x-auth: ${TOKEN}" \
    --data-binary "$line" \
    "${URL%/}/ingest/$DOMAIN"
done

echo "✓ Gesendet: letzte ${N} Events aus $(basename "$FILE") → ${URL%/}/ingest/$DOMAIN" >&2
