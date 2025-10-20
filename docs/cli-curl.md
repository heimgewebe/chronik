# Curl-Cheatsheet
```bash
# Health
curl -H "X-Auth:$LEITSTAND_TOKEN" http://localhost:8788/health

# Version
curl -H "X-Auth:$LEITSTAND_TOKEN" http://localhost:8788/version

# Ingest Beispiel
curl -X POST "http://localhost:8788/ingest/example.com" \
  -H "Content-Type: application/json" -H "X-Auth: $LEITSTAND_TOKEN" \
  -d '{"event":"deploy","status":"success"}'

# Ingest Array (schreibt zwei JSONL-Zeilen)
curl -X POST "http://localhost:8788/ingest/example.com" \
  -H "Content-Type: application/json" -H "X-Auth: $LEITSTAND_TOKEN" \
  -d '[{"event":"deploy","status":"success"},{"event":"deploy","status":"rollback"}]'

# Ergebnis prüfen (jede Zeile ein Ereignis)
cat "$LEITSTAND_DATA_DIR/example.com.jsonl"

```

