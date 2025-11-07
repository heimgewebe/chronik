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


# Beispiel: 429 Retry mit Curl (exponentieller Backoff, bis zu 5 Versuche)
```bash
for i in 1 2 3 4 5; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Auth:$LEITSTAND_TOKEN" -H "Content-Type: application/json" \
    -d '{"event":"batch","status":"ok"}' \
    http://localhost:8788/ingest/example.com)
  [ "$code" = "200" ] && echo ok && break
  [ "$code" != "429" ] && echo "fail:$code" && exit 1
  sleep $((2**i))
done
```
