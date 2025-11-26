PORT := $(if $(CHRONIK_PORT),$(CHRONIK_PORT),$(if $(LEITSTAND_PORT),$(LEITSTAND_PORT),8788))
AUTH_TOKEN := $(if $(CHRONIK_TOKEN),$(CHRONIK_TOKEN),$(LEITSTAND_TOKEN))

.PHONY: dev ingest-test ensure-token

dev:
uvicorn app:app --reload --port $(PORT)

ingest-test: ensure-token
	curl --fail-with-body -sS -X POST "http://localhost:$(PORT)/ingest/aussen" \
	-H "Content-Type: application/json" \
	-H "X-Auth: $(AUTH_TOKEN)" \
	-d '{"event": "demo", "status": "ok"}'

ensure-token:
@if [ -z "$${CHRONIK_TOKEN:-$${LEITSTAND_TOKEN:-}}" ]; then \
echo "CHRONIK_TOKEN is undefined (legacy LEITSTAND_TOKEN also accepted)" >&2; \
exit 1; \
fi
