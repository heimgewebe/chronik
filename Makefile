PORT := $(if $(CHRONIK_PORT),$(CHRONIK_PORT),8788)
AUTH_TOKEN := $(if $(CHRONIK_TOKEN),$(CHRONIK_TOKEN))

.PHONY: dev ingest-test ensure-token

dev:
	uvicorn app:app --reload --port $(PORT)

ingest-test: ensure-token
	curl --fail-with-body -sS -X POST "http://localhost:$(PORT)/v1/ingest?domain=aussen" \
	-H "Content-Type: application/json" \
	-H "X-Auth: $(AUTH_TOKEN)" \
	-d '{"event": "demo", "status": "ok"}'

ensure-token:
	@if [ -z "$${CHRONIK_TOKEN}" ]; then \
	echo "CHRONIK_TOKEN is undefined" >&2; \
	exit 1; \
	fi
