LEITSTAND_PORT ?= 8788

.PHONY: dev ingest-test ensure-token

dev:
	uvicorn app:app --reload --port $(LEITSTAND_PORT)

ingest-test: ensure-token
	curl --fail-with-body -sS -X POST "http://localhost:$(LEITSTAND_PORT)/ingest/aussen" \
		-H "Content-Type: application/json" \
		-H "X-Auth: $(LEITSTAND_TOKEN)" \
		-d '{"event": "demo", "status": "ok"}'

ensure-token:
	@if [ -z "$${LEITSTAND_TOKEN}" ]; then \
		echo "LEITSTAND_TOKEN is undefined" >&2; \
		exit 1; \
	fi
