# OS Context Ingest (mitschreiber → chronik)

chronik ist Single Point of Ingest, Audit & Panels.

## Endpoints
- `POST /v1/ingest?domain=os.context.state`
- `POST /v1/ingest?domain=os.context.text.embed`

### Auth
- Lokaler Token (env/Secret); mTLS empfohlen, wenn getrennte Prozesse/Hosts.

### Beispiel-Requests
```http
POST /v1/ingest?domain=os.context.state
{
  "ts": "...",
  "source": "os.context.state",
  "app": "code",
  "window": "projX/main.py — VSCode",
  "focus": true,
  "activity_rpm": 240
}
```

```http
POST /v1/ingest?domain=os.context.text.embed
{
  "ts": "...",
  "source": "os.context.text.embed",
  "app": "code",
  "window": "projX/main.py",
  "keyphrases": ["oauth flow", "retry policy"],
  "embedding": [0.012, -0.034, ...],
  "hash_id": "sha256:..."
}
```

## Panels

- **Now:** aktive App/Fenster/Focus.
    
- **Privacy:** Redactions/min, Drops{reason}, Rate-Limit hits.
    
- **Scribe:** Embedding-Heatmap pro App/Workspace.
    

## Retention/TTL

- `os.context.text.embed` → regulär (konfigurierbar).
    
- `os.context.text.redacted` → **nicht** persistieren; nur WAL-Debug (falls überhaupt).
    

## Hinweise

- Validierung über metarepo-Reusable (`reusable-validate-jsonl.yml`).
    
- Audit-Trail für Rejects (Blocklist, PII-Gate, RL).
    
