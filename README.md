# leitstand

## Run (Codex/Codespaces)
```
pip install -r requirements.txt
export LEITSTAND_TOKEN=$(openssl rand -hex 12)   # optional
uvicorn app:app --host 0.0.0.0 --port 8788
# In Codex/Codespaces: Port 8788 → Public schalten, URL kopieren
```
