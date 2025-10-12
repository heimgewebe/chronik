from fastapi import FastAPI, Request, Header
from fastapi.responses import PlainTextResponse
import json, pathlib, os
app = FastAPI(title="leitstand-ingest")
DATA = pathlib.Path("data"); DATA.mkdir(parents=True, exist_ok=True)
SECRET = os.environ.get("LEITSTAND_TOKEN","")
@app.post("/ingest/{domain}")
async def ingest(domain: str, req: Request, x_auth: str = Header(default="")):
    if SECRET and x_auth != SECRET:
        return PlainTextResponse("unauthorized", status_code=401)
    try:
        obj = json.loads((await req.body()).decode("utf-8"))
    except Exception:
        return PlainTextResponse("invalid json", status_code=400)
    # Only allow alphanumerics, dash, underscore in domain
    import re
    safe_domain = re.sub(r"[^a-zA-Z0-9_-]", "_", domain)
    target_path = (DATA / f"{safe_domain}.jsonl").resolve()
    if DATA.resolve() not in target_path.parents:
        return PlainTextResponse("invalid domain", status_code=400)
    target_path.open("a", encoding="utf-8").write(json.dumps(obj, ensure_ascii=False)+"\n")
    return PlainTextResponse("ok")
