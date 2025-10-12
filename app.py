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
    (DATA / f"{domain}.jsonl}").open("a", encoding="utf-8").write(json.dumps(obj, ensure_ascii=False)+"\n")
    return PlainTextResponse("ok")
