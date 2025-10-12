#!/usr/bin/env python3
import sys, os, json
if len(sys.argv) < 3:
    print("usage: ingest_append.py <domain> <json-payload>", file=sys.stderr); sys.exit(2)
domain = sys.argv[1]
payload = json.loads(sys.argv[2])
os.makedirs("data", exist_ok=True)
path = os.path.join("data", f"{domain}.jsonl")
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(payload, ensure_ascii=False) + "\n")
print(path)
