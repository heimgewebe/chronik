#!/usr/bin/env python3
"""Import, query and freeze Chronik coding history without a network service."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
root_path=str(ROOT)
if root_path in sys.path: sys.path.remove(root_path)
sys.path.insert(0,root_path)
import coding_memory

def load(path: Path):
    text=path.read_text(encoding="utf-8").strip()
    if not text: return []
    if path.suffix==".jsonl": return [json.loads(line) for line in text.splitlines() if line.strip()]
    value=json.loads(text); return value if isinstance(value,list) else [value]

def filters(args):
    return {"repo":args.repo,"component":args.component,"operation":args.operation,"outcome":args.outcome,"since":args.since,"limit":args.limit}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir",default=str(Path.home()/".local/state/chronik"))
    sub=parser.add_subparsers(dest="command",required=True)
    imp=sub.add_parser("import"); imp.add_argument("input",type=Path)
    for name in ("query","freeze"):
        p=sub.add_parser(name); p.add_argument("--repo",required=True); p.add_argument("--component"); p.add_argument("--operation",choices=["implement","review","merge","deploy","runtime_verify","recovery"]); p.add_argument("--outcome",choices=["completed","blocked","failed","reverted","outcome_unknown","started"]); p.add_argument("--since"); p.add_argument("--limit",type=int,default=20)
        if name=="freeze": p.add_argument("--output",required=True,type=Path)
    args=parser.parse_args(argv)
    try:
        data_path = Path(args.data_dir).expanduser()
        query_filters = filters(args) if args.command in {"query", "freeze"} else None
        if query_filters is not None:
            coding_memory.validate_query(**query_filters)
        if args.command == "query" and not data_path.exists():
            result = {
                "schema_version": "chronik-coding-history.v1",
                "query": query_filters,
                "events": [],
                "event_ids": [],
                "historical_only": True,
                "does_not_establish": coding_memory.DOES_NOT_ESTABLISH,
            }
            print(json.dumps(result,indent=2,sort_keys=True)); return 0
        coding_memory.configure_data_dir(data_path, create=args.command in {"import", "freeze"})
        if args.command=="import": result=coding_memory.import_events(load(args.input))
        elif args.command=="query": result=coding_memory.query_history(**query_filters)
        else: result=coding_memory.freeze_history(args.output,**query_filters)
    except (OSError,ValueError) as exc:
        print(f"chronik-coding-memory: {exc}",file=sys.stderr); return 2
    print(json.dumps(result,indent=2,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
