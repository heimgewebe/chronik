# ADR-0002: Per-Domain JSONL in `data/` + optional Token
Status: Accepted
Date: 2025-10-12

## Kontext
Einfacher Speicher für eingehende Events.

## Entscheidung
- Append-only `data/{domain}.jsonl`
- Optionaler Header `x-auth` mit `LEITSTAND_TOKEN`

## Konsequenzen
- Einfach zu debuggen; Logs git-ignorieren.

## Alternativen
- DB früh: unnötig für MVP.
