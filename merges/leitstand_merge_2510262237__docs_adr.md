### 📄 docs/adr/0001-python-fastapi-panels.md

**Größe:** 340 B | **md5:** `4af2d5ce2d5fb8a77410968008b21b26`

```markdown
# ADR-0001: Python/FastAPI für Ingest & Panels
Status: Accepted
Date: 2025-10-12

## Kontext
Schnelle IO/UI-Iteration, geringe Einstiegshürde.

## Entscheidung
- Python (FastAPI) für Ingest, später Panels.

## Konsequenzen
- Schneller MVP; bei Bedarf Rust-Worker daneben.

## Alternativen
- Rust-Only: mehr Entwicklungsaufwand für UI.
```

### 📄 docs/adr/0002-data-jsonl-per-domain.md

**Größe:** 398 B | **md5:** `6de517f4f3af39e46f5946161e11df57`

```markdown
# ADR-0002: Per-Domain JSONL in `data/` + verpflichtendes Token
Status: Accepted
Date: 2025-10-12

## Kontext
Einfacher Speicher für eingehende Events.

## Entscheidung
- Append-only `data/{domain}.jsonl`
- Header `x-auth` ist verpflichtend und muss mit `LEITSTAND_TOKEN` übereinstimmen

## Konsequenzen
- Einfach zu debuggen; Logs git-ignorieren.

## Alternativen
- DB früh: unnötig für MVP.
```

### 📄 docs/adr/README.md

**Größe:** 219 B | **md5:** `ba08bde8bf1388440cc252feda49a816`

```markdown
# Architekturentscheidungsaufzeichnungen (ADR)

- [ADR-0001: Python/FastAPI für Ingest & Panels](0001-python-fastapi-panels.md)
- [ADR-0002: Per-Domain JSONL in `data/` + optional Token](0002-data-jsonl-per-domain.md)
```

