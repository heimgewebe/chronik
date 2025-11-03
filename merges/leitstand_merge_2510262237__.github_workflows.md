### 📄 .github/workflows/validate-aussen-fixtures.yml

**Größe:** 1 KB | **md5:** `e27e39e8fcedf8853dfdcdbbf63bf675`

```yaml
name: validate (aussen fixtures)
on:
  push:
  pull_request:
  workflow_dispatch:

# Principle of least privilege
permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false

jobs:
  fixtures:
    name: fixtures (aussen JSONL)
    # Nur laufen, wenn mind. eine Fixture existiert
    if: hashFiles('tests/fixtures/aussen/*.jsonl') != ''
    # ⚠️ Pin auf immutablen Tag/Commit (statt main)
    uses: heimgewebe/metarepo/.github/workflows/reusable-validate-jsonl.yml@contracts-v1
    with:
      # Das Reusable erwartet (Fleet-Variante) einen einzelnen Pfad:
      # Für den Anfang prüfen wir die Beispiel-Fixture. Wenn weitere Dateien dazukommen,
      # entweder weitere Jobs anlegen oder das Reusable auf Mehrfachpfade erweitern.
      jsonl_path: tests/fixtures/aussen/sample-ok.jsonl
      # ⚠️ Schema-URL ebenfalls an den gleichen Tag pinnen
      schema_url: https://raw.githubusercontent.com/heimgewebe/metarepo/contracts-v1/contracts/aussen.event.schema.json
      strict: false
      validate_formats: true
```

### 📄 .github/workflows/validate-leitstand-fixtures.yml

**Größe:** 965 B | **md5:** `31acdc7a29704c7bf3f975bbde0ee82a`

```yaml
name: validate-leitstand-fixtures
permissions:
  contents: read

on:
  push:
  pull_request:

jobs:
  fixtures:
    name: fixtures (tests/fixtures/leitstand.jsonl)
    if: hashFiles('tests/fixtures/leitstand.jsonl') != ''
    uses: heimgewebe/metarepo/.github/workflows/reusable-validate-jsonl.yml@codex/add-github-workflows
    with:
      jsonl_path: tests/fixtures/leitstand.jsonl
      schema_url: https://raw.githubusercontent.com/heimgewebe/metarepo/main/contracts/leitstand-fixtures.schema.json
      strict: false
      validate_formats: true

  demo:
    name: demo (demo/leitstand.jsonl)
    if: hashFiles('demo/leitstand.jsonl') != ''
    uses: heimgewebe/metarepo/.github/workflows/reusable-validate-jsonl.yml@codex/add-github-workflows
    with:
      jsonl_path: demo/leitstand.jsonl
      schema_url: https://raw.githubusercontent.com/heimgewebe/metarepo/main/contracts/leitstand-fixtures.schema.json
      strict: false
      validate_formats: true
```

