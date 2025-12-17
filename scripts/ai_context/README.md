# ai_context tooling

## validate_ai_context.py

Validiert `.ai-context.yml` (Repo-Root) und optional Templates unter `ai-contexts/`.

### Was wird geprüft?
- YAML parsebar
- `project.name`, `project.summary`, `project.role` vorhanden und nicht leer
- `ai_guidance.do` und `ai_guidance.dont` vorhanden und nicht leer
- keine offensichtlichen Platzhalter: TODO / TBD / FIXME / lorem / ipsum

### Rollout-Logik (Patch in alle Repos einspeisen)
- In NON-metarepo Repos reicht die Root-Datei: `/.ai-context.yml`
- Template-Validierung (`--templates-dir`) läuft nur, wenn `ai-contexts/` existiert

### Beispiele

Repo-Root prüfen:
python scripts/ai_context/validate_ai_context.py --file .ai-context.yml

Templates prüfen (metarepo):
python scripts/ai_context/validate_ai_context.py --templates-dir ai-contexts
