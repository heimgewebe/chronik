# leitstand

`leitstand` stellt einen sehr kleinen HTTP-Ingest-Dienst bereit, der strukturierte Ereignisse
als JSON entgegennimmt und domain-spezifisch in JSON Lines Dateien ablegt. Die Anwendung ist in
FastAPI implementiert und lässt sich lokal oder in Codespaces betreiben.

## Quickstart
```bash
git clone <repository-url>
cd leitstand
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8788
```

Sobald der Server läuft, sind die interaktiven API-Dokumente unter
`http://localhost:8788/docs` verfügbar.

## Voraussetzungen
* Python 3.10+
* Abhängigkeiten aus `requirements.txt`

## Installation & Start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# optional: Authentifizierungs-Token setzen
export LEITSTAND_TOKEN=$(openssl rand -hex 12)
# optional: Zielverzeichnis der JSONL-Dateien anpassen
export LEITSTAND_DATA_DIR=./data
uvicorn app:app --host 0.0.0.0 --port 8788
```

In GitHub Codespaces sollte der Port 8788 veröffentlicht werden, um Anfragen an die API senden zu können.

## Konfigurations- und Umgebungsvariablen
| Variable               | Pflicht | Standard | Beschreibung |
|------------------------|:-------:|----------|--------------|
| `LEITSTAND_TOKEN`      | nein    | ``       | Optionales Shared-Secret. Ist es gesetzt, muss jeder Request den Header `X-Auth` mit exakt diesem Wert enthalten. |
| `LEITSTAND_DATA_DIR`   | nein    | `data`   | Zielverzeichnis für die pro Domain erzeugten JSONL-Dateien. Wird beim Start erstellt, falls nicht vorhanden. |

## API
### `POST /ingest/{domain}`
* **Pfadparameter** `domain`: Muss dem Muster  
  `^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(?:\.(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?))*$`  
  entsprechen. Ungültige Werte führen zu `400 invalid domain`.
* **Header** `X-Auth`: erforderlich, wenn `LEITSTAND_TOKEN` gesetzt ist, sonst optional. Fehlerhafte Werte führen zu `401 unauthorized`.
* **Request-Body**: UTF-8-kodiertes JSON-Objekt oder -Array. Einzelne Objekte ohne `domain`-Feld erhalten automatisch das Feld `domain` mit dem bereinigten Domainnamen.
* **Antwort**: `200 ok` als Text bei Erfolg. Bei ungültigem JSON wird `400 invalid json` zurückgegeben.

### Beispiel
```bash
curl -X POST "http://localhost:8788/ingest/example.com" \
     -H "Content-Type: application/json" \
     -H "X-Auth: ${LEITSTAND_TOKEN}" \
     -d '{"event": "deploy", "status": "success"}'
```

## Datenspeicherung
* Für jede Domain entsteht eine JSONL-Datei im Verzeichnis `LEITSTAND_DATA_DIR`.
* Der Dateiname basiert auf dem SHA-256-Hash der Domain (`<hash>[:32].jsonl`) und verhindert so unzulässige Zeichen im Dateisystem.
* Jeder Request wird unverändert (bzw. um das Feld `domain` ergänzt) als einzelne Zeile im JSONL-Format angehängt.

## Betrieb & Wartung
* Logs: `uvicorn` schreibt standardmäßig auf STDOUT; bei Bedarf Output umleiten oder in eine zentrale Log-Pipeline integrieren.
* Backups: Das Datenverzeichnis lässt sich als Ganzes sichern. Durch die reine Anhänge-Strategie eignen sich inkrementelle Backups.
* Monitoring: Ein erfolgreicher `POST` liefert Status 200. Fehlermeldungen (`400`, `401`) sollten ausgewertet werden, um Integrationsfehler zu erkennen.
* Rotierendes Secret: Wird `LEITSTAND_TOKEN` geändert, muss der neue Wert zeitgleich bei allen Clients hinterlegt werden.

## Entwicklung & Tests
* Formatierung: Standard Python Code-Formatierung (z. B. `black`) kann verwendet werden.
* Tests: Für die API können `pytest`-basierte Tests oder Integrationstests mit `httpx` genutzt werden.
* FastAPI generiert automatisch eine OpenAPI-Spezifikation unter `http://localhost:8788/docs`, sobald der Server läuft.
