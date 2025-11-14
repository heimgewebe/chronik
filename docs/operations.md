# Betriebshandbuch

Dieses Dokument fasst die wichtigsten Betriebs- und Wartungsaufgaben für den Chronik-Ingest-Dienst zusammen.

## Lifecycle
### Starten
```bash
uvicorn app:app --host 0.0.0.0 --port 8788
```
* Vor dem Start sicherstellen, dass `CHRONIK_DATA_DIR` beschreibbar ist.
* `CHRONIK_TOKEN` muss gesetzt sein (ohne Token startet der Dienst nicht).

### Stoppen
* Uvicorn-Prozess kontrolliert beenden (z. B. per `Ctrl+C`, `systemctl stop`, Kubernetes Rollout etc.).
* Warten, bis keine weiteren Schreibzugriffe auf dem Datenverzeichnis stattfinden.

## Überwachung
* **Health**: Ein Test-Request gegen `/ingest/<test-domain>` (ggf. mit Dummy-Token) sollte Status `200` liefern.
* **Logging**: Standardmäßig loggt Uvicorn nach STDOUT. Produktionsumgebungen sollten die Ausgabe an ein Log-Aggregationssystem weiterleiten.
* **Metriken**: Anzahl erfolgreicher Ingest-Requests kann über Log-Analyse oder Reverse-Proxy-Zähler ermittelt werden.

## Sicherheit
* Token regelmäßig rotieren und nur über TLS-geschützte Verbindungen übertragen.
* Datenverzeichnis vor unbefugtem Zugriff schützen (Filesystem-Rechte, Verschlüsselung).
* Eingehende Domains werden validiert; zusätzliche Allow-/Deny-Listen können vorgeschaltet werden.

## Backup & Restore
* JSONL-Dateien sind anhängende Logs. Regelmäßige inkrementelle Backups des Verzeichnisses `CHRONIK_DATA_DIR` sind ausreichend.
* Für Wiederherstellungen Dateien in ein leeres Datenverzeichnis kopieren und Dienst neu starten.

## Fehlerbehebung
| Symptom                        | Maßnahme |
|--------------------------------|----------|
| `401 unauthorized`             | Token-Header prüfen, Abgleich mit `CHRONIK_TOKEN`. |
| `400 invalid domain`           | Domain-Format prüfen. Nur Kleinbuchstaben, Ziffern und `-` erlaubt. |
| `400 invalid json`             | Payload auf gültiges JSON prüfen. Sonderzeichen ggf. escapen. |
| Keine neuen Dateien unter `data`| Schreibrechte des Prozesses und Pfadkonfiguration kontrollieren. |
| Dienst startet nicht           | Fehlermeldungen im Uvicorn-Log auswerten, Python-Abhängigkeiten prüfen. |

## Deployment-Hinweise
* Containerisierung: Für Docker-Deployments `CHRONIK_DATA_DIR` als Volume mounten und `CHRONIK_TOKEN` per Secret setzen.
* Skalierung: Da pro Request eine Datei geöffnet und beschrieben wird, sollte bei hohem Durchsatz ein vorgeschalteter Message-Broker erwogen werden.
* Infrastruktur: Reverse Proxy (z. B. Traefik, Nginx) kann TLS beenden und Auth-Token verwalten.
