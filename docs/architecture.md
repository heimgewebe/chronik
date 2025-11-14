# Architekturübersicht

Chronik ist ein einfacher Ingest-Dienst, der auf Python und FastAPI basiert. Die Architektur ist darauf ausgelegt, leichtgewichtig und einfach zu betreiben zu sein.

## Komponenten

1.  **FastAPI-Anwendung (`app.py`):**
    *   Dies ist der Kern des Dienstes, der die HTTP-Endpunkte bereitstellt.
    *   Es verwendet `uvicorn` als ASGI-Server.

2.  **Ingest-Endpunkt (`/ingest/{domain}`):**
    *   Nimmt JSON-Daten per `POST`-Request entgegen.
    *   Authentifiziert Anfragen über einen Shared-Secret-Token (`CHRONIK_TOKEN`), der im `X-Auth`-Header übergeben wird.
    *   Validiert und bereinigt den `domain`-Pfadparameter.

3.  **Speicherschicht (`storage.py`):**
    *   Eingehende Daten werden in domain-spezifischen JSON-Lines-Dateien (`.jsonl`) im `CHRONIK_DATA_DIR`-Verzeichnis gespeichert.
    *   Die `filelock`-Bibliothek wird verwendet, um Race Conditions beim Schreiben in die Dateien zu verhindern.
    *   Die Funktion `sanitize_domain` normalisiert Domain-Schlüssel streng deterministisch (Lowercase, Whitespace entfernen, unerlaubte Zeichen ersetzen) und stellt sicher, dass anschließend ein sicherer Dateiname erzeugt werden kann.
    *   Die Funktion `secure_filename` sorgt für sichere Dateinamen.

## Datenfluss

1.  Ein Client sendet eine `POST`-Anfrage mit einem JSON-Body an `/ingest/{domain}`.
2.  Die FastAPI-Anwendung empfängt die Anfrage.
3.  Die Authentifizierung wird über den `X-Auth`-Header überprüft.
4.  Der `domain`-Parameter wird validiert und bereinigt.
5.  Die Größe des Request-Bodys wird überprüft (maximal 1 MiB).
6.  Der JSON-Body wird gelesen und validiert.
7.  Die Anwendung fügt dem JSON-Objekt (oder jedem Objekt in einem Array) ein `domain`-Feld hinzu.
8.  Das resultierende JSON-Objekt wird als eine einzelne Zeile in die entsprechende `<domain>.jsonl`-Datei geschrieben.
9.  Ein `FileLock` stellt sicher, dass Schreibvorgänge atomar sind.

## Design-Entscheidungen

Die wichtigsten Architekturentscheidungen sind in den [Architectural Decision Records (ADRs)](adr/README.md) dokumentiert.
