#!/bin/bash
set -e

# Prüfen, ob das .venv-Verzeichnis bereits existiert.
# Wenn nicht, wird es erstellt und die Abhängigkeiten installiert.
if [ ! -d ".venv" ]; then
  echo "INFO: .venv-Verzeichnis nicht gefunden. Erstelle es und installiere Abhängigkeiten..."
  python -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
else
  echo "INFO: .venv-Verzeichnis bereits vorhanden. Überspringe die Erstellung."
fi
