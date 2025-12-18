#!/usr/bin/env bash
set -euo pipefail

# Prüfen, ob das .venv-Verzeichnis bereits existiert.
# Wenn nicht, wird es erstellt und die Abhängigkeiten installiert.
if [ ! -d ".venv" ]; then
  echo "INFO: .venv-Verzeichnis nicht gefunden. Erstelle es und installiere Abhängigkeiten..."
  python3 -m venv .venv
  . .venv/bin/activate
  python3 -m pip install --upgrade pip setuptools wheel || true
  pip install -r requirements.txt
  if [ -f "requirements-dev.txt" ]; then
    echo "INFO: Installiere zusätzliche Entwicklungsabhängigkeiten..."
    pip install -r requirements-dev.txt
  fi
else
  echo "INFO: .venv-Verzeichnis bereits vorhanden. Überspringe die Erstellung."
fi
