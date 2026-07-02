#!/usr/bin/env bash
set -euo pipefail

# Ensure the local virtual environment exists and matches the current
# runtime/development requirements. Reinstalling requirements on every run keeps
# this script useful after dependency changes instead of only on first checkout.
if [ ! -d ".venv" ]; then
  echo "INFO: .venv-Verzeichnis nicht gefunden. Erstelle es..."
  python3 -m venv .venv
else
  echo "INFO: .venv-Verzeichnis bereits vorhanden. Prüfe Abhängigkeiten..."
fi

. .venv/bin/activate
python3 -m pip install --upgrade pip setuptools wheel || true
python3 -m pip install -r requirements.txt
if [ -f "requirements-dev.txt" ]; then
  echo "INFO: Installiere/aktualisiere zusätzliche Entwicklungsabhängigkeiten..."
  python3 -m pip install -r requirements-dev.txt
fi
