"""Exportiere den neuesten metrics.snapshot aus chronik nach VAULT_ROOT.

Zweck
-----
- chronik speichert metrics.snapshot-Events als JSONL-Dateien im CHRONIK_DATA_DIR.
- leitstand erwartet einzelne Snapshot-Dateien in
  $VAULT_ROOT/.gewebe/wgx/metrics/YYYY-MM-DD.json (+ latest.json).

Dieses Modul schlägt die Brücke:
- liest alle metrics.snapshot-Events,
- wählt den neuesten,
- schreibt dessen Snapshot-Payload ins Vault.

Konfiguration per Umgebungsvariablen:
- CHRONIK_DATA_DIR (optional, Default: ./data)
- VAULT_ROOT       (pflicht, z. B. /pfad/zu/deinem/vault)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


METRICS_DOMAIN = "metrics.snapshot"
DATA_ENV_VAR = "CHRONIK_DATA_DIR"
VAULT_ENV_VAR = "VAULT_ROOT"


@dataclass
class MetricsSnapshot:
    timestamp: datetime
    payload: Dict[str, Any]


def _parse_timestamp(value: str) -> datetime:
    """ISO-8601 Parser, der auch 'Z' (UTC) akzeptiert."""
    v = value
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    return datetime.fromisoformat(v)


def _get_data_dir() -> Path:
    """Bestimme das chronik-Datenverzeichnis.

    Entspricht der Beschreibung in den chronik-Dokumenten:
    - CHRONIK_DATA_DIR setzt das Verzeichnis explizit
    - sonst wird ./data relativ zum Repo verwendet
    """
    env = os.environ.get(DATA_ENV_VAR)
    base = Path(env) if env else Path("data")
    return base


def _get_vault_root() -> Path:
    """Bestimme VAULT_ROOT oder breche mit klarer Fehlermeldung ab."""
    env = os.environ.get(VAULT_ENV_VAR)
    if not env:
        raise RuntimeError(
            f"{VAULT_ENV_VAR} ist nicht gesetzt. "
            "Bitte z. B. 'export VAULT_ROOT=/pfad/zu/deinem/vault' ausführen."
        )

    root = Path(env).expanduser()
    if not root.exists():
        raise RuntimeError(f"{VAULT_ENV_VAR} verweist auf einen nicht existierenden Pfad: {root}")
    if not root.is_dir():
        raise RuntimeError(f"{VAULT_ENV_VAR} muss auf ein Verzeichnis zeigen, nicht auf eine Datei: {root}")
    return root


def load_metrics_snapshots(data_dir: Path) -> List[MetricsSnapshot]:
    """Lade alle metrics.snapshot-Snapshots aus der JSONL-Datei.

    Erwartete Event-Formate (beide werden unterstützt):

    1) Event-Line mit Payload (typisch für chronik):
       {
         "timestamp": "...",      # Event-Zeit
         "domain": "metrics.snapshot",
         "kind": "snapshot",
         "payload": {
           "timestamp": "...",    # optional, Snapshot-Zeit
           "repoCount": 5,
           "status": { ... },
           "metadata": { ... }
         }
       }

    2) Direktes Snapshot-Objekt (Fallback):
       {
         "timestamp": "...",
         "repoCount": 5,
         "status": { ... },
         "metadata": { ... }
       }
    """
    path = data_dir / f"{METRICS_DOMAIN}.jsonl"
    if not path.exists():
        return []

    snapshots: List[MetricsSnapshot] = []

    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                # Chronik bleibt robust: kaputte Zeile wird übersprungen.
                continue

            # Event-Zeit hat Vorrang für die Sortierung
            ts_raw = raw.get("timestamp") or raw.get("ts")
            if not isinstance(ts_raw, str):
                continue

            try:
                ts = _parse_timestamp(ts_raw)
            except ValueError:
                continue

            payload = raw.get("payload")
            if not isinstance(payload, dict):
                payload = raw

            snapshots.append(MetricsSnapshot(timestamp=ts, payload=payload))

    return snapshots


def select_latest_snapshot(snapshots: List[MetricsSnapshot]) -> Optional[MetricsSnapshot]:
    """Wähle den neuesten Snapshot (größter Timestamp)."""
    if not snapshots:
        return None
    return max(snapshots, key=lambda s: s.timestamp)


def export_latest_to_vault(
    *,
    data_dir: Optional[Path] = None,
    vault_root: Optional[Path] = None,
) -> bool:
    """Exportiere den neuesten metrics.snapshot nach VAULT_ROOT.

    Returns:
        True, wenn ein Snapshot exportiert wurde, sonst False.
    """
    if data_dir is None:
        data_dir = _get_data_dir()
    if vault_root is None:
        vault_root = _get_vault_root()

    snapshots = load_metrics_snapshots(data_dir)
    latest = select_latest_snapshot(snapshots)
    if latest is None:
        return False

    date_str = latest.timestamp.date().isoformat()

    metrics_dir = vault_root / ".gewebe" / "wgx" / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)

    date_path = metrics_dir / f"{date_str}.json"
    latest_path = metrics_dir / "latest.json"

    payload = latest.payload

    date_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    latest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    return True


def main() -> None:
    try:
        ok = export_latest_to_vault()
    except RuntimeError as exc:
        raise SystemExit(str(exc))

    if not ok:
        raise SystemExit("No metrics.snapshot entries found in chronik data dir")

    print("Exported latest metrics.snapshot to VAULT_ROOT/.gewebe/wgx/metrics")


if __name__ == "__main__":  # pragma: no cover
    main()
