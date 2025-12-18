from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path

from tools import wgx_metrics_export


def _write_metrics_jsonl(path: Path) -> None:
    """Hilfsfunktion: zwei Snapshots, damit 'neuester' geprüft werden kann."""
    entries = [
        {
            "timestamp": "2025-12-04T10:00:00Z",
            "domain": "metrics.snapshot",
            "kind": "snapshot",
            "payload": {
                "timestamp": "2025-12-04T10:00:00Z",
                "repoCount": 3,
                "status": {"ok": 2, "warn": 1, "fail": 0},
                "metadata": {"source": "wgx-snapshot", "label": "older"},
            },
        },
        {
            "timestamp": "2025-12-05T12:00:00Z",
            "domain": "metrics.snapshot",
            "kind": "snapshot",
            "payload": {
                "timestamp": "2025-12-05T12:00:00Z",
                "repoCount": 5,
                "status": {"ok": 3, "warn": 1, "fail": 1},
                "metadata": {"source": "wgx-snapshot", "label": "newer"},
            },
        },
    ]
    path.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")


def test_export_latest_to_vault(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    metrics_file = data_dir / "metrics.snapshot.jsonl"
    _write_metrics_jsonl(metrics_file)

    vault_root = tmp_path / "vault"
    vault_root.mkdir()

    # Konfiguration per Umgebungsvariablen wie im echten Betrieb
    monkeypatch.setenv("CHRONIK_DATA_DIR", str(data_dir))
    monkeypatch.setenv("VAULT_ROOT", str(vault_root))

    ok = wgx_metrics_export.export_latest_to_vault()
    assert ok is True

    metrics_dir = vault_root / ".gewebe" / "wgx" / "metrics"
    date_file = metrics_dir / "2025-12-05.json"
    latest_file = metrics_dir / "latest.json"

    assert date_file.exists()
    assert latest_file.exists()

    latest = json.loads(latest_file.read_text(encoding="utf-8"))
    assert latest["repoCount"] == 5
    assert latest["status"]["fail"] == 1
    assert latest["metadata"]["label"] == "newer"


def test_export_returns_false_if_no_file(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    vault_root = tmp_path / "vault"
    vault_root.mkdir()

    monkeypatch.setenv("CHRONIK_DATA_DIR", str(data_dir))
    monkeypatch.setenv("VAULT_ROOT", str(vault_root))

    ok = wgx_metrics_export.export_latest_to_vault()
    assert ok is False


def test_load_metrics_snapshots_accepts_direct_snapshot_shape(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    f = data_dir / "metrics.snapshot.jsonl"

    # Direktes Snapshot-Objekt ohne payload (Fallback-Format)
    entry = {
        "timestamp": "2025-12-06T08:00:00Z",
        "repoCount": 7,
        "status": {"ok": 5, "warn": 1, "fail": 1},
    }
    f.write_text(json.dumps(entry), encoding="utf-8")

    snapshots = wgx_metrics_export.load_metrics_snapshots(data_dir)
    assert len(snapshots) == 1


def test_load_metrics_snapshots_normalizes_naive_timestamps(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    f = data_dir / "metrics.snapshot.jsonl"

    entries = [
        {
            "timestamp": "2025-12-06T08:00:00",
            "repoCount": 1,
            "status": {"ok": 1, "warn": 0, "fail": 0},
            "metadata": {"label": "naive"},
        },
        {
            "timestamp": "2025-12-06T08:00:01Z",
            "repoCount": 2,
            "status": {"ok": 1, "warn": 0, "fail": 1},
            "metadata": {"label": "aware"},
        },
    ]
    f.write_text("\n".join(json.dumps(e) for e in entries), encoding="utf-8")

    snapshots = wgx_metrics_export.load_metrics_snapshots(data_dir)
    assert all(s.timestamp.tzinfo == timezone.utc for s in snapshots)

    latest = wgx_metrics_export.select_latest_snapshot(snapshots)
    assert latest is not None
    assert latest.payload["metadata"]["label"] == "aware"


def test_parse_timestamp_warns_on_naive(caplog):
    with caplog.at_level("WARNING"):
        ts = wgx_metrics_export._parse_timestamp("2025-12-06T08:00:00")
    assert ts.tzinfo == timezone.utc
    assert any("naiver Timestamp wird als UTC interpretiert" in r.message for r in caplog.records)
