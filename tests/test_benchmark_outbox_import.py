import json
import subprocess
import sys
from pathlib import Path


def test_benchmark_reports_single_scan_first_and_repeat(tmp_path):
    root = Path(__file__).parents[1]
    output = tmp_path / "benchmark.json"
    result = subprocess.run(
        [
            sys.executable,
            str(root / "tools" / "benchmark_outbox_import.py"),
            "--name",
            "test",
            "--source-files",
            "3",
            "--preexisting-events",
            "4",
            "--max-seconds",
            "5",
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text())
    tier = report["tiers"][0]
    assert report["passed"] is True
    assert tier["first"]["target_scans"] == 1
    assert tier["repeat"]["target_scans"] == 1
    assert tier["first"]["events_imported"] == 6
    assert tier["repeat"]["events_skipped_existing"] == 6
    assert tier["compaction"]["sources_removed"] == 3
    assert tier["loose_files_before"] == 3
    assert tier["loose_files_after"] == 0
    assert tier["bundled_repeat"]["target_scans"] == 1
    assert tier["bundled_repeat"]["events_skipped_existing"] == 6
    assert tier["passed"] is True
