import json
import subprocess
import sys
from pathlib import Path


def test_benchmark_reports_persistent_index_reuse(tmp_path):
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
    assert report["schema_version"] == "chronik-outbox-import-benchmark.v3"
    assert report["thresholds"]["representative_no_change_max_seconds"] == 1.0
    assert report["thresholds"]["small_delta_max_seconds"] == 2.0
    assert tier["first"]["steady_fast_path"] is False
    assert tier["repeat"]["steady_fast_path"] is True
    assert tier["small_delta"]["steady_fast_path"] is False
    assert tier["bundled_rebuild"]["steady_fast_path"] is False
    assert tier["bundled_repeat"]["steady_fast_path"] is True
    assert tier["first"]["target_scans"] == 0
    assert tier["first"]["target_records_scanned"] == 0
    assert tier["repeat"]["target_scans"] == 0
    assert tier["repeat"]["target_records_scanned"] == 0
    assert tier["first"]["events_imported"] == 6
    assert tier["repeat"]["events_skipped_existing"] == 6
    assert tier["repeat"]["sources_reused"] == 3
    assert tier["repeat"]["sources_revalidated"] == 0
    assert tier["repeat"]["source_bytes_read"] == 0
    assert tier["repeat"]["elapsed_seconds"] < 1
    assert tier["small_delta"]["events_imported"] == 2
    assert tier["small_delta"]["sources_reused"] == 3
    assert tier["small_delta"]["sources_revalidated"] == 1
    assert tier["small_delta"]["elapsed_seconds"] < 2
    assert tier["compaction"]["sources_removed"] == 4
    assert tier["loose_files_before"] == 4
    assert tier["loose_files_after"] == 0
    assert tier["bundled_rebuild"]["events_skipped_existing"] == 8
    assert tier["bundled_repeat"]["target_scans"] == 0
    assert tier["bundled_repeat"]["target_records_scanned"] == 0
    assert tier["bundled_repeat"]["events_skipped_existing"] == 8
    assert tier["bundled_repeat"]["sources_reused"] == 4
    assert tier["bundled_repeat"]["sources_revalidated"] == 0
    assert tier["bundled_repeat"]["source_bytes_read"] == 0
    assert tier["bundled_repeat"]["elapsed_seconds"] < 1
    assert tier["passed"] is True
