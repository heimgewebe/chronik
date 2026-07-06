from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_service_file_exists_and_names_chronik():
    matches = list((ROOT / "deploy").rglob("chronik.service"))
    assert len(matches) == 1
    text = matches[0].read_text(encoding="utf-8")
    assert "chronik local event store" in text
    assert "CHRONIK_PORT=8788" in text
    assert "EnvironmentFile=-%h/.config/chronik/chronik.env" in text


def test_service_notes_exist():
    text = (ROOT / "docs" / "chronik-service.md").read_text(encoding="utf-8")
    assert "Phase 0" in text
    assert "append/read" in text
    assert "must not dispatch tasks" in text
