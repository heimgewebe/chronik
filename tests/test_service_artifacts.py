from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_service_file_exists_and_names_chronik():
    matches = list((ROOT / "deploy").rglob("chronik.service"))
    assert len(matches) == 1
    text = matches[0].read_text(encoding="utf-8")
    assert "chronik local event store" in text
    assert "CHRONIK_PORT=8788" in text
    assert "EnvironmentFile=-%h/.config/chronik/chronik.env" in text
    assert "run-chronik-service.sh" in text


def test_service_notes_exist():
    text = (ROOT / "docs" / "chronik-service.md").read_text(encoding="utf-8")
    assert "Phase 0" in text
    assert "append/read" in text
    assert "must not dispatch tasks" in text



def test_service_env_example_is_service_specific_and_safe():
    text = (ROOT / "deploy" / "systemd" / "user" / "chronik.env.example").read_text(encoding="utf-8")
    assert "strong-local" in text
    assert not any(line.strip().endswith("=dev") for line in text.splitlines())
    assert "%h" not in text
    assert "absolute values" in text


def test_service_runner_fails_closed_and_honors_bind_env():
    text = (ROOT / "scripts" / "run-chronik-service.sh").read_text(encoding="utf-8")
    assert "is required" in text
    assert "exit 78" in text
    assert "--host" in text
    assert "--port" in text
