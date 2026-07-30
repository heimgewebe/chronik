import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _markdown_section(document: str, heading: str) -> str:
    marker = f"### {heading}\n"
    if marker not in document:
        raise AssertionError(f"Runbook is missing section: {heading}")

    tail = document.split(marker, 1)[1]
    next_heading = re.search(r"^### ", tail, flags=re.MULTILINE)
    if next_heading is not None:
        tail = tail[: next_heading.start()]
    return tail.strip()


@pytest.fixture(scope="module")
def runbook_content() -> str:
    return (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")


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
    assert "export CHRONIK_DATA_DIR" in text
    assert "export CHRONIK_ROOT" in text


def test_outbox_import_units_are_direct_bounded_and_hardened():
    service = (ROOT / "deploy" / "systemd" / "user" / "chronik-outbox-import.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "systemd" / "user" / "chronik-outbox-import.timer").read_text(encoding="utf-8")

    assert "import-outbox" in service
    assert "plexer" not in service.lower()
    assert "ReadOnlyPaths=%h/.local/state/grabowski/chronik-outbox" in service
    assert "ReadWritePaths=%h/.local/state/chronik" in service
    assert "ProtectSystem=strict" in service
    assert "ProtectHome=read-only" in service
    assert "NoNewPrivileges=true" in service
    assert "PrivateDevices=true" not in service
    assert "ProtectKernelModules=true" not in service
    assert "OnUnitActiveSec=2min" in timer
    assert "Persistent=true" in timer
    assert "WantedBy=timers.target" in timer


def test_operator_docs_close_ai_context_loop(runbook_content: str):
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    ai_context = (ROOT / ".ai-context.yml").read_text(encoding="utf-8")

    assert "append-only event ledger" in agents
    assert "Runtime activation" in agents
    assert "docs/runbook.md" in ai_context
    assert "not an orchestrator" in runbook_content
    assert "requires its own explicit approval" in runbook_content
    assert "CHRONIK_TOKEN=dev" in runbook_content


def test_agent_test_commands_use_project_virtualenv():
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert "python3 -m pytest" not in agents
    assert "./scripts/setup-venv.sh" in agents
    assert "./.venv/bin/python -m pytest -q tests/" in agents
    assert "make test" in agents
    assert "test:" in makefile
    assert "./scripts/setup-venv.sh" in makefile
    assert "./.venv/bin/python -m pytest -q" in makefile


def test_runtime_activation_gate_has_ordered_phases(runbook_content: str):
    headings = (
        "### Effects requiring separate approval",
        "### Evidence required before approval",
        "### Approved execution boundary",
        "### Verification after approved activation",
        "### Rollback plan and execution",
        "### Receipt requirements",
    )
    positions = [runbook_content.index(heading) for heading in headings]
    assert positions == sorted(positions), "Runtime activation phases are out of order"


@pytest.mark.parametrize(
    "effect",
    (
        "`systemctl enable`",
        "`systemctl start`",
        "`systemctl restart`",
        "Installation or deployment",
        "fleet mutation",
        "Secret handling",
    ),
)
def test_runtime_effects_require_separate_approval(runbook_content: str, effect: str):
    section = _markdown_section(runbook_content, "Effects requiring separate approval")
    assert effect in section, f"Approval section is missing effect: {effect}"
    assert "separate runtime action" in section
    assert "requires its own explicit approval" in section


def test_pre_approval_evidence_is_immutable_and_contains_no_runtime_smokes(runbook_content: str):
    section = _markdown_section(runbook_content, "Evidence required before approval")

    assert "exact Git commit ID" in section
    assert "SHA-256 hashes of every non-secret artifact" in section
    assert "path, owner, group, mode, size, and existence state" in section
    assert "complete rollback plan" in section
    assert "drift invalidates the approval request" in section
    assert "health/version smoke" not in section
    assert "append/read smoke" not in section


def test_execution_is_bound_to_approved_evidence_and_fails_closed(runbook_content: str):
    section = _markdown_section(runbook_content, "Approved execution boundary")

    assert "only after an approval matches the frozen evidence" in section
    assert "fail closed" in section
    assert "does not execute the activation or its rollback" in section


def test_runtime_smokes_are_post_activation_only(runbook_content: str):
    section = _markdown_section(runbook_content, "Verification after approved activation")

    assert "Only after the separately approved activation has executed" in section
    assert "health/version smoke test" in section
    assert "append/read smoke test" in section
    assert "post-activation verification" in section
    assert "not pre-approval preparation checks" in section


def test_rollback_plan_is_pre_reviewed_but_execution_is_separately_authorized(runbook_content: str):
    section = _markdown_section(runbook_content, "Rollback plan and execution")

    assert "reviewed before approval" in section
    assert "authorize execution of that exact rollback" in section
    assert "previous hash-bound non-secret artifacts" in section
    assert "inactive and disabled" in section
    assert "no Chronik process or listener remains" in section
    assert "does not execute it" in section
    assert "only when an approved trigger occurs" in section


def test_receipts_bind_non_secret_artifacts_without_secret_derivatives(runbook_content: str):
    section = _markdown_section(runbook_content, "Receipt requirements")

    assert "exact Git commit ID" in section
    assert "SHA-256 hashes of installed or restored non-secret artifacts" in section
    assert "target paths" in section
    assert "unit state" in section
    assert "process checks" in section
    assert "listener checks" in section
    assert "only paths and non-secret metadata" in section
    assert "must not contain tokens" in section
    assert "hashes derived from secret contents" in section
