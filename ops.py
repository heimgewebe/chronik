import json
import os
from typing import Any, List, Optional
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

router = APIRouter()

# --- Models ---

class AuditCheck(BaseModel):
    id: str
    status: str  # ok, warn, error
    message: str
    evidence: Optional[dict[str, Any]] = None

class Routine(BaseModel):
    id: str
    risk: str  # low, medium, high
    mutating: bool
    dry_run_supported: bool
    reason: str
    requires: List[str]

class RoutinePreview(BaseModel):
    kind: str = "routine.preview"
    id: str
    mode: str = "dry-run"
    mutating: bool
    risk: str
    steps: List[dict[str, str]]  # {"cmd": "...", "why": "..."}
    confirm_token: str

class RoutineResult(BaseModel):
    kind: str = "routine.result"
    id: str
    mode: str = "apply"
    mutating: bool
    risk: str
    steps: List[dict[str, str]]
    state_hash: dict[str, str]
    stdout: str
    ok: bool

class AuditResult(BaseModel):
    kind: str = "audit.git"
    schema_version: str = "v1"
    ts: str
    repo: str
    status: str
    facts: dict[str, Any]
    checks: List[AuditCheck]
    uncertainty: dict[str, Any]
    suggested_routines: List[Routine]

# --- Stub Logic ---

@router.post("/api/ops/audit", response_model=AuditResult)
async def run_audit(request: Request):
    """
    Run a Git Audit (Stub).
    """
    # Simulate a "missing origin/main" scenario
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return AuditResult(
        ts=ts,
        repo="metarepo",
        status="error",
        facts={
            "head_sha": "a1b2c3d4",
            "head_ref": "refs/heads/feature/ops",
            "is_detached_head": False,
            "local_branch": "feature/ops",
            "remote_refs": {
                "origin_main": False,
                "origin_head": False
            }
        },
        checks=[
            AuditCheck(id="git.repo.present", status="ok", message="Repo detected."),
            AuditCheck(id="git.remote.origin.present", status="ok", message="Remote origin present."),
            AuditCheck(id="git.remote_head.discoverable", status="error", message="origin/HEAD missing or dangling.")
        ],
        uncertainty={
            "level": 0.15,
            "causes": [{"kind": "remote_ref_inconsistency", "note": "Remote tracking refs incomplete"}],
            "meta": "productive"
        },
        suggested_routines=[
            Routine(
                id="git.repair.remote-head",
                risk="low",
                mutating=True,
                dry_run_supported=True,
                reason="origin/HEAD missing/dangling; restore remote head + refs.",
                requires=["git", "jq"]
            )
        ]
    )

class PreviewRequest(BaseModel):
    repo: str
    routine_id: str

@router.post("/api/ops/routine/preview", response_model=RoutinePreview)
async def preview_routine(req: PreviewRequest):
    if req.routine_id != "git.repair.remote-head":
        raise HTTPException(status_code=404, detail="Routine not found")

    return RoutinePreview(
        id=req.routine_id,
        mutating=True,
        risk="low",
        steps=[
            {"cmd": "git remote set-head origin --auto", "why": "Restore origin/HEAD from remote HEAD"},
            {"cmd": "git fetch origin --prune", "why": "Rebuild remote-tracking refs"}
        ],
        confirm_token="valid_token_123"
    )

class ApplyRequest(BaseModel):
    repo: str
    routine_id: str
    confirm_token: str

@router.post("/api/ops/routine/apply", response_model=RoutineResult)
async def apply_routine(req: ApplyRequest):
    if req.confirm_token != "valid_token_123":
        raise HTTPException(status_code=403, detail="Invalid token")

    return RoutineResult(
        id=req.routine_id,
        mutating=True,
        risk="low",
        steps=[
            {"cmd": "git remote set-head origin --auto", "why": "Restore origin/HEAD from remote HEAD"},
            {"cmd": "git fetch origin --prune", "why": "Rebuild remote-tracking refs"}
        ],
        state_hash={"before": "abc", "after": "def"},
        stdout="Fetching origin...\nFrom github.com:heimgewebe/metarepo\n * [new branch] main -> origin/main",
        ok=True
    )

@router.get("/ops", response_class=HTMLResponse)
async def get_ops_panel():
    """
    Serve the Ops Panel UI.
    """
    template_path = Path("templates/ops.html")
    if not template_path.exists():
        return HTMLResponse("<h1>Error: templates/ops.html not found</h1>", status_code=500)

    return HTMLResponse(template_path.read_text(encoding="utf-8"))
