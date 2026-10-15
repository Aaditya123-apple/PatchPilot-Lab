"""FastAPI service exposing the audit pipeline. Run with: uvicorn src.api:app --reload"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import get_settings
from .models import AuditReport
from .orchestrator import AuditOrchestrator
from .repo import combined_patch

app = FastAPI(
    title="Nebius-AgentX",
    version=__version__,
    description="Autonomous multi-agent code refactoring and security audit on Nebius AI Cloud with NVIDIA models.",
)


class AuditRequest(BaseModel):
    source: str | None = Field(None, description="Local path or Git URL to audit")
    code: str | None = Field(None, description="Raw code to audit instead of a path")
    filename: str | None = Field(None, description="File name for raw code, e.g. app.py")
    max_iterations: int = Field(2, ge=1, le=5)
    approve_threshold: float = Field(0.8, ge=0.0, le=1.0)
    use_llm: bool = True


@app.get("/health")
async def health() -> dict[str, object]:
    s = get_settings()
    return {"status": "ok", "version": __version__, "mode": "offline" if s.offline else "nebius", "models": list(s.model_chain)}


async def _run(req: AuditRequest) -> AuditReport:
    if not (req.code or req.source):
        raise HTTPException(status_code=422, detail="Provide either `source` (path or Git URL) or `code`.")
    orchestrator = AuditOrchestrator(
        max_iterations=req.max_iterations, approve_threshold=req.approve_threshold, use_llm=req.use_llm
    )
    try:
        if req.code:
            return await orchestrator.audit(req.code, filename=req.filename, snippet=True)
        return await orchestrator.audit(req.source or "")
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/audit", response_model=AuditReport)
async def audit(req: AuditRequest) -> AuditReport:
    return await _run(req)


@app.post("/audit/patch", response_class=PlainTextResponse)
async def audit_patch(req: AuditRequest) -> str:
    """Same audit, returned as a single unified diff ready for `git apply`."""
    return combined_patch(await _run(req))
