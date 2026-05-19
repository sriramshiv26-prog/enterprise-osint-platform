"""
Hermes Agent API Routes.

Endpoints for running investigations with the AI-powered Hermes Agent.
"""
import logging
from typing import Any, Dict, List, Optional, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from src.osint_platform.agent.service import get_agent_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/agent", tags=["Hermes Agent"])


# ─── Request / Response Schemas ──────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    """Request to start a Hermes investigation."""
    target: str = Field(
        ...,
        description="The target to investigate (IP, domain, email, URL, hash, username, or phone number)",
        min_length=1,
    )
    target_type: str = Field(
        default="auto",
        description="Optional type hint: ip, domain, email, hash, url, username, phone, or auto",
    )
    context: Optional[str] = Field(
        default=None,
        description="Additional context about the investigation target",
    )


class InvestigationResponse(BaseModel):
    """Response from an investigation request."""
    investigation_id: str = Field(..., description="Unique ID to track the investigation")
    target: str = Field(..., description="The investigated target")
    target_type: str = Field(..., description="Detected or specified target type")
    status: str = Field(..., description="Status: pending, running, completed, failed, or cancelled")
    timestamp: str = Field(..., description="ISO timestamp of when the investigation started")
    report: Optional[str] = Field(default=None, description="Full investigation report (markdown)")
    error: Optional[str] = Field(default=None, description="Error message if investigation failed")


class InvestigationStatusResponse(BaseModel):
    """Status of a specific investigation."""
    investigation_id: str
    status: str
    progress: Optional[str] = None
    report: Optional[str] = None
    error: Optional[str] = None


class HistoryResponse(BaseModel):
    """Investigation history list."""
    total: int
    investigations: List[Dict[str, Any]]


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/investigate", response_model=InvestigationResponse)
async def investigate(request: InvestigateRequest) -> InvestigationResponse:
    """Run a Hermes investigation on a target (synchronous).

    Runs the full investigation pipeline: Investigator gathers evidence,
    Analyst assesses threats, Reporter generates report.
    The request blocks until the investigation is complete.
    """
    service = get_agent_service()

    try:
        result = await service.investigate(
            target=request.target,
            target_type=request.target_type,
            context=request.context,
        )

        return InvestigationResponse(
            investigation_id=result.get("investigation_id", ""),
            target=result.get("target", request.target),
            target_type=result.get("target_type", request.target_type),
            status=result.get("status", "completed" if result.get("success") else "failed"),
            timestamp=result.get("timestamp", ""),
            report=result.get("report"),
            error=result.get("error"),
        )

    except Exception as e:
        logger.error(f"Investigation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigate/async", response_model=InvestigationResponse)
async def investigate_async(request: InvestigateRequest) -> InvestigationResponse:
    """Start an async investigation on a target (non-blocking).

    Returns immediately with an investigation ID. Poll /agent/status/{id}
    to get results when complete.
    """
    service = get_agent_service()

    try:
        inv_id = await service.investigate_async(
            target=request.target,
            target_type=request.target_type,
            context=request.context,
        )

        return InvestigationResponse(
            investigation_id=inv_id,
            target=request.target,
            target_type=request.target_type,
            status="running",
            timestamp="",  # Will be populated when complete
        )

    except Exception as e:
        logger.error(f"Async investigation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{investigation_id}", response_model=InvestigationStatusResponse)
async def get_investigation_status(investigation_id: str) -> InvestigationStatusResponse:
    """Get the status and result of an investigation.

    Poll this endpoint to check progress on async investigations.
    """
    service = get_agent_service()
    result = service.get_result(investigation_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation '{investigation_id}' not found",
        )

    return InvestigationStatusResponse(
        investigation_id=investigation_id,
        status=result.get("status", "unknown"),
        report=result.get("report"),
        error=result.get("error"),
    )


@router.get("/history", response_model=HistoryResponse)
async def get_investigation_history(
    limit: int = Query(default=10, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[Literal["completed", "failed", "running", "pending"]] = Query(default=None),
) -> HistoryResponse:
    """Get investigation history.

    Returns a paginated list of past investigations.
    """
    service = get_agent_service()
    investigations = service.get_history(limit=limit, offset=offset, status=status)

    return HistoryResponse(
        total=len(investigations),
        investigations=investigations,
    )


@router.post("/cancel/{investigation_id}")
async def cancel_investigation(investigation_id: str) -> Dict[str, Any]:
    """Cancel a running investigation."""
    service = get_agent_service()
    cancelled = service.cancel_investigation(investigation_id)

    if not cancelled:
        # Check if it exists at all
        result = service.get_result(investigation_id)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{investigation_id}' not found",
            )
        return {
            "investigation_id": investigation_id,
            "status": result.get("status", "unknown"),
            "message": "Investigation is not currently running or already completed",
        }

    return {
        "investigation_id": investigation_id,
        "status": "cancelled",
        "message": "Investigation cancelled successfully",
    }


@router.get("/tools")
async def list_available_tools() -> Dict[str, Any]:
    """List all available OSINT tools the agent can use."""
    from src.osint_platform.agent.tools import AVAILABLE_TOOLS

    return {
        "tool_count": len(AVAILABLE_TOOLS),
        "tools": [
            {"name": name, "description": desc}
            for name, desc in AVAILABLE_TOOLS.items()
        ],
    }
