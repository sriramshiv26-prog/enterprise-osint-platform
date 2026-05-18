"""
FastAPI routes for OSINT tool invocation.

Endpoints for executing tools and tracking results.
"""
import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from src.osint_platform.tools.tool_manager import get_tool_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tools", tags=["Tools"])


class ToolExecutionRequest(BaseModel):
    """Request to execute a tool."""
    query: str = Field(..., description="Query or target for the tool")
    sites: Optional[list[str]] = Field(None, description="Optional sites filter (for sherlock)")
    threads: Optional[int] = Field(None, description="Number of threads (for sublist3r)")
    scan_osint: Optional[bool] = Field(None, description="Enable OSINT scanning (for phoneinfoga)")


class ToolExecutionResponse(BaseModel):
    """Response with request tracking ID."""
    request_id: str
    tool_name: str
    query: str
    status: str = "queued"
    message: str = "Request queued for processing"


class ToolStatusResponse(BaseModel):
    """Response with tool execution status."""
    request_id: str
    tool_name: str
    query: str
    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time_seconds: Optional[float] = None


class ToolStatsResponse(BaseModel):
    """Response with tool executor statistics."""
    tool_name: str
    queue_size: int
    queue_capacity: int
    rate_limit: str
    max_concurrent: int
    stats: Dict[str, int]


@router.post("/sherlock/search", response_model=ToolExecutionResponse)
async def execute_sherlock(request: ToolExecutionRequest) -> ToolExecutionResponse:
    """
    Search for username across social media and websites (Sherlock).

    Rate limit: 2 requests/second
    """
    try:
        manager = get_tool_manager()
        request_id = await manager.execute_tool(
            "sherlock",
            request.query,
            sites=request.sites,
        )

        return ToolExecutionResponse(
            request_id=request_id,
            tool_name="sherlock",
            query=request.query,
            status="queued",
        )
    except Exception as e:
        logger.error(f"Sherlock execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sublist3r/enum", response_model=ToolExecutionResponse)
async def execute_sublist3r(request: ToolExecutionRequest) -> ToolExecutionResponse:
    """
    Enumerate subdomains for a domain (Sublist3r).

    Rate limit: 10 requests/minute
    """
    try:
        manager = get_tool_manager()
        request_id = await manager.execute_tool(
            "sublist3r",
            request.query,
            threads=request.threads or 100,
        )

        return ToolExecutionResponse(
            request_id=request_id,
            tool_name="sublist3r",
            query=request.query,
            status="queued",
        )
    except Exception as e:
        logger.error(f"Sublist3r execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/amass/enum", response_model=ToolExecutionResponse)
async def execute_amass(request: ToolExecutionRequest) -> ToolExecutionResponse:
    """
    Asset discovery and reconnaissance (Amass).

    Rate limit: 100 requests/hour
    """
    try:
        manager = get_tool_manager()
        request_id = await manager.execute_tool(
            "amass",
            request.query,
        )

        return ToolExecutionResponse(
            request_id=request_id,
            tool_name="amass",
            query=request.query,
            status="queued",
        )
    except Exception as e:
        logger.error(f"Amass execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/holehe/search", response_model=ToolExecutionResponse)
async def execute_holehe(request: ToolExecutionRequest) -> ToolExecutionResponse:
    """
    Search for email in breaches (Holehe).

    Rate limit: 1 request/second
    """
    try:
        manager = get_tool_manager()
        request_id = await manager.execute_tool(
            "holehe",
            request.query,
        )

        return ToolExecutionResponse(
            request_id=request_id,
            tool_name="holehe",
            query=request.query,
            status="queued",
        )
    except Exception as e:
        logger.error(f"Holehe execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/phoneinfoga/scan", response_model=ToolExecutionResponse)
async def execute_phoneinfoga(request: ToolExecutionRequest) -> ToolExecutionResponse:
    """
    Phone number reconnaissance (PhoneInfoga).

    Rate limit: 30 requests/minute
    """
    try:
        manager = get_tool_manager()
        request_id = await manager.execute_tool(
            "phoneinfoga",
            request.query,
            scan_osint=request.scan_osint or True,
        )

        return ToolExecutionResponse(
            request_id=request_id,
            tool_name="phoneinfoga",
            query=request.query,
            status="queued",
        )
    except Exception as e:
        logger.error(f"PhoneInfoga execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status/{tool_name}/{request_id}", response_model=Optional[ToolStatusResponse])
async def get_tool_status(
    tool_name: str,
    request_id: str,
) -> Optional[ToolStatusResponse]:
    """Get status of a tool execution request."""
    try:
        manager = get_tool_manager()
        status = manager.get_request_status(tool_name, request_id)

        if not status:
            raise HTTPException(status_code=404, detail="Request not found")

        return ToolStatusResponse(**status)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Status check error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats", response_model=Dict[str, Any])
async def get_all_stats() -> Dict[str, Any]:
    """Get statistics for all tool executors."""
    try:
        manager = get_tool_manager()
        return manager.get_all_stats()
    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/{tool_name}", response_model=Optional[ToolStatsResponse])
async def get_tool_stats(tool_name: str) -> Optional[ToolStatsResponse]:
    """Get statistics for a specific tool."""
    try:
        manager = get_tool_manager()
        stats = manager.get_tool_stats(tool_name)

        if not stats:
            raise HTTPException(status_code=404, detail="Tool not found")

        return ToolStatsResponse(**stats)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Tool stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
