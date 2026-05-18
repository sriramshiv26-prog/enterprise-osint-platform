"""
FastAPI routes for OSINT API integrations.

Endpoints for orchestrating queries across multiple threat intelligence APIs.
"""
import logging
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from src.osint_platform.api_integrations.manager import get_api_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/apis", tags=["OSINT APIs"])


class APIQueryRequest(BaseModel):
    """Request to query multiple APIs."""
    query: str = Field(..., description="Search query (IP, domain, email, URL, hash)")
    apis: Optional[List[str]] = Field(None, description="Specific APIs to query (optional, auto-detected if None)")
    use_cache: bool = Field(default=True, description="Use cached results if available")


class APIQueryResponse(BaseModel):
    """Response with query results."""
    query: str
    execution_time_seconds: float
    total_results: int
    total_sources: int
    deduplicated_count: int
    sources: List[str]


class APIStatsResponse(BaseModel):
    """Response with API manager statistics."""
    initialized: bool
    apis_registered: int
    cache_size: int
    executions: int
    avg_execution_time: float


@router.post("/query", response_model=APIQueryResponse)
async def query_apis(request: APIQueryRequest) -> APIQueryResponse:
    """
    Query multiple OSINT APIs concurrently.

    Returns correlated and deduplicated results across all APIs.
    Supports auto-detection of query type (IP, domain, email, URL, hash).
    """
    try:
        manager = get_api_manager()

        if not manager._initialized:
            raise HTTPException(status_code=503, detail="API Manager not initialized")

        logger.info(f"API query: {request.query}")
        result = await manager.query(
            query=request.query,
            apis=request.apis,
            use_cache=request.use_cache,
        )

        correlation = result["correlation"]
        return APIQueryResponse(
            query=request.query,
            execution_time_seconds=result["execution_time_seconds"],
            total_results=correlation["total_results"],
            total_sources=len(correlation["sources"]),
            deduplicated_count=len(correlation["deduplicated"]),
            sources=correlation["sources"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/query/{query_id}/results", response_model=Dict[str, Any])
async def get_query_results(query_id: str) -> Dict[str, Any]:
    """
    Get full results for a query (with raw API responses).

    Returns deduplicated data from all sources with source attribution.
    """
    try:
        manager = get_api_manager()

        # Find execution log entry by query
        execution = None
        for log_entry in manager.execution_log:
            if log_entry["query"] == query_id:
                execution = log_entry
                break

        if not execution:
            raise HTTPException(status_code=404, detail="Query not found in execution log")

        return {
            "query": query_id,
            "timestamp": execution["timestamp"],
            "apis_queried": execution["apis_queried"],
            "apis_succeeded": execution["apis_succeeded"],
            "total_results": execution["total_results"],
            "execution_time_seconds": execution["execution_time_seconds"],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Results retrieval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/clear-cache")
async def clear_cache() -> Dict[str, str]:
    """Clear the API result cache."""
    try:
        manager = get_api_manager()
        cache_size_before = len(manager.cache.cache)
        manager.cache.clear()
        logger.info(f"Cache cleared ({cache_size_before} entries removed)")

        return {
            "status": "success",
            "message": f"Cache cleared ({cache_size_before} entries removed)",
        }

    except Exception as e:
        logger.error(f"Cache clear error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats", response_model=APIStatsResponse)
async def get_api_stats() -> APIStatsResponse:
    """Get API Manager statistics."""
    try:
        manager = get_api_manager()
        stats = manager.get_stats()

        return APIStatsResponse(
            initialized=stats["initialized"],
            apis_registered=stats["apis_registered"],
            cache_size=stats["cache_size"],
            executions=stats["executions"],
            avg_execution_time=stats["avg_execution_time"],
        )

    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/registered", response_model=Dict[str, List[str]])
async def get_registered_apis() -> Dict[str, List[str]]:
    """Get list of registered APIs."""
    try:
        manager = get_api_manager()
        return {
            "apis": list(manager.apis.keys()),
            "count": len(manager.apis),
        }

    except Exception as e:
        logger.error(f"Registration list error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
