"""
FastAPI routes for context graph operations.

Endpoints for entity/relationship management and graph analysis.
"""
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.osint_platform.context_graph.engine import get_context_graph_engine
from src.osint_platform.context_graph.models import (
    Entity, Relationship, EntityType, RelationType, RiskLevel,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/graph", tags=["Context Graph"])


class EntityRequest(BaseModel):
    """Request to add entity."""
    graph_id: str
    type: str
    value: str
    risk_level: str = "info"
    source_apis: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class RelationshipRequest(BaseModel):
    """Request to add relationship."""
    graph_id: str
    source_id: str
    target_id: str
    type: str
    confidence: float = 1.0
    source_apis: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)


class EntityResponse(BaseModel):
    """Response with entity details."""
    id: str
    type: str
    value: str
    risk_level: str
    source_apis: List[str]
    tags: List[str]


class RelationshipResponse(BaseModel):
    """Response with relationship details."""
    id: str
    source_id: str
    target_id: str
    type: str
    confidence: float
    source_apis: List[str]


@router.post("/entities")
async def add_entity(request: EntityRequest) -> Dict[str, str]:
    """Add entity to context graph."""
    try:
        engine = get_context_graph_engine()
        graph = engine.get_graph(request.graph_id)
        if not graph:
            graph = engine.create_graph(request.graph_id)

        entity = Entity(
            id=f"{request.graph_id}:{request.type}:{request.value}",
            type=EntityType(request.type),
            value=request.value,
            risk_level=RiskLevel(request.risk_level),
            source_apis=request.source_apis,
            tags=request.tags,
            metadata=request.metadata,
            attributes=request.attributes,
        )

        engine.add_entity(request.graph_id, entity)

        return {"entity_id": entity.id, "status": "created"}

    except ValueError as e:
        logger.error(f"Entity creation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/relationships")
async def add_relationship(request: RelationshipRequest) -> Dict[str, str]:
    """Add relationship between entities."""
    try:
        engine = get_context_graph_engine()

        relationship = Relationship(
            id=f"{request.source_id}-{request.type}-{request.target_id}",
            source_id=request.source_id,
            target_id=request.target_id,
            type=RelationType(request.type),
            confidence=request.confidence,
            source_apis=request.source_apis,
            evidence=request.evidence,
        )

        engine.add_relationship(request.graph_id, relationship)

        return {"relationship_id": relationship.id, "status": "created"}

    except ValueError as e:
        logger.error(f"Relationship creation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{graph_id}/stats")
async def get_graph_stats(graph_id: str) -> Dict[str, Any]:
    """Get context graph statistics."""
    try:
        engine = get_context_graph_engine()
        graph = engine.get_graph(graph_id)
        if not graph:
            raise HTTPException(status_code=404, detail="Graph not found")

        return graph.get_stats()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{graph_id}/clusters")
async def get_clusters(graph_id: str) -> Dict[str, Any]:
    """Get entity clusters in graph."""
    try:
        engine = get_context_graph_engine()
        graph = engine.get_graph(graph_id)
        if not graph:
            raise HTTPException(status_code=404, detail="Graph not found")

        clusters = graph.find_clusters()
        return {
            "cluster_count": len(clusters),
            "clusters": [
                {
                    "id": c.id,
                    "size": c.size,
                    "risk_level": c.risk_level,
                    "entity_count": len(c.entities),
                    "relationship_count": len(c.relationships),
                }
                for c in clusters
            ],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Cluster detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{graph_id}/patterns")
async def detect_patterns(graph_id: str) -> Dict[str, Any]:
    """Detect patterns in graph."""
    try:
        engine = get_context_graph_engine()
        graph = engine.get_graph(graph_id)
        if not graph:
            raise HTTPException(status_code=404, detail="Graph not found")

        patterns = graph.detect_patterns()
        return {
            "pattern_count": len(patterns),
            "patterns": [
                {
                    "id": p.id,
                    "type": p.pattern_type,
                    "confidence": p.confidence,
                    "entities": len(p.entities),
                    "description": p.description,
                }
                for p in patterns
            ],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Pattern detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{graph_id}/path")
async def find_path(
    graph_id: str,
    source_id: str,
    target_id: str,
    max_depth: int = 5,
) -> Dict[str, Any]:
    """Find path between two entities."""
    try:
        engine = get_context_graph_engine()
        graph = engine.get_graph(graph_id)
        if not graph:
            raise HTTPException(status_code=404, detail="Graph not found")

        path = graph.find_path(source_id, target_id, max_depth)
        if not path:
            return {"found": False, "reason": "No path found"}

        return {
            "found": True,
            "distance": path.distance,
            "path": path.path,
            "hop_count": len(path.path) - 1,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Path finding error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{graph_id}/neighbors/{entity_id}")
async def get_neighbors(graph_id: str, entity_id: str) -> Dict[str, Any]:
    """Get all neighbors of an entity."""
    try:
        engine = get_context_graph_engine()
        graph = engine.get_graph(graph_id)
        if not graph:
            raise HTTPException(status_code=404, detail="Graph not found")

        neighbors = graph.get_neighbors(entity_id)
        predecessors = graph.get_predecessors(entity_id)

        return {
            "entity_id": entity_id,
            "outbound": [
                {"id": n.id, "type": n.type, "value": n.value, "risk_level": n.risk_level}
                for n in neighbors
            ],
            "inbound": [
                {"id": p.id, "type": p.type, "value": p.value, "risk_level": p.risk_level}
                for p in predecessors
            ],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Neighbor lookup error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{graph_id}/snapshot")
async def create_snapshot(graph_id: str, investigation_id: str) -> Dict[str, Any]:
    """Create snapshot of graph state."""
    try:
        engine = get_context_graph_engine()
        snapshot = engine.create_snapshot(graph_id, investigation_id)

        return {
            "snapshot_id": snapshot.id,
            "investigation_id": snapshot.investigation_id,
            "entity_count": snapshot.entity_count,
            "relationship_count": snapshot.relationship_count,
            "cluster_count": snapshot.cluster_count,
            "pattern_count": snapshot.pattern_count,
            "graph_density": snapshot.graph_density,
            "avg_node_degree": snapshot.avg_node_degree,
        }

    except Exception as e:
        logger.error(f"Snapshot creation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
