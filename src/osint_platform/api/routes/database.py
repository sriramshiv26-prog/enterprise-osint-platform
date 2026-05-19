"""Database API routes for entity and relationship management."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import List, Optional
from datetime import datetime
import uuid

from src.osint_platform.database.models import (
    Entity, Relationship, ThreatScore, Finding, Investigation, User,
    SyncEvent, InvestigationSnapshot
)
from src.osint_platform.database.session import get_db
from src.osint_platform.api.schemas import (
    EntityCreate, EntityUpdate, EntityResponse,
    RelationshipCreate, RelationshipResponse,
    ThreatScoreResponse, FindingResponse,
    InvestigationResponse, SnapshotResponse
)

router = APIRouter(prefix="/api/v1/database", tags=["database"])


# Entity endpoints

@router.post("/entities", response_model=EntityResponse)
async def create_entity(
    investigation_id: str,
    entity: EntityCreate,
    db: Session = Depends(get_db),
) -> EntityResponse:
    """Create a new entity."""
    try:
        # Verify investigation exists
        investigation = db.get(Investigation, investigation_id)
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Create entity
        new_entity = Entity(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            entity_type=entity.entity_type,
            value=entity.value,
            risk_level=entity.risk_level or "INFO",
            confidence=entity.confidence or 0.0,
            source=entity.source,
            first_seen=entity.first_seen,
            last_seen=entity.last_seen,
            custom_metadata=entity.custom_metadata or {},
        )

        db.add(new_entity)
        db.commit()
        db.refresh(new_entity)

        # Enqueue sync event
        sync_event = SyncEvent(
            event_type="entity_created",
            investigation_id=investigation_id,
            entity_id=new_entity.id,
            payload={
                "entity_id": new_entity.id,
                "entity_type": new_entity.entity_type,
                "value": new_entity.value,
            },
        )
        db.add(sync_event)
        db.commit()

        return EntityResponse.from_orm(new_entity)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/entities/{entity_id}", response_model=EntityResponse)
async def get_entity(
    entity_id: str,
    db: Session = Depends(get_db),
) -> EntityResponse:
    """Get an entity by ID."""
    entity = db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    return EntityResponse.from_orm(entity)


@router.get("/investigations/{investigation_id}/entities", response_model=List[EntityResponse])
async def list_entities(
    investigation_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    risk_level: Optional[str] = None,
    db: Session = Depends(get_db),
) -> List[EntityResponse]:
    """List entities for an investigation."""
    stmt = select(Entity).where(Entity.investigation_id == investigation_id)

    if risk_level:
        stmt = stmt.where(Entity.risk_level == risk_level)

    stmt = stmt.offset(skip).limit(limit)
    entities = db.execute(stmt).scalars().all()

    return [EntityResponse.from_orm(e) for e in entities]


@router.put("/entities/{entity_id}", response_model=EntityResponse)
async def update_entity(
    entity_id: str,
    entity_update: EntityUpdate,
    db: Session = Depends(get_db),
) -> EntityResponse:
    """Update an entity."""
    entity = db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    update_data = entity_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(entity, field, value)

    entity.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(entity)

    return EntityResponse.from_orm(entity)


@router.delete("/entities/{entity_id}")
async def delete_entity(
    entity_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Delete an entity."""
    entity = db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    db.delete(entity)
    db.commit()

    return {"status": "deleted", "entity_id": entity_id}


# Relationship endpoints

@router.post("/relationships", response_model=RelationshipResponse)
async def create_relationship(
    investigation_id: str,
    relationship: RelationshipCreate,
    db: Session = Depends(get_db),
) -> RelationshipResponse:
    """Create a relationship between entities."""
    try:
        # Verify both entities exist
        source = db.get(Entity, relationship.source_id)
        target = db.get(Entity, relationship.target_id)

        if not source or not target:
            raise HTTPException(status_code=404, detail="Source or target entity not found")

        # Create relationship
        new_rel = Relationship(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            source_id=relationship.source_id,
            target_id=relationship.target_id,
            relationship_type=relationship.relationship_type,
            confidence=relationship.confidence or 0.0,
            evidence=relationship.evidence or {},
            custom_metadata=relationship.custom_metadata or {},
        )

        db.add(new_rel)
        db.commit()
        db.refresh(new_rel)

        # Enqueue sync event
        sync_event = SyncEvent(
            event_type="relationship_added",
            investigation_id=investigation_id,
            payload={
                "relationship_id": new_rel.id,
                "source_id": new_rel.source_id,
                "target_id": new_rel.target_id,
            },
        )
        db.add(sync_event)
        db.commit()

        return RelationshipResponse.from_orm(new_rel)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/relationships/{relationship_id}", response_model=RelationshipResponse)
async def get_relationship(
    relationship_id: str,
    db: Session = Depends(get_db),
) -> RelationshipResponse:
    """Get a relationship by ID."""
    rel = db.get(Relationship, relationship_id)
    if not rel:
        raise HTTPException(status_code=404, detail="Relationship not found")
    return RelationshipResponse.from_orm(rel)


@router.get("/investigations/{investigation_id}/relationships", response_model=List[RelationshipResponse])
async def list_relationships(
    investigation_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    relationship_type: Optional[str] = None,
    db: Session = Depends(get_db),
) -> List[RelationshipResponse]:
    """List relationships for an investigation."""
    stmt = select(Relationship).where(Relationship.investigation_id == investigation_id)

    if relationship_type:
        stmt = stmt.where(Relationship.relationship_type == relationship_type)

    stmt = stmt.offset(skip).limit(limit)
    relationships = db.execute(stmt).scalars().all()

    return [RelationshipResponse.from_orm(r) for r in relationships]


@router.delete("/relationships/{relationship_id}")
async def delete_relationship(
    relationship_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Delete a relationship."""
    rel = db.get(Relationship, relationship_id)
    if not rel:
        raise HTTPException(status_code=404, detail="Relationship not found")

    db.delete(rel)
    db.commit()

    return {"status": "deleted", "relationship_id": relationship_id}


# Investigation endpoints

@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
) -> InvestigationResponse:
    """Get investigation details."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return InvestigationResponse.from_orm(investigation)


@router.get("/investigations/{investigation_id}/stats")
async def get_investigation_stats(
    investigation_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Get investigation statistics."""
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    entity_count = len(investigation.entities)
    relationship_count = len(investigation.relationships)
    threat_score_count = len(investigation.threat_scores)
    alert_count = len(investigation.alerts)
    finding_count = len(investigation.findings)

    return {
        "entity_count": entity_count,
        "relationship_count": relationship_count,
        "threat_score_count": threat_score_count,
        "alert_count": alert_count,
        "finding_count": finding_count,
        "total_risk_indicators": entity_count + relationship_count,
    }


# Snapshot endpoints

@router.get("/investigations/{investigation_id}/snapshots", response_model=List[SnapshotResponse])
async def list_snapshots(
    investigation_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
) -> List[SnapshotResponse]:
    """List investigation snapshots."""
    stmt = (
        select(InvestigationSnapshot)
        .where(InvestigationSnapshot.investigation_id == investigation_id)
        .order_by(InvestigationSnapshot.created_at.desc())
        .offset(skip)
        .limit(limit)
    )

    snapshots = db.execute(stmt).scalars().all()
    return [SnapshotResponse.from_orm(s) for s in snapshots]


# Sync status endpoint

@router.get("/sync/status")
async def get_sync_status(db: Session = Depends(get_db)) -> dict:
    """Get synchronization status."""
    pending_events = len(db.execute(
        select(SyncEvent).where(SyncEvent.synced_to_neo4j == False)
    ).scalars().all())

    return {
        "pending_sync_events": pending_events,
        "sync_status": "healthy" if pending_events == 0 else "catching_up",
    }
