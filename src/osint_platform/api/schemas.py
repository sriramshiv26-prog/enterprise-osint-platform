"""Pydantic schemas for API requests and responses."""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


# Entity schemas

class EntityCreate(BaseModel):
    """Create entity request."""
    entity_type: str
    value: str
    risk_level: Optional[str] = "INFO"
    confidence: Optional[float] = 0.0
    source: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    custom_metadata: Optional[Dict[str, Any]] = None


class EntityUpdate(BaseModel):
    """Update entity request."""
    risk_level: Optional[str] = None
    confidence: Optional[float] = None
    last_seen: Optional[datetime] = None
    custom_metadata: Optional[Dict[str, Any]] = None


class EntityResponse(BaseModel):
    """Entity response."""
    id: str
    investigation_id: str
    entity_type: str
    value: str
    risk_level: str
    confidence: float
    source: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    custom_metadata: Dict[str, Any]

    class Config:
        from_attributes = True


# Relationship schemas

class RelationshipCreate(BaseModel):
    """Create relationship request."""
    source_id: str
    target_id: str
    relationship_type: str
    confidence: Optional[float] = 0.0
    evidence: Optional[Dict[str, Any]] = None
    custom_metadata: Optional[Dict[str, Any]] = None


class RelationshipResponse(BaseModel):
    """Relationship response."""
    id: str
    investigation_id: str
    source_id: str
    target_id: str
    relationship_type: str
    confidence: float
    evidence: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    custom_metadata: Dict[str, Any]

    class Config:
        from_attributes = True


# Threat Score schemas

class ThreatScoreResponse(BaseModel):
    """Threat score response."""
    id: str
    investigation_id: str
    entity_id: str
    overall_score: float
    threat_level: str
    malware_score: float
    phishing_score: float
    c2_score: float
    breach_history_score: float
    reputation_score: float
    infrastructure_sharing_score: float
    recency_score: float
    credential_exposure_score: float
    evidence: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Finding schemas

class FindingResponse(BaseModel):
    """Finding response."""
    id: str
    investigation_id: str
    finding_type: str
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any]
    recommendations: List[str]
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Investigation schemas

class InvestigationResponse(BaseModel):
    """Investigation response."""
    id: str
    user_id: str
    title: str
    description: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime
    custom_metadata: Dict[str, Any]
    entity_count: int = 0
    relationship_count: int = 0

    class Config:
        from_attributes = True

    @classmethod
    def from_orm(cls, obj):
        """Convert ORM object to response."""
        return cls(
            id=obj.id,
            user_id=obj.user_id,
            title=obj.title,
            description=obj.description,
            status=obj.status,
            created_at=obj.created_at,
            updated_at=obj.updated_at,
            custom_metadata=obj.custom_metadata,
            entity_count=len(obj.entities),
            relationship_count=len(obj.relationships),
        )


# Snapshot schemas

class SnapshotResponse(BaseModel):
    """Investigation snapshot response."""
    id: str
    investigation_id: str
    entity_count: int
    relationship_count: int
    cluster_count: int
    pattern_count: int
    risk_distribution: Dict[str, Any]
    graph_density: float
    avg_node_degree: float
    created_at: datetime

    class Config:
        from_attributes = True


# User schemas

class UserCreate(BaseModel):
    """Create user request."""
    email: str
    username: str
    password: str


class UserResponse(BaseModel):
    """User response."""
    id: str
    email: str
    username: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
