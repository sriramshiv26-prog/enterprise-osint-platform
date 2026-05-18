"""
Context Graph data models.

Defines entity types, relationships, and graph structures.
"""
from typing import Dict, Any, List, Optional, Set
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """Entity types in the context graph."""
    IP = "ip"
    DOMAIN = "domain"
    EMAIL = "email"
    HASH = "hash"
    URL = "url"
    CERT = "certificate"
    NAMESERVER = "nameserver"
    REGISTRAR = "registrar"
    ASN = "asn"


class RelationType(str, Enum):
    """Types of relationships between entities."""
    RESOLVES_TO = "resolves_to"  # Domain → IP
    HOSTED_ON = "hosted_on"  # URL/Hash → IP
    REGISTERED_WITH = "registered_with"  # Domain → Registrar
    NAMESERVER = "nameserver"  # Domain → Nameserver
    CERT_ISSUED_FOR = "cert_issued_for"  # Certificate → Domain
    COMMUNICATES_WITH = "communicates_with"  # IP ↔ IP
    SHARES_INFRASTRUCTURE = "shares_infrastructure"  # IP ↔ IP (same ASN)
    USED_BY = "used_by"  # Email/Hash → Campaign
    PHISHING = "phishing"  # Email/URL → Target
    MALWARE = "malware"  # Hash → Family
    C2 = "c2"  # IP/Domain → Campaign


class RiskLevel(str, Enum):
    """Risk assessment levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Entity(BaseModel):
    """Node in the context graph."""
    id: str = Field(..., description="Unique entity identifier")
    type: EntityType = Field(..., description="Entity type")
    value: str = Field(..., description="Entity value")
    risk_level: RiskLevel = Field(default=RiskLevel.INFO)
    source_apis: List[str] = Field(default_factory=list, description="APIs that discovered this entity")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Type-specific attributes")
    tags: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True


class Relationship(BaseModel):
    """Edge between two entities in the context graph."""
    id: str = Field(..., description="Unique relationship ID")
    source_id: str = Field(..., description="Source entity ID")
    target_id: str = Field(..., description="Target entity ID")
    type: RelationType = Field(..., description="Relationship type")
    confidence: float = Field(default=1.0, description="Confidence score (0.0-1.0)")
    source_apis: List[str] = Field(default_factory=list, description="APIs that found this relationship")
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[str] = Field(default_factory=list, description="Supporting evidence")

    class Config:
        use_enum_values = True


class EntityPath(BaseModel):
    """Path between two entities in the graph."""
    source_id: str
    target_id: str
    path: List[str] = Field(description="Ordered list of entity IDs in path")
    relationships: List[Relationship] = Field(description="Relationships along the path")
    distance: int = Field(description="Number of hops")


class Cluster(BaseModel):
    """Connected component in the graph (possible campaign/threat group)."""
    id: str = Field(..., description="Cluster identifier")
    entities: List[str] = Field(description="Entity IDs in this cluster")
    relationships: List[str] = Field(description="Relationship IDs in this cluster")
    size: int = Field(description="Number of entities in cluster")
    risk_level: RiskLevel = Field(default=RiskLevel.INFO)
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Pattern(BaseModel):
    """Detected pattern in the context graph."""
    id: str
    pattern_type: str  # "shared_infrastructure", "campaign_activity", "botnet", etc.
    entities: List[str]  # Entities involved in pattern
    confidence: float  # Pattern confidence score
    indicators: Dict[str, Any]  # Pattern-specific data
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    description: str


class InvestigationSnapshot(BaseModel):
    """Snapshot of investigation state at a point in time."""
    id: str
    investigation_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    entity_count: int
    relationship_count: int
    cluster_count: int
    pattern_count: int
    risk_distribution: Dict[str, int]  # Risk level → count
    graph_density: float  # Relationship density
    avg_node_degree: float  # Average connections per node
