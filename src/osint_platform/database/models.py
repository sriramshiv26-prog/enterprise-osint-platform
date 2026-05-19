"""SQLAlchemy ORM models for database persistence."""
from datetime import datetime
from typing import Optional
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index, Enum, Table
from sqlalchemy.orm import declarative_base, relationship
import enum
import uuid

Base = declarative_base()


class User(Base):
    """User account model."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(128), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    investigations = relationship("Investigation", back_populates="user")
    __table_args__ = (
        Index("idx_user_email_active", "email", "is_active"),
        Index("idx_user_created_at", "created_at"),
    )


class Investigation(Base):
    """Investigation case model."""
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(String(50), default="active", index=True)  # active, archived, closed
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    custom_metadata = Column(JSON, default=dict)

    user = relationship("User", back_populates="investigations")
    entities = relationship("Entity", back_populates="investigation", cascade="all, delete-orphan")
    relationships = relationship("Relationship", back_populates="investigation", cascade="all, delete-orphan")
    threat_scores = relationship("ThreatScore", back_populates="investigation", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="investigation", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="investigation", cascade="all, delete-orphan")
    snapshots = relationship("InvestigationSnapshot", back_populates="investigation", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_investigation_user_status", "user_id", "status"),
        Index("idx_investigation_created_at", "created_at"),
    )


class EntityTypeEnum(str, enum.Enum):
    """Entity types enumeration."""
    IP = "IP"
    DOMAIN = "DOMAIN"
    EMAIL = "EMAIL"
    HASH = "HASH"
    URL = "URL"
    CERT = "CERT"
    NAMESERVER = "NAMESERVER"
    REGISTRAR = "REGISTRAR"
    ASN = "ASN"


class Entity(Base):
    """Entity model for threat indicators."""
    __tablename__ = "entities"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False, index=True)
    value = Column(String(512), nullable=False, index=True)
    risk_level = Column(String(50), default="INFO", index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=0.0)
    source = Column(String(128))
    first_seen = Column(DateTime, index=True)
    last_seen = Column(DateTime, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    custom_metadata = Column(JSON, default=dict)

    investigation = relationship("Investigation", back_populates="entities")
    outbound_relationships = relationship("Relationship", foreign_keys="Relationship.source_id", back_populates="source_entity")
    inbound_relationships = relationship("Relationship", foreign_keys="Relationship.target_id", back_populates="target_entity")
    threat_scores = relationship("ThreatScore", back_populates="entity", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_entity_investigation_type", "investigation_id", "entity_type"),
        Index("idx_entity_value", "value"),
        Index("idx_entity_risk_level", "risk_level"),
        Index("idx_entity_created_at", "created_at"),
    )


class Relationship(Base):
    """Relationship between entities model."""
    __tablename__ = "relationships"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, index=True)
    source_id = Column(String(36), ForeignKey("entities.id"), nullable=False, index=True)
    target_id = Column(String(36), ForeignKey("entities.id"), nullable=False, index=True)
    relationship_type = Column(String(128), nullable=False, index=True)
    confidence = Column(Float, default=0.0)
    evidence = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    custom_metadata = Column(JSON, default=dict)

    investigation = relationship("Investigation", back_populates="relationships")
    source_entity = relationship("Entity", foreign_keys=[source_id], back_populates="outbound_relationships")
    target_entity = relationship("Entity", foreign_keys=[target_id], back_populates="inbound_relationships")

    __table_args__ = (
        Index("idx_relationship_investigation", "investigation_id"),
        Index("idx_relationship_source_target", "source_id", "target_id"),
        Index("idx_relationship_type", "relationship_type"),
        Index("idx_relationship_created_at", "created_at"),
    )


class ThreatScore(Base):
    """Threat score model."""
    __tablename__ = "threat_scores"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, index=True)
    entity_id = Column(String(36), ForeignKey("entities.id"), nullable=False, index=True)
    overall_score = Column(Float, nullable=False, index=True)
    threat_level = Column(String(50), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    malware_score = Column(Float, default=0.0)
    phishing_score = Column(Float, default=0.0)
    c2_score = Column(Float, default=0.0)
    breach_history_score = Column(Float, default=0.0)
    reputation_score = Column(Float, default=0.0)
    infrastructure_sharing_score = Column(Float, default=0.0)
    recency_score = Column(Float, default=0.0)
    credential_exposure_score = Column(Float, default=0.0)
    evidence = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="threat_scores")
    entity = relationship("Entity", back_populates="threat_scores")

    __table_args__ = (
        Index("idx_threat_score_investigation", "investigation_id"),
        Index("idx_threat_score_entity", "entity_id"),
        Index("idx_threat_score_overall", "overall_score"),
        Index("idx_threat_score_level", "threat_level"),
    )


class Alert(Base):
    """Alert model for threat detections."""
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, index=True)
    threat_score_id = Column(String(36), ForeignKey("threat_scores.id"), nullable=False, index=True)
    alert_type = Column(String(128), nullable=False, index=True)  # MALWARE, PHISHING, C2_COMMUNICATION, etc.
    severity = Column(String(50), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    title = Column(String(255), nullable=False)
    description = Column(Text)
    evidence = Column(JSON, default=dict)
    is_acknowledged = Column(Boolean, default=False, index=True)
    acknowledged_at = Column(DateTime)
    acknowledged_by = Column(String(36), ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="alerts")

    __table_args__ = (
        Index("idx_alert_investigation", "investigation_id"),
        Index("idx_alert_type", "alert_type"),
        Index("idx_alert_severity", "severity"),
        Index("idx_alert_acknowledged", "is_acknowledged"),
        Index("idx_alert_created_at", "created_at"),
    )


class Finding(Base):
    """Finding model for investigation conclusions."""
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, index=True)
    finding_type = Column(String(128), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False, index=True)
    evidence = Column(JSON, default=dict)
    recommendations = Column(JSON, default=list)
    status = Column(String(50), default="open", index=True)  # open, in_progress, resolved
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="findings")

    __table_args__ = (
        Index("idx_finding_investigation", "investigation_id"),
        Index("idx_finding_severity", "severity"),
        Index("idx_finding_status", "status"),
    )


class InvestigationSnapshot(Base):
    """Snapshot of investigation state at a point in time."""
    __tablename__ = "investigation_snapshots"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, index=True)
    entity_count = Column(Integer, default=0)
    relationship_count = Column(Integer, default=0)
    cluster_count = Column(Integer, default=0)
    pattern_count = Column(Integer, default=0)
    risk_distribution = Column(JSON, default=dict)
    graph_density = Column(Float, default=0.0)
    avg_node_degree = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    investigation = relationship("Investigation", back_populates="snapshots")

    __table_args__ = (
        Index("idx_snapshot_investigation", "investigation_id"),
        Index("idx_snapshot_created_at", "created_at"),
    )


class SyncEvent(Base):
    """Event tracking for PostgreSQL → Neo4j synchronization."""
    __tablename__ = "sync_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String(50), nullable=False, index=True)  # entity_created, entity_updated, relationship_added, etc.
    entity_id = Column(String(36), index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id"), nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    synced_to_neo4j = Column(Boolean, default=False, index=True)
    sync_attempts = Column(Integer, default=0)
    last_sync_attempt = Column(DateTime)
    last_sync_error = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    synced_at = Column(DateTime)

    investigation = relationship("Investigation")

    __table_args__ = (
        Index("idx_sync_event_investigation", "investigation_id"),
        Index("idx_sync_event_synced", "synced_to_neo4j"),
        Index("idx_sync_event_created_at", "created_at"),
    )


class SyncLog(Base):
    """Log of synchronization operations."""
    __tablename__ = "sync_log"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    batch_id = Column(String(36), nullable=False, index=True)
    event_count = Column(Integer, nullable=False)
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    status = Column(String(50), nullable=False, index=True)  # pending, in_progress, success, partial, failed
    error_message = Column(Text)
    duration_ms = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime)

    __table_args__ = (
        Index("idx_sync_log_batch_id", "batch_id"),
        Index("idx_sync_log_status", "status"),
        Index("idx_sync_log_created_at", "created_at"),
    )
