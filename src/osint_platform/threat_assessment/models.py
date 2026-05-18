"""
Threat Assessment models.

Defines threat scoring, alerts, and evidence collection.
"""
from typing import Dict, Any, List, Optional
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    """Types of security alerts."""
    MALWARE = "malware"
    PHISHING = "phishing"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    POLICY_VIOLATION = "policy_violation"


class Evidence(BaseModel):
    """Piece of evidence supporting a finding."""
    id: str = Field(..., description="Unique evidence ID")
    type: str = Field(..., description="Evidence type (API response, detection, etc.)")
    source: str = Field(..., description="Source API/tool")
    content: Dict[str, Any] = Field(..., description="Evidence data")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    reliability: float = Field(default=1.0, description="Reliability score (0.0-1.0)")


class ThreatScore(BaseModel):
    """Calculated threat score for an entity."""
    entity_id: str
    entity_value: str
    entity_type: str
    threat_level: ThreatLevel
    score: float = Field(..., description="Numerical score (0-100)")
    confidence: float = Field(..., description="Confidence in score (0.0-1.0)")
    factors: Dict[str, float] = Field(default_factory=dict, description="Contributing factors")
    evidence: List[Evidence] = Field(default_factory=list)
    calculated_at: datetime = Field(default_factory=datetime.utcnow)


class Alert(BaseModel):
    """Security alert triggered by detection."""
    id: str
    alert_type: AlertType
    threat_level: ThreatLevel
    title: str
    description: str
    affected_entities: List[str] = Field(description="Entity IDs involved")
    threat_score: Optional[ThreatScore] = None
    evidence_ids: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved: bool = False
    resolved_at: Optional[datetime] = None


class Finding(BaseModel):
    """A complete finding from an investigation."""
    id: str
    title: str
    description: str
    threat_level: ThreatLevel
    entity_id: str
    investigation_id: str
    evidence: List[Evidence]
    related_alerts: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ReportSection(BaseModel):
    """Section of an investigation report."""
    title: str
    content: str
    findings: List[Finding] = Field(default_factory=list)
    subsections: List["ReportSection"] = Field(default_factory=list)


class InvestigationReport(BaseModel):
    """Complete investigation report."""
    id: str
    title: str
    investigation_id: str
    threat_level: ThreatLevel
    executive_summary: str
    sections: List[ReportSection]
    findings: List[Finding]
    alerts: List[Alert]
    recommendations: List[str]
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str = "Enterprise OSINT Platform"


class DetectionRule(BaseModel):
    """Rule for automated threat detection."""
    id: str
    name: str
    description: str
    condition: Dict[str, Any] = Field(description="Detection condition (JSON logic)")
    alert_type: AlertType
    severity: ThreatLevel
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_triggered: Optional[datetime] = None
