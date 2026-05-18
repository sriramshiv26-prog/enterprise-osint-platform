"""
FastAPI routes for threat assessment, alerts, and reporting.

Endpoints for threat scoring, alert generation, and report creation.
"""
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.osint_platform.threat_assessment.models import (
    ThreatScore, Alert, Finding, Evidence,
)
from src.osint_platform.threat_assessment.scoring import ThreatScoringEngine, AlertGenerator
from src.osint_platform.threat_assessment.reporting import ReportGenerator, TimelineBuilder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-assessment", tags=["Threat Assessment"])


class ThreatAssessmentRequest(BaseModel):
    """Request to assess threat of an entity."""
    entity_id: str
    entity_value: str
    entity_type: str  # ip, domain, email, hash, url
    evidence: List[Dict[str, Any]] = Field(default_factory=list)


class ThreatAssessmentResponse(BaseModel):
    """Response with threat score and recommendations."""
    entity_id: str
    entity_value: str
    threat_level: str
    threat_score: float
    confidence: float
    alerts: List[Dict[str, Any]]
    factors: Dict[str, float]


class ReportRequest(BaseModel):
    """Request to generate report."""
    investigation_id: str
    title: str
    threat_score_id: str
    alert_ids: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    format: str = "html"  # html or text


@router.post("/assess", response_model=ThreatAssessmentResponse)
async def assess_threat(request: ThreatAssessmentRequest) -> ThreatAssessmentResponse:
    """
    Assess threat level of an entity.

    Calculates threat score based on evidence from APIs.
    """
    try:
        # Convert evidence dicts to Evidence objects
        evidence_objects = [
            Evidence(
                id=f"{request.entity_id}:ev:{i}",
                type=ev.get("type", "unknown"),
                source=ev.get("source", "unknown"),
                content=ev.get("content", {}),
                reliability=ev.get("reliability", 1.0),
            )
            for i, ev in enumerate(request.evidence)
        ]

        # Calculate threat score
        threat_score = ThreatScoringEngine.calculate_score(
            entity_id=request.entity_id,
            entity_value=request.entity_value,
            entity_type=request.entity_type,
            evidence=evidence_objects,
        )

        # Generate alerts
        alerts = AlertGenerator.generate_alerts(threat_score)

        return ThreatAssessmentResponse(
            entity_id=threat_score.entity_id,
            entity_value=threat_score.entity_value,
            threat_level=threat_score.threat_level.value,
            threat_score=threat_score.score,
            confidence=threat_score.confidence,
            alerts=[
                {
                    "type": alert.alert_type.value,
                    "level": alert.threat_level.value,
                    "title": alert.title,
                    "description": alert.description,
                    "actions": alert.recommended_actions,
                }
                for alert in alerts
            ],
            factors=threat_score.factors,
        )

    except Exception as e:
        logger.error(f"Threat assessment error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/report")
async def generate_report(request: ReportRequest) -> Dict[str, Any]:
    """
    Generate investigation report.

    Creates HTML or text report from findings and alerts.
    """
    try:
        # For demo, generate mock findings
        findings = [
            Finding(
                id="finding_1",
                title="Suspicious IP Registration",
                description="IP registered in high-risk jurisdiction",
                threat_level="high",
                entity_id="entity_1",
                investigation_id=request.investigation_id,
                evidence=[],
            ),
        ]

        alerts = [
            Alert(
                id="alert_1",
                alert_type="suspicious_activity",
                threat_level="high",
                title=f"High-Risk Entity Detected",
                description="Entity exhibits multiple threat indicators",
                affected_entities=["entity_1"],
                recommended_actions=["Block at perimeter", "Monitor communications"],
            ),
        ]

        # Create mock threat score
        threat_score = ThreatScore(
            entity_id="entity_1",
            entity_value="192.168.1.1",
            entity_type="ip",
            threat_level="high",
            score=72.5,
            confidence=0.85,
            factors={
                "malware_detection": 0.9,
                "phishing_indicators": 0.2,
                "c2_communication": 0.1,
                "breach_history": 0.8,
                "reputation_score": 0.7,
                "infrastructure_sharing": 0.3,
                "temporal_recency": 0.6,
                "credential_exposure": 0.4,
            },
            evidence=[],
        )

        if request.format == "html":
            report_content = ReportGenerator.generate_html_report(
                title=request.title,
                investigation_id=request.investigation_id,
                threat_score=threat_score,
                alerts=alerts,
                findings=findings,
                recommendations=request.recommendations,
            )
        else:
            report_content = ReportGenerator.generate_text_report(
                title=request.title,
                investigation_id=request.investigation_id,
                threat_score=threat_score,
                alerts=alerts,
                findings=findings,
                recommendations=request.recommendations,
            )

        return {
            "report_id": f"report_{request.investigation_id}",
            "investigation_id": request.investigation_id,
            "title": request.title,
            "format": request.format,
            "generated_at": __import__("datetime").datetime.utcnow().isoformat(),
            "findings_count": len(findings),
            "alerts_count": len(alerts),
            "preview": report_content[:500] if request.format == "html" else report_content[:300],
        }

    except Exception as e:
        logger.error(f"Report generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def get_alerts(investigation_id: str, severity: Optional[str] = None) -> Dict[str, Any]:
    """Get alerts for an investigation."""
    try:
        # For demo, return mock alerts
        alerts = [
            {
                "id": "alert_1",
                "type": "malware",
                "severity": "critical",
                "title": "Malware Detected",
                "description": "Multiple sources confirm malware presence",
                "created_at": __import__("datetime").datetime.utcnow().isoformat(),
            },
            {
                "id": "alert_2",
                "type": "suspicious_activity",
                "severity": "high",
                "title": "Suspicious Infrastructure",
                "description": "Multiple domains on same IP address",
                "created_at": __import__("datetime").datetime.utcnow().isoformat(),
            },
        ]

        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]

        return {
            "investigation_id": investigation_id,
            "alert_count": len(alerts),
            "alerts": alerts,
        }

    except Exception as e:
        logger.error(f"Alert retrieval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/timeline/{investigation_id}")
async def get_timeline(investigation_id: str) -> Dict[str, Any]:
    """Get event timeline for investigation."""
    try:
        # Mock timeline
        timeline = [
            {
                "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
                "type": "finding",
                "title": "Initial Threat Detection",
                "severity": "high",
            },
            {
                "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
                "type": "alert",
                "title": "Malware Confirmed",
                "severity": "critical",
            },
        ]

        return {
            "investigation_id": investigation_id,
            "event_count": len(timeline),
            "timeline": timeline,
        }

    except Exception as e:
        logger.error(f"Timeline retrieval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
