"""
Tests for Threat Assessment Engine.

Tests threat scoring, alerts, and report generation.
"""
import pytest
from datetime import datetime

from src.osint_platform.threat_assessment.models import (
    ThreatScore, Alert, Evidence, ThreatLevel, AlertType,
)
from src.osint_platform.threat_assessment.scoring import ThreatScoringEngine, AlertGenerator
from src.osint_platform.threat_assessment.reporting import ReportGenerator, TimelineBuilder


class TestThreatScoringEngine:
    """Tests for threat scoring."""

    def test_calculate_score_with_malware(self):
        """Test threat score calculation with malware evidence."""
        evidence = [
            Evidence(
                id="ev1",
                type="detection",
                source="virustotal",
                content={"detections": 45, "malware": True},
            ),
        ]

        score = ThreatScoringEngine.calculate_score(
            entity_id="entity1",
            entity_value="192.168.1.1",
            entity_type="ip",
            evidence=evidence,
        )

        assert score.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        assert score.score > 50
        assert score.factors["malware_detection"] > 0.7

    def test_calculate_score_with_phishing(self):
        """Test threat score calculation with phishing evidence."""
        evidence = [
            Evidence(
                id="ev1",
                type="detection",
                source="urlscan",
                content={"phishing": True, "suspicious": True},
            ),
        ]

        score = ThreatScoringEngine.calculate_score(
            entity_id="entity1",
            entity_value="phishing-site.com",
            entity_type="domain",
            evidence=evidence,
        )

        assert score.factors["phishing_indicators"] > 0.5

    def test_calculate_score_with_breach_history(self):
        """Test threat score with breach history."""
        evidence = [
            Evidence(
                id="ev1",
                type="breach",
                source="haveibeenpwned",
                content={"breached": True, "count": 1000},
            ),
        ]

        score = ThreatScoringEngine.calculate_score(
            entity_id="entity1",
            entity_value="admin@example.com",
            entity_type="email",
            evidence=evidence,
        )

        assert score.factors["breach_history"] > 0.7

    def test_score_to_level_critical(self):
        """Test score to threat level conversion - critical."""
        level = ThreatScoringEngine._score_to_level(95)
        assert level == ThreatLevel.CRITICAL

    def test_score_to_level_high(self):
        """Test score to threat level conversion - high."""
        level = ThreatScoringEngine._score_to_level(70)
        assert level == ThreatLevel.HIGH

    def test_score_to_level_medium(self):
        """Test score to threat level conversion - medium."""
        level = ThreatScoringEngine._score_to_level(50)
        assert level == ThreatLevel.MEDIUM

    def test_score_to_level_low(self):
        """Test score to threat level conversion - low."""
        level = ThreatScoringEngine._score_to_level(25)
        assert level == ThreatLevel.LOW

    def test_score_to_level_info(self):
        """Test score to threat level conversion - info."""
        level = ThreatScoringEngine._score_to_level(10)
        assert level == ThreatLevel.INFO

    def test_confidence_based_on_evidence_count(self):
        """Test confidence increases with more evidence."""
        evidence_small = [Evidence(id="e1", type="test", source="api", content={})]
        evidence_large = [
            Evidence(id=f"e{i}", type="test", source="api", content={})
            for i in range(10)
        ]

        score_small = ThreatScoringEngine.calculate_score(
            "e1", "test", "ip", evidence_small
        )
        score_large = ThreatScoringEngine.calculate_score(
            "e1", "test", "ip", evidence_large
        )

        assert score_large.confidence > score_small.confidence


class TestAlertGenerator:
    """Tests for alert generation."""

    def test_generate_alerts_critical(self):
        """Test alert generation for critical threat."""
        threat_score = ThreatScore(
            entity_id="entity1",
            entity_value="192.168.1.1",
            entity_type="ip",
            threat_level=ThreatLevel.CRITICAL,
            score=95,
            confidence=0.9,
            factors={"malware_detection": 0.95},
        )

        alerts = AlertGenerator.generate_alerts(threat_score)
        assert len(alerts) > 0
        assert any(a.threat_level == ThreatLevel.CRITICAL for a in alerts)

    def test_generate_malware_alert(self):
        """Test malware alert generation."""
        threat_score = ThreatScore(
            entity_id="entity1",
            entity_value="malware.exe",
            entity_type="hash",
            threat_level=ThreatLevel.CRITICAL,
            score=90,
            confidence=0.95,
            factors={"malware_detection": 0.95},
        )

        alerts = AlertGenerator.generate_alerts(threat_score)
        malware_alerts = [a for a in alerts if a.alert_type == AlertType.MALWARE]
        assert len(malware_alerts) > 0

    def test_generate_credential_alert(self):
        """Test credential exposure alert."""
        threat_score = ThreatScore(
            entity_id="entity1",
            entity_value="user@example.com",
            entity_type="email",
            threat_level=ThreatLevel.HIGH,
            score=75,
            confidence=0.8,
            factors={"credential_exposure": 0.9},
        )

        alerts = AlertGenerator.generate_alerts(threat_score)
        cred_alerts = [
            a for a in alerts
            if a.alert_type == AlertType.CREDENTIAL_COMPROMISE
        ]
        assert len(cred_alerts) > 0


class TestReportGenerator:
    """Tests for report generation."""

    def test_generate_html_report(self):
        """Test HTML report generation."""
        threat_score = ThreatScore(
            entity_id="entity1",
            entity_value="192.168.1.1",
            entity_type="ip",
            threat_level=ThreatLevel.HIGH,
            score=75,
            confidence=0.85,
            factors={"malware_detection": 0.9},
        )

        html = ReportGenerator.generate_html_report(
            title="Test Report",
            investigation_id="inv1",
            threat_score=threat_score,
            alerts=[],
            findings=[],
            recommendations=["Block IP", "Investigate logs"],
        )

        assert "<html>" in html.lower()
        assert "75.0/100" in html
        assert "Test Report" in html
        assert "Block IP" in html

    def test_generate_text_report(self):
        """Test text report generation."""
        threat_score = ThreatScore(
            entity_id="entity1",
            entity_value="192.168.1.1",
            entity_type="ip",
            threat_level=ThreatLevel.HIGH,
            score=75,
            confidence=0.85,
            factors={"malware_detection": 0.9},
        )

        text = ReportGenerator.generate_text_report(
            title="Test Report",
            investigation_id="inv1",
            threat_score=threat_score,
            alerts=[],
            findings=[],
            recommendations=["Block IP"],
        )

        assert "THREAT INTELLIGENCE INVESTIGATION REPORT" in text
        assert "75.0/100" in text
        assert "Test Report" in text
        assert "Block IP" in text

    def test_html_contains_threat_factors(self):
        """Test HTML report includes threat factors."""
        threat_score = ThreatScore(
            entity_id="entity1",
            entity_value="192.168.1.1",
            entity_type="ip",
            threat_level=ThreatLevel.HIGH,
            score=70,
            confidence=0.8,
            factors={
                "malware_detection": 0.9,
                "phishing_indicators": 0.2,
            },
        )

        html = ReportGenerator.generate_html_report(
            title="Test",
            investigation_id="inv1",
            threat_score=threat_score,
            alerts=[],
            findings=[],
            recommendations=[],
        )

        assert "Malware Detection" in html
        assert "Phishing Indicators" in html


class TestTimelineBuilder:
    """Tests for timeline building."""

    def test_build_timeline_empty(self):
        """Test timeline building with no events."""
        timeline = TimelineBuilder.build_timeline([], [])
        assert len(timeline) == 0

    def test_build_timeline_sorted(self):
        """Test that timeline events are sorted."""
        from src.osint_platform.threat_assessment.models import Finding
        from datetime import datetime, timedelta

        now = datetime.utcnow()
        findings = [
            Finding(
                id="f1",
                title="Finding 1",
                description="",
                threat_level=ThreatLevel.HIGH,
                entity_id="e1",
                investigation_id="inv1",
                evidence=[],
                created_at=now,
            ),
            Finding(
                id="f2",
                title="Finding 2",
                description="",
                threat_level=ThreatLevel.HIGH,
                entity_id="e1",
                investigation_id="inv1",
                evidence=[],
                created_at=now + timedelta(hours=1),
            ),
        ]

        timeline = TimelineBuilder.build_timeline(findings, [])
        assert len(timeline) == 2
        assert timeline[0]["title"] == "Finding 1"
        assert timeline[1]["title"] == "Finding 2"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
