"""
Threat Scoring Engine.

Calculates threat scores based on multiple factors and evidence.
"""
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from src.osint_platform.threat_assessment.models import (
    ThreatScore, ThreatLevel, Evidence, Alert, AlertType,
)

logger = logging.getLogger(__name__)


class ThreatScoringEngine:
    """Calculates threat scores for entities."""

    # Scoring weights (how much each factor contributes)
    WEIGHTS = {
        "malware_detection": 25,  # Malware found
        "phishing_indicators": 20,  # Phishing signs
        "c2_communication": 25,  # C2 server indicators
        "breach_history": 15,  # Previously breached
        "reputation_score": 20,  # API reputation
        "infrastructure_sharing": 15,  # Shared infra with threats
        "temporal_recency": 10,  # How recent the threat is
        "credential_exposure": 20,  # Exposed credentials
    }

    @staticmethod
    def calculate_score(
        entity_id: str,
        entity_value: str,
        entity_type: str,
        evidence: List[Evidence],
    ) -> ThreatScore:
        """
        Calculate threat score for an entity.

        Returns: ThreatScore with numerical score and contributing factors
        """
        factors = {}
        total_weighted = 0
        total_weight = 0

        # Factor 1: Malware Detection
        malware_factor = ThreatScoringEngine._assess_malware(evidence)
        factors["malware_detection"] = malware_factor
        total_weighted += malware_factor * ThreatScoringEngine.WEIGHTS["malware_detection"]
        total_weight += ThreatScoringEngine.WEIGHTS["malware_detection"]

        # Factor 2: Phishing Indicators
        phishing_factor = ThreatScoringEngine._assess_phishing(evidence, entity_value)
        factors["phishing_indicators"] = phishing_factor
        total_weighted += phishing_factor * ThreatScoringEngine.WEIGHTS["phishing_indicators"]
        total_weight += ThreatScoringEngine.WEIGHTS["phishing_indicators"]

        # Factor 3: C2 Communication
        c2_factor = ThreatScoringEngine._assess_c2(evidence)
        factors["c2_communication"] = c2_factor
        total_weighted += c2_factor * ThreatScoringEngine.WEIGHTS["c2_communication"]
        total_weight += ThreatScoringEngine.WEIGHTS["c2_communication"]

        # Factor 4: Breach History
        breach_factor = ThreatScoringEngine._assess_breach_history(evidence)
        factors["breach_history"] = breach_factor
        total_weighted += breach_factor * ThreatScoringEngine.WEIGHTS["breach_history"]
        total_weight += ThreatScoringEngine.WEIGHTS["breach_history"]

        # Factor 5: Reputation
        reputation_factor = ThreatScoringEngine._assess_reputation(evidence)
        factors["reputation_score"] = reputation_factor
        total_weighted += reputation_factor * ThreatScoringEngine.WEIGHTS["reputation_score"]
        total_weight += ThreatScoringEngine.WEIGHTS["reputation_score"]

        # Factor 6: Infrastructure Sharing
        infra_factor = ThreatScoringEngine._assess_infrastructure_sharing(evidence)
        factors["infrastructure_sharing"] = infra_factor
        total_weighted += infra_factor * ThreatScoringEngine.WEIGHTS["infrastructure_sharing"]
        total_weight += ThreatScoringEngine.WEIGHTS["infrastructure_sharing"]

        # Factor 7: Temporal Recency
        recency_factor = ThreatScoringEngine._assess_recency(evidence)
        factors["temporal_recency"] = recency_factor
        total_weighted += recency_factor * ThreatScoringEngine.WEIGHTS["temporal_recency"]
        total_weight += ThreatScoringEngine.WEIGHTS["temporal_recency"]

        # Factor 8: Credential Exposure
        cred_factor = ThreatScoringEngine._assess_credential_exposure(evidence)
        factors["credential_exposure"] = cred_factor
        total_weighted += cred_factor * ThreatScoringEngine.WEIGHTS["credential_exposure"]
        total_weight += ThreatScoringEngine.WEIGHTS["credential_exposure"]

        # Calculate final score (0-100)
        score = (total_weighted / total_weight * 100) if total_weight > 0 else 0
        score = min(100, max(0, score))  # Clamp to 0-100

        # Override: Strong malware or C2 detection always means CRITICAL
        if factors.get("malware_detection", 0) > 0.7 or factors.get("c2_communication", 0) > 0.7:
            score = max(score, 85)
        # Strong credential exposure means HIGH at minimum
        elif factors.get("credential_exposure", 0) > 0.7:
            score = max(score, 60)

        # Determine threat level
        threat_level = ThreatScoringEngine._score_to_level(score)

        # Calculate confidence based on evidence count
        confidence = min(1.0, len(evidence) / 5)  # More evidence = higher confidence

        return ThreatScore(
            entity_id=entity_id,
            entity_value=entity_value,
            entity_type=entity_type,
            threat_level=threat_level,
            score=score,
            confidence=confidence,
            factors=factors,
            evidence=evidence,
        )

    @staticmethod
    def _assess_malware(evidence: List[Evidence]) -> float:
        """Assess malware indicators in evidence."""
        malware_keywords = ["malware", "virus", "trojan", "ransomware", "exploit", "backdoor"]
        detected = False
        for ev in evidence:
            content_str = str(ev.content).lower()
            if any(keyword in content_str for keyword in malware_keywords):
                detected = True
                break
        return 0.9 if detected else 0.1

    @staticmethod
    def _assess_phishing(evidence: List[Evidence], entity_value: str) -> float:
        """Assess phishing indicators."""
        phishing_keywords = ["phishing", "phish", "spoofed", "lookalike", "fake"]
        detected = False
        for ev in evidence:
            content_str = str(ev.content).lower()
            if any(keyword in content_str for keyword in phishing_keywords):
                detected = True
                break
        # Also check for domain similarity if entity is email/domain
        if "@" in entity_value:
            return 0.7 if detected else 0.2
        return 0.8 if detected else 0.1

    @staticmethod
    def _assess_c2(evidence: List[Evidence]) -> float:
        """Assess C2 (command & control) indicators."""
        c2_keywords = ["c2", "command and control", "beacon", "callback"]
        detected = False
        for ev in evidence:
            content_str = str(ev.content).lower()
            if any(keyword in content_str for keyword in c2_keywords):
                detected = True
                break
        return 0.95 if detected else 0.05

    @staticmethod
    def _assess_breach_history(evidence: List[Evidence]) -> float:
        """Assess breach/compromise history."""
        breach_keywords = ["breach", "compromised", "leaked", "pwned", "dumped"]
        detected = False
        for ev in evidence:
            content_str = str(ev.content).lower()
            if any(keyword in content_str for keyword in breach_keywords):
                detected = True
                break
        return 0.85 if detected else 0.1

    @staticmethod
    def _assess_reputation(evidence: List[Evidence]) -> float:
        """Assess reputation from APIs."""
        bad_reputation = 0
        total_apis = 0
        for ev in evidence:
            if ev.source in ["virustotal", "abuseipdb", "shodan"]:
                total_apis += 1
                # Check for detection/reputation score in content
                if isinstance(ev.content, dict):
                    if "reputation" in ev.content and ev.content["reputation"] < 0:
                        bad_reputation += 1
                    elif "detections" in ev.content and ev.content["detections"] > 5:
                        bad_reputation += 1

        if total_apis == 0:
            return 0.0  # No reputation data available
        return min(1.0, bad_reputation / total_apis)

    @staticmethod
    def _assess_infrastructure_sharing(evidence: List[Evidence]) -> float:
        """Assess infrastructure sharing with known threats."""
        # This would check if IP shared with other malicious domains, etc.
        # For now, return based on evidence availability
        if any(ev.source in ["censys", "securitytrails", "shodan"] for ev in evidence):
            return 0.3  # Some risk if shared infrastructure detected
        return 0.0

    @staticmethod
    def _assess_recency(evidence: List[Evidence]) -> float:
        """Assess how recent the threat is."""
        if not evidence:
            return 0.0

        now = datetime.utcnow()
        recent_count = 0
        for ev in evidence:
            # If evidence timestamp is missing, assume it's recent
            if ev.timestamp is None or ev.timestamp > now - timedelta(days=7):
                recent_count += 1
            elif ev.timestamp > now - timedelta(days=30):
                recent_count += 0.5

        return min(1.0, recent_count / len(evidence)) if evidence else 0.0

    @staticmethod
    def _assess_credential_exposure(evidence: List[Evidence]) -> float:
        """Assess credential exposure risk."""
        cred_keywords = ["credential", "password", "username", "email breach", "dump"]
        exposed = False
        for ev in evidence:
            if ev.source in ["haveibeenpwned", "emailrep", "intelx"]:
                content_str = str(ev.content).lower()
                if any(keyword in content_str for keyword in cred_keywords):
                    exposed = True
                    break

        return 0.9 if exposed else 0.1

    @staticmethod
    def _score_to_level(score: float) -> ThreatLevel:
        """Convert numerical score to threat level."""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        elif score >= 20:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO


class AlertGenerator:
    """Generates alerts from threat scores and detections."""

    @staticmethod
    def generate_alerts(threat_score: ThreatScore) -> List[Alert]:
        """Generate alerts based on threat score."""
        alerts = []

        # Alert 1: High/Critical threat
        if threat_score.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            alert = Alert(
                id=f"alert_{threat_score.entity_id}_{threat_score.calculated_at.timestamp()}",
                alert_type=AlertType.SUSPICIOUS_ACTIVITY,
                threat_level=threat_score.threat_level,
                title=f"High-Risk Entity Detected: {threat_score.entity_value}",
                description=f"Entity scored {threat_score.score:.1f}/100 threat level",
                affected_entities=[threat_score.entity_id],
                threat_score=threat_score,
                recommended_actions=[
                    "Block at perimeter if applicable",
                    "Review incident response procedures",
                    "Alert security team",
                    "Initiate investigation",
                ],
            )
            alerts.append(alert)

        # Alert 2: Credential exposure
        if threat_score.factors.get("credential_exposure", 0) > 0.7:
            alert = Alert(
                id=f"alert_cred_{threat_score.entity_id}",
                alert_type=AlertType.CREDENTIAL_COMPROMISE,
                threat_level=ThreatLevel.HIGH,
                title=f"Credential Exposure: {threat_score.entity_value}",
                description="Evidence of credential exposure detected in breaches",
                affected_entities=[threat_score.entity_id],
                threat_score=threat_score,
                recommended_actions=[
                    "Force password reset",
                    "Enable MFA",
                    "Monitor for unauthorized access",
                    "Review access logs",
                ],
            )
            alerts.append(alert)

        # Alert 3: Malware detection
        if threat_score.factors.get("malware_detection", 0) > 0.7:
            alert = Alert(
                id=f"alert_malware_{threat_score.entity_id}",
                alert_type=AlertType.MALWARE,
                threat_level=ThreatLevel.CRITICAL,
                title=f"Malware Detected: {threat_score.entity_value}",
                description="Multiple sources confirm malware presence",
                affected_entities=[threat_score.entity_id],
                threat_score=threat_score,
                recommended_actions=[
                    "Isolate affected systems immediately",
                    "Initiate incident response",
                    "Conduct forensic analysis",
                    "Notify relevant teams",
                ],
            )
            alerts.append(alert)

        # Alert 4: C2 Communication
        if threat_score.factors.get("c2_communication", 0) > 0.7:
            alert = Alert(
                id=f"alert_c2_{threat_score.entity_id}",
                alert_type=AlertType.C2_COMMUNICATION,
                threat_level=ThreatLevel.CRITICAL,
                title=f"C2 Server Suspected: {threat_score.entity_value}",
                description="Entity exhibits command & control communication patterns",
                affected_entities=[threat_score.entity_id],
                threat_score=threat_score,
                recommended_actions=[
                    "Block domain/IP immediately",
                    "Alert threat intelligence",
                    "Investigate communication logs",
                    "Coordinate with ISP/hosting provider",
                ],
            )
            alerts.append(alert)

        return alerts
