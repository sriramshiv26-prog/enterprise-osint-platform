"""
Report Generation Engine.

Creates investigation reports in HTML and text formats.
"""
import logging
from datetime import datetime
from typing import List, Dict, Any

from src.osint_platform.threat_assessment.models import (
    InvestigationReport, ThreatScore, Alert, Finding, ThreatLevel,
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates investigation reports."""

    @staticmethod
    def generate_html_report(
        title: str,
        investigation_id: str,
        threat_score: ThreatScore,
        alerts: List[Alert],
        findings: List[Finding],
        recommendations: List[str],
    ) -> str:
        """
        Generate HTML report.

        Returns: HTML string
        """
        threat_color = ReportGenerator._threat_color(threat_score.threat_level)
        score_bar = ReportGenerator._score_bar(threat_score.score)

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            color: #333;
        }}
        .header {{
            border-bottom: 3px solid {threat_color};
            padding-bottom: 20px;
        }}
        .threat-badge {{
            display: inline-block;
            background-color: {threat_color};
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 18px;
        }}
        .score-section {{
            background-color: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .score-bar {{
            background-color: #e0e0e0;
            height: 30px;
            border-radius: 5px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .score-fill {{
            background-color: {threat_color};
            height: 100%;
            width: {threat_score.score}%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}
        .alert {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 3px;
        }}
        .alert.critical {{
            background-color: #f8d7da;
            border-left-color: #dc3545;
        }}
        .alert.high {{
            background-color: #fff3cd;
            border-left-color: #ffc107;
        }}
        .finding {{
            background-color: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin: 10px 0;
            border-radius: 3px;
        }}
        .factors {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin: 20px 0;
        }}
        .factor {{
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ddd;
        }}
        .factor-name {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .factor-value {{
            font-size: 24px;
            color: {threat_color};
        }}
        .recommendation {{
            background-color: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 10px 0;
            border-radius: 3px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 12px;
            color: #666;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #f5f5f5;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <p>Investigation ID: {investigation_id}</p>
        <div class="threat-badge">{threat_score.threat_level.value.upper()}</div>
    </div>

    <div class="score-section">
        <h2>Threat Assessment Score</h2>
        <p>Overall Threat Score: <strong>{threat_score.score:.1f}/100</strong></p>
        <p>Confidence: <strong>{threat_score.confidence:.0%}</strong></p>
        <div class="score-bar">
            <div class="score-fill">{threat_score.score:.0f}</div>
        </div>
    </div>

    <h2>Contributing Factors</h2>
    <div class="factors">
"""
        for factor_name, factor_value in threat_score.factors.items():
            factor_display = factor_name.replace("_", " ").title()
            html += f"""
        <div class="factor">
            <div class="factor-name">{factor_display}</div>
            <div class="factor-value">{factor_value:.0%}</div>
        </div>
"""
        html += """
    </div>
"""

        # Alerts Section
        if alerts:
            html += "<h2>Security Alerts</h2>\n"
            for alert in alerts:
                alert_class = "critical" if alert.threat_level == ThreatLevel.CRITICAL else "high"
                html += f"""
    <div class="alert {alert_class}">
        <strong>{alert.alert_type.value.upper()}</strong> - {alert.title}
        <p>{alert.description}</p>
"""
                if alert.recommended_actions:
                    html += "<strong>Recommended Actions:</strong><ul>\n"
                    for action in alert.recommended_actions:
                        html += f"<li>{action}</li>\n"
                    html += "</ul>\n"
                html += "</div>\n"

        # Findings Section
        if findings:
            html += "<h2>Key Findings</h2>\n"
            for finding in findings:
                html += f"""
    <div class="finding">
        <h3>{finding.title}</h3>
        <p>{finding.description}</p>
        <p>Severity: <strong>{finding.threat_level.value.upper()}</strong></p>
    </div>
"""

        # Recommendations Section
        if recommendations:
            html += "<h2>Recommended Actions</h2>\n"
            for rec in recommendations:
                html += f"""
    <div class="recommendation">
        <strong>→</strong> {rec}
    </div>
"""

        # Footer
        html += f"""
    <div class="footer">
        <p>Report generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p>Enterprise OSINT Platform v0.5.0</p>
    </div>
</body>
</html>
"""
        return html

    @staticmethod
    def generate_text_report(
        title: str,
        investigation_id: str,
        threat_score: ThreatScore,
        alerts: List[Alert],
        findings: List[Finding],
        recommendations: List[str],
    ) -> str:
        """
        Generate text report.

        Returns: Plain text report
        """
        report = f"""
{'='*80}
THREAT INTELLIGENCE INVESTIGATION REPORT
{'='*80}

Title:              {title}
Investigation ID:   {investigation_id}
Generated:          {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

{'='*80}
EXECUTIVE SUMMARY
{'='*80}

Threat Level:       {threat_score.threat_level.value.upper()}
Threat Score:       {threat_score.score:.1f}/100
Confidence:         {threat_score.confidence:.0%}
Entity:             {threat_score.entity_value} ({threat_score.entity_type})

{'='*80}
THREAT ASSESSMENT FACTORS
{'='*80}

"""
        for factor_name, factor_value in threat_score.factors.items():
            factor_display = factor_name.replace("_", " ").title()
            report += f"{factor_display:.<50} {factor_value:.0%}\n"

        # Alerts
        if alerts:
            report += f"\n{'='*80}\nSECURITY ALERTS ({len(alerts)})\n{'='*80}\n\n"
            for i, alert in enumerate(alerts, 1):
                report += f"""
Alert {i}: {alert.alert_type.value.upper()}
Severity:       {alert.threat_level.value.upper()}
Title:          {alert.title}
Description:    {alert.description}

Recommended Actions:
"""
                for action in alert.recommended_actions:
                    report += f"  • {action}\n"

        # Findings
        if findings:
            report += f"\n{'='*80}\nKEY FINDINGS ({len(findings)})\n{'='*80}\n\n"
            for i, finding in enumerate(findings, 1):
                report += f"""
Finding {i}: {finding.title}
Severity:    {finding.threat_level.value.upper()}
Description: {finding.description}
"""

        # Recommendations
        if recommendations:
            report += f"\n{'='*80}\nRECOMMENDED ACTIONS\n{'='*80}\n\n"
            for i, rec in enumerate(recommendations, 1):
                report += f"{i}. {rec}\n"

        report += f"\n{'='*80}\n"
        report += "Report generated by Enterprise OSINT Platform v0.5.0\n"
        report += f"{'='*80}\n"

        return report

    @staticmethod
    def _threat_color(threat_level) -> str:
        """Get color for threat level."""
        colors = {
            ThreatLevel.INFO: "#17a2b8",
            ThreatLevel.LOW: "#28a745",
            ThreatLevel.MEDIUM: "#ffc107",
            ThreatLevel.HIGH: "#fd7e14",
            ThreatLevel.CRITICAL: "#dc3545",
        }
        return colors.get(threat_level, "#6c757d")

    @staticmethod
    def _score_bar(score: float) -> str:
        """Generate HTML for score bar."""
        color = "#17a2b8" if score < 20 else "#28a745" if score < 40 else "#ffc107" if score < 60 else "#fd7e14" if score < 80 else "#dc3545"
        return f'<div style="width: {score}%; background-color: {color}; height: 20px;"></div>'


class TimelineBuilder:
    """Builds event timeline from investigation data."""

    @staticmethod
    def build_timeline(findings: List[Finding], alerts: List[Alert]) -> List[Dict[str, Any]]:
        """
        Build chronological timeline of events.

        Returns: Sorted list of timeline events
        """
        timeline = []

        # Add findings
        for finding in findings:
            timeline.append({
                "timestamp": finding.created_at,
                "type": "finding",
                "title": finding.title,
                "severity": finding.threat_level.value,
                "description": finding.description,
            })

        # Add alerts
        for alert in alerts:
            timeline.append({
                "timestamp": alert.created_at,
                "type": "alert",
                "title": alert.title,
                "severity": alert.threat_level.value,
                "description": alert.description,
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])

        return timeline
