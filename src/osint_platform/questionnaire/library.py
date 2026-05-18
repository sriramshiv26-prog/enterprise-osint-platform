"""
Built-in Questionnaire Library.

Pre-configured questionnaires for common threat intelligence scenarios.
"""
from src.osint_platform.questionnaire.models import (
    Questionnaire, Question, QuestionType, AnswerValidation,
)


def create_threat_assessment_questionnaire() -> Questionnaire:
    """Questionnaire for threat assessment of an indicator."""
    return Questionnaire(
        id="threat_assessment_v1",
        name="Threat Assessment",
        description="Comprehensive threat assessment for a suspicious indicator",
        category="threat_intel",
        questions=[
            Question(
                id="indicator_type",
                text="What type of indicator are you investigating?",
                type=QuestionType.CHOICE,
                choices=["IP Address", "Domain", "Email", "File Hash", "URL"],
                help_text="Select the type of indicator you want to investigate",
            ),
            Question(
                id="indicator_value",
                text="Enter the indicator value",
                type=QuestionType.TEXT,
                validation=AnswerValidation(required=True, min_length=3),
                branching={
                    "IP Address": "q_ip_context",
                    "Domain": "q_domain_context",
                    "Email": "q_email_context",
                    "File Hash": "q_hash_context",
                    "URL": "q_url_context",
                },
                help_text="Provide the specific IP, domain, email, hash, or URL to investigate",
            ),
            # IP branch
            Question(
                id="q_ip_context",
                text="What is the context of this IP?",
                type=QuestionType.CHOICE,
                choices=["Suspicious traffic", "Malware C2", "Botnet node", "Phishing server", "Unknown"],
                conditional={"indicator_type": "IP Address"},
                next_question="q_timeframe",
            ),
            # Domain branch
            Question(
                id="q_domain_context",
                text="What is the context of this domain?",
                type=QuestionType.CHOICE,
                choices=["Phishing", "Malware distribution", "C2 server", "Typosquatting", "Unknown"],
                conditional={"indicator_type": "Domain"},
                next_question="q_timeframe",
            ),
            # Email branch
            Question(
                id="q_email_context",
                text="What is the context of this email?",
                type=QuestionType.CHOICE,
                choices=["Phishing", "Spam", "Credential harvesting", "Unknown"],
                conditional={"indicator_type": "Email"},
                next_question="q_timeframe",
            ),
            # Hash branch
            Question(
                id="q_hash_context",
                text="What is the context of this hash?",
                type=QuestionType.CHOICE,
                choices=["Malware", "Exploit", "Trojan", "Ransomware", "Unknown"],
                conditional={"indicator_type": "File Hash"},
                next_question="q_timeframe",
            ),
            # URL branch
            Question(
                id="q_url_context",
                text="What is the context of this URL?",
                type=QuestionType.CHOICE,
                choices=["Phishing", "Malware hosting", "Suspicious redirect", "Unknown"],
                conditional={"indicator_type": "URL"},
                next_question="q_timeframe",
            ),
            # Common questions
            Question(
                id="q_timeframe",
                text="What timeframe should we check?",
                type=QuestionType.CHOICE,
                choices=["Past 24 hours", "Past week", "Past month", "All time"],
                next_question="q_severity",
            ),
            Question(
                id="q_severity",
                text="Expected severity level?",
                type=QuestionType.CHOICE,
                choices=["Low", "Medium", "High", "Critical", "Unknown"],
                next_question="q_jurisdiction",
            ),
            Question(
                id="q_jurisdiction",
                text="Geographic scope?",
                type=QuestionType.MULTI_CHOICE,
                choices=["US", "EU", "APAC", "Middle East", "Global"],
                next_question="q_internal_breach",
            ),
            Question(
                id="q_internal_breach",
                text="Internal breach likelihood?",
                type=QuestionType.CHOICE,
                choices=["None", "Low", "Medium", "High"],
            ),
        ],
        start_question_id="indicator_type",
    )


def create_reconnaissance_questionnaire() -> Questionnaire:
    """Questionnaire for reconnaissance on a target domain."""
    return Questionnaire(
        id="reconnaissance_v1",
        name="Domain Reconnaissance",
        description="Gather intelligence on a target domain",
        category="reconnaissance",
        questions=[
            Question(
                id="target_domain",
                text="What is the target domain?",
                type=QuestionType.DOMAIN,
                validation=AnswerValidation(required=True),
                next_question="reconnaissance_scope",
            ),
            Question(
                id="reconnaissance_scope",
                text="What is the scope of reconnaissance?",
                type=QuestionType.MULTI_CHOICE,
                choices=["DNS records", "Subdomains", "History", "Technology stack", "WHOIS data", "SSL certificates"],
                next_question="depth_level",
            ),
            Question(
                id="depth_level",
                text="How deep should the reconnaissance be?",
                type=QuestionType.CHOICE,
                choices=["Shallow (basic info)", "Medium (comprehensive)", "Deep (exhaustive)"],
                next_question="q_timeframe",
            ),
            Question(
                id="q_timeframe",
                text="Historical data timeframe?",
                type=QuestionType.CHOICE,
                choices=["Current only", "Past 30 days", "Past year", "All available"],
            ),
        ],
        start_question_id="target_domain",
    )


def create_compliance_check_questionnaire() -> Questionnaire:
    """Questionnaire for compliance checking on indicators."""
    return Questionnaire(
        id="compliance_check_v1",
        name="Compliance Check",
        description="Check if indicators violate compliance policies",
        category="compliance",
        questions=[
            Question(
                id="indicator",
                text="What indicator would you like to check?",
                type=QuestionType.TEXT,
                validation=AnswerValidation(required=True),
                next_question="compliance_framework",
            ),
            Question(
                id="compliance_framework",
                text="Which compliance framework applies?",
                type=QuestionType.CHOICE,
                choices=["GDPR", "HIPAA", "PCI-DSS", "SOC 2", "Custom policy"],
                next_question="breach_notification_required",
            ),
            Question(
                id="breach_notification_required",
                text="Is breach notification required?",
                type=QuestionType.BOOLEAN,
                next_question="data_scope",
            ),
            Question(
                id="data_scope",
                text="Scope of potentially affected data?",
                type=QuestionType.CHOICE,
                choices=["Customer data", "Employee data", "Both", "Other"],
            ),
        ],
        start_question_id="indicator",
    )


def create_incident_response_questionnaire() -> Questionnaire:
    """Questionnaire for incident response and triage."""
    return Questionnaire(
        id="incident_response_v1",
        name="Incident Response",
        description="Triage and respond to security incidents",
        category="incident_response",
        questions=[
            Question(
                id="incident_type",
                text="What type of incident is this?",
                type=QuestionType.CHOICE,
                choices=["Malware infection", "Data breach", "Unauthorized access", "DDoS", "Phishing", "Other"],
                next_question="affected_systems",
            ),
            Question(
                id="affected_systems",
                text="How many systems are affected?",
                type=QuestionType.CHOICE,
                choices=["1", "2-5", "6-10", "11-50", "50+"],
                next_question="containment_status",
            ),
            Question(
                id="containment_status",
                text="Containment status?",
                type=QuestionType.CHOICE,
                choices=["Uncontained", "Partially contained", "Fully contained"],
                next_question="threat_level",
            ),
            Question(
                id="threat_level",
                text="Estimated threat level?",
                type=QuestionType.CHOICE,
                choices=["Low", "Medium", "High", "Critical"],
                next_question="indicators",
            ),
            Question(
                id="indicators",
                text="Known indicators (IPs, domains, hashes)?",
                type=QuestionType.TEXT,
                validation=AnswerValidation(required=False),
                help_text="Comma-separated list of indicators to investigate",
            ),
        ],
        start_question_id="incident_type",
    )


QUESTIONNAIRE_LIBRARY = {
    "threat_assessment_v1": create_threat_assessment_questionnaire,
    "reconnaissance_v1": create_reconnaissance_questionnaire,
    "compliance_check_v1": create_compliance_check_questionnaire,
    "incident_response_v1": create_incident_response_questionnaire,
}


def get_questionnaire_template(template_id: str) -> Questionnaire:
    """Get a questionnaire template by ID."""
    factory = QUESTIONNAIRE_LIBRARY.get(template_id)
    if not factory:
        raise ValueError(f"Questionnaire template not found: {template_id}")
    return factory()
