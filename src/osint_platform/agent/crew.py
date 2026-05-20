"""
Hermes Agent - CrewAI crew definitions.

Defines the three specialized agents (Investigator, Analyst, Reporter)
that form the Hermes OSINT investigation crew.
"""
import logging
from typing import Any, Dict, List, Optional

from crewai import Agent, Crew, Process, Task

from src.osint_platform.config import get_config
from src.osint_platform.agent.tools import get_agent_tools

logger = logging.getLogger(__name__)


def _get_llm(agent_role: str) -> str:
    """Get the appropriate LLM string identifier for an agent based on config.

    Returns a string that CrewAI can resolve to an LLM.
    Uses Ollama (local, free) when available, falls back to Claude.
    """
    config = get_config()

    ollama_cfg = config.get("ollama", {})
    claude_cfg = config.get("claude", {})

    ollama_enabled = ollama_cfg.get("enabled", False)
    fallback_to_claude = ollama_cfg.get("fallback_to_claude", True)

    if ollama_enabled:
        model = ollama_cfg.get("model", "qwen2.5-coder:1.5b")
        logger.info(f"Using Ollama for {agent_role}: {model}")
        return f"ollama/{model}"

    if fallback_to_claude and claude_cfg.get("api_key"):
        model = claude_cfg.get("model", "claude-3-5-sonnet-20241022")
        logger.info(f"Using Claude for {agent_role}: {model}")
        return f"claude/{model}"

    # Try Ollama as last resort even if not enabled
    logger.warning(f"No preferred LLM configured for {agent_role}, trying Ollama default")
    return "ollama/qwen2.5-coder:1.5b"


# ─── Crew Agents ──────────────────────────────────────────────────────────────

def create_investigator() -> Agent:
    """Create the Investigator agent - executes OSINT tools to gather evidence."""
    return Agent(
        role="OSINT Investigator",
        goal="Execute OSINT tools and API queries to gather comprehensive evidence "
             "about targets. Dig deep and leave no stone unturned.",
        backstory=(
            "You are a veteran digital forensic investigator with 15 years of experience. "
            "You know exactly which tools to use for each type of investigation. "
            "When investigating an IP, you check threat intel APIs first, then domain tools. "
            "For emails, you check breach databases and social footprint. "
            "You work methodically, running all relevant tools in parallel when possible. "
            "You always gather comprehensive evidence before passing to the analyst."
        ),
        verbose=True,
        allow_delegation=False,
        llm=_get_llm("investigator"),
        tools=get_agent_tools(),
        max_iter=8,
        memory=True,
    )


def create_analyst() -> Agent:
    """Create the Analyst agent - interprets results and assesses threats."""
    return Agent(
        role="Threat Intelligence Analyst",
        goal="Analyze gathered evidence to identify threats, assess severity, "
             "and provide actionable intelligence. Connect the dots between findings.",
        backstory=(
            "You are a senior threat intelligence analyst who has worked at major SOCs. "
            "You excel at correlating disparate pieces of evidence into a coherent threat picture. "
            "You assess indicators against the Diamond Model of Intrusion Analysis. "
            "You categorize threats accurately and identify patterns that others miss. "
            "Your threat assessments are trusted by CISO-level decision makers."
        ),
        verbose=True,
        allow_delegation=False,
        llm=_get_llm("analyst"),
        tools=get_agent_tools(),
        max_iter=10,
        memory=True,
    )


def create_reporter() -> Agent:
    """Create the Reporter agent - generates structured reports."""
    return Agent(
        role="Threat Intelligence Reporter",
        goal="Generate clear, actionable investigation reports with severity ratings, "
             "recommendations, and executive summaries suitable for technical and non-technical audiences.",
        backstory=(
            "You are a technical writer specialized in cybersecurity reporting. "
            "You translate complex threat intelligence into clear, actionable reports. "
            "Your reports have a standard structure: Executive Summary, Key Findings, "
            "Detailed Analysis, Threat Assessment, and Remediation Recommendations. "
            "You include evidence references and confidence levels for every finding. "
            "Your writing is precise, concise, and actionable."
        ),
        verbose=True,
        allow_delegation=False,
        llm=_get_llm("reporter"),
        tools=[],
        max_iter=8,
        memory=True,
    )


# ─── Investigation Tasks ─────────────────────────────────────────────────────

def create_investigation_tasks(
    investigator: Agent,
    analyst: Agent,
    reporter: Agent,
    target: str,
    target_type: str = "auto",
    context: Optional[str] = None,
) -> List[Task]:
    """Create the task pipeline for a full investigation.

    Args:
        investigator: The investigator agent.
        analyst: The analyst agent.
        reporter: The reporter agent.
        target: The target indicator to investigate (IP, domain, email, etc.).
        target_type: Type of target (ip, domain, email, hash, url, username, phone).
                     Use "auto" for automatic detection.
        context: Additional context from the user.

    Returns:
        List of Task objects for the crew.
    """
    type_guidance = ""
    if target_type and target_type != "auto":
        type_guidance = f"The target is a {target_type.upper()} indicator."

    if context:
        context_clause = f"\n\nAdditional Context: {context}"
    else:
        context_clause = ""

    return [
        Task(
            description=(
                f"Conduct a thorough OSINT investigation on the target: '{target}'.{context_clause}\n\n"
                f"{type_guidance}\n\n"
                "1. First, determine the indicator type (IP, domain, email, URL, hash, username, or phone).\n"
                "2. Use the threat_intelligence_query tool to query all relevant APIs simultaneously.\n"
                "3. Based on the target type, run additional specialized tools:\n"
                "   - For usernames: Use sherlock_username_search\n"
                "   - For domains: Use sublist3r_subdomain_enumeration and amass_asset_discovery\n"
                "   - For emails: Use holehe_email_check\n"
                "   - For phone numbers: Use phoneinfoga_phone_scan\n"
                "   - For image URLs: Use photo_osint_search (EXIF, GPS, face detection, reverse search)\n"
                "4. Document ALL findings including sources and confidence levels.\n"
                "5. For web footprinting, use google_dork_search to find:\n"
                "   - Exposed admin panels, config files, logs, backups\n"
                "   - Database dumps, password files, error messages\n"
                "   - Directory listings, login pages, file upload interfaces\n"
                "   - Exposed documents (PDFs, spreadsheets, CSVs)\n"
                "   - Subdomains via site:* target\n"
                "   - Email addresses and social media mentions\n"
                "   Use dork queries scoped to the target domain via site:{target}.\n"
                "6. Identify any related entities discovered during the investigation.\n\n"
                "Return a comprehensive evidence package with all findings organized by source."
            ),
            agent=investigator,
            expected_output=(
                "A comprehensive evidence report listing all findings from each tool/API used, "
                "including source names, raw findings, related entities discovered, and confidence levels."
            ),
        ),
        Task(
            description=(
                "Analyze the investigator's findings and produce a threat intelligence assessment.\n\n"
                "1. Identify all threat indicators and their severity levels.\n"
                "2. Correlate findings across multiple sources to identify patterns.\n"
                "3. Apply threat scoring based on the Diamond Model.\n"
                "4. Determine the overall threat level (INFO/LOW/MEDIUM/HIGH/CRITICAL).\n"
                "5. List specific actionable recommendations.\n\n"
                "Use the threat_intelligence_query tool if you need additional data to "
                "verify any findings or correlations."
            ),
            agent=analyst,
            expected_output=(
                "A threat intelligence assessment including: overall threat level with score, "
                "key findings with severity ratings, correlated patterns, "
                "and prioritized remediation recommendations."
            ),
        ),
        Task(
            description=(
                "Generate a professional investigation report based on the analyst's assessment.\n\n"
                "Structure the report with these sections:\n"
                "1. **Executive Summary** - Brief overview for non-technical stakeholders\n"
                "2. **Investigation Scope** - What was investigated and how\n"
                "3. **Key Findings** - Bulleted list of critical findings with severity tags\n"
                "4. **Detailed Analysis** - Technical breakdown of each finding\n"
                "5. **Threat Assessment** - Overall score and threat level\n"
                "6. **Recommendations** - Actionable next steps in priority order\n"
                "7. **Sources** - All tools and APIs used\n\n"
                "Format the report in clear markdown."
            ),
            agent=reporter,
            expected_output=(
                "A complete markdown-formatted investigation report with all sections: "
                "Executive Summary, Investigation Scope, Key Findings, Detailed Analysis, "
                "Threat Assessment, Recommendations, and Sources."
            ),
        ),
    ]


# ─── Crew Factory ────────────────────────────────────────────────────────────

class HermesCrew:
    """Manages the Hermes Agent crew and executes investigations."""

    def __init__(self):
        self.investigator = create_investigator()
        self.analyst = create_analyst()
        self.reporter = create_reporter()
        self._crew: Optional[Crew] = None

    def investigate(
        self,
        target: str,
        target_type: str = "auto",
        context: Optional[str] = None,
        verbose: bool = True,
    ) -> Dict[str, Any]:
        """Run a full investigation on a target.

        Args:
            target: The target indicator to investigate.
            target_type: Type hint (ip, domain, email, hash, url, username, phone, auto).
            context: Additional user-provided context.
            verbose: Whether to show detailed CrewAI output.

        Returns:
            Dict with investigation results and report.
        """
        tasks = create_investigation_tasks(
            self.investigator, self.analyst, self.reporter,
            target=target,
            target_type=target_type,
            context=context,
        )

        self._crew = Crew(
            agents=[self.investigator, self.analyst, self.reporter],
            tasks=tasks,
            process=Process.sequential,
            verbose=verbose,
        )

        logger.info(f"Starting Hermes investigation on '{target}' (type: {target_type})")

        try:
            result = self._crew.kickoff()
            # CrewAI returns the final output as a string
            return {
                "target": target,
                "target_type": target_type,
                "success": True,
                "report": str(result),
            }
        except Exception as e:
            logger.error(f"Hermes investigation failed: {e}")
            return {
                "target": target,
                "target_type": target_type,
                "success": False,
                "error": str(e),
                "report": f"Investigation failed: {e}",
            }

    @property
    def last_crew(self) -> Optional[Crew]:
        """Get the last crew instance."""
        return self._crew


def create_hermes_crew() -> HermesCrew:
    """Factory function to create a HermesCrew instance."""
    return HermesCrew()
