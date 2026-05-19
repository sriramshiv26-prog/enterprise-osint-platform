"""Hermes Agent - AI-powered OSINT Investigation Agent.

Uses CrewAI with LangChain tools to orchestrate multi-step investigations
using the platform's OSINT tools and API integrations.
"""

from src.osint_platform.agent.tools import get_agent_tools, get_tool_descriptions, TOOL_LIST
from src.osint_platform.agent.crew import HermesCrew, create_hermes_crew
from src.osint_platform.agent.service import AgentService

__all__ = [
    "HermesCrew",
    "create_hermes_crew",
    "AgentService",
    "get_agent_tools",
    "get_tool_descriptions",
    "TOOL_LIST",
]
