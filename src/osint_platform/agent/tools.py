"""
CrewAI tool wrappers for all OSINT capabilities.

Wraps the existing executors and API integrations as CrewAI Tools
so the Hermes agent can call them dynamically.
"""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List

from crewai.tools import BaseTool, tool

from src.osint_platform.tools.tool_manager import get_tool_manager
from src.osint_platform.api_integrations.manager import get_api_manager

logger = logging.getLogger(__name__)

# ─── Async Bridge ────────────────────────────────────────────────────────────

# Shared thread pool for bridging sync CrewAI tools to async platform methods
_async_bridge_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="hermes_async_bridge")


def _run_async(coro) -> Any:
    """Run an async coroutine synchronously.

    Uses a thread pool to call asyncio.run() from a separate thread,
    safely bridging sync CrewAI tool functions to the async platform internals.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            future = _async_bridge_executor.submit(asyncio.run, coro)
            return future.result()
        else:
            return asyncio.run(coro)
    except RuntimeError:
        return _async_bridge_executor.submit(asyncio.run, coro).result()


def _poll_for_result(tool_name: str, manager, request_id: str, timeout: float = 30.0) -> str:
    """Poll a tool executor for results until complete or timeout.

    Periodically checks the request status and returns the formatted result
    once the execution is complete.
    """
    import time
    start = time.monotonic()
    poll_interval = 0.5

    while True:
        elapsed = time.monotonic() - start
        if elapsed >= timeout:
            return (
                f"{tool_name.capitalize()} request {request_id} still processing "
                f"after {timeout}s. Check /api/v1/tools/status/{tool_name}/{request_id} "
                "for the result when complete."
            )

        status = manager.get_request_status(tool_name, request_id)
        if status is None:
            time.sleep(poll_interval)
            continue

        if status["status"] == "completed":
            result = status.get("result")
            if result and result.get("data"):
                data = result["data"]
                items = data if isinstance(data, list) else [data]
                lines = [f"{tool_name.capitalize()} results for '{status.get('query', '')}':"]
                for item in items[:20]:  # Limit to 20 items to avoid huge responses
                    if isinstance(item, dict):
                        for key, val in item.items():
                            lines.append(f"  - {key}: {val}")
                    else:
                        lines.append(f"  - {item}")
                exec_time = status.get("execution_time_seconds", 0)
                lines.append(f"\nExecution time: {exec_time:.2f}s")
                return "\n".join(lines)
            return f"{tool_name.capitalize()} completed for '{status.get('query', '')}' with no data."

        if status["status"] == "failed":
            error = status.get("error", "Unknown error")
            return f"{tool_name.capitalize()} request failed: {error}"

        time.sleep(poll_interval)


# ─── Safe Manager Access ─────────────────────────────────────────────────────


def _get_tool_manager_safe():
    """Get tool manager, handling initialization."""
    try:
        return get_tool_manager()
    except Exception as e:
        logger.warning(f"Tool manager not available: {e}")
        return None


def _get_api_manager_safe():
    """Get API manager, handling initialization."""
    try:
        return get_api_manager()
    except Exception as e:
        logger.warning(f"API manager not available: {e}")
        return None


# ─── CrewAI Tool Definitions ─────────────────────────────────────────────────


@tool("sherlock_username_search")
def sherlock_username_search(username: str) -> str:
    """
    Search for a username across hundreds of social media and website platforms.
    Use this when you need to find all accounts associated with a username.
    """
    manager = _get_tool_manager_safe()
    if not manager:
        return "Sherlock tool manager not available. Ensure the platform is running."
    try:
        request_id = _run_async(manager.execute_tool("sherlock", username))
        return _poll_for_result("sherlock", manager, request_id)
    except Exception as e:
        return f"Sherlock search failed: {e}"


@tool("sublist3r_subdomain_enumeration")
def sublist3r_subdomain_enumeration(domain: str, threads: int = 100) -> str:
    """
    Enumerate subdomains for a given domain. Use this to discover
    subdomains and understand the attack surface of a target domain.
    """
    manager = _get_tool_manager_safe()
    if not manager:
        return "Sublist3r tool manager not available."
    try:
        request_id = _run_async(manager.execute_tool("sublist3r", domain, threads=threads))
        return _poll_for_result("sublist3r", manager, request_id)
    except Exception as e:
        return f"Sublist3r enumeration failed: {e}"


@tool("amass_asset_discovery")
def amass_asset_discovery(domain: str) -> str:
    """
    Run comprehensive asset discovery and reconnaissance on a domain.
    Uses multiple techniques to find subdomains, IPs, and related infrastructure.
    """
    manager = _get_tool_manager_safe()
    if not manager:
        return "Amass tool manager not available."
    try:
        request_id = _run_async(manager.execute_tool("amass", domain))
        return _poll_for_result("amass", manager, request_id)
    except Exception as e:
        return f"Amass discovery failed: {e}"


@tool("holehe_email_check")
def holehe_email_check(email: str) -> str:
    """
    Check if an email address is registered on various online services and
    platforms. Useful for footprinting a target email address.
    """
    manager = _get_tool_manager_safe()
    if not manager:
        return "Holehe tool manager not available."
    try:
        request_id = _run_async(manager.execute_tool("holehe", email))
        return _poll_for_result("holehe", manager, request_id)
    except Exception as e:
        return f"Holehe email check failed: {e}"


@tool("phoneinfoga_phone_scan")
def phoneinfoga_phone_scan(phone: str) -> str:
    """
    Perform phone number reconnaissance and OSINT gathering.
    Returns carrier info, location, and associated services for a phone number.
    """
    manager = _get_tool_manager_safe()
    if not manager:
        return "PhoneInfoga tool manager not available."
    try:
        request_id = _run_async(manager.execute_tool("phoneinfoga", phone, scan_osint=True))
        return _poll_for_result("phoneinfoga", manager, request_id)
    except Exception as e:
        return f"PhoneInfoga scan failed: {e}"


@tool("threat_intelligence_query")
def threat_intelligence_query(query: str) -> str:
    """
    Query multiple threat intelligence APIs (Shodan, VirusTotal, SecurityTrails,
    AbuseIPDB, URLScan, HaveIBeenPwned, Whois) to investigate an IP, domain,
    email, URL, or file hash. Results are correlated and deduplicated across
    all sources. This is the primary tool for threat investigation.
    """
    manager = _get_api_manager_safe()
    if not manager:
        return "API Manager not available. Ensure API keys are configured."
    try:
        result = _run_async(manager.query(query=query, apis=None, use_cache=True))
        correlation = result.get("correlation", {})
        summary_parts = [f"Investigated: {query}"]
        summary_parts.append(f"Sources queried: {len(correlation.get('sources', []))}")
        summary_parts.append(f"Total results: {correlation.get('total_results', 0)}")
        summary_parts.append(
            f"Deduplicated findings: {len(correlation.get('deduplicated', []))}"
        )
        summary_parts.append(
            f"Time: {result.get('execution_time_seconds', 0):.2f}s"
        )

        deduped = correlation.get("deduplicated", [])
        if deduped:
            summary_parts.append("\nKey findings:")
            for item in deduped[:5]:
                sources = item.get("sources", [])
                ip = item.get("ip", item.get("domain", item.get("email", "unknown")))
                summary_parts.append(f"  - {ip} (from: {', '.join(sources)})")

        return "\n".join(summary_parts)
    except Exception as e:
        return f"Threat intelligence query failed: {e}"


# ─── Tool Registry ───────────────────────────────────────────────────────────

AVAILABLE_TOOLS = {
    "sherlock_username_search": "Search username across social media",
    "sublist3r_subdomain_enumeration": "Enumerate domain subdomains",
    "amass_asset_discovery": "Comprehensive asset discovery on a domain",
    "holehe_email_check": "Check email account presence across services",
    "phoneinfoga_phone_scan": "Phone number reconnaissance",
    "threat_intelligence_query": "Query multiple threat intel APIs for any indicator",
}

TOOL_LIST = [
    sherlock_username_search,
    sublist3r_subdomain_enumeration,
    amass_asset_discovery,
    holehe_email_check,
    phoneinfoga_phone_scan,
    threat_intelligence_query,
]


def get_agent_tools() -> List[BaseTool]:
    """Get all CrewAI tools for the Hermes agent."""
    return TOOL_LIST


def get_tool_descriptions() -> str:
    """Get human-readable tool descriptions for the agent prompt."""
    lines = ["Available OSINT Tools:", ""]
    for name, desc in AVAILABLE_TOOLS.items():
        lines.append(f"  - {name}: {desc}")
    return "\n".join(lines)
