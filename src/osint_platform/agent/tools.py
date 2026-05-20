"""
CrewAI tool wrappers for all OSINT capabilities.

Wraps the existing executors and API integrations as CrewAI Tools
so the Hermes agent can call them dynamically.
"""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

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


# ─── Photo Polling Helper ────────────────────────────────────────────────────


def _photo_poll_for_result(manager, request_id: str, timeout: float = 120.0) -> str:
    """Poll the photo OSINT executor for results.

    Photo analysis can take longer due to image downloads.
    Formats findings by category (EXIF, face detection, reverse search).
    """
    import time
    start = time.monotonic()
    poll_interval = 0.5

    while True:
        elapsed = time.monotonic() - start
        if elapsed >= timeout:
            return (
                f"Photo OSINT request {request_id} still processing after {timeout}s. "
                "Check /api/v1/tools/status/photo_osint/{request_id} for results."
            )

        status = manager.get_request_status("photo_osint", request_id)
        if status is None:
            time.sleep(poll_interval)
            continue

        if status["status"] == "completed":
            result = status.get("result")
            if result and result.get("data"):
                data = result["data"]
                items = data if isinstance(data, list) else [data]
                lines = [f"Photo OSINT results:", ""]

                for item in items[:15]:
                    item_type = item.get("type", "unknown")
                    summary = item.get("summary", "")
                    risk_level = item.get("risk_level", "INFO")
                    lines.append(f"  [{risk_level}] {summary}")

                    if item_type == "exif_metadata":
                        details = item.get("details", [])
                        for d in details[:8]:
                            lines.append(f"    • {d}")

                    if item_type == "gps_location":
                        details = item.get("details", [])
                        for d in details[:3]:
                            lines.append(f"    📍 {d}")

                    if item_type == "reverse_search":
                        engines = item.get("engines", [])
                        for eng in engines[:4]:
                            lines.append(f"    🔍 {eng['name']}: {eng['url']}")

                    if item_type == "social_media_match":
                        matches = item.get("matches", [])
                        for m in matches[:5]:
                            lines.append(f"    👤 {m['platform']} ({m.get('confidence', 'unknown')})")

                    if item_type == "face_detected":
                        details = item.get("details", [])
                        for d in details[:3]:
                            lines.append(f"    {d}")

                    lines.append("")

                exec_time = status.get("execution_time_seconds", 0)
                lines.append(f"Total findings: {len(items)}")
                lines.append(f"Execution time: {exec_time:.2f}s")
                return "\n".join(lines)
            return f"Photo OSINT completed with no findings."

        if status["status"] == "failed":
            error = status.get("error", "Unknown error")
            return f"Photo OSINT failed: {error}"

        time.sleep(poll_interval)


# ─── Dork Polling Helper ─────────────────────────────────────────────────────


def _dork_poll_for_result(manager, request_id: str, timeout: float = 60.0) -> str:
    """Poll the dork executor for results.

    Dork queries can take longer since they involve web scraping.
    Deduplicates results and formats them by category.
    """
    import time
    start = time.monotonic()
    poll_interval = 0.5

    while True:
        elapsed = time.monotonic() - start
        if elapsed >= timeout:
            return (
                f"Google Dork request {request_id} still processing after {timeout}s. "
                "Check /api/v1/tools/status/google_dork/{request_id} for results."
            )

        status = manager.get_request_status("google_dork", request_id)
        if status is None:
            time.sleep(poll_interval)
            continue

        if status["status"] == "completed":
            result = status.get("result")
            if result and result.get("data"):
                data = result["data"]
                items = data if isinstance(data, list) else [data]
                seen_urls = set()
                lines = [f"Google Dork results for '{status.get('query', '')}':", ""]
                for item in items[:30]:
                    url = item.get("url", "")
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    title = item.get("title", "")
                    snippet = item.get("snippet", "")
                    lines.append(f"  • {title}")
                    lines.append(f"    URL: {url}")
                    if snippet:
                        lines.append(f"    {snippet[:200]}")
                    lines.append("")
                exec_time = status.get("execution_time_seconds", 0)
                lines.append(f"Total unique results: {len(seen_urls)}")
                lines.append(f"Execution time: {exec_time:.2f}s")
                return "\n".join(lines)
            return f"Google Dork completed for '{status.get('query', '')}' with no results."

        if status["status"] == "failed":
            error = status.get("error", "Unknown error")
            return f"Google Dork search failed: {error}"

        time.sleep(poll_interval)


# ─── CrewAI Tool Definitions ─────────────────────────────────────────────────


@tool("google_dork_search")
def google_dork_search(dork_query: str, max_results: int = 20) -> str:
    """
    Execute a Google dork search query to find exposed information.

    Use for:
    - Finding admin panels (inurl:admin)
    - Exposed config files (ext:env, ext:sql)
    - Password leaks (ext:pem "PRIVATE KEY")
    - Backup files (ext:tar, ext:zip, ext:bak)
    - Error messages revealing system info
    - Directory listings (intitle:index.of)
    - Exposed documents (ext:pdf, ext:xlsx)
    - Camera/webcam interfaces
    - Database dumps (ext:sql, ext:db)
    - Emails on target domain
    - Subdomain discovery

    Use site:{target} to scope results to a specific domain.
    Example: "site:example.com ext:env"

    Max results is capped at 30 per query to avoid hitting limits.
    """
    manager = _get_tool_manager_safe()
    if not manager:
        return "Google Dork tool manager not available."
    try:
        request_id = _run_async(manager.execute_tool("google_dork", dork_query, max_results=min(max_results, 30)))
        return _dork_poll_for_result(manager, request_id)
    except Exception as e:
        return f"Google Dork search failed: {e}"


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


@tool("photo_osint_search")
def photo_osint_search(image_url: str, extract_exif: bool = True, detect_faces: bool = True) -> str:
    """
    Perform Photo OSINT analysis on an image URL.

    Capabilities:
    - EXIF metadata extraction: camera make/model, GPS coordinates, timestamps, software used
    - Reverse image search: generates search URLs for Google Images, Bing, Yandex, TinEye
    - Face detection: basic heuristic face presence detection
    - Social media photo pattern matching: identifies known profile photo sources
    - Image hashing: MD5/SHA1/SHA256 for deduplication

    Use this when you have an image URL from any source (social media, web, etc.)
    and need to extract intelligence from it. Provide a direct URL to the image file.
    """
    manager = _get_tool_manager_safe()
    if not manager:
        return "Photo OSINT tool manager not available."
    try:
        request_id = _run_async(manager.execute_tool(
            "photo_osint", image_url,
            extract_exif=extract_exif,
            detect_faces=detect_faces,
            reverse_search=True,
        ))
        return _photo_poll_for_result(manager, request_id)
    except Exception as e:
        return f"Photo OSINT search failed: {e}"


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
    "photo_osint_search": "Analyze image URL for EXIF metadata, GPS coordinates, face detection, and reverse image search links",
    "google_dork_search": "Execute Google dork queries for exposed info, configs, docs, and vulnerabilities",
    "sherlock_username_search": "Search username across social media",
    "sublist3r_subdomain_enumeration": "Enumerate domain subdomains",
    "amass_asset_discovery": "Comprehensive asset discovery on a domain",
    "holehe_email_check": "Check email account presence across services",
    "phoneinfoga_phone_scan": "Phone number reconnaissance",
    "threat_intelligence_query": "Query multiple threat intel APIs for any indicator",
}

TOOL_LIST = [
    google_dork_search,
    sherlock_username_search,
    sublist3r_subdomain_enumeration,
    amass_asset_discovery,
    holehe_email_check,
    phoneinfoga_phone_scan,
    photo_osint_search,
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
