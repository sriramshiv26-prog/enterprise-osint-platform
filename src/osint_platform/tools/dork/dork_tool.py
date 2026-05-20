"""
Google Dork Tool — executes Google dork queries and returns structured results.

Supports two backends:
  1. googlesearch-python library (default, no API key needed)
  2. Google Programmable Search API (requires API key + CX, more reliable)
"""
import logging
import time
from typing import Any, Dict, List, Optional

from src.osint_platform.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)


class DorkTool(BaseTool):
    """
    OSINT tool for executing Google dork queries.

    Uses googlesearch-python library by default, with fallback
    to Google Custom Search API if credentials are configured.
    """

    def __init__(
        self,
        timeout: int = 30,
        max_results: int = 20,
        delay_between_queries: float = 1.0,
        api_key: Optional[str] = None,
        search_engine_id: Optional[str] = None,
    ):
        super().__init__(name="google_dork", timeout=timeout)
        self.max_results = max_results
        self.delay = delay_between_queries
        self.api_key = api_key
        self.search_engine_id = search_engine_id
        self._use_api = bool(api_key and search_engine_id)
        self._googlesearch_available = None

    def _check_googlesearch(self) -> bool:
        """Check if googlesearch library is available."""
        if self._googlesearch_available is not None:
            return self._googlesearch_available
        try:
            import googlesearch  # noqa: F401
            self._googlesearch_available = True
        except ImportError:
            self._googlesearch_available = False
            logger.warning("googlesearch-python not installed, falling back to httpx")
        return self._googlesearch_available

    async def search(self, query: str, **kwargs) -> ToolResult:
        """
        Execute a Google dork search.

        Args:
            query: The Google dork query string (e.g. "site:example.com ext:pdf")
            **kwargs:
                max_results: Override max results (default: 20)
                use_api: Force use of Google API (default: False)
                target: Optional target name for result metadata

        Returns:
            ToolResult with list of result dicts containing url, title, snippet
        """
        start_time = time.monotonic()
        self._current_query = query

        max_results = kwargs.get("max_results", self.max_results)
        use_api = kwargs.get("use_api", self._use_api)

        try:
            if use_api and self.api_key and self.search_engine_id:
                results = await self._search_via_api(query, max_results)
            else:
                results = await self._search_via_scrape(query, max_results)

            elapsed = time.monotonic() - start_time

            return ToolResult(
                tool_name=self.name,
                query=query,
                success=True,
                data=results,
                execution_time_seconds=round(elapsed, 2),
            )

        except Exception as e:
            elapsed = time.monotonic() - start_time
            logger.error(f"Dork search failed for query '{query}': {e}")
            return ToolResult(
                tool_name=self.name,
                query=query,
                success=False,
                data=[],
                error=str(e),
                execution_time_seconds=round(elapsed, 2),
            )

    async def _search_via_scrape(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        """Search using googlesearch-python library (scraping)."""
        if self._check_googlesearch():
            return await self._search_via_googlesearch(query, max_results)
        return await self._search_via_httpx(query, max_results)

    async def _search_via_googlesearch(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        """Search using the googlesearch-python library."""
        import googlesearch

        results: List[Dict[str, Any]] = []
        seen_urls: set = set()

        try:
            # Run in executor since googlesearch is synchronous
            loop = asyncio.get_event_loop()

            def _do_search():
                return list(googlesearch.search(
                    query,
                    num_results=max_results,
                    lang="en",
                    advanced=True,
                ))

            search_results = await loop.run_in_executor(None, _do_search)

            for item in search_results:
                url = str(item.url) if hasattr(item, "url") else str(item)
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                result = {
                    "url": url,
                    "title": str(item.title) if hasattr(item, "title") else "",
                    "snippet": str(item.description) if hasattr(item, "description") else "",
                    "source": "google_dork_scrape",
                }
                results.append(result)

                if len(results) >= max_results:
                    break

        except Exception as e:
            logger.warning(f"googlesearch library failed: {e}, falling back to httpx")
            return await self._search_via_httpx(query, max_results)

        return results

    async def _search_via_httpx(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        """Fallback search using raw httpx requests to Google."""
        import httpx
        import re
        from urllib.parse import quote_plus

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
        }

        url = f"https://www.google.com/search?q={quote_plus(query)}&num={min(max_results, 100)}"

        results: List[Dict[str, Any]] = []
        seen_urls: set = set()

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()

            # Parse result blocks from HTML
            html = response.text

            # Pattern: <a href="/url?q=..."> or <h3>...title...</h3>
            # Google's HTML varies, so use multiple extraction strategies
            result_blocks = re.findall(
                r'<div[^>]*class="[^"]*g[^"]*"[^>]*>(.*?)</div>\s*</div>',
                html,
                re.DOTALL,
            )

            if not result_blocks:
                # Try alternate pattern for newer Google SERP
                result_blocks = re.findall(
                    r'<div[^>]*data-hveid[^>]*>(.*?)</div>\s*</div>\s*</div>',
                    html,
                    re.DOTALL,
                )

            for block in result_blocks[:max_results]:
                # Extract URL — handle Google redirect URLs (/url?q=...) and direct URLs
                url_match = re.search(r'href="(https?://[^"]+)"', block)
                if not url_match:
                    url_match = re.search(r'href="(/url\?q=)(https?://[^"&]+)', block)
                    if not url_match:
                        continue
                    url = url_match.group(2)
                else:
                    url = url_match.group(1)
                    # Clean Google redirect URLs
                    if url.startswith("/url?q="):
                        url = re.sub(r"^/url\?q=", "", url)
                        url = re.sub(r"&sa=.*$", "", url)
                        from urllib.parse import unquote
                        url = unquote(url)

                if url in seen_urls or not url.startswith("http"):
                    continue
                seen_urls.add(url)

                # Extract title
                title_match = re.search(r'<h3[^>]*>(.*?)</h3>', block, re.DOTALL)
                title = ""
                if title_match:
                    title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip()

                # Extract snippet
                snippet_match = re.search(
                    r'<div[^>]*class="[^"]*[Ss]t\w*[^"]*"[^>]*>(.*?)</div>',
                    block, re.DOTALL,
                )
                snippet = ""
                if snippet_match:
                    snippet = re.sub(r"<[^>]+>", "", snippet_match.group(1)).strip()
                    snippet = re.sub(r"\s+", " ", snippet)

                results.append({
                    "url": url,
                    "title": title,
                    "snippet": snippet[:500],
                    "source": "google_dork_httpx",
                })

        return results

    async def _search_via_api(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        """Search using Google Programmable Search API (more reliable)."""
        import httpx

        url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "key": self.api_key,
            "cx": self.search_engine_id,
            "q": query,
            "num": min(max_results, 10),  # Google API max is 10 per request
        }

        results: List[Dict[str, Any]] = []
        start_index = 1

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while len(results) < max_results:
                params["start"] = start_index
                response = await client.get(url, params=params)
                response.raise_for_status()
                data = response.json()

                if "items" not in data:
                    break

                for item in data["items"]:
                    results.append({
                        "url": item.get("link", ""),
                        "title": item.get("title", ""),
                        "snippet": item.get("snippet", ""),
                        "source": "google_api",
                    })

                # Check if there are more results
                queries = data.get("queries", {})
                if "nextPage" not in queries:
                    break
                start_index = queries["nextPage"][0].get("startIndex", start_index + 10)

        return results


# ─── Helper function for batch dorking ───────────────────────────────────────

async def run_dork_batch(
    tool: DorkTool,
    target: str,
    categories: Optional[List[str]] = None,
    risk_levels: Optional[List[str]] = None,
    max_per_dork: int = 5,
) -> Dict[str, Any]:
    """
    Run multiple dork queries against a target.

    Args:
        tool: DorkTool instance
        target: Target domain/name
        categories: List of categories to run (None = all)
        risk_levels: Filter by risk level
        max_per_dork: Max results per individual dork

    Returns:
        Dict with aggregated results per category
    """
    from src.osint_platform.tools.dork.dork_library import (
        get_all_dorks,
        get_dorks_by_category,
        DORKS_BY_CATEGORY,
        resolve_dork_query,
    )

    results_by_category: Dict[str, List[Dict[str, Any]]] = {}
    total_results = 0

    # Determine which dorks to run
    if categories:
        dork_list = []
        for cat in categories:
            dork_list.extend(get_dorks_by_category(cat))
    else:
        dork_list = get_all_dorks()

    # Filter by risk level if specified
    if risk_levels:
        risk_levels_upper = [r.upper() for r in risk_levels]
        dork_list = [d for d in dork_list if d["risk_level"] in risk_levels_upper]

    for dork in dork_list:
        query = resolve_dork_query(dork, target)
        result = await tool.search(query, max_results=max_per_dork)

        cat = dork["category"]
        if cat not in results_by_category:
            results_by_category[cat] = []

        if result.success and result.data:
            for item in result.data:
                item["dork_name"] = dork["name"]
                item["dork_description"] = dork["description"]
                item["risk_level"] = dork["risk_level"]
                results_by_category[cat].append(item)
                total_results += 1

    return {
        "target": target,
        "total_results": total_results,
        "categories_tested": len(dork_list),
        "categories_with_results": len([c for c, r in results_by_category.items() if r]),
        "results_by_category": results_by_category,
    }


# Import asyncio here since it's used in the helper methods
import asyncio  # noqa: E402
