"""Google Dork executor with rate limiting."""
import logging
from src.osint_platform.tools.executor import RateLimitedToolExecutor
from src.osint_platform.tools.dork.dork_tool import DorkTool
from src.osint_platform.tools.base import ToolResult

logger = logging.getLogger(__name__)


class DorkExecutor(RateLimitedToolExecutor):
    """Rate-limited executor for Google Dork searches."""

    def __init__(self, max_results: int = 20, **kwargs):
        # Google: ~1 search per second to avoid blocking
        super().__init__(
            tool_name="google_dork",
            requests_per_second=1.0,
            max_concurrent=1,
            queue_size=100,
            timeout_seconds=120,
            **kwargs,
        )
        self.tool = DorkTool(timeout=30, max_results=max_results)

    async def execute(self, query: str, **kwargs) -> ToolResult:
        """Execute a Google dork search query."""
        return await self.tool.search(query, **kwargs)
