"""Sherlock tool executor with rate limiting."""
import logging
from src.osint_platform.tools.executor import RateLimitedToolExecutor
from src.osint_platform.tools.sherlock.sherlock_tool import SherlockTool
from src.osint_platform.tools.base import ToolResult

logger = logging.getLogger(__name__)


class SherlockExecutor(RateLimitedToolExecutor):
    """Rate-limited executor for Sherlock username OSINT."""

    def __init__(self, **kwargs):
        # Sherlock: 2 requests/second
        super().__init__(
            tool_name="sherlock",
            requests_per_second=2.0,
            max_concurrent=1,
            queue_size=100,
            timeout_seconds=60,
            **kwargs,
        )
        self.tool = SherlockTool(timeout=60)

    async def execute(self, query: str, **kwargs) -> ToolResult:
        """Execute Sherlock username search."""
        return await self.tool.search(query, **kwargs)
