"""Holehe tool executor with rate limiting."""
import logging
from src.osint_platform.tools.executor import RateLimitedToolExecutor
from src.osint_platform.tools.holehe.holehe_tool import HoleheTool
from src.osint_platform.tools.base import ToolResult

logger = logging.getLogger(__name__)


class HoleheExecutor(RateLimitedToolExecutor):
    """Rate-limited executor for Holehe email breach detection."""

    def __init__(self, **kwargs):
        # Holehe: 1 request/second
        super().__init__(
            tool_name="holehe",
            requests_per_second=1.0,
            max_concurrent=1,
            queue_size=100,
            timeout_seconds=30,
            **kwargs,
        )
        self.tool = HoleheTool(timeout=30)

    async def execute(self, query: str, **kwargs) -> ToolResult:
        """Execute Holehe email breach search."""
        return await self.tool.search(query, **kwargs)
