"""Sublist3r tool executor with rate limiting."""
import logging
from src.osint_platform.tools.executor import RateLimitedToolExecutor
from src.osint_platform.tools.sublist3r.sublist3r_tool import Sublist3rTool
from src.osint_platform.tools.base import ToolResult

logger = logging.getLogger(__name__)


class Sublist3rExecutor(RateLimitedToolExecutor):
    """Rate-limited executor for Sublist3r subdomain enumeration."""

    def __init__(self, **kwargs):
        # Sublist3r: 10 requests/minute = 0.167 requests/second
        super().__init__(
            tool_name="sublist3r",
            requests_per_second=0.167,  # 1 request every 6 seconds
            max_concurrent=1,
            queue_size=100,
            timeout_seconds=120,
            **kwargs,
        )
        self.tool = Sublist3rTool(timeout=120)

    async def execute(self, query: str, **kwargs) -> ToolResult:
        """Execute Sublist3r subdomain enumeration."""
        return await self.tool.search(query, **kwargs)
