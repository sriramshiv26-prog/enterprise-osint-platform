"""Amass tool executor with rate limiting."""
import logging
from src.osint_platform.tools.executor import RateLimitedToolExecutor
from src.osint_platform.tools.amass.amass_tool import AmassTool
from src.osint_platform.tools.base import ToolResult

logger = logging.getLogger(__name__)


class AmassExecutor(RateLimitedToolExecutor):
    """Rate-limited executor for Amass asset discovery."""

    def __init__(self, **kwargs):
        # Amass: 100 requests/hour = 0.0278 requests/second
        super().__init__(
            tool_name="amass",
            requests_per_second=0.0278,  # 1 request every 36 seconds
            max_concurrent=1,
            queue_size=100,
            timeout_seconds=300,
            **kwargs,
        )
        self.tool = AmassTool(timeout=300)

    async def execute(self, query: str, **kwargs) -> ToolResult:
        """Execute Amass asset discovery."""
        return await self.tool.search(query, **kwargs)
