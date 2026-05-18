"""PhoneInfoga tool executor with rate limiting."""
import logging
from src.osint_platform.tools.executor import RateLimitedToolExecutor
from src.osint_platform.tools.phoneinfogar.phoneinfoga_tool import PhoneInfogaTool
from src.osint_platform.tools.base import ToolResult

logger = logging.getLogger(__name__)


class PhoneInfogaExecutor(RateLimitedToolExecutor):
    """Rate-limited executor for PhoneInfoga phone number OSINT."""

    def __init__(self, **kwargs):
        # PhoneInfoga: 30 requests/minute = 0.5 requests/second
        super().__init__(
            tool_name="phoneinfoga",
            requests_per_second=0.5,  # 1 request every 2 seconds
            max_concurrent=1,
            queue_size=100,
            timeout_seconds=30,
            **kwargs,
        )
        self.tool = PhoneInfogaTool(timeout=30)

    async def execute(self, query: str, **kwargs) -> ToolResult:
        """Execute PhoneInfoga phone number reconnaissance."""
        return await self.tool.search(query, **kwargs)
