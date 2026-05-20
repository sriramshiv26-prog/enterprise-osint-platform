"""Photo OSINT executor with rate limiting."""
import logging
from src.osint_platform.tools.executor import RateLimitedToolExecutor
from src.osint_platform.tools.photo.photo_tool import PhotoTool
from src.osint_platform.tools.base import ToolResult

logger = logging.getLogger(__name__)


class PhotoExecutor(RateLimitedToolExecutor):
    """Rate-limited executor for Photo OSINT operations."""

    def __init__(self, **kwargs):
        # Photo downloads and search: ~2 per second maximum to avoid rate limiting
        # Allow caller to override timeout_seconds via kwargs, default to 120
        timeout = kwargs.pop("timeout_seconds", 120)
        super().__init__(
            tool_name="photo_osint",
            requests_per_second=2.0,
            max_concurrent=1,
            queue_size=50,
            timeout_seconds=timeout,
            **kwargs,
        )
        self.tool = PhotoTool(timeout=60, max_results=20)

    async def execute(self, query: str, **kwargs) -> ToolResult:
        """Execute a photo OSINT search query.

        Args:
            query: Image URL or file path
            **kwargs: extract_exif, reverse_search, detect_faces, match_social, image_data

        Returns:
            ToolResult with photo intelligence findings
        """
        return await self.tool.search(query, **kwargs)
