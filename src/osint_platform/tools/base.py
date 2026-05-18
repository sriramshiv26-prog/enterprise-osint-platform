"""
Base class for OSINT tools - defines interface and common functionality.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Standardized result from OSINT tool execution."""
    tool_name: str
    query: str
    success: bool
    data: List[Dict[str, Any]]
    error: Optional[str] = None
    execution_time_seconds: float = 0.0
    timestamp: datetime = None
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class BaseTool(ABC):
    """
    Base class for all OSINT tools.

    Defines interface for:
    - Query execution
    - Result standardization
    - Error handling
    - Rate limit tracking
    """

    def __init__(self, name: str, timeout: int = 30):
        self.name = name
        self.timeout = timeout
        self.logger = logging.getLogger(f"osint.{name}")

    @abstractmethod
    async def search(self, query: str, **kwargs) -> ToolResult:
        """
        Execute OSINT search.

        Args:
            query: Search query/target
            **kwargs: Tool-specific options

        Returns:
            ToolResult with standardized data
        """
        pass

    def _standardize_result(
        self,
        data: List[Dict[str, Any]],
        success: bool = True,
        error: Optional[str] = None,
        execution_time: float = 0.0,
        rate_limit_remaining: Optional[int] = None,
        rate_limit_reset: Optional[datetime] = None,
    ) -> ToolResult:
        """Convert tool-specific result to standardized format."""
        return ToolResult(
            tool_name=self.name,
            query=getattr(self, '_current_query', ''),
            success=success,
            data=data,
            error=error,
            execution_time_seconds=execution_time,
            rate_limit_remaining=rate_limit_remaining,
            rate_limit_reset=rate_limit_reset,
        )

    def validate_query(self, query: str) -> bool:
        """Validate query format. Override in subclasses for specific validation."""
        return query and len(query.strip()) > 0


class RateLimitTracker:
    """Track rate limits across multiple tools."""

    def __init__(self):
        self.limits: Dict[str, Dict[str, Any]] = {}

    def set_limit(
        self,
        tool_name: str,
        remaining: int,
        reset_time: Optional[datetime] = None,
    ):
        """Update rate limit info for a tool."""
        self.limits[tool_name] = {
            "remaining": remaining,
            "reset_time": reset_time,
            "last_updated": datetime.utcnow(),
        }

    def get_limit(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get current rate limit status for a tool."""
        return self.limits.get(tool_name)

    def is_rate_limited(self, tool_name: str) -> bool:
        """Check if tool is currently rate limited."""
        limit = self.get_limit(tool_name)
        if not limit:
            return False

        remaining = limit.get("remaining", 0)
        reset_time = limit.get("reset_time")

        if remaining == 0 and reset_time:
            if datetime.utcnow() < reset_time:
                return True

        return False

    def reset(self):
        """Reset all tracked limits."""
        self.limits.clear()
