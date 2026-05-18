"""
Rate limiter implementation for OSINT tools.
Uses asyncio-native patterns for accurate rate limiting.
"""
import asyncio
import logging
from typing import Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Token-bucket style rate limiter using asyncio.

    Ensures requests are spaced out according to rate limit.
    Thread-safe and async-friendly.
    """

    def __init__(self, requests_per_second: float):
        """
        Initialize rate limiter.

        Args:
            requests_per_second: Rate limit (e.g., 2 requests/sec = 2.0)
        """
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second  # Time between requests
        self.last_request_time: Optional[datetime] = None
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        """
        Wait until safe to make next request.

        Blocks if rate limit would be exceeded, sleeps for required duration.
        """
        async with self.lock:
            if self.last_request_time is None:
                # First request
                self.last_request_time = datetime.utcnow()
                return

            # Calculate time since last request
            elapsed = (datetime.utcnow() - self.last_request_time).total_seconds()

            # If not enough time has passed, sleep
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                logger.debug(
                    f"Rate limiter: sleeping {sleep_time:.3f}s "
                    f"({self.requests_per_second} req/s)"
                )
                await asyncio.sleep(sleep_time)

            self.last_request_time = datetime.utcnow()

    def reset(self) -> None:
        """Reset the rate limiter (useful for testing)."""
        self.last_request_time = None

    def time_until_available(self) -> float:
        """
        Get seconds until next request is allowed.

        Returns:
            Seconds to wait (0 if can request immediately)
        """
        if self.last_request_time is None:
            return 0.0

        elapsed = (datetime.utcnow() - self.last_request_time).total_seconds()
        return max(0.0, self.min_interval - elapsed)


class MultiToolRateLimiter:
    """
    Manages rate limiters for multiple tools.

    Tracks requests per tool and prevents rate limit violations.
    """

    def __init__(self):
        self.limiters: dict[str, RateLimiter] = {}
        self.request_counts: dict[str, int] = {}
        self.last_request_times: dict[str, datetime] = {}

    def register_tool(self, tool_name: str, requests_per_second: float) -> None:
        """Register a tool with its rate limit."""
        self.limiters[tool_name] = RateLimiter(requests_per_second)
        self.request_counts[tool_name] = 0
        logger.info(f"Registered {tool_name}: {requests_per_second} req/s")

    async def acquire(self, tool_name: str) -> None:
        """Acquire rate limit token for a tool."""
        if tool_name not in self.limiters:
            raise ValueError(f"Tool {tool_name} not registered")

        await self.limiters[tool_name].acquire()
        self.request_counts[tool_name] += 1
        self.last_request_times[tool_name] = datetime.utcnow()

    def get_status(self, tool_name: str) -> dict:
        """Get rate limit status for a tool."""
        if tool_name not in self.limiters:
            return {}

        return {
            "tool_name": tool_name,
            "total_requests": self.request_counts.get(tool_name, 0),
            "time_until_available": self.limiters[tool_name].time_until_available(),
            "last_request_time": self.last_request_times.get(tool_name),
        }

    def reset(self, tool_name: Optional[str] = None) -> None:
        """Reset rate limiter(s) for testing."""
        if tool_name:
            if tool_name in self.limiters:
                self.limiters[tool_name].reset()
                self.request_counts[tool_name] = 0
        else:
            for limiter in self.limiters.values():
                limiter.reset()
            self.request_counts = {k: 0 for k in self.request_counts}


# Global instance for application-wide rate limiting
_global_rate_limiter = MultiToolRateLimiter()


def get_rate_limiter() -> MultiToolRateLimiter:
    """Get global rate limiter instance."""
    return _global_rate_limiter
