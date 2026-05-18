"""Tests for rate limiter."""
import asyncio
import time
import pytest
from src.osint_platform.tools.rate_limiter import RateLimiter, MultiToolRateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_basic():
    """Test basic rate limiting functionality."""
    limiter = RateLimiter(requests_per_second=2.0)  # 2 req/sec = 0.5s interval

    start = time.time()
    await limiter.acquire()
    await limiter.acquire()
    elapsed = time.time() - start

    # Should take ~0.5 seconds between requests
    assert elapsed >= 0.4, f"Rate limiting too fast: {elapsed}s"


@pytest.mark.asyncio
async def test_rate_limiter_first_request_immediate():
    """Test that first request is immediate."""
    limiter = RateLimiter(requests_per_second=1.0)

    start = time.time()
    await limiter.acquire()
    elapsed = time.time() - start

    # First request should be essentially immediate
    assert elapsed < 0.1


@pytest.mark.asyncio
async def test_rate_limiter_time_until_available():
    """Test time_until_available calculation."""
    limiter = RateLimiter(requests_per_second=1.0)

    await limiter.acquire()
    time_until = limiter.time_until_available()

    # Should be close to 1 second
    assert 0.9 < time_until <= 1.0


@pytest.mark.asyncio
async def test_rate_limiter_reset():
    """Test rate limiter reset."""
    limiter = RateLimiter(requests_per_second=1.0)

    await limiter.acquire()
    limiter.reset()

    # After reset, next request should be immediate
    start = time.time()
    await limiter.acquire()
    elapsed = time.time() - start

    assert elapsed < 0.1


@pytest.mark.asyncio
async def test_multi_tool_rate_limiter():
    """Test managing multiple tools with different rate limits."""
    manager = MultiToolRateLimiter()

    # Register tools with different rates
    manager.register_tool("fast", 10.0)  # 10 req/sec
    manager.register_tool("slow", 1.0)   # 1 req/sec

    # Both should be available immediately
    start = time.time()
    await manager.acquire("fast")
    await manager.acquire("slow")
    elapsed = time.time() - start

    assert elapsed < 0.1


@pytest.mark.asyncio
async def test_multi_tool_rate_limiter_independence():
    """Test that tool rate limits don't affect each other."""
    manager = MultiToolRateLimiter()

    manager.register_tool("tool1", 2.0)  # 2 req/sec
    manager.register_tool("tool2", 1.0)  # 1 req/sec

    # Tool1 should be fast, Tool2 should be slow
    start1 = time.time()
    await manager.acquire("tool1")
    await manager.acquire("tool1")
    elapsed1 = time.time() - start1

    start2 = time.time()
    await manager.acquire("tool2")
    await manager.acquire("tool2")
    elapsed2 = time.time() - start2

    # Tool2 should take significantly longer
    assert elapsed2 > elapsed1 * 1.5, "Rate limits not independent"


@pytest.mark.asyncio
async def test_multi_tool_rate_limiter_status():
    """Test getting status of tool rate limits."""
    manager = MultiToolRateLimiter()

    manager.register_tool("test", 1.0)
    await manager.acquire("test")

    status = manager.get_status("test")

    assert status["tool_name"] == "test"
    assert status["total_requests"] == 1
    assert status["time_until_available"] > 0.9


def test_multi_tool_rate_limiter_unknown_tool():
    """Test error handling for unknown tools."""
    manager = MultiToolRateLimiter()

    status = manager.get_status("unknown")
    assert status == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
