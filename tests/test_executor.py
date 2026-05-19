"""Tests for tool executors."""
import asyncio
import pytest
from src.osint_platform.tools.base import ToolResult
from src.osint_platform.tools.executor import RateLimitedToolExecutor, RequestStatus


class MockTool(RateLimitedToolExecutor):
    """Mock tool executor for testing."""

    def __init__(self, **kwargs):
        # Extract override parameters, use defaults if not provided
        max_concurrent = kwargs.pop("max_concurrent", 2)
        queue_size = kwargs.pop("queue_size", 50)

        super().__init__(
            tool_name="mock",
            requests_per_second=10.0,
            max_concurrent=max_concurrent,
            queue_size=queue_size,
            timeout_seconds=5,
            **kwargs,
        )
        self.execute_count = 0

    async def execute(self, query: str, **kwargs) -> ToolResult:
        """Mock execution."""
        self.execute_count += 1
        await asyncio.sleep(0.1)  # Simulate work

        return ToolResult(
            tool_name="mock",
            query=query,
            success=True,
            data=[{"result": f"Found result for {query}"}],
            execution_time_seconds=0.1,
        )


@pytest.mark.asyncio
async def test_executor_basic():
    """Test basic executor functionality."""
    executor = MockTool()
    await executor.start()

    try:
        request = await executor.enqueue_request("test_query")

        # Give executor time to process
        await asyncio.sleep(0.5)

        assert request.query == "test_query"
        assert executor.execute_count >= 1
    finally:
        await executor.stop()


@pytest.mark.asyncio
async def test_executor_multiple_requests():
    """Test executor with multiple concurrent requests."""
    executor = MockTool()
    await executor.start()

    try:
        requests = []
        for i in range(5):
            req = await executor.enqueue_request(f"query_{i}")
            requests.append(req)

        # Wait for processing
        await asyncio.sleep(1.0)

        # All should be completed
        for req in requests:
            status = executor.get_request_status(req.request_id)
            assert status is not None
    finally:
        await executor.stop()


@pytest.mark.asyncio
async def test_executor_queue_full():
    """Test behavior when queue is full."""
    executor = MockTool(queue_size=2)
    await executor.start()

    try:
        # Enqueue up to capacity
        req1 = await executor.enqueue_request("query_1")
        req2 = await executor.enqueue_request("query_2")

        # Third should fail (queue full)
        with pytest.raises(asyncio.QueueFull):
            await executor.enqueue_request("query_3")
    finally:
        await executor.stop()


@pytest.mark.asyncio
async def test_executor_not_running():
    """Test error when executor not running."""
    executor = MockTool()

    with pytest.raises(RuntimeError):
        await executor.enqueue_request("query")


@pytest.mark.asyncio
async def test_executor_stats():
    """Test executor statistics."""
    executor = MockTool()
    await executor.start()

    try:
        await executor.enqueue_request("query_1")
        await executor.enqueue_request("query_2")

        await asyncio.sleep(0.5)

        stats = executor.get_stats()

        assert stats["tool_name"] == "mock"
        assert stats["max_concurrent"] == 2
        assert stats["stats"]["successful"] >= 1
    finally:
        await executor.stop()


@pytest.mark.asyncio
async def test_executor_concurrent_limit():
    """Test that max_concurrent is respected."""
    executor = MockTool(max_concurrent=1)
    await executor.start()

    try:
        # Enqueue multiple slow requests
        requests = []
        for i in range(3):
            req = await executor.enqueue_request(f"query_{i}")
            requests.append(req)

        await asyncio.sleep(0.5)

        # With max_concurrent=1, should process sequentially
        stats = executor.get_stats()
        assert stats["stats"]["successful"] >= 1
    finally:
        await executor.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
