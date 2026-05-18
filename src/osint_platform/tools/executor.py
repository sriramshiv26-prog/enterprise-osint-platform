"""
Tool execution system with rate limiting and request queuing.

Manages per-tool request queues with rate limiting and concurrent execution.
Implements producer-consumer pattern for async tool invocation.
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from src.osint_platform.tools.base import ToolResult
from src.osint_platform.tools.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class RequestStatus(str, Enum):
    """Status of a tool execution request."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ToolRequest:
    """Represents a queued tool execution request."""
    request_id: str
    tool_name: str
    query: str
    kwargs: Dict[str, Any] = field(default_factory=dict)
    status: RequestStatus = RequestStatus.PENDING
    result: Optional[ToolResult] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    @property
    def execution_time_seconds(self) -> Optional[float]:
        """Get execution time in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class RateLimitedToolExecutor(ABC):
    """
    Base class for rate-limited tool execution.

    Manages:
    - Request queuing (bounded queue prevents OOM)
    - Rate limiting (respects tool's rate limit)
    - Concurrent execution (semaphore controls max concurrent)
    - Worker management (background task)
    - Result tracking (for monitoring)
    """

    def __init__(
        self,
        tool_name: str,
        requests_per_second: float,
        max_concurrent: int = 1,
        queue_size: int = 100,
        timeout_seconds: int = 60,
    ):
        """
        Initialize executor.

        Args:
            tool_name: Name of the tool
            requests_per_second: Rate limit
            max_concurrent: Max concurrent executions
            queue_size: Max queued requests
            timeout_seconds: Timeout per execution
        """
        self.tool_name = tool_name
        self.requests_per_second = requests_per_second
        self.max_concurrent = max_concurrent
        self.queue_size = queue_size
        self.timeout_seconds = timeout_seconds

        # Queue and concurrency control
        self.request_queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.rate_limiter = RateLimiter(requests_per_second)

        # Worker management
        self.worker_task: Optional[asyncio.Task] = None
        self.is_running = False

        # Request tracking
        self.request_history: Dict[str, ToolRequest] = {}
        self.stats = {
            "total_requests": 0,
            "successful": 0,
            "failed": 0,
            "cancelled": 0,
        }

    async def start(self) -> None:
        """Start the worker task."""
        if self.is_running:
            logger.warning(f"Executor {self.tool_name} already running")
            return

        self.is_running = True
        self.worker_task = asyncio.create_task(self._worker_loop())
        logger.info(f"Started executor for {self.tool_name}")

    async def stop(self) -> None:
        """Stop the worker task and cancel pending requests."""
        if not self.is_running:
            return

        self.is_running = False

        # Cancel pending requests
        while not self.request_queue.empty():
            try:
                request = self.request_queue.get_nowait()
                request.status = RequestStatus.CANCELLED
            except asyncio.QueueEmpty:
                break

        # Wait for worker to finish
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass

        logger.info(f"Stopped executor for {self.tool_name}")

    async def enqueue_request(
        self,
        query: str,
        request_id: Optional[str] = None,
        **kwargs,
    ) -> ToolRequest:
        """
        Enqueue a tool execution request.

        Args:
            query: Query/target for the tool
            request_id: Optional custom request ID
            **kwargs: Tool-specific parameters

        Returns:
            ToolRequest object (can track status via request_id)

        Raises:
            asyncio.QueueFull: If queue is full
        """
        if not self.is_running:
            raise RuntimeError(f"Executor {self.tool_name} is not running")

        request_id = request_id or f"{self.tool_name}_{datetime.utcnow().timestamp()}"

        request = ToolRequest(
            request_id=request_id,
            tool_name=self.tool_name,
            query=query,
            kwargs=kwargs,
        )

        try:
            self.request_queue.put_nowait(request)
            self.request_history[request_id] = request
            logger.debug(f"Enqueued request {request_id} for {self.tool_name}")
            return request
        except asyncio.QueueFull:
            logger.error(f"Queue full for {self.tool_name}, rejecting request")
            raise

    async def _worker_loop(self) -> None:
        """
        Worker loop: dequeue → rate limit → execute.

        Runs continuously until stopped.
        """
        logger.info(f"Worker loop started for {self.tool_name}")

        try:
            while self.is_running:
                try:
                    # Get next request (blocks if queue empty)
                    request = await asyncio.wait_for(
                        self.request_queue.get(),
                        timeout=5.0,
                    )

                    # Respect rate limit
                    await self.rate_limiter.acquire()

                    # Execute with semaphore (max concurrent)
                    async with self.semaphore:
                        await self._execute_request(request)

                    self.request_queue.task_done()

                except asyncio.TimeoutError:
                    # Queue timeout (no requests for 5s), continue waiting
                    continue
                except asyncio.CancelledError:
                    logger.info(f"Worker loop cancelled for {self.tool_name}")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in worker loop: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Worker loop crashed for {self.tool_name}: {e}", exc_info=True)
        finally:
            self.is_running = False
            logger.info(f"Worker loop stopped for {self.tool_name}")

    async def _execute_request(self, request: ToolRequest) -> None:
        """
        Execute a single request.

        Handles timing, error handling, and result tracking.
        """
        request.status = RequestStatus.RUNNING
        request.started_at = datetime.utcnow()

        try:
            logger.debug(f"Executing request {request.request_id}")

            # Call abstract execute method
            result = await asyncio.wait_for(
                self.execute(request.query, **request.kwargs),
                timeout=self.timeout_seconds,
            )

            request.result = result
            request.status = RequestStatus.COMPLETED
            request.completed_at = datetime.utcnow()
            self.stats["successful"] += 1

            logger.info(
                f"Completed request {request.request_id}: "
                f"{len(result.data)} results in {result.execution_time_seconds:.2f}s"
            )

        except asyncio.TimeoutError:
            request.status = RequestStatus.FAILED
            request.error = f"Timeout after {self.timeout_seconds}s"
            request.completed_at = datetime.utcnow()
            self.stats["failed"] += 1
            logger.warning(f"Timeout on request {request.request_id}")

        except Exception as e:
            request.status = RequestStatus.FAILED
            request.error = str(e)
            request.completed_at = datetime.utcnow()
            self.stats["failed"] += 1
            logger.error(f"Failed request {request.request_id}: {e}")

    @abstractmethod
    async def execute(self, query: str, **kwargs) -> ToolResult:
        """
        Execute the tool with given query.

        Implement in subclass with actual tool invocation.

        Args:
            query: Query/target
            **kwargs: Tool-specific parameters

        Returns:
            ToolResult with findings
        """
        pass

    def get_request_status(self, request_id: str) -> Optional[ToolRequest]:
        """Get status of a request by ID."""
        return self.request_history.get(request_id)

    def get_stats(self) -> Dict[str, Any]:
        """Get executor statistics."""
        return {
            "tool_name": self.tool_name,
            "queue_size": self.request_queue.qsize(),
            "queue_capacity": self.queue_size,
            "rate_limit": f"{self.requests_per_second} req/s",
            "max_concurrent": self.max_concurrent,
            "stats": self.stats,
        }

    async def wait_until_empty(self) -> None:
        """Wait until request queue is empty and all requests processed."""
        await self.request_queue.join()
