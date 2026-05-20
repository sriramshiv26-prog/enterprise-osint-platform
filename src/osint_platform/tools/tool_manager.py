"""
Tool manager - centralizes all OSINT tool executors.

Handles lifecycle management (startup/shutdown) and provides API for tool invocation.
"""
import logging
from typing import Dict, Optional, Any
from src.osint_platform.tools.executor import RateLimitedToolExecutor
from src.osint_platform.tools.executors import (
    SherlockExecutor,
    Sublist3rExecutor,
    AmassExecutor,
    HoleheExecutor,
    PhoneInfogaExecutor,
    DorkExecutor,
    PhotoExecutor,
)

logger = logging.getLogger(__name__)


class ToolManager:
    """
    Manages all OSINT tool executors.

    Responsibilities:
    - Initialize all tool executors
    - Start/stop worker tasks
    - Route tool requests to correct executor
    - Track executor health
    - Provide stats and monitoring
    """

    def __init__(self):
        """Initialize tool manager with all executors."""
        self.executors: Dict[str, RateLimitedToolExecutor] = {}
        self._initialized = False

        # Create all executors
        self._create_executors()

    def _create_executors(self) -> None:
        """Create instances of all tool executors."""
        self.executors["sherlock"] = SherlockExecutor()
        self.executors["sublist3r"] = Sublist3rExecutor()
        self.executors["amass"] = AmassExecutor()
        self.executors["holehe"] = HoleheExecutor()
        self.executors["phoneinfoga"] = PhoneInfogaExecutor()
        self.executors["google_dork"] = DorkExecutor(max_results=30)
        self.executors["photo_osint"] = PhotoExecutor()

        logger.info(f"Created {len(self.executors)} tool executors")

    async def start(self) -> None:
        """Start all tool executor workers."""
        if self._initialized:
            logger.warning("ToolManager already initialized")
            return

        logger.info("Starting tool executors...")
        for tool_name, executor in self.executors.items():
            try:
                await executor.start()
                logger.info(f"Started {tool_name} executor")
            except Exception as e:
                logger.error(f"Failed to start {tool_name} executor: {e}")

        self._initialized = True
        logger.info("All tool executors started")

    async def stop(self) -> None:
        """Stop all tool executor workers."""
        if not self._initialized:
            logger.warning("ToolManager not initialized")
            return

        logger.info("Stopping tool executors...")
        for tool_name, executor in self.executors.items():
            try:
                await executor.stop()
                logger.info(f"Stopped {tool_name} executor")
            except Exception as e:
                logger.error(f"Error stopping {tool_name} executor: {e}")

        self._initialized = False
        logger.info("All tool executors stopped")

    async def execute_tool(
        self,
        tool_name: str,
        query: str,
        request_id: Optional[str] = None,
        **kwargs,
    ) -> str:
        """
        Queue a tool execution request.

        Args:
            tool_name: Name of tool (sherlock, sublist3r, amass, holehe, phoneinfoga)
            query: Query/target for the tool
            request_id: Optional custom request ID
            **kwargs: Tool-specific parameters

        Returns:
            Request ID for tracking

        Raises:
            ValueError: If tool not found
            RuntimeError: If executor not running
        """
        if tool_name not in self.executors:
            raise ValueError(f"Unknown tool: {tool_name}")

        executor = self.executors[tool_name]

        try:
            request = await executor.enqueue_request(query, request_id, **kwargs)
            return request.request_id
        except Exception as e:
            logger.error(f"Failed to execute {tool_name}: {e}")
            raise

    def get_request_status(self, tool_name: str, request_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a tool execution request.

        Args:
            tool_name: Tool name
            request_id: Request ID

        Returns:
            Request details or None if not found
        """
        if tool_name not in self.executors:
            return None

        request = self.executors[tool_name].get_request_status(request_id)
        if not request:
            return None

        return {
            "request_id": request.request_id,
            "tool_name": request.tool_name,
            "query": request.query,
            "status": request.status.value,
            "result": request.result.model_dump() if request.result else None,
            "error": request.error,
            "created_at": request.created_at.isoformat(),
            "started_at": request.started_at.isoformat() if request.started_at else None,
            "completed_at": request.completed_at.isoformat() if request.completed_at else None,
            "execution_time_seconds": request.execution_time_seconds,
        }

    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all tool executors."""
        stats = {
            "initialized": self._initialized,
            "tools": {},
        }

        for tool_name, executor in self.executors.items():
            stats["tools"][tool_name] = executor.get_stats()

        return stats

    def get_tool_stats(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific tool."""
        if tool_name not in self.executors:
            return None

        return self.executors[tool_name].get_stats()


# Global instance
_tool_manager: Optional[ToolManager] = None


def get_tool_manager() -> ToolManager:
    """Get or create global tool manager instance."""
    global _tool_manager
    if _tool_manager is None:
        _tool_manager = ToolManager()
    return _tool_manager
