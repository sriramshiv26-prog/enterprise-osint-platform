"""
Hermes Agent Service Layer.

Manages agent lifecycle, investigation history, and async execution.
Provides a clean interface for the API layer to interact with the agent.
"""
import logging
import asyncio
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from uuid import uuid4

from src.osint_platform.agent.crew import create_hermes_crew, HermesCrew

logger = logging.getLogger(__name__)


class AgentService:
    """Service for managing Hermes Agent investigations.

    Provides sync and async interfaces, tracks investigation history,
    and manages agent instances.
    """

    def __init__(self):
        self._crew: Optional[HermesCrew] = None
        self._investigations: Dict[str, Dict[str, Any]] = {}
        self._active_investigations: Dict[str, asyncio.Task] = {}

    @property
    def crew(self) -> HermesCrew:
        """Get or create the Hermes crew instance."""
        if self._crew is None:
            self._crew = create_hermes_crew()
        return self._crew

    async def investigate(
        self,
        target: str,
        target_type: str = "auto",
        context: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run a synchronous investigation (blocks until complete).

        Args:
            target: Indicator to investigate (IP, domain, email, etc.).
            target_type: Type hint for the target.
            context: Additional context from the user.
            investigation_id: Optional ID for tracking. Auto-generated if not provided.

        Returns:
            Investigation result with report.
        """
        inv_id = investigation_id or str(uuid4())

        # Run in executor to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self.crew.investigate(
                target=target,
                target_type=target_type,
                context=context,
                verbose=False,
            ),
        )

        result["investigation_id"] = inv_id
        result["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Store in history
        self._investigations[inv_id] = result

        return result

    def investigate_sync(
        self,
        target: str,
        target_type: str = "auto",
        context: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run a synchronous investigation (blocks current thread).

        Args:
            target: Indicator to investigate.
            target_type: Type hint for the target.
            context: Additional context.
            investigation_id: Optional ID for tracking.

        Returns:
            Investigation result with report.
        """
        inv_id = investigation_id or str(uuid4())

        result = self.crew.investigate(
            target=target,
            target_type=target_type,
            context=context,
            verbose=True,
        )

        result["investigation_id"] = inv_id
        result["timestamp"] = datetime.now(timezone.utc).isoformat()

        self._investigations[inv_id] = result

        return result

    async def investigate_async(
        self,
        target: str,
        target_type: str = "auto",
        context: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> str:
        """Start an async investigation and return immediately with an ID.

        The investigation runs in the background. Use get_result() to poll.

        Args:
            target: Indicator to investigate.
            target_type: Type hint for the target.
            context: Additional context.
            investigation_id: Optional ID for tracking.

        Returns:
            Investigation ID to poll for results.
        """
        inv_id = investigation_id or str(uuid4())

        # Store initial pending state
        self._investigations[inv_id] = {
            "investigation_id": inv_id,
            "target": target,
            "target_type": target_type,
            "status": "pending",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Create background task
        task = asyncio.create_task(
            self._run_investigation_async(inv_id, target, target_type, context)
        )
        self._active_investigations[inv_id] = task

        return inv_id

    async def _run_investigation_async(
        self,
        inv_id: str,
        target: str,
        target_type: str,
        context: Optional[str],
    ):
        """Background task for async investigation."""
        try:
            result = await self.investigate(
                target=target,
                target_type=target_type,
                context=context,
                investigation_id=inv_id,
            )
            result["status"] = "completed"
            self._investigations[inv_id] = result
        except Exception as e:
            logger.error(f"Async investigation {inv_id} failed: {e}")
            self._investigations[inv_id] = {
                "investigation_id": inv_id,
                "target": target,
                "target_type": target_type,
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        finally:
            self._active_investigations.pop(inv_id, None)

    def get_result(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Get the result of an investigation by ID.

        Args:
            investigation_id: The investigation ID.

        Returns:
            Investigation result dict, or None if not found.
        """
        result = self._investigations.get(investigation_id)
        if result:
            # Check if still running
            if investigation_id in self._active_investigations:
                result["status"] = "running"
            return result
        return None

    def get_history(
        self,
        limit: int = 10,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get investigation history.

        Args:
            limit: Max results to return.
            offset: Pagination offset.
            status: Filter by status (completed, failed, running, pending).

        Returns:
            List of investigation results.
        """
        results = list(self._investigations.values())

        if status:
            results = [r for r in results if r.get("status") == status]

        # Sort by timestamp descending
        results.sort(key=lambda r: r.get("timestamp", ""), reverse=True)

        return results[offset:offset + limit]

    def cancel_investigation(self, investigation_id: str) -> bool:
        """Cancel a running investigation.

        Args:
            investigation_id: The investigation ID.

        Returns:
            True if cancelled, False if not found or already complete.
        """
        task = self._active_investigations.get(investigation_id)
        if task and not task.done():
            task.cancel()
            self._investigations[investigation_id]["status"] = "cancelled"
            return True
        return False

    @property
    def active_count(self) -> int:
        """Number of currently running investigations."""
        return len([t for t in self._active_investigations.values() if not t.done()])


# Singleton
_agent_service: Optional[AgentService] = None


def get_agent_service() -> AgentService:
    """Get or create the singleton AgentService."""
    global _agent_service
    if _agent_service is None:
        _agent_service = AgentService()
    return _agent_service
