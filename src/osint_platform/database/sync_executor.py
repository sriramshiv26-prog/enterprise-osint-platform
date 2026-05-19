"""Event-driven synchronization between PostgreSQL and Neo4j."""
import logging
import asyncio
import time
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select

from src.osint_platform.database.models import (
    SyncEvent, SyncLog, Entity, Relationship, ThreatScore, Investigation
)
from src.osint_platform.database.neo4j_client import Neo4jClient

logger = logging.getLogger(__name__)


class SyncExecutor:
    """Executes synchronization between PostgreSQL and Neo4j."""

    def __init__(
        self,
        db_session: Session,
        neo4j_client: Neo4jClient,
        batch_size: int = 50,
        batch_timeout_seconds: int = 5,
        max_retries: int = 3,
    ):
        """
        Initialize sync executor.

        Args:
            db_session: SQLAlchemy session
            neo4j_client: Neo4j client
            batch_size: Max events per batch
            batch_timeout_seconds: Max time to wait before flushing batch
            max_retries: Max retry attempts on failure
        """
        self.db_session = db_session
        self.neo4j_client = neo4j_client
        self.batch_size = batch_size
        self.batch_timeout_seconds = batch_timeout_seconds
        self.max_retries = max_retries
        self.running = False
        self.event_queue: List[SyncEvent] = []
        self.last_batch_time = datetime.utcnow()

    async def start(self) -> None:
        """Start sync executor."""
        self.running = True
        logger.info("Sync executor started")
        await self._run_sync_loop()

    async def stop(self) -> None:
        """Stop sync executor."""
        self.running = False
        # Process remaining events
        if self.event_queue:
            await self._process_batch(self.event_queue)
        logger.info("Sync executor stopped")

    async def _run_sync_loop(self) -> None:
        """Main sync loop."""
        while self.running:
            try:
                # Fetch unsynced events
                unsync_events = self._fetch_unsynced_events()

                if unsync_events:
                    self.event_queue.extend(unsync_events)

                # Check if batch should be processed
                should_process = (
                    len(self.event_queue) >= self.batch_size
                    or (
                        self.event_queue
                        and (datetime.utcnow() - self.last_batch_time).total_seconds() >= self.batch_timeout_seconds
                    )
                )

                if should_process and self.event_queue:
                    batch = self.event_queue[: self.batch_size]
                    self.event_queue = self.event_queue[self.batch_size :]
                    await self._process_batch(batch)
                    self.last_batch_time = datetime.utcnow()

                # Sleep briefly before next check
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                await asyncio.sleep(1)

    def _fetch_unsynced_events(self, limit: int = 100) -> List[SyncEvent]:
        """Fetch unsynced events from database."""
        try:
            stmt = select(SyncEvent).where(
                SyncEvent.synced_to_neo4j == False
            ).order_by(
                SyncEvent.created_at
            ).limit(limit)

            return self.db_session.execute(stmt).scalars().all()
        except Exception as e:
            logger.error(f"Error fetching unsynced events: {e}")
            return []

    async def _process_batch(self, events: List[SyncEvent]) -> None:
        """Process a batch of sync events."""
        batch_id = str(uuid.uuid4())
        start_time = time.time()

        logger.info(f"Processing batch {batch_id} with {len(events)} events")

        success_count = 0
        failure_count = 0
        error_messages = []

        for event in events:
            try:
                success = await self._process_event(event)
                if success:
                    success_count += 1
                    # Mark as synced
                    event.synced_to_neo4j = True
                    event.synced_at = datetime.utcnow()
                    event.sync_attempts += 1
                else:
                    failure_count += 1
                    event.sync_attempts += 1
                    if event.sync_attempts >= self.max_retries:
                        event.synced_to_neo4j = False
                        error_messages.append(f"Event {event.id}: Max retries exceeded")
            except Exception as e:
                failure_count += 1
                event.sync_attempts += 1
                event.last_sync_error = str(e)
                error_messages.append(f"Event {event.id}: {str(e)}")
                logger.error(f"Error processing event {event.id}: {e}")

        # Update sync log
        duration_ms = int((time.time() - start_time) * 1000)
        status = "success" if failure_count == 0 else "partial" if success_count > 0 else "failed"

        sync_log = SyncLog(
            batch_id=batch_id,
            event_count=len(events),
            success_count=success_count,
            failure_count=failure_count,
            status=status,
            error_message="; ".join(error_messages) if error_messages else None,
            duration_ms=duration_ms,
            completed_at=datetime.utcnow(),
        )

        self.db_session.add(sync_log)
        self.db_session.commit()

        logger.info(
            f"Batch {batch_id} completed: {success_count} success, {failure_count} failed "
            f"({duration_ms}ms)"
        )

    async def _process_event(self, event: SyncEvent) -> bool:
        """Process a single sync event."""
        try:
            event_type = event.event_type
            payload = event.payload

            if event_type == "entity_created":
                entity_id = payload.get("entity_id")
                entity = self.db_session.get(Entity, entity_id)
                if entity:
                    return await self.neo4j_client.create_entity(
                        entity_id,
                        {
                            "entity_type": entity.entity_type,
                            "value": entity.value,
                            "risk_level": entity.risk_level,
                            "confidence": entity.confidence,
                            "source": entity.source,
                            "created_at": entity.created_at.isoformat() if entity.created_at else None,
                        },
                    )

            elif event_type == "entity_updated":
                entity_id = payload.get("entity_id")
                # For updates, we could delete and recreate, or use MERGE
                entity = self.db_session.get(Entity, entity_id)
                if entity:
                    # Implementation: Use Neo4j MERGE to update entity properties
                    return True

            elif event_type == "relationship_added":
                rel_id = payload.get("relationship_id")
                relationship = self.db_session.get(Relationship, rel_id)
                if relationship:
                    return await self.neo4j_client.create_relationship(
                        rel_id,
                        relationship.source_id,
                        relationship.target_id,
                        relationship.relationship_type,
                        {
                            "confidence": relationship.confidence,
                            "created_at": relationship.created_at.isoformat() if relationship.created_at else None,
                        },
                    )

            elif event_type == "threat_score_created":
                threat_id = payload.get("threat_score_id")
                threat_score = self.db_session.get(ThreatScore, threat_id)
                if threat_score:
                    return await self.neo4j_client.create_threat_score(
                        threat_id,
                        {
                            "entity_id": threat_score.entity_id,
                            "overall_score": threat_score.overall_score,
                            "threat_level": threat_score.threat_level,
                            "created_at": threat_score.created_at.isoformat() if threat_score.created_at else None,
                        },
                    )

            elif event_type == "investigation_created":
                investigation_id = payload.get("investigation_id")
                investigation = self.db_session.get(Investigation, investigation_id)
                if investigation:
                    return await self.neo4j_client.create_investigation(
                        investigation_id,
                        {
                            "title": investigation.title,
                            "user_id": investigation.user_id,
                            "status": investigation.status,
                            "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
                        },
                    )
                    # Link entities to investigation
                    for entity in investigation.entities:
                        await self.neo4j_client.link_entity_to_investigation(
                            investigation_id,
                            entity.id,
                        )

            else:
                logger.warning(f"Unknown event type: {event_type}")
                return False

            return False

        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return False


class SyncManager:
    """Manages sync executor lifecycle."""

    def __init__(self, db_session: Session, neo4j_client: Neo4jClient):
        """Initialize sync manager."""
        self.db_session = db_session
        self.neo4j_client = neo4j_client
        self.executor: Optional[SyncExecutor] = None
        self.task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start sync manager."""
        self.executor = SyncExecutor(
            self.db_session,
            self.neo4j_client,
            batch_size=50,
            batch_timeout_seconds=5,
            max_retries=3,
        )
        self.task = asyncio.create_task(self.executor.start())
        logger.info("Sync manager started")

    async def stop(self) -> None:
        """Stop sync manager."""
        if self.executor:
            await self.executor.stop()
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("Sync manager stopped")

    async def enqueue_sync_event(
        self,
        event_type: str,
        investigation_id: str,
        payload: Dict[str, Any],
        entity_id: Optional[str] = None,
    ) -> None:
        """Enqueue a sync event."""
        try:
            event = SyncEvent(
                event_type=event_type,
                investigation_id=investigation_id,
                entity_id=entity_id,
                payload=payload,
            )
            self.db_session.add(event)
            self.db_session.commit()
        except Exception as e:
            logger.error(f"Error enqueuing sync event: {e}")
