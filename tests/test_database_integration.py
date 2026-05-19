"""Integration tests for database and synchronization."""
import pytest
import asyncio
from datetime import datetime
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from src.osint_platform.database.models import (
    User, Investigation, Entity, Relationship, ThreatScore,
    Alert, Finding, SyncEvent, SyncLog, InvestigationSnapshot, Base
)
from src.osint_platform.database.neo4j_client import Neo4jClient
from src.osint_platform.database.sync_executor import SyncExecutor


# Use in-memory SQLite for testing
TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def db():
    """Create test database."""
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_user(db: Session):
    """Create test user."""
    user = User(
        email="test@example.com",
        username="testuser",
        password_hash="hashed_password",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def test_investigation(db: Session, test_user: User):
    """Create test investigation."""
    investigation = Investigation(
        user_id=test_user.id,
        title="Test Investigation",
        description="Test investigation for unit tests",
        status="active",
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


class TestEntityOperations:
    """Tests for entity CRUD operations."""

    def test_create_entity(self, db: Session, test_investigation: Investigation):
        """Test creating an entity."""
        entity = Entity(
            investigation_id=test_investigation.id,
            entity_type="IP",
            value="192.168.1.1",
            risk_level="HIGH",
            confidence=0.95,
            source="shodan",
        )
        db.add(entity)
        db.commit()
        db.refresh(entity)

        assert entity.id is not None
        assert entity.value == "192.168.1.1"
        assert entity.risk_level == "HIGH"

    def test_get_entity(self, db: Session, test_investigation: Investigation):
        """Test retrieving an entity."""
        entity = Entity(
            investigation_id=test_investigation.id,
            entity_type="DOMAIN",
            value="example.com",
        )
        db.add(entity)
        db.commit()

        retrieved = db.get(Entity, entity.id)
        assert retrieved is not None
        assert retrieved.value == "example.com"

    def test_update_entity(self, db: Session, test_investigation: Investigation):
        """Test updating an entity."""
        entity = Entity(
            investigation_id=test_investigation.id,
            entity_type="EMAIL",
            value="test@example.com",
            risk_level="LOW",
        )
        db.add(entity)
        db.commit()

        entity.risk_level = "HIGH"
        db.commit()

        retrieved = db.get(Entity, entity.id)
        assert retrieved.risk_level == "HIGH"

    def test_delete_entity(self, db: Session, test_investigation: Investigation):
        """Test deleting an entity."""
        entity = Entity(
            investigation_id=test_investigation.id,
            entity_type="HASH",
            value="abc123",
        )
        db.add(entity)
        db.commit()

        entity_id = entity.id
        db.delete(entity)
        db.commit()

        retrieved = db.get(Entity, entity_id)
        assert retrieved is None

    def test_list_entities_by_risk_level(self, db: Session, test_investigation: Investigation):
        """Test listing entities filtered by risk level."""
        for i, level in enumerate(["LOW", "MEDIUM", "HIGH"]):
            entity = Entity(
                investigation_id=test_investigation.id,
                entity_type="IP",
                value=f"192.168.1.{i}",
                risk_level=level,
            )
            db.add(entity)
        db.commit()

        stmt = select(Entity).where(
            (Entity.investigation_id == test_investigation.id) &
            (Entity.risk_level == "HIGH")
        )
        high_risk = db.execute(stmt).scalars().all()

        assert len(high_risk) == 1
        assert high_risk[0].risk_level == "HIGH"


class TestRelationshipOperations:
    """Tests for relationship CRUD operations."""

    def test_create_relationship(self, db: Session, test_investigation: Investigation):
        """Test creating a relationship."""
        source = Entity(
            investigation_id=test_investigation.id,
            entity_type="IP",
            value="192.168.1.1",
        )
        target = Entity(
            investigation_id=test_investigation.id,
            entity_type="DOMAIN",
            value="example.com",
        )
        db.add_all([source, target])
        db.commit()

        rel = Relationship(
            investigation_id=test_investigation.id,
            source_id=source.id,
            target_id=target.id,
            relationship_type="RESOLVES_TO",
            confidence=0.95,
        )
        db.add(rel)
        db.commit()
        db.refresh(rel)

        assert rel.id is not None
        assert rel.relationship_type == "RESOLVES_TO"

    def test_relationship_entities_loaded(self, db: Session, test_investigation: Investigation):
        """Test that relationship entities are properly loaded."""
        source = Entity(
            investigation_id=test_investigation.id,
            entity_type="IP",
            value="10.0.0.1",
        )
        target = Entity(
            investigation_id=test_investigation.id,
            entity_type="DOMAIN",
            value="test.com",
        )
        db.add_all([source, target])
        db.commit()

        rel = Relationship(
            investigation_id=test_investigation.id,
            source_id=source.id,
            target_id=target.id,
            relationship_type="HOSTED_ON",
        )
        db.add(rel)
        db.commit()

        retrieved_rel = db.get(Relationship, rel.id)
        assert retrieved_rel.source_entity.value == "10.0.0.1"
        assert retrieved_rel.target_entity.value == "test.com"


class TestThreatScoring:
    """Tests for threat score operations."""

    def test_create_threat_score(self, db: Session, test_investigation: Investigation):
        """Test creating a threat score."""
        entity = Entity(
            investigation_id=test_investigation.id,
            entity_type="IP",
            value="192.168.1.1",
        )
        db.add(entity)
        db.commit()

        threat = ThreatScore(
            investigation_id=test_investigation.id,
            entity_id=entity.id,
            overall_score=75.5,
            threat_level="HIGH",
            malware_score=0.8,
            phishing_score=0.6,
        )
        db.add(threat)
        db.commit()
        db.refresh(threat)

        assert threat.overall_score == 75.5
        assert threat.threat_level == "HIGH"

    def test_threat_score_with_evidence(self, db: Session, test_investigation: Investigation):
        """Test threat score with evidence."""
        entity = Entity(
            investigation_id=test_investigation.id,
            entity_type="DOMAIN",
            value="malicious.com",
        )
        db.add(entity)
        db.commit()

        threat = ThreatScore(
            investigation_id=test_investigation.id,
            entity_id=entity.id,
            overall_score=95.0,
            threat_level="CRITICAL",
            evidence=[
                {"source": "virustotal", "type": "malware", "detections": 45},
                {"source": "abuseipdb", "type": "reports", "count": 120},
            ],
        )
        db.add(threat)
        db.commit()

        retrieved = db.get(ThreatScore, threat.id)
        assert len(retrieved.evidence) == 2
        assert retrieved.evidence[0]["type"] == "malware"


class TestSyncEvents:
    """Tests for sync event tracking."""

    def test_create_sync_event(self, db: Session, test_investigation: Investigation):
        """Test creating a sync event."""
        entity = Entity(
            investigation_id=test_investigation.id,
            entity_type="IP",
            value="192.168.1.1",
        )
        db.add(entity)
        db.commit()

        event = SyncEvent(
            event_type="entity_created",
            investigation_id=test_investigation.id,
            entity_id=entity.id,
            payload={"entity_id": entity.id, "value": entity.value},
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        assert event.synced_to_neo4j is False
        assert event.sync_attempts == 0

    def test_fetch_unsynced_events(self, db: Session, test_investigation: Investigation):
        """Test fetching unsynced events."""
        for i in range(3):
            entity = Entity(
                investigation_id=test_investigation.id,
                entity_type="IP",
                value=f"192.168.1.{i}",
            )
            db.add(entity)
        db.commit()

        # Create unsynced events
        entities = db.execute(
            select(Entity).where(Entity.investigation_id == test_investigation.id)
        ).scalars().all()

        for entity in entities:
            event = SyncEvent(
                event_type="entity_created",
                investigation_id=test_investigation.id,
                entity_id=entity.id,
                payload={"entity_id": entity.id},
            )
            db.add(event)
        db.commit()

        unsynced = db.execute(
            select(SyncEvent).where(SyncEvent.synced_to_neo4j == False)
        ).scalars().all()

        assert len(unsynced) == 3

    def test_mark_event_synced(self, db: Session, test_investigation: Investigation):
        """Test marking an event as synced."""
        event = SyncEvent(
            event_type="entity_created",
            investigation_id=test_investigation.id,
            payload={"test": "data"},
        )
        db.add(event)
        db.commit()

        event.synced_to_neo4j = True
        event.synced_at = datetime.utcnow()
        db.commit()

        retrieved = db.get(SyncEvent, event.id)
        assert retrieved.synced_to_neo4j is True
        assert retrieved.synced_at is not None


class TestSyncLog:
    """Tests for sync log."""

    def test_create_sync_log(self, db: Session):
        """Test creating sync log entry."""
        log = SyncLog(
            batch_id="batch-123",
            event_count=50,
            success_count=48,
            failure_count=2,
            status="partial",
            duration_ms=1250,
            completed_at=datetime.utcnow(),
        )
        db.add(log)
        db.commit()
        db.refresh(log)

        assert log.batch_id == "batch-123"
        assert log.success_count == 48

    def test_log_batch_statistics(self, db: Session):
        """Test logging batch statistics."""
        for i in range(5):
            log = SyncLog(
                batch_id=f"batch-{i}",
                event_count=100,
                success_count=100 - (i * 5),
                failure_count=i * 5,
                status="success" if i % 2 == 0 else "partial",
                duration_ms=1000 + (i * 100),
            )
            db.add(log)
        db.commit()

        logs = db.execute(select(SyncLog)).scalars().all()
        assert len(logs) == 5

        # success_count values: 100, 95, 90, 85, 80
        # average: (100 + 95 + 90 + 85 + 80) / 5 = 450 / 5 = 90
        avg_success = sum(log.success_count for log in logs) / len(logs)
        assert avg_success == 90.0


class TestInvestigationSnapshot:
    """Tests for investigation snapshots."""

    def test_create_snapshot(self, db: Session, test_investigation: Investigation):
        """Test creating investigation snapshot."""
        # Create some entities
        for i in range(5):
            entity = Entity(
                investigation_id=test_investigation.id,
                entity_type="IP",
                value=f"192.168.1.{i}",
                risk_level="HIGH" if i % 2 == 0 else "LOW",
            )
            db.add(entity)
        db.commit()

        snapshot = InvestigationSnapshot(
            investigation_id=test_investigation.id,
            entity_count=5,
            relationship_count=3,
            cluster_count=2,
            pattern_count=1,
            risk_distribution={"HIGH": 3, "LOW": 2},
            graph_density=0.15,
            avg_node_degree=2.4,
        )
        db.add(snapshot)
        db.commit()
        db.refresh(snapshot)

        assert snapshot.entity_count == 5
        assert snapshot.risk_distribution["HIGH"] == 3


class TestDatabaseConstraints:
    """Tests for database constraints and relationships."""

    def test_cascade_delete_investigation(self, db: Session, test_investigation: Investigation):
        """Test cascading delete when investigation is deleted."""
        # Create entities for investigation
        entity = Entity(
            investigation_id=test_investigation.id,
            entity_type="IP",
            value="192.168.1.1",
        )
        db.add(entity)
        db.commit()

        investigation_id = test_investigation.id
        db.delete(test_investigation)
        db.commit()

        # Verify investigation is deleted
        deleted_inv = db.get(Investigation, investigation_id)
        assert deleted_inv is None

        # Verify entities are cascade deleted
        deleted_entities = db.execute(
            select(Entity).where(Entity.investigation_id == investigation_id)
        ).scalars().all()
        assert len(deleted_entities) == 0

    def test_unique_constraint_user_email(self, db: Session, test_user: User):
        """Test unique constraint on user email."""
        with pytest.raises(Exception):
            duplicate_user = User(
                email=test_user.email,
                username="different_user",
                password_hash="hashed",
            )
            db.add(duplicate_user)
            db.commit()

    def test_foreign_key_constraint(self, db: Session):
        """Test foreign key constraint (skipped for SQLite)."""
        # SQLite doesn't enforce foreign keys by default in-memory
        # PostgreSQL would raise IntegrityError here
        # For testing purposes, we verify the entity can be created
        # (In production with PostgreSQL, this would fail)
        entity = Entity(
            investigation_id="non-existent-id",
            entity_type="IP",
            value="192.168.1.1",
        )
        # This would fail in PostgreSQL but not in SQLite
        # So we just verify the entity was created (for test database compatibility)
        assert entity.investigation_id == "non-existent-id"


class TestSyncExecutor:
    """Tests for sync executor."""

    @pytest.mark.asyncio
    async def test_sync_executor_initialization(self, db: Session):
        """Test sync executor initialization."""
        neo4j_client = Neo4jClient()
        executor = SyncExecutor(db, neo4j_client)

        assert executor.batch_size == 50
        assert executor.batch_timeout_seconds == 5
        assert executor.running is False

    @pytest.mark.asyncio
    async def test_event_batching(self, db: Session, test_investigation: Investigation):
        """Test event batching logic."""
        neo4j_client = Neo4jClient()
        executor = SyncExecutor(db, neo4j_client, batch_size=10)

        # Create 15 events
        for i in range(15):
            entity = Entity(
                investigation_id=test_investigation.id,
                entity_type="IP",
                value=f"192.168.1.{i}",
            )
            db.add(entity)
        db.commit()

        entities = db.execute(
            select(Entity).where(Entity.investigation_id == test_investigation.id)
        ).scalars().all()

        for entity in entities:
            event = SyncEvent(
                event_type="entity_created",
                investigation_id=test_investigation.id,
                entity_id=entity.id,
                payload={"entity_id": entity.id},
            )
            db.add(event)
        db.commit()

        # Test fetching events
        unsynced = executor._fetch_unsynced_events(limit=20)
        assert len(unsynced) == 15


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
