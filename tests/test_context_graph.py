"""
Tests for Context Graph Engine.

Tests entity management, relationships, clustering, and pattern detection.
"""
import pytest
from src.osint_platform.context_graph.models import (
    Entity, Relationship, EntityType, RelationType, RiskLevel,
)
from src.osint_platform.context_graph.engine import (
    ContextGraph, ContextGraphEngine, get_context_graph_engine,
)


class TestContextGraph:
    """Tests for context graph."""

    def test_add_entity(self):
        """Test adding entity to graph."""
        graph = ContextGraph()
        entity = Entity(
            id="test:ip:1.1.1.1",
            type=EntityType.IP,
            value="1.1.1.1",
        )

        graph.add_entity(entity)
        assert "test:ip:1.1.1.1" in graph.entities

    def test_add_relationship(self):
        """Test adding relationship."""
        graph = ContextGraph()

        # Add entities first
        ip = Entity(id="ip:1", type=EntityType.IP, value="1.1.1.1")
        domain = Entity(id="domain:1", type=EntityType.DOMAIN, value="example.com")
        graph.add_entity(ip)
        graph.add_entity(domain)

        # Add relationship
        rel = Relationship(
            id="rel:1",
            source_id="domain:1",
            target_id="ip:1",
            type=RelationType.RESOLVES_TO,
        )
        graph.add_relationship(rel)

        assert "rel:1" in graph.relationships

    def test_get_neighbors(self):
        """Test getting neighbors of entity."""
        graph = ContextGraph()

        ip = Entity(id="ip:1", type=EntityType.IP, value="1.1.1.1")
        domain = Entity(id="domain:1", type=EntityType.DOMAIN, value="example.com")
        graph.add_entity(ip)
        graph.add_entity(domain)

        rel = Relationship(
            id="rel:1",
            source_id="domain:1",
            target_id="ip:1",
            type=RelationType.RESOLVES_TO,
        )
        graph.add_relationship(rel)

        neighbors = graph.get_neighbors("domain:1")
        assert len(neighbors) == 1
        assert neighbors[0].id == "ip:1"

    def test_find_path_direct(self):
        """Test finding direct path between entities."""
        graph = ContextGraph()

        e1 = Entity(id="e1", type=EntityType.IP, value="1.1.1.1")
        e2 = Entity(id="e2", type=EntityType.DOMAIN, value="example.com")
        graph.add_entity(e1)
        graph.add_entity(e2)

        rel = Relationship(
            id="rel",
            source_id="e1",
            target_id="e2",
            type=RelationType.RESOLVES_TO,
        )
        graph.add_relationship(rel)

        path = graph.find_path("e1", "e2")
        assert path is not None
        assert path.distance == 1
        assert path.path == ["e1", "e2"]

    def test_find_path_indirect(self):
        """Test finding indirect path."""
        graph = ContextGraph()

        e1 = Entity(id="e1", type=EntityType.IP, value="1.1.1.1")
        e2 = Entity(id="e2", type=EntityType.DOMAIN, value="example.com")
        e3 = Entity(id="e3", type=EntityType.EMAIL, value="admin@example.com")
        graph.add_entity(e1)
        graph.add_entity(e2)
        graph.add_entity(e3)

        rel1 = Relationship(id="r1", source_id="e1", target_id="e2", type=RelationType.RESOLVES_TO)
        rel2 = Relationship(id="r2", source_id="e2", target_id="e3", type=RelationType.USED_BY)
        graph.add_relationship(rel1)
        graph.add_relationship(rel2)

        path = graph.find_path("e1", "e3")
        assert path is not None
        assert path.distance == 2
        assert path.path == ["e1", "e2", "e3"]

    def test_find_clusters(self):
        """Test cluster detection."""
        graph = ContextGraph()

        # Cluster 1: IP, Domain, Email
        ip1 = Entity(id="ip1", type=EntityType.IP, value="1.1.1.1")
        domain1 = Entity(id="domain1", type=EntityType.DOMAIN, value="example.com")
        graph.add_entity(ip1)
        graph.add_entity(domain1)
        rel = Relationship(id="r1", source_id="domain1", target_id="ip1", type=RelationType.RESOLVES_TO)
        graph.add_relationship(rel)

        # Isolated entity (separate cluster)
        ip2 = Entity(id="ip2", type=EntityType.IP, value="2.2.2.2")
        graph.add_entity(ip2)

        clusters = graph.find_clusters()
        assert len(clusters) == 2

    def test_detect_shared_infrastructure(self):
        """Test detection of multiple domains on same IP."""
        graph = ContextGraph()

        ip = Entity(id="ip1", type=EntityType.IP, value="1.1.1.1", risk_level=RiskLevel.HIGH)
        d1 = Entity(id="d1", type=EntityType.DOMAIN, value="example1.com")
        d2 = Entity(id="d2", type=EntityType.DOMAIN, value="example2.com")
        d3 = Entity(id="d3", type=EntityType.DOMAIN, value="example3.com")

        graph.add_entity(ip)
        graph.add_entity(d1)
        graph.add_entity(d2)
        graph.add_entity(d3)

        graph.add_relationship(Relationship(id="r1", source_id="d1", target_id="ip1", type=RelationType.RESOLVES_TO))
        graph.add_relationship(Relationship(id="r2", source_id="d2", target_id="ip1", type=RelationType.RESOLVES_TO))
        graph.add_relationship(Relationship(id="r3", source_id="d3", target_id="ip1", type=RelationType.RESOLVES_TO))

        patterns = graph.detect_patterns()
        assert any(p.pattern_type == "shared_infrastructure" for p in patterns)

    def test_detect_hub_nodes(self):
        """Test detection of high-connectivity nodes."""
        graph = ContextGraph()

        hub = Entity(id="hub", type=EntityType.IP, value="1.1.1.1")
        graph.add_entity(hub)

        # Add 10 connected nodes
        for i in range(10):
            node = Entity(id=f"node{i}", type=EntityType.DOMAIN, value=f"example{i}.com")
            graph.add_entity(node)
            rel = Relationship(
                id=f"r{i}",
                source_id="hub",
                target_id=f"node{i}",
                type=RelationType.SHARES_INFRASTRUCTURE,
            )
            graph.add_relationship(rel)

        patterns = graph.detect_patterns()
        assert any(p.pattern_type == "hub_entity" for p in patterns)

    def test_get_stats(self):
        """Test graph statistics."""
        graph = ContextGraph()

        e1 = Entity(id="e1", type=EntityType.IP, value="1.1.1.1")
        e2 = Entity(id="e2", type=EntityType.DOMAIN, value="example.com")
        graph.add_entity(e1)
        graph.add_entity(e2)

        rel = Relationship(id="r1", source_id="e1", target_id="e2", type=RelationType.RESOLVES_TO)
        graph.add_relationship(rel)

        stats = graph.get_stats()
        assert stats["entity_count"] == 2
        assert stats["relationship_count"] == 1
        assert "entity_types" in stats
        assert "risk_distribution" in stats


class TestContextGraphEngine:
    """Tests for context graph engine."""

    def test_create_graph(self):
        """Test creating graph."""
        engine = ContextGraphEngine()
        graph = engine.create_graph("test_graph")
        assert engine.get_graph("test_graph") == graph

    def test_add_entity(self):
        """Test adding entity via engine."""
        engine = ContextGraphEngine()
        entity = Entity(
            id="e1",
            type=EntityType.IP,
            value="1.1.1.1",
        )
        engine.add_entity("test", entity)

        graph = engine.get_graph("test")
        assert "e1" in graph.entities

    def test_create_snapshot(self):
        """Test creating graph snapshot."""
        engine = ContextGraphEngine()
        graph = engine.create_graph("test")

        e1 = Entity(id="e1", type=EntityType.IP, value="1.1.1.1")
        graph.add_entity(e1)

        snapshot = engine.create_snapshot("test", "inv1")
        assert snapshot.investigation_id == "inv1"
        assert snapshot.entity_count == 1


class TestGlobalEngine:
    """Test global engine singleton."""

    def test_singleton(self):
        """Test that get_context_graph_engine returns same instance."""
        engine1 = get_context_graph_engine()
        engine2 = get_context_graph_engine()
        assert engine1 is engine2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
