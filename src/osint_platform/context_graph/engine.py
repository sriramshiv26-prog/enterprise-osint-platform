"""
Context Graph Engine.

Manages entity relationships, pattern detection, and graph analysis.
"""
import logging
import uuid
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from collections import defaultdict, deque

from src.osint_platform.context_graph.models import (
    Entity, Relationship, EntityType, RelationType, RiskLevel,
    EntityPath, Cluster, Pattern, InvestigationSnapshot,
)

logger = logging.getLogger(__name__)


class ContextGraph:
    """In-memory context graph for entity relationships."""

    def __init__(self):
        """Initialize graph."""
        self.entities: Dict[str, Entity] = {}
        self.relationships: Dict[str, Relationship] = {}
        # Adjacency lists for fast lookup
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)

    def add_entity(self, entity: Entity) -> None:
        """Add entity to graph."""
        self.entities[entity.id] = entity
        logger.debug(f"Added entity: {entity.id} ({entity.type})")

    def add_relationship(self, relationship: Relationship) -> None:
        """Add relationship to graph."""
        # Verify entities exist
        if relationship.source_id not in self.entities:
            raise ValueError(f"Source entity not found: {relationship.source_id}")
        if relationship.target_id not in self.entities:
            raise ValueError(f"Target entity not found: {relationship.target_id}")

        self.relationships[relationship.id] = relationship
        self.adjacency[relationship.source_id].add(relationship.target_id)
        self.reverse_adjacency[relationship.target_id].add(relationship.source_id)
        logger.debug(f"Added relationship: {relationship.source_id} → {relationship.target_id}")

    def get_neighbors(self, entity_id: str) -> List[Entity]:
        """Get all entities directly connected to this entity."""
        neighbor_ids = self.adjacency.get(entity_id, set())
        return [self.entities[nid] for nid in neighbor_ids if nid in self.entities]

    def get_predecessors(self, entity_id: str) -> List[Entity]:
        """Get all entities that point to this entity."""
        pred_ids = self.reverse_adjacency.get(entity_id, set())
        return [self.entities[pid] for pid in pred_ids if pid in self.entities]

    def find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> Optional[EntityPath]:
        """
        Find shortest path between two entities using BFS.

        Returns path with all intermediate relationships.
        """
        if source_id not in self.entities or target_id not in self.entities:
            return None

        if source_id == target_id:
            return EntityPath(source_id=source_id, target_id=target_id, path=[source_id], relationships=[], distance=0)

        # BFS
        queue = deque([(source_id, [source_id], [])])
        visited = {source_id}

        while queue:
            current, path, rels = queue.popleft()

            if len(path) > max_depth + 1:
                continue

            for neighbor_id in self.adjacency.get(current, set()):
                if neighbor_id == target_id:
                    # Found target
                    rel = self._get_relationship(current, neighbor_id)
                    if rel:
                        rels.append(rel)
                    return EntityPath(
                        source_id=source_id,
                        target_id=target_id,
                        path=path + [neighbor_id],
                        relationships=rels,
                        distance=len(path),
                    )

                if neighbor_id not in visited and len(path) < max_depth:
                    visited.add(neighbor_id)
                    rel = self._get_relationship(current, neighbor_id)
                    new_rels = rels.copy()
                    if rel:
                        new_rels.append(rel)
                    queue.append((neighbor_id, path + [neighbor_id], new_rels))

        return None

    def _get_relationship(self, source_id: str, target_id: str) -> Optional[Relationship]:
        """Get relationship from source to target."""
        for rel in self.relationships.values():
            if rel.source_id == source_id and rel.target_id == target_id:
                return rel
        return None

    def find_clusters(self) -> List[Cluster]:
        """
        Find connected components (clusters) in the graph.

        Each cluster represents related entities (possible campaign).
        """
        visited = set()
        clusters = []

        for entity_id in self.entities.keys():
            if entity_id in visited:
                continue

            # DFS to find cluster
            cluster_entities = set()
            cluster_relationships = set()
            stack = [entity_id]

            while stack:
                current = stack.pop()
                if current in visited:
                    continue

                visited.add(current)
                cluster_entities.add(current)

                # Add neighbors (both forward and backward)
                for neighbor_id in self.adjacency.get(current, set()):
                    if neighbor_id not in visited:
                        stack.append(neighbor_id)

                for pred_id in self.reverse_adjacency.get(current, set()):
                    if pred_id not in visited:
                        stack.append(pred_id)

            # Find relationships within cluster
            for rel_id, rel in self.relationships.items():
                if rel.source_id in cluster_entities and rel.target_id in cluster_entities:
                    cluster_relationships.add(rel_id)

            # Calculate risk level
            entity_risks = [self.entities[eid].risk_level for eid in cluster_entities]
            max_risk = max(entity_risks, default=RiskLevel.INFO)

            cluster = Cluster(
                id=str(uuid.uuid4()),
                entities=list(cluster_entities),
                relationships=list(cluster_relationships),
                size=len(cluster_entities),
                risk_level=max_risk,
            )
            clusters.append(cluster)

        return clusters

    def detect_patterns(self) -> List[Pattern]:
        """Detect common patterns in the graph."""
        patterns = []

        # Pattern 1: Shared Infrastructure (multiple domains on same IP)
        ip_to_domains = defaultdict(list)
        for entity in self.entities.values():
            if entity.type == EntityType.DOMAIN:
                for rel in self.relationships.values():
                    if rel.target_id == entity.id and rel.type == RelationType.RESOLVES_TO:
                        ip = self.entities.get(rel.source_id)
                        if ip and ip.type == EntityType.IP:
                            ip_to_domains[ip.id].append(entity.id)

        for ip_id, domain_ids in ip_to_domains.items():
            if len(domain_ids) > 2:  # Threshold
                patterns.append(Pattern(
                    id=str(uuid.uuid4()),
                    pattern_type="shared_infrastructure",
                    entities=[ip_id] + domain_ids,
                    confidence=min(1.0, len(domain_ids) / 10),
                    indicators={"ip": ip_id, "domains": domain_ids},
                    description=f"Multiple domains ({len(domain_ids)}) resolving to same IP",
                ))

        # Pattern 2: High Connectivity (hub nodes)
        for entity_id, neighbors in self.adjacency.items():
            if len(neighbors) > 5:  # Threshold
                patterns.append(Pattern(
                    id=str(uuid.uuid4()),
                    pattern_type="hub_entity",
                    entities=[entity_id],
                    confidence=min(1.0, len(neighbors) / 20),
                    indicators={"entity": entity_id, "connections": len(neighbors)},
                    description=f"High connectivity entity with {len(neighbors)} outbound connections",
                ))

        return patterns

    def get_stats(self) -> Dict[str, any]:
        """Get graph statistics."""
        total_connections = sum(len(neighbors) for neighbors in self.adjacency.values())
        avg_degree = total_connections / len(self.entities) if self.entities else 0
        density = total_connections / (len(self.entities) * (len(self.entities) - 1)) if len(self.entities) > 1 else 0

        entity_types = defaultdict(int)
        risk_levels = defaultdict(int)
        for entity in self.entities.values():
            entity_types[entity.type] += 1
            risk_levels[entity.risk_level] += 1

        return {
            "entity_count": len(self.entities),
            "relationship_count": len(self.relationships),
            "entity_types": dict(entity_types),
            "risk_distribution": dict(risk_levels),
            "average_degree": avg_degree,
            "density": density,
        }


class ContextGraphEngine:
    """Main context graph engine."""

    def __init__(self):
        """Initialize engine."""
        self.graphs: Dict[str, ContextGraph] = {}
        self.snapshots: Dict[str, List[InvestigationSnapshot]] = defaultdict(list)

    def create_graph(self, graph_id: str) -> ContextGraph:
        """Create a new context graph."""
        graph = ContextGraph()
        self.graphs[graph_id] = graph
        logger.info(f"Created context graph: {graph_id}")
        return graph

    def get_graph(self, graph_id: str) -> Optional[ContextGraph]:
        """Get a context graph."""
        return self.graphs.get(graph_id)

    def add_entity(self, graph_id: str, entity: Entity) -> None:
        """Add entity to graph."""
        graph = self.get_graph(graph_id)
        if not graph:
            graph = self.create_graph(graph_id)
        graph.add_entity(entity)

    def add_relationship(self, graph_id: str, relationship: Relationship) -> None:
        """Add relationship to graph."""
        graph = self.get_graph(graph_id)
        if not graph:
            raise ValueError(f"Graph not found: {graph_id}")
        graph.add_relationship(relationship)

    def create_snapshot(self, graph_id: str, investigation_id: str) -> InvestigationSnapshot:
        """Create snapshot of graph state."""
        graph = self.get_graph(graph_id)
        if not graph:
            raise ValueError(f"Graph not found: {graph_id}")

        stats = graph.get_stats()
        clusters = graph.find_clusters()

        snapshot = InvestigationSnapshot(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            entity_count=stats["entity_count"],
            relationship_count=stats["relationship_count"],
            cluster_count=len(clusters),
            pattern_count=len(graph.detect_patterns()),
            risk_distribution=stats["risk_distribution"],
            graph_density=stats["density"],
            avg_node_degree=stats["average_degree"],
        )

        self.snapshots[graph_id].append(snapshot)
        return snapshot


# Global engine instance
_engine: Optional[ContextGraphEngine] = None


def get_context_graph_engine() -> ContextGraphEngine:
    """Get or create global context graph engine."""
    global _engine
    if _engine is None:
        _engine = ContextGraphEngine()
    return _engine
