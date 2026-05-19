"""Neo4j graph database client."""
import logging
from typing import Dict, List, Optional, Any
from neo4j import GraphDatabase, Session, Result

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Neo4j database client for threat graph operations."""

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        username: str = "neo4j",
        password: str = "password",
    ):
        """
        Initialize Neo4j client.

        Args:
            uri: Neo4j connection URI
            username: Neo4j username
            password: Neo4j password
        """
        self.uri = uri
        self.username = username
        self.password = password
        self.driver = None
        self.is_connected = False

    async def connect(self) -> bool:
        """
        Connect to Neo4j database.

        Returns:
            True if connection successful
        """
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                connection_timeout=5,
            )
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            self.is_connected = True
            logger.info("Connected to Neo4j successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self.is_connected = False
            return False

    async def close(self) -> None:
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            self.is_connected = False
            logger.info("Closed Neo4j connection")

    def _execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> Optional[Result]:
        """Execute Cypher query."""
        if not self.is_connected or not self.driver:
            logger.error("Neo4j client not connected")
            return None

        try:
            with self.driver.session() as session:
                return session.run(query, parameters or {})
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            return None

    async def initialize_schema(self) -> bool:
        """Initialize Neo4j schema with constraints and indexes."""
        try:
            constraints = [
                "CREATE CONSTRAINT entity_id IF NOT EXISTS ON (e:Entity) ASSERT e.id IS UNIQUE",
                "CREATE CONSTRAINT investigation_id IF NOT EXISTS ON (i:Investigation) ASSERT i.id IS UNIQUE",
                "CREATE CONSTRAINT finding_id IF NOT EXISTS ON (f:Finding) ASSERT f.id IS UNIQUE",
                "CREATE CONSTRAINT threat_score_id IF NOT EXISTS ON (t:ThreatScore) ASSERT t.id IS UNIQUE",
                "CREATE CONSTRAINT alert_id IF NOT EXISTS ON (a:Alert) ASSERT a.id IS UNIQUE",
            ]

            indexes = [
                "CREATE INDEX entity_type IF NOT EXISTS FOR (e:Entity) ON (e.entity_type)",
                "CREATE INDEX entity_value IF NOT EXISTS FOR (e:Entity) ON (e.value)",
                "CREATE INDEX entity_risk_level IF NOT EXISTS FOR (e:Entity) ON (e.risk_level)",
                "CREATE INDEX investigation_user_id IF NOT EXISTS FOR (i:Investigation) ON (i.user_id)",
                "CREATE INDEX investigation_status IF NOT EXISTS FOR (i:Investigation) ON (i.status)",
                "CREATE INDEX finding_type IF NOT EXISTS FOR (f:Finding) ON (f.finding_type)",
                "CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity)",
                "CREATE INDEX threat_level IF NOT EXISTS FOR (t:ThreatScore) ON (t.threat_level)",
                "CREATE INDEX alert_type IF NOT EXISTS FOR (a:Alert) ON (a.alert_type)",
                "CREATE INDEX alert_severity IF NOT EXISTS FOR (a:Alert) ON (a.severity)",
            ]

            for constraint in constraints:
                try:
                    self._execute_query(constraint)
                except Exception as e:
                    logger.warning(f"Constraint creation failed (may already exist): {e}")

            for index in indexes:
                try:
                    self._execute_query(index)
                except Exception as e:
                    logger.warning(f"Index creation failed (may already exist): {e}")

            logger.info("Neo4j schema initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Neo4j schema: {e}")
            return False

    async def create_entity(self, entity_id: str, entity_data: Dict[str, Any]) -> bool:
        """Create entity node in Neo4j."""
        query = """
        CREATE (e:Entity {
            id: $id,
            entity_type: $entity_type,
            value: $value,
            risk_level: $risk_level,
            confidence: $confidence,
            source: $source,
            created_at: $created_at
        })
        RETURN e
        """
        params = {
            "id": entity_id,
            "entity_type": entity_data.get("entity_type", "UNKNOWN"),
            "value": entity_data.get("value", ""),
            "risk_level": entity_data.get("risk_level", "INFO"),
            "confidence": entity_data.get("confidence", 0.0),
            "source": entity_data.get("source"),
            "created_at": entity_data.get("created_at"),
        }
        try:
            result = self._execute_query(query, params)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to create entity: {e}")
            return False

    async def create_relationship(
        self,
        relationship_id: str,
        source_id: str,
        target_id: str,
        relationship_type: str,
        relationship_data: Dict[str, Any],
    ) -> bool:
        """Create relationship between entities."""
        query = f"""
        MATCH (source:Entity {{id: $source_id}})
        MATCH (target:Entity {{id: $target_id}})
        CREATE (source)-[r:{relationship_type} {{
            id: $rel_id,
            confidence: $confidence,
            created_at: $created_at
        }}]->(target)
        RETURN r
        """
        params = {
            "source_id": source_id,
            "target_id": target_id,
            "rel_id": relationship_id,
            "confidence": relationship_data.get("confidence", 0.0),
            "created_at": relationship_data.get("created_at"),
        }
        try:
            result = self._execute_query(query, params)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to create relationship: {e}")
            return False

    async def create_investigation(self, investigation_id: str, investigation_data: Dict[str, Any]) -> bool:
        """Create investigation node."""
        query = """
        CREATE (i:Investigation {
            id: $id,
            title: $title,
            user_id: $user_id,
            status: $status,
            created_at: $created_at
        })
        RETURN i
        """
        params = {
            "id": investigation_id,
            "title": investigation_data.get("title", ""),
            "user_id": investigation_data.get("user_id", ""),
            "status": investigation_data.get("status", "active"),
            "created_at": investigation_data.get("created_at"),
        }
        try:
            result = self._execute_query(query, params)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to create investigation: {e}")
            return False

    async def link_entity_to_investigation(self, investigation_id: str, entity_id: str) -> bool:
        """Link entity to investigation."""
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        MATCH (e:Entity {id: $entity_id})
        MERGE (i)-[r:CONTAINS]->(e)
        RETURN r
        """
        params = {
            "investigation_id": investigation_id,
            "entity_id": entity_id,
        }
        try:
            result = self._execute_query(query, params)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to link entity to investigation: {e}")
            return False

    async def create_threat_score(self, threat_score_id: str, threat_data: Dict[str, Any]) -> bool:
        """Create threat score node."""
        query = """
        MATCH (e:Entity {id: $entity_id})
        CREATE (t:ThreatScore {
            id: $id,
            overall_score: $overall_score,
            threat_level: $threat_level,
            created_at: $created_at
        })-[r:SCORED]->(e)
        RETURN t
        """
        params = {
            "id": threat_score_id,
            "entity_id": threat_data.get("entity_id", ""),
            "overall_score": threat_data.get("overall_score", 0.0),
            "threat_level": threat_data.get("threat_level", "INFO"),
            "created_at": threat_data.get("created_at"),
        }
        try:
            result = self._execute_query(query, params)
            return result is not None
        except Exception as e:
            logger.error(f"Failed to create threat score: {e}")
            return False

    async def get_entity_neighbors(self, entity_id: str) -> List[Dict[str, Any]]:
        """Get all neighbors of an entity."""
        query = """
        MATCH (e:Entity {id: $entity_id})-[r]->(neighbor)
        RETURN neighbor, TYPE(r) as relationship_type, properties(r) as relationship_props
        LIMIT 50
        """
        try:
            result = self._execute_query(query, {"entity_id": entity_id})
            if result:
                return [
                    {
                        "entity": dict(record["neighbor"]),
                        "relationship_type": record["relationship_type"],
                        "relationship_props": record["relationship_props"],
                    }
                    for record in result
                ]
            return []
        except Exception as e:
            logger.error(f"Failed to get entity neighbors: {e}")
            return []

    async def find_paths(self, source_id: str, target_id: str, max_depth: int = 5) -> List[List[str]]:
        """Find paths between entities."""
        query = f"""
        MATCH p = (source:Entity {{id: $source_id}})-[*1..{max_depth}]->(target:Entity {{id: $target_id}})
        RETURN [node in nodes(p) | node.id] as path
        LIMIT 10
        """
        try:
            result = self._execute_query(query, {"source_id": source_id, "target_id": target_id})
            if result:
                return [record["path"] for record in result]
            return []
        except Exception as e:
            logger.error(f"Failed to find paths: {e}")
            return []

    async def get_investigation_stats(self, investigation_id: str) -> Dict[str, Any]:
        """Get statistics for investigation graph."""
        query = """
        MATCH (i:Investigation {id: $investigation_id})-[:CONTAINS]->(e:Entity)
        WITH i, COUNT(DISTINCT e) as entity_count
        MATCH (i)-[:CONTAINS]->(e1:Entity)-[r]->(e2:Entity)
        WITH i, entity_count, COUNT(DISTINCT r) as relationship_count
        RETURN {
            entity_count: entity_count,
            relationship_count: relationship_count
        } as stats
        """
        try:
            result = self._execute_query(query, {"investigation_id": investigation_id})
            if result:
                record = result.single()
                return record["stats"] if record else {}
            return {}
        except Exception as e:
            logger.error(f"Failed to get investigation stats: {e}")
            return {}


_neo4j_client: Optional[Neo4jClient] = None


async def get_neo4j_client() -> Neo4jClient:
    """Get or create Neo4j client."""
    global _neo4j_client
    if _neo4j_client is None:
        _neo4j_client = Neo4jClient()
        await _neo4j_client.connect()
    return _neo4j_client
