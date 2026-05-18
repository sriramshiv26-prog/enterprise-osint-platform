"""
Central API Manager - orchestrates all OSINT API integrations.

Handles:
- Request routing to optimal APIs
- Rate limit coordination
- Result correlation & deduplication
- Caching layer
- Error handling & fallbacks
- Execution tracking
"""
import logging
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio

from src.osint_platform.api_integrations.models import StandardResult, APIMetadata
from src.osint_platform.api_integrations.apis.threat_intel.shodan import ShodanAPI
from src.osint_platform.api_integrations.apis.threat_intel.virustotal import VirusTotalAPI
from src.osint_platform.api_integrations.apis.threat_intel.securitytrails import SecurityTrailsAPI
from src.osint_platform.api_integrations.apis.email_breach.haveibeenpwned import HaveIBeenPwnedAPI
from src.osint_platform.api_integrations.apis.ip_geolocation.abuseipdb import AbuseIPDBI
from src.osint_platform.api_integrations.apis.web_scanning.urlscan import URLScanAPI
from src.osint_platform.api_integrations.apis.domain_intel.whois import WhoisAPI
from src.osint_platform.api_integrations.apis.social_media.twitter import TwitterAPIv2

logger = logging.getLogger(__name__)


class APICache:
    """Simple in-memory cache for API results."""

    def __init__(self, ttl_minutes: int = 60):
        self.cache: Dict[str, tuple] = {}
        self.ttl = timedelta(minutes=ttl_minutes)

    def _cache_key(self, api_name: str, query: str) -> str:
        """Generate cache key."""
        key_str = f"{api_name}:{query}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, api_name: str, query: str) -> Optional[StandardResult]:
        """Get cached result if exists and not expired."""
        key = self._cache_key(api_name, query)
        if key in self.cache:
            result, timestamp = self.cache[key]
            if datetime.utcnow() - timestamp < self.ttl:
                logger.debug(f"Cache hit for {api_name}:{query}")
                return result
            else:
                del self.cache[key]
        return None

    def set(self, api_name: str, query: str, result: StandardResult) -> None:
        """Cache a result."""
        key = self._cache_key(api_name, query)
        self.cache[key] = (result, datetime.utcnow())
        logger.debug(f"Cached result for {api_name}:{query}")

    def clear(self) -> None:
        """Clear cache."""
        self.cache.clear()


class APIRouter:
    """Routes queries to optimal APIs based on query type."""

    # Map query types to best APIs
    ROUTING_MAP = {
        "ip": ["abuseipdb", "shodan", "virustotal"],
        "domain": ["securitytrails", "whois", "virustotal"],
        "email": ["haveibeenpwned"],
        "username": [],  # Not in Phase 3 APIs
        "url": ["urlscan", "virustotal"],
        "hash": ["virustotal"],
    }

    @staticmethod
    def detect_query_type(query: str) -> str:
        """Detect query type (ip, domain, email, etc.)."""
        import re

        # IP address
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", query):
            return "ip"

        # Email
        if "@" in query and "." in query:
            return "email"

        # URL
        if query.startswith(("http://", "https://", "www.")):
            return "url"

        # MD5/SHA hash
        if len(query) in [32, 40, 64]:
            if all(c in "0123456789abcdefABCDEF" for c in query):
                return "hash"

        # Default to domain
        return "domain"

    @staticmethod
    def get_optimal_apis(query: str) -> List[str]:
        """Get list of APIs to query in priority order."""
        query_type = APIRouter.detect_query_type(query)
        return APIRouter.ROUTING_MAP.get(query_type, ["shodan", "virustotal"])


class ResultCorrelator:
    """Correlates and deduplicates results from multiple APIs."""

    @staticmethod
    def deduplicate(results: List[StandardResult]) -> List[Dict[str, Any]]:
        """Merge and deduplicate results from multiple APIs."""
        seen = set()
        deduplicated = []

        for result in results:
            if result.success:
                for item in result.data:
                    # Simple dedup based on common fields
                    key_parts = [
                        str(item.get("ip")),
                        str(item.get("domain")),
                        str(item.get("subdomain")),
                        str(item.get("email")),
                        str(item.get("url")),
                    ]
                    key = "|".join([p for p in key_parts if p != "None"])

                    if key and key not in seen:
                        seen.add(key)
                        item["sources"] = [result.source]
                        deduplicated.append(item)
                    elif key in seen:
                        # Add source to existing item
                        for existing in deduplicated:
                            if any(
                                existing.get(k) == item.get(k)
                                for k in ["ip", "domain", "email", "url"]
                                if item.get(k)
                            ):
                                existing["sources"].append(result.source)
                                break

        return deduplicated

    @staticmethod
    def correlate(results: List[StandardResult]) -> Dict[str, Any]:
        """Correlate results across APIs."""
        correlation = {
            "total_sources": len([r for r in results if r.success]),
            "total_results": sum(r.result_count for r in results),
            "sources": [r.source for r in results if r.success],
            "deduplicated": ResultCorrelator.deduplicate(results),
        }
        return correlation


class APIManager:
    """Central orchestration manager for all OSINT APIs."""

    def __init__(self):
        """Initialize API manager."""
        self.apis: Dict[str, Any] = {}
        self.cache = APICache(ttl_minutes=60)
        self.router = APIRouter()
        self.correlator = ResultCorrelator()
        self.execution_log: List[Dict] = []
        self.rate_limit_state: Dict[str, Dict] = defaultdict(dict)
        self._initialized = False

    async def initialize(self, api_keys: Dict[str, str]) -> None:
        """Initialize all registered APIs with credentials."""
        logger.info("Initializing API Manager...")

        # Register and initialize APIs
        self.apis["shodan"] = ShodanAPI(api_keys.get("shodan", ""))
        self.apis["virustotal"] = VirusTotalAPI(api_keys.get("virustotal", ""))
        self.apis["securitytrails"] = SecurityTrailsAPI(api_keys.get("securitytrails", ""))
        self.apis["haveibeenpwned"] = HaveIBeenPwnedAPI(api_keys.get("haveibeenpwned", ""))
        self.apis["abuseipdb"] = AbuseIPDBI(api_keys.get("abuseipdb", ""))
        self.apis["urlscan"] = URLScanAPI(api_keys.get("urlscan", ""))
        self.apis["whois"] = WhoisAPI(api_keys.get("whois", ""))
        self.apis["twitter"] = TwitterAPIv2(api_keys.get("twitter", ""))

        # Initialize each API
        for name, api in self.apis.items():
            try:
                await api.initialize()
                logger.info(f"Initialized {name}")
            except Exception as e:
                logger.warning(f"Failed to initialize {name}: {e}")

        self._initialized = True
        logger.info(f"API Manager initialized with {len(self.apis)} APIs")

    async def query(
        self,
        query: str,
        apis: Optional[List[str]] = None,
        use_cache: bool = True,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Execute query across optimal APIs.

        Args:
            query: Search query
            apis: Specific APIs to use (optional, auto-detect if None)
            use_cache: Use cached results
            **kwargs: Additional parameters

        Returns:
            Correlated results from multiple APIs
        """
        if not self._initialized:
            raise RuntimeError("API Manager not initialized")

        logger.info(f"Querying: {query}")
        start_time = datetime.utcnow()

        # Determine which APIs to query
        target_apis = apis or self.router.get_optimal_apis(query)
        logger.debug(f"Target APIs: {target_apis}")

        # Execute queries
        results = []
        tasks = []

        for api_name in target_apis:
            if api_name not in self.apis:
                logger.warning(f"Unknown API: {api_name}")
                continue

            # Check cache first
            if use_cache:
                cached = self.cache.get(api_name, query)
                if cached:
                    results.append(cached)
                    continue

            # Queue API query
            api = self.apis[api_name]
            tasks.append(self._execute_api(api_name, api, query, **kwargs))

        # Execute all queries concurrently
        if tasks:
            new_results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in new_results:
                if isinstance(result, StandardResult):
                    results.append(result)
                    if result.success:
                        self.cache.set(api_name, query, result)
                elif isinstance(result, Exception):
                    logger.error(f"API query failed: {result}")

        execution_time = (datetime.utcnow() - start_time).total_seconds()

        # Correlate results
        correlation = self.correlator.correlate(results)

        # Log execution
        self._log_execution(query, target_apis, results, execution_time)

        return {
            "query": query,
            "execution_time_seconds": execution_time,
            "correlation": correlation,
            "raw_results": [r.to_dict() for r in results],
        }

    async def _execute_api(
        self,
        api_name: str,
        api,
        query: str,
        **kwargs,
    ) -> StandardResult:
        """Execute a single API query with error handling."""
        try:
            logger.debug(f"Executing {api_name} for {query}")
            result = await api.search(query, **kwargs)
            logger.debug(f"{api_name} returned {result.result_count} results")
            return result
        except Exception as e:
            logger.error(f"{api_name} error: {e}")
            return StandardResult(
                source=api_name,
                query=query,
                success=False,
                error=str(e),
            )

    def _log_execution(
        self,
        query: str,
        apis: List[str],
        results: List[StandardResult],
        execution_time: float,
    ) -> None:
        """Log query execution for monitoring."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "query": query,
            "apis_queried": apis,
            "apis_succeeded": [r.source for r in results if r.success],
            "total_results": sum(r.result_count for r in results),
            "execution_time_seconds": execution_time,
        }
        self.execution_log.append(log_entry)

    def get_stats(self) -> Dict[str, Any]:
        """Get manager statistics."""
        return {
            "initialized": self._initialized,
            "apis_registered": len(self.apis),
            "cache_size": len(self.cache.cache),
            "executions": len(self.execution_log),
            "avg_execution_time": (
                sum(e["execution_time_seconds"] for e in self.execution_log)
                / len(self.execution_log)
                if self.execution_log
                else 0
            ),
        }

    async def close(self) -> None:
        """Close all API connections."""
        for api in self.apis.values():
            await api.close()
        logger.info("API Manager closed")


# Global instance
_api_manager: Optional[APIManager] = None


def get_api_manager() -> APIManager:
    """Get or create global API manager instance."""
    global _api_manager
    if _api_manager is None:
        _api_manager = APIManager()
    return _api_manager
