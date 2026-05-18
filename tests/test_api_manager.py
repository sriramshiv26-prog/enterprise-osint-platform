"""
Tests for API Manager and related components.

Tests routing, caching, result correlation, and orchestration.
"""
import pytest
from datetime import datetime, timedelta
from src.osint_platform.api_integrations.manager import (
    APICache,
    APIRouter,
    ResultCorrelator,
    APIManager,
)
from src.osint_platform.api_integrations.models import StandardResult


class TestAPICache:
    """Tests for APICache."""

    def test_cache_set_and_get(self):
        """Test setting and retrieving cached results."""
        cache = APICache(ttl_minutes=60)
        result = StandardResult(
            source="test_api",
            query="example.com",
            success=True,
            data=[{"domain": "example.com"}],
        )

        cache.set("test_api", "example.com", result)
        retrieved = cache.get("test_api", "example.com")

        assert retrieved is not None
        assert retrieved.source == "test_api"
        assert retrieved.query == "example.com"

    def test_cache_miss(self):
        """Test cache miss on non-existent key."""
        cache = APICache(ttl_minutes=60)
        result = cache.get("test_api", "nonexistent.com")
        assert result is None

    def test_cache_expiration(self):
        """Test cache expiration after TTL."""
        cache = APICache(ttl_minutes=0)
        result = StandardResult(
            source="test_api",
            query="example.com",
            success=True,
            data=[{"domain": "example.com"}],
        )

        cache.set("test_api", "example.com", result)
        # Manually advance time for testing
        cache.cache[cache._cache_key("test_api", "example.com")] = (
            result,
            datetime.utcnow() - timedelta(minutes=1),
        )

        retrieved = cache.get("test_api", "example.com")
        assert retrieved is None

    def test_cache_clear(self):
        """Test clearing cache."""
        cache = APICache(ttl_minutes=60)
        result = StandardResult(
            source="test_api",
            query="example.com",
            success=True,
            data=[{"domain": "example.com"}],
        )

        cache.set("test_api", "example.com", result)
        assert len(cache.cache) == 1

        cache.clear()
        assert len(cache.cache) == 0


class TestAPIRouter:
    """Tests for APIRouter."""

    def test_detect_ip_address(self):
        """Test IP address detection."""
        assert APIRouter.detect_query_type("192.168.1.1") == "ip"
        assert APIRouter.detect_query_type("1.1.1.1") == "ip"

    def test_detect_email(self):
        """Test email detection."""
        assert APIRouter.detect_query_type("test@example.com") == "email"
        assert APIRouter.detect_query_type("user@domain.org") == "email"

    def test_detect_url(self):
        """Test URL detection."""
        assert APIRouter.detect_query_type("http://example.com") == "url"
        assert APIRouter.detect_query_type("https://example.com/path") == "url"
        assert APIRouter.detect_query_type("www.example.com") == "url"

    def test_detect_hash(self):
        """Test hash detection (MD5, SHA1, SHA256)."""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        assert APIRouter.detect_query_type(md5_hash) == "hash"

        sha1_hash = "356a192b7913b04c54574d18c28d46e6395428ab"
        assert APIRouter.detect_query_type(sha1_hash) == "hash"

        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert APIRouter.detect_query_type(sha256_hash) == "hash"

    def test_detect_domain(self):
        """Test domain detection (default)."""
        assert APIRouter.detect_query_type("example.com") == "domain"
        assert APIRouter.detect_query_type("subdomain.example.org") == "domain"

    def test_get_optimal_apis_for_ip(self):
        """Test optimal APIs for IP queries."""
        apis = APIRouter.get_optimal_apis("192.168.1.1")
        assert "abuseipdb" in apis
        assert "shodan" in apis
        assert "virustotal" in apis

    def test_get_optimal_apis_for_domain(self):
        """Test optimal APIs for domain queries."""
        apis = APIRouter.get_optimal_apis("example.com")
        assert "securitytrails" in apis
        assert "whois" in apis
        assert "virustotal" in apis

    def test_get_optimal_apis_for_email(self):
        """Test optimal APIs for email queries."""
        apis = APIRouter.get_optimal_apis("test@example.com")
        assert "haveibeenpwned" in apis

    def test_get_optimal_apis_for_url(self):
        """Test optimal APIs for URL queries."""
        apis = APIRouter.get_optimal_apis("http://example.com")
        assert "urlscan" in apis
        assert "virustotal" in apis

    def test_get_optimal_apis_for_hash(self):
        """Test optimal APIs for hash queries."""
        hash_val = "5d41402abc4b2a76b9719d911017c592"
        apis = APIRouter.get_optimal_apis(hash_val)
        assert "virustotal" in apis


class TestResultCorrelator:
    """Tests for ResultCorrelator."""

    def test_deduplicate_single_result(self):
        """Test deduplication with single result."""
        result = StandardResult(
            source="test_api",
            query="example.com",
            success=True,
            data=[{"domain": "example.com", "ip": "1.1.1.1"}],
        )

        deduplicated = ResultCorrelator.deduplicate([result])
        assert len(deduplicated) == 1
        assert deduplicated[0]["domain"] == "example.com"
        assert deduplicated[0]["sources"] == ["test_api"]

    def test_deduplicate_duplicate_results(self):
        """Test deduplication with duplicate data from multiple sources."""
        result1 = StandardResult(
            source="api1",
            query="example.com",
            success=True,
            data=[{"domain": "example.com", "ip": "1.1.1.1"}],
        )

        result2 = StandardResult(
            source="api2",
            query="example.com",
            success=True,
            data=[{"domain": "example.com", "ip": "1.1.1.1"}],
        )

        deduplicated = ResultCorrelator.deduplicate([result1, result2])
        assert len(deduplicated) == 1
        assert "api1" in deduplicated[0]["sources"]
        assert "api2" in deduplicated[0]["sources"]

    def test_deduplicate_unique_results(self):
        """Test deduplication with unique results."""
        result1 = StandardResult(
            source="api1",
            query="example.com",
            success=True,
            data=[{"domain": "example.com", "ip": "1.1.1.1"}],
        )

        result2 = StandardResult(
            source="api2",
            query="example.com",
            success=True,
            data=[{"domain": "example.com", "ip": "2.2.2.2"}],
        )

        deduplicated = ResultCorrelator.deduplicate([result1, result2])
        assert len(deduplicated) == 2

    def test_deduplicate_failed_results(self):
        """Test deduplication ignores failed results."""
        result1 = StandardResult(
            source="api1",
            query="example.com",
            success=False,
            error="API Error",
        )

        result2 = StandardResult(
            source="api2",
            query="example.com",
            success=True,
            data=[{"domain": "example.com"}],
        )

        deduplicated = ResultCorrelator.deduplicate([result1, result2])
        assert len(deduplicated) == 1
        assert deduplicated[0]["sources"] == ["api2"]

    def test_correlate_results(self):
        """Test correlation of results."""
        results = [
            StandardResult(
                source="api1",
                query="example.com",
                success=True,
                data=[{"domain": "example.com"}],
            ),
            StandardResult(
                source="api2",
                query="example.com",
                success=True,
                data=[{"domain": "example.com"}],
            ),
        ]

        correlation = ResultCorrelator.correlate(results)
        assert correlation["total_sources"] == 2
        assert correlation["total_results"] == 2
        assert "api1" in correlation["sources"]
        assert "api2" in correlation["sources"]
        assert len(correlation["deduplicated"]) >= 1


class TestAPIManager:
    """Tests for APIManager."""

    def test_api_manager_initialization(self):
        """Test API manager initialization."""
        manager = APIManager()
        assert not manager._initialized
        assert len(manager.apis) == 0
        assert manager.cache is not None
        assert manager.router is not None
        assert manager.correlator is not None

    def test_get_api_manager_singleton(self):
        """Test API manager singleton pattern."""
        from src.osint_platform.api_integrations.manager import get_api_manager

        manager1 = get_api_manager()
        manager2 = get_api_manager()
        assert manager1 is manager2

    def test_get_stats(self):
        """Test getting manager statistics."""
        manager = APIManager()
        stats = manager.get_stats()

        assert "initialized" in stats
        assert "apis_registered" in stats
        assert "cache_size" in stats
        assert "executions" in stats
        assert "avg_execution_time" in stats
        assert stats["initialized"] is False
        assert stats["apis_registered"] == 0

    @pytest.mark.asyncio
    async def test_api_manager_lifecycle(self):
        """Test API manager initialization and cleanup."""
        manager = APIManager()
        api_keys = {
            "shodan": "",
            "virustotal": "",
            "securitytrails": "",
            "haveibeenpwned": "",
            "abuseipdb": "",
            "urlscan": "",
            "whois": "",
            "twitter": "",
        }

        await manager.initialize(api_keys)
        assert manager._initialized
        assert len(manager.apis) == 8

        await manager.close()


class TestAPIManagerIntegration:
    """Integration tests for API Manager with mocked APIs."""

    @pytest.mark.asyncio
    async def test_query_with_cache(self):
        """Test query execution with caching."""
        from unittest.mock import AsyncMock, MagicMock

        manager = APIManager()

        # Mock an API
        mock_api = AsyncMock()
        mock_api.search = AsyncMock(
            return_value=StandardResult(
                source="mock_api",
                query="192.168.1.1",
                success=True,
                data=[{"ip": "192.168.1.1", "country": "US"}],
            )
        )

        manager.apis["mock_api"] = mock_api
        manager._initialized = True

        # First query (should call API)
        result1 = await manager.query("192.168.1.1", apis=["mock_api"], use_cache=True)
        assert result1["query"] == "192.168.1.1"
        assert mock_api.search.call_count == 1

        # Second query (should use cache)
        result2 = await manager.query("192.168.1.1", apis=["mock_api"], use_cache=True)
        assert result2["query"] == "192.168.1.1"
        assert mock_api.search.call_count == 1  # No additional call

    @pytest.mark.asyncio
    async def test_query_without_cache(self):
        """Test query execution bypassing cache."""
        from unittest.mock import AsyncMock

        manager = APIManager()

        mock_api = AsyncMock()
        mock_api.search = AsyncMock(
            return_value=StandardResult(
                source="mock_api",
                query="example.com",
                success=True,
                data=[{"domain": "example.com"}],
            )
        )

        manager.apis["mock_api"] = mock_api
        manager._initialized = True

        # First query
        await manager.query("example.com", apis=["mock_api"], use_cache=True)
        assert mock_api.search.call_count == 1

        # Second query without cache
        await manager.query("example.com", apis=["mock_api"], use_cache=False)
        assert mock_api.search.call_count == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
