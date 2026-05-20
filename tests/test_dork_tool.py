"""
Unit tests for the Google Dork Engine module.

Tests cover:
  - Dork library: categories, risk levels, query resolution
  - DorkTool: search execution, error handling, result formatting
  - DorkExecutor: rate limiting, queue management
  - Integration: tool manager registration, agent tool availability
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Any, Dict, List

from src.osint_platform.tools.dork.dork_library import (
    get_all_dorks,
    get_dorks_by_category,
    get_dorks_by_risk,
    resolve_dork_query,
    DorkCategory,
    CATEGORY_DESCRIPTIONS,
    DORKS_BY_CATEGORY,
)
from src.osint_platform.tools.dork.dork_tool import DorkTool
from src.osint_platform.tools.executors.dork_executor import DorkExecutor
from src.osint_platform.tools.base import ToolResult


# ═══════════════════════════════════════════════════════════════════════════════
# Dork Library Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestDorkLibrary:
    """Test the dork template library."""

    def test_all_dorks_have_required_fields(self):
        """Every dork record must have name, description, query, category, risk_level."""
        for dork in get_all_dorks():
            assert "name" in dork
            assert "description" in dork
            assert "query" in dork
            assert "category" in dork
            assert "risk_level" in dork
            assert isinstance(dork["name"], str) and len(dork["name"]) > 0
            assert isinstance(dork["description"], str) and len(dork["description"]) > 0
            assert isinstance(dork["query"], str) and len(dork["query"]) > 0

    def test_all_risk_levels_valid(self):
        """Risk levels must be one of: CRITICAL, HIGH, MEDIUM, LOW."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for dork in get_all_dorks():
            assert dork["risk_level"] in valid, (
                f"Dork '{dork['name']}' has invalid risk_level: {dork['risk_level']}"
            )

    def test_all_categories_defined(self):
        """Every dork's category must be registered in CATEGORY_DESCRIPTIONS."""
        for dork in get_all_dorks():
            assert dork["category"] in CATEGORY_DESCRIPTIONS, (
                f"Dork '{dork['name']}' has unregistered category: {dork['category']}"
            )

    def test_all_categories_have_dorks(self):
        """Every category in the library must have at least one dork."""
        for category in DORKS_BY_CATEGORY:
            assert len(DORKS_BY_CATEGORY[category]) > 0, (
                f"Category '{category}' has no dorks"
            )

    def test_get_all_dorks_returns_all(self):
        """get_all_dorks should return all dorks across all categories."""
        expected_count = sum(len(dorks) for dorks in DORKS_BY_CATEGORY.values())
        assert len(get_all_dorks()) == expected_count

    def test_get_dorks_by_category(self):
        """get_dorks_by_category returns only dorks in that category."""
        admin_dorks = get_dorks_by_category(DorkCategory.ADMIN_PANELS)
        for dork in admin_dorks:
            assert dork["category"] == DorkCategory.ADMIN_PANELS
        assert len(admin_dorks) > 0

    def test_get_dorks_by_category_invalid(self):
        """get_dorks_by_category returns empty list for unknown category."""
        assert get_dorks_by_category("nonexistent_category") == []

    def test_get_dorks_by_risk_critical(self):
        """get_dorks_by_risk returns only CRITICAL dorks."""
        critical = get_dorks_by_risk("CRITICAL")
        for dork in critical:
            assert dork["risk_level"] == "CRITICAL"
        assert len(critical) > 0

    def test_get_dorks_by_risk_case_insensitive(self):
        """get_dorks_by_risk should handle lowercase input."""
        high = get_dorks_by_risk("high")
        for dork in high:
            assert dork["risk_level"] == "HIGH"
        assert len(high) > 0

    def test_resolve_dork_query(self):
        """resolve_dork_query replaces {target} with the given target."""
        dork = {
            "name": "Test Dork",
            "description": "Test",
            "query": "site:{target} ext:pdf",
            "category": "test",
            "risk_level": "LOW",
        }
        resolved = resolve_dork_query(dork, "example.com")
        assert resolved == "site:example.com ext:pdf"

    def test_resolve_dork_query_no_placeholder(self):
        """Dork queries without {target} should remain unchanged."""
        dork = {
            "name": "Camera Dork",
            "description": "Camera search",
            "query": 'intitle:"Live View" "Axis"',
            "category": "test",
            "risk_level": "LOW",
        }
        resolved = resolve_dork_query(dork, "anything")
        assert resolved == dork["query"]

    def test_dork_category_enum_values(self):
        """All DorkCategory enum values should be present in DORKS_BY_CATEGORY."""
        category_values = [v for v in dir(DorkCategory) if not v.startswith("_")]
        for cat in category_values:
            value = getattr(DorkCategory, cat)
            if isinstance(value, str):
                assert value in DORKS_BY_CATEGORY, f"Category {value} not in DORKS_BY_CATEGORY"


# ═══════════════════════════════════════════════════════════════════════════════
# DorkTool Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestDorkTool:
    """Test the DorkTool class."""

    @pytest.fixture
    def tool(self):
        return DorkTool(timeout=30, max_results=10)

    def test_initialization(self, tool):
        """Tool should initialize with correct defaults."""
        assert tool.name == "google_dork"
        assert tool.timeout == 30
        assert tool.max_results == 10
        assert tool.delay == 1.0
        assert tool._use_api is False

    def test_initialization_with_api(self):
        """Tool should set _use_api when credentials provided."""
        tool = DorkTool(api_key="test-key", search_engine_id="test-cx")
        assert tool._use_api is True

    def test_validate_query_valid(self, tool):
        """validate_query should return True for non-empty queries."""
        assert tool.validate_query("site:example.com ext:pdf") is True

    def test_validate_query_empty(self, tool):
        """validate_query should return False for empty queries."""
        assert tool.validate_query("") is False
        assert tool.validate_query("   ") is False

    @pytest.mark.asyncio
    async def test_search_httpx_fallback_success(self):
        """Test search with httpx fallback returning results."""
        tool = DorkTool(timeout=30, max_results=5)

        mock_response = MagicMock()
        mock_response.text = """
        <div class="g">
          <div>
            <h3><a href="/url?q=https://example.com/file.pdf&sa=U">Test PDF</a></h3>
            <div class="VwiC3b">A sample PDF document for testing</div>
          </div>
        </div>
        """

        with patch("src.osint_platform.tools.dork.dork_tool.DorkTool._check_googlesearch", return_value=False), \
             patch("httpx.AsyncClient") as mock_client:
            mock_ctx = AsyncMock()
            mock_ctx.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_ctx

            result = await tool.search("site:example.com ext:pdf")

        assert result.success is True
        assert result.tool_name == "google_dork"
        assert result.query == "site:example.com ext:pdf"
        assert len(result.data) > 0

    @pytest.mark.asyncio
    async def test_search_httpx_no_results(self):
        """Test search with no results found."""
        tool = DorkTool(timeout=30, max_results=5)

        mock_response = MagicMock()
        mock_response.text = "<html><body>No results found</body></html>"

        with patch("src.osint_platform.tools.dork.dork_tool.DorkTool._check_googlesearch", return_value=False), \
             patch("httpx.AsyncClient") as mock_client:
            mock_ctx = AsyncMock()
            mock_ctx.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_ctx

            result = await tool.search("site:example.com nonexistent234567")

        assert result.success is True
        assert len(result.data) == 0

    @pytest.mark.asyncio
    async def test_search_http_error(self):
        """Test search with HTTP error should return failed result."""
        tool = DorkTool(timeout=30, max_results=5)

        with patch("src.osint_platform.tools.dork.dork_tool.DorkTool._check_googlesearch", return_value=False), \
             patch("httpx.AsyncClient") as mock_client:
            mock_ctx = AsyncMock()
            mock_ctx.get.side_effect = Exception("HTTP 429: Too Many Requests")
            mock_client.return_value.__aenter__.return_value = mock_ctx

            result = await tool.search("site:example.com ext:pdf")

        assert result.success is False
        assert "429" in str(result.error) or "error" in str(result.error).lower()

    def test_search_validates_query(self, tool):
        """Empty query should not crash."""
        assert tool.validate_query("") is False

    @pytest.mark.asyncio
    async def test_run_dork_batch(self, tool):
        """Test batch dork execution against a target."""
        from src.osint_platform.tools.dork.dork_tool import run_dork_batch

        mock_result = ToolResult(
            tool_name="google_dork",
            query="site:example.com ext:pdf",
            success=True,
            data=[
                {"url": "https://example.com/file.pdf", "title": "File", "snippet": "Test file", "source": "google_dork_httpx"}
            ],
            execution_time_seconds=0.5,
        )

        with patch.object(tool, "search", AsyncMock(return_value=mock_result)):
            result = await run_dork_batch(tool, target="example.com", categories=[DorkCategory.ADMIN_PANELS])

        assert result["target"] == "example.com"
        assert result["total_results"] >= 0

    @pytest.mark.asyncio
    async def test_search_returns_toolresult_type(self, tool):
        """Search should always return a ToolResult instance."""
        with patch("src.osint_platform.tools.dork.dork_tool.DorkTool._check_googlesearch", return_value=False), \
             patch("httpx.AsyncClient") as mock_client:
            mock_ctx = AsyncMock()
            mock_response = MagicMock()
            mock_response.text = "<html></html>"
            mock_ctx.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_ctx

            result = await tool.search("site:example.com")
            assert isinstance(result, ToolResult)


# ═══════════════════════════════════════════════════════════════════════════════
# DorkExecutor Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestDorkExecutor:
    """Test the DorkExecutor class."""

    def test_initialization(self):
        """Executor should initialize with correct settings."""
        executor = DorkExecutor(max_results=25)
        assert executor.tool_name == "google_dork"
        assert executor.requests_per_second == 1.0
        assert executor.max_concurrent == 1
        assert executor.timeout_seconds == 120
        assert executor.tool.max_results == 25

    def test_default_initialization(self):
        """Executor should use defaults when no kwargs provided."""
        executor = DorkExecutor()
        assert executor.tool_name == "google_dork"
        assert executor.tool.max_results == 20

    @pytest.mark.asyncio
    async def test_execute_delegates_to_tool(self):
        """execute() should delegate to the underlying DorkTool.search()."""
        executor = DorkExecutor()
        mock_result = ToolResult(
            tool_name="google_dork",
            query="site:example.com ext:pdf",
            success=True,
            data=[{"url": "https://example.com/test.pdf", "title": "Test", "snippet": "Snippet", "source": "test"}],
            execution_time_seconds=0.3,
        )

        with patch.object(executor.tool, "search", AsyncMock(return_value=mock_result)) as mock_search:
            result = await executor.execute("site:example.com ext:pdf")

        assert result == mock_result
        mock_search.assert_called_once_with("site:example.com ext:pdf")

    @pytest.mark.asyncio
    async def test_execute_passes_kwargs_to_tool(self):
        """execute() should pass kwargs to the tool's search method."""
        executor = DorkExecutor()
        mock_result = ToolResult(
            tool_name="google_dork",
            query="test",
            success=True,
            data=[],
            execution_time_seconds=0.1,
        )

        with patch.object(executor.tool, "search", AsyncMock(return_value=mock_result)) as mock_search:
            await executor.execute("test", max_results=15)

        mock_search.assert_called_once_with("test", max_results=15)


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestDorkIntegration:
    """Test integration with the rest of the platform."""

    def test_tool_manager_registers_dork(self):
        """ToolManager should include the google_dork executor."""
        from src.osint_platform.tools.tool_manager import ToolManager

        manager = ToolManager()
        assert "google_dork" in manager.executors

    def test_tool_manager_dork_executor_type(self):
        """The google_dork executor should be a DorkExecutor instance."""
        from src.osint_platform.tools.tool_manager import ToolManager
        from src.osint_platform.tools.executors.dork_executor import DorkExecutor

        manager = ToolManager()
        assert isinstance(manager.executors["google_dork"], DorkExecutor)

    def test_agent_tools_include_google_dork(self):
        """The agent tool registry should include google_dork_search."""
        from src.osint_platform.agent.tools import AVAILABLE_TOOLS, TOOL_LIST

        assert "google_dork_search" in AVAILABLE_TOOLS

        # Check that it's in the tool list
        tool_names = [t.name if hasattr(t, "name") else str(t) for t in TOOL_LIST]
        assert any("google_dork" in name for name in tool_names)

    def test_agent_tool_descriptions(self):
        """Tool descriptions should mention dork usage."""
        from src.osint_platform.agent.tools import get_tool_descriptions

        desc = get_tool_descriptions()
        assert "google_dork_search" in desc
        assert "dork" in desc.lower()

    def test_executors_init_exports_dork(self):
        """executors.__init__ should export DorkExecutor."""
        from src.osint_platform.tools.executors import DorkExecutor
        assert DorkExecutor is not None

    def test_dork_module_init_exports(self):
        """dork.__init__ should export all expected symbols."""
        from src.osint_platform.tools.dork import (
            DorkTool,
            run_dork_batch,
            get_all_dorks,
            DorkCategory,
            CATEGORY_DESCRIPTIONS,
        )
        assert DorkTool is not None
        assert callable(run_dork_batch)
        assert callable(get_all_dorks)
        assert DorkCategory is not None
        assert isinstance(CATEGORY_DESCRIPTIONS, dict)


# ═══════════════════════════════════════════════════════════════════════════════
# Dork Category Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestDorkLibraryEdgeCases:
    """Test edge cases in the dork library."""

    def test_dork_query_contains_placeholder(self):
        """Dorks should consistently use {target} or have no placeholder."""
        all_dorks = get_all_dorks()
        dorks_with_placeholder = [
            d for d in all_dorks if "{target}" in d["query"]
        ]
        dorks_without = [
            d for d in all_dorks if "{target}" not in d["query"]
        ]
        # All dorks either have {target} or don't need domain scoping
        # Camera dorks, IoT devices, network devices, and global dorks don't need a target
        exempt_categories = [
            DorkCategory.CAMERAS,
            DorkCategory.SHODAN,
            DorkCategory.SOCIAL_MEDIA,
            DorkCategory.IOT_DEVICES,
            DorkCategory.NETWORK_DEVICES,
            DorkCategory.WEB_SERVERS,
        ]
        for dork in dorks_without:
            assert dork["category"] in exempt_categories, (
                f"Dork '{dork['name']}' in category '{dork['category']}' lacks {{target}}"
            )

    def test_dork_query_placeholder_format(self):
        """All {target} placeholders should be consistently formatted."""
        for dork in get_all_dorks():
            query = dork["query"]
            # If it has {target}, it should be used consistently
            if "{target}" in query:
                count = query.count("{target}")
                assert count == 1, (
                    f"Dork '{dork['name']}' has {count} {{target}} placeholders (expected 1)"
                )

    def test_no_empty_queries(self):
        """No dork should have an empty query."""
        for dork in get_all_dorks():
            assert len(dork["query"].strip()) > 0

    def test_no_duplicate_names(self):
        """No two dorks should have the same name."""
        all_dorks = get_all_dorks()
        names = [d["name"] for d in all_dorks]
        duplicates = set(n for n in names if names.count(n) > 1)
        assert len(duplicates) == 0, f"Duplicate dork names: {duplicates}"

    def test_all_categories_in_enum(self):
        """Every category key in DORKS_BY_CATEGORY should be in the DorkCategory enum."""
        for category in DORKS_BY_CATEGORY:
            found = False
            for attr_name in dir(DorkCategory):
                attr_value = getattr(DorkCategory, attr_name)
                if isinstance(attr_value, str) and attr_value == category:
                    found = True
                    break
            assert found, f"Category '{category}' not found in DorkCategory enum"
