"""
Tests for the Hermes Agent system.

Tests tool creation, crew agent definitions, service layer,
and API routes with mocked dependencies.
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock, PropertyMock
from uuid import uuid4

# ─── Agent Tools Tests ────────────────────────────────────────────────────────


class TestAgentTools:
    """Tests for agent tool definitions."""

    def test_get_agent_tools_returns_list(self):
        """Test get_agent_tools returns a list of tools."""
        from src.osint_platform.agent.tools import get_agent_tools

        tools = get_agent_tools()
        assert isinstance(tools, list)
        assert len(tools) == 8  # 6 executors + 1 API query + 1 dork tool

    def test_all_tools_have_names(self):
        """Test all tools have descriptive names."""
        from src.osint_platform.agent.tools import get_agent_tools

        for tool in get_agent_tools():
            assert hasattr(tool, "name"), f"Tool missing name attribute"
            assert tool.name, f"Tool name is empty"

    def test_tool_names_match_expected(self):
        """Test tool names match expected identifiers."""
        from src.osint_platform.agent.tools import get_agent_tools

        names = {t.name for t in get_agent_tools()}
        expected = {
            "sherlock_username_search",
            "sublist3r_subdomain_enumeration",
            "amass_asset_discovery",
            "holehe_email_check",
            "phoneinfoga_phone_scan",
            "threat_intelligence_query",
            "google_dork_search",
            "photo_osint_search",
        }
        assert names == expected, f"Tools mismatch. Got {names}"

    def test_available_tools_dict(self):
        """Test AVAILABLE_TOOLS dictionary is complete."""
        from src.osint_platform.agent.tools import AVAILABLE_TOOLS

        assert len(AVAILABLE_TOOLS) == 8
        for name, desc in AVAILABLE_TOOLS.items():
            assert isinstance(name, str) and len(name) > 0
            assert isinstance(desc, str) and len(desc) > 0

    def test_tool_descriptions_non_empty(self):
        """Test get_tool_descriptions returns formatted string."""
        from src.osint_platform.agent.tools import get_tool_descriptions

        desc = get_tool_descriptions()
        assert "Available OSINT Tools" in desc
        assert "sherlock_username_search" in desc
        assert "threat_intelligence_query" in desc

    def test_sherlock_tool_calls_manager(self):
        """Test sherlock tool calls execute_tool on manager."""
        from src.osint_platform.agent.tools import sherlock_username_search

        with patch(
            "src.osint_platform.agent.tools._get_tool_manager_safe"
        ) as mock_get_manager, patch(
            "src.osint_platform.agent.tools._run_async"
        ) as mock_run_async, patch(
            "src.osint_platform.agent.tools._poll_for_result"
        ) as mock_poll:
            mock_manager = MagicMock()
            mock_get_manager.return_value = mock_manager
            mock_run_async.return_value = "req-123"
            mock_poll.return_value = "Found 3 accounts for 'testuser' on social media platforms"

            result = sherlock_username_search.run("testuser")

            assert "testuser" in result
            assert "Found 3 accounts" in result
            mock_poll.assert_called_once_with("sherlock", mock_manager, "req-123")

    def test_threat_intel_tool_calls_api_manager(self):
        """Test threat_intelligence_query tool calls api manager query."""
        from src.osint_platform.agent.tools import threat_intelligence_query

        with patch(
            "src.osint_platform.agent.tools._get_api_manager_safe"
        ) as mock_get_manager:
            mock_manager = MagicMock()
            mock_get_manager.return_value = mock_manager

            with patch(
                "src.osint_platform.agent.tools._run_async"
            ) as mock_run_async:
                mock_run_async.return_value = {
                    "query": "example.com",
                    "correlation": {
                        "sources": ["virustotal", "shodan"],
                        "total_results": 5,
                        "deduplicated": [
                            {"ip": "1.1.1.1", "sources": ["virustotal"]}
                        ],
                    },
                    "execution_time_seconds": 1.2,
                }

                result = threat_intelligence_query.run("example.com")

                assert "example.com" in result
                assert "virustotal" in result
                assert "1.1.1.1" in result

    def test_tool_manager_unavailable(self):
        """Test graceful handling when tool manager is unavailable."""
        from src.osint_platform.agent.tools import sherlock_username_search

        with patch(
            "src.osint_platform.agent.tools._get_tool_manager_safe"
        ) as mock_get_manager:
            mock_get_manager.return_value = None

            result = sherlock_username_search.run("testuser")
            assert "not available" in result.lower()

    def test_api_manager_unavailable(self):
        """Test graceful handling when API manager is unavailable."""
        from src.osint_platform.agent.tools import threat_intelligence_query

        with patch(
            "src.osint_platform.agent.tools._get_api_manager_safe"
        ) as mock_get_manager:
            mock_get_manager.return_value = None

            result = threat_intelligence_query.run("1.1.1.1")
            assert "not available" in result.lower()


# ─── Agent Crew Tests ─────────────────────────────────────────────────────────


class TestAgentCrew:
    """Tests for crew agent definitions and task creation."""

    def test_create_investigator(self):
        """Test investigator agent creation."""
        with patch(
            "src.osint_platform.agent.crew.get_agent_tools"
        ) as mock_tools:
            mock_tools.return_value = []

            from src.osint_platform.agent.crew import create_investigator

            agent = create_investigator()
            assert agent.role == "OSINT Investigator"
            assert "gather" in agent.goal.lower()

    def test_create_analyst(self):
        """Test analyst agent creation."""
        with patch(
            "src.osint_platform.agent.crew.get_agent_tools"
        ) as mock_tools:
            mock_tools.return_value = []

            from src.osint_platform.agent.crew import create_analyst

            agent = create_analyst()
            assert agent.role == "Threat Intelligence Analyst"
            assert "analyze" in agent.goal.lower()

    def test_create_reporter(self):
        """Test reporter agent creation."""
        from src.osint_platform.agent.crew import create_reporter

        agent = create_reporter()
        assert agent.role == "Threat Intelligence Reporter"
        assert "report" in agent.goal.lower()
        assert len(agent.tools) == 0  # Reporter has no tools

    @patch("src.osint_platform.agent.crew.get_agent_tools")
    def test_create_investigation_tasks(self, mock_tools):
        """Test creation of investigation task pipeline."""
        mock_tools.return_value = []

        from src.osint_platform.agent.crew import (
            create_investigator,
            create_analyst,
            create_reporter,
            create_investigation_tasks,
        )

        investigator = create_investigator()
        analyst = create_analyst()
        reporter = create_reporter()

        tasks = create_investigation_tasks(
            investigator, analyst, reporter,
            target="1.1.1.1",
            target_type="ip",
            context="Suspicious login attempt",
        )

        assert len(tasks) == 3
        # First task should be for investigator
        assert tasks[0].agent.role == "OSINT Investigator"
        # Second task should be for analyst
        assert tasks[1].agent.role == "Threat Intelligence Analyst"
        # Third task should be for reporter
        assert tasks[2].agent.role == "Threat Intelligence Reporter"
        # Target should be in the first task description
        assert "1.1.1.1" in tasks[0].description
        # Context should be in the first task description
        assert "Suspicious login attempt" in tasks[0].description

    @patch("src.osint_platform.agent.crew.get_agent_tools")
    def test_create_investigation_tasks_no_context(self, mock_tools):
        """Test task creation without additional context."""
        mock_tools.return_value = []

        from src.osint_platform.agent.crew import (
            create_investigator,
            create_analyst,
            create_reporter,
            create_investigation_tasks,
        )

        investigator = create_investigator()
        analyst = create_analyst()
        reporter = create_reporter()

        tasks = create_investigation_tasks(
            investigator, analyst, reporter,
            target="test@example.com",
            target_type="email",
        )

        assert len(tasks) == 3
        assert "test@example.com" in tasks[0].description

    def test_hermes_crew_investigate_success(self):
        """Test HermesCrew investigate runs full pipeline successfully."""
        from src.osint_platform.agent.crew import HermesCrew

        # Create real Agent instances using minimal CrewAI agents
        from crewai import Agent as CrewAgent

        real_investigator = CrewAgent(
            role="Investigator", goal="test", backstory="test", tools=[], verbose=False
        )
        real_analyst = CrewAgent(
            role="Analyst", goal="test", backstory="test", tools=[], verbose=False
        )
        real_reporter = CrewAgent(
            role="Reporter", goal="test", backstory="test", tools=[], verbose=False
        )

        with patch(
            "src.osint_platform.agent.crew.create_investigator"
        ) as mock_inv, patch(
            "src.osint_platform.agent.crew.create_analyst"
        ) as mock_analyst, patch(
            "src.osint_platform.agent.crew.create_reporter"
        ) as mock_reporter:

            mock_inv.return_value = real_investigator
            mock_analyst.return_value = real_analyst
            mock_reporter.return_value = real_reporter

            crew = HermesCrew()

            # Mock the internal crew's kickoff
            # Patch where `Crew` is used (imported reference in crew.py)
            with patch("src.osint_platform.agent.crew.Crew") as MockCrew:
                mock_crew_instance = MagicMock()
                mock_crew_instance.kickoff.return_value = (
                    "# Investigation Report\n\n**Target:** 1.1.1.1\n\n"
                    "## Key Findings\n- Malicious IP detected\n"
                )
                MockCrew.return_value = mock_crew_instance

                result = crew.investigate(
                    target="1.1.1.1",
                    target_type="ip",
                    context="Suspicious traffic",
                )

                assert result["success"] is True
                assert result["target"] == "1.1.1.1"
                assert "Malicious IP detected" in result["report"]

    def test_hermes_crew_investigate_failure(self):
        """Test HermesCrew handles investigation failures gracefully."""
        from src.osint_platform.agent.crew import HermesCrew

        from crewai import Agent as CrewAgent

        real_investigator = CrewAgent(
            role="Investigator", goal="test", backstory="test", tools=[], verbose=False
        )
        real_analyst = CrewAgent(
            role="Analyst", goal="test", backstory="test", tools=[], verbose=False
        )
        real_reporter = CrewAgent(
            role="Reporter", goal="test", backstory="test", tools=[], verbose=False
        )

        with patch(
            "src.osint_platform.agent.crew.create_investigator"
        ) as mock_inv, patch(
            "src.osint_platform.agent.crew.create_analyst"
        ) as mock_analyst, patch(
            "src.osint_platform.agent.crew.create_reporter"
        ) as mock_reporter:

            mock_inv.return_value = real_investigator
            mock_analyst.return_value = real_analyst
            mock_reporter.return_value = real_reporter

            crew = HermesCrew()

            with patch("src.osint_platform.agent.crew.Crew") as MockCrew:
                mock_crew_instance = MagicMock()
                mock_crew_instance.kickoff.side_effect = RuntimeError(
                    "LLM unavailable"
                )
                MockCrew.return_value = mock_crew_instance

                result = crew.investigate(
                    target="1.1.1.1",
                )

                assert result["success"] is False
                assert "LLM unavailable" in result.get("error", "")

    def test_hermes_crew_factory(self):
        """Test create_hermes_crew factory function."""
        from src.osint_platform.agent.crew import create_hermes_crew

        with patch(
            "src.osint_platform.agent.crew.create_investigator"
        ), patch(
            "src.osint_platform.agent.crew.create_analyst"
        ), patch(
            "src.osint_platform.agent.crew.create_reporter"
        ):
            crew = create_hermes_crew()
            assert isinstance(crew, object)


# ─── Agent Service Tests ─────────────────────────────────────────────────────


class TestAgentService:
    """Tests for AgentService layer."""

    def test_service_singleton(self):
        """Test get_agent_service returns singleton."""
        from src.osint_platform.agent.service import get_agent_service

        service1 = get_agent_service()
        service2 = get_agent_service()
        assert service1 is service2

    def test_service_initial_state(self):
        """Test initial service state."""
        from src.osint_platform.agent.service import AgentService

        service = AgentService()
        assert service.active_count == 0
        assert len(service._investigations) == 0

    @pytest.mark.asyncio
    async def test_investigate_async_returns_id(self):
        """Test investigate_async returns investigation ID immediately."""
        from src.osint_platform.agent.service import AgentService

        service = AgentService()

        with patch.object(service, '_run_investigation_async') as mock_run:
            mock_run.return_value = None

            inv_id = await service.investigate_async(
                target="1.1.1.1",
                target_type="ip",
            )

            assert isinstance(inv_id, str)
            assert len(inv_id) > 0

    def test_get_result_not_found(self):
        """Test get_result returns None for unknown ID."""
        from src.osint_platform.agent.service import AgentService

        service = AgentService()
        result = service.get_result("nonexistent-id")
        assert result is None

    def test_investigate_sync_returns_result(self):
        """Test investigate_sync returns investigation result."""
        from src.osint_platform.agent.service import AgentService

        service = AgentService()

        with patch.object(service.crew, 'investigate') as mock_investigate:
            mock_investigate.return_value = {
                "target": "1.1.1.1",
                "target_type": "ip",
                "success": True,
                "report": "# Report\n\nTest",
            }

            result = service.investigate_sync(
                target="1.1.1.1",
                target_type="ip",
                context="Test",
            )

            assert result["success"] is True
            assert result["target"] == "1.1.1.1"
            assert "investigation_id" in result
            assert "timestamp" in result

    def test_get_history_empty(self):
        """Test get_history returns empty list when no investigations."""
        from src.osint_platform.agent.service import AgentService

        service = AgentService()
        history = service.get_history()
        assert isinstance(history, list)
        assert len(history) == 0

    def test_get_history_with_results(self):
        """Test get_history returns stored investigations."""
        from src.osint_platform.agent.service import AgentService

        service = AgentService()

        # Add some investigations
        service._investigations = {
            "id-1": {
                "investigation_id": "id-1",
                "target": "1.1.1.1",
                "status": "completed",
                "timestamp": "2026-01-01T00:00:00",
            },
            "id-2": {
                "investigation_id": "id-2",
                "target": "example.com",
                "status": "failed",
                "timestamp": "2026-01-02T00:00:00",
            },
        }

        history = service.get_history()
        assert len(history) == 2

        # Test filtering by status
        completed = service.get_history(status="completed")
        assert len(completed) == 1
        assert completed[0]["investigation_id"] == "id-1"

        # Test pagination
        limited = service.get_history(limit=1)
        assert len(limited) == 1

    def test_cancel_nonexistent(self):
        """Test cancel returns False for unknown investigation."""
        from src.osint_platform.agent.service import AgentService

        service = AgentService()
        result = service.cancel_investigation("nonexistent")
        assert result is False

    def test_active_count_initial(self):
        """Test active_count is 0 initially."""
        from src.osint_platform.agent.service import AgentService

        service = AgentService()
        assert service.active_count == 0


# ─── API Routes Tests ────────────────────────────────────────────────────────


class TestAgentAPIRoutes:
    """Tests for agent API endpoints."""

    def test_investigate_endpoint_validation(self):
        """Test investigate endpoint validates request body."""
        from src.osint_platform.api.routes.agent import InvestigateRequest

        # Valid request
        req = InvestigateRequest(target="1.1.1.1")
        assert req.target == "1.1.1.1"
        assert req.target_type == "auto"
        assert req.context is None

        # With all fields
        req = InvestigateRequest(
            target="example.com",
            target_type="domain",
            context="Suspicious domain",
        )
        assert req.target == "example.com"
        assert req.target_type == "domain"
        assert req.context == "Suspicious domain"

    def test_investigate_response_model(self):
        """Test investigation response model fields."""
        from src.osint_platform.api.routes.agent import InvestigationResponse

        resp = InvestigationResponse(
            investigation_id="test-id",
            target="1.1.1.1",
            target_type="ip",
            status="completed",
            timestamp="2026-01-01T00:00:00",
            report="# Report",
        )

        assert resp.investigation_id == "test-id"
        assert resp.target == "1.1.1.1"
        assert resp.status == "completed"
        assert resp.report == "# Report"

    def test_investigate_response_with_error(self):
        """Test investigation response with error field."""
        from src.osint_platform.api.routes.agent import InvestigationResponse

        resp = InvestigationResponse(
            investigation_id="test-id",
            target="1.1.1.1",
            target_type="ip",
            status="failed",
            timestamp="2026-01-01T00:00:00",
            error="LLM unavailable",
        )

        assert resp.status == "failed"
        assert resp.error == "LLM unavailable"

    def test_status_response_model(self):
        """Test investigation status response model."""
        from src.osint_platform.api.routes.agent import (
            InvestigationStatusResponse,
        )

        resp = InvestigationStatusResponse(
            investigation_id="test-id",
            status="running",
        )

        assert resp.investigation_id == "test-id"
        assert resp.status == "running"
        assert resp.report is None
        assert resp.error is None

    def test_history_response_model(self):
        """Test history response model."""
        from src.osint_platform.api.routes.agent import HistoryResponse

        resp = HistoryResponse(
            total=2,
            investigations=[
                {"target": "1.1.1.1", "status": "completed"},
                {"target": "example.com", "status": "failed"},
            ],
        )

        assert resp.total == 2
        assert len(resp.investigations) == 2

    @pytest.mark.asyncio
    async def test_investigate_endpoint_success(self):
        """Test POST /investigate returns successful response."""
        from src.osint_platform.api.routes.agent import router
        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        client = TestClient(app)

        with patch(
            "src.osint_platform.api.routes.agent.get_agent_service"
        ) as mock_get_service:
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service

            # Mock the investigate method
            async def mock_investigate(target, target_type, context):
                return {
                    "investigation_id": "test-inv-123",
                    "target": target,
                    "target_type": target_type,
                    "status": "completed",
                    "timestamp": "2026-01-01T00:00:00",
                    "report": "# Investigation Report\n\nTest content",
                    "success": True,
                }

            mock_service.investigate = mock_investigate

            response = client.post(
                "/api/v1/agent/investigate",
                json={"target": "1.1.1.1", "target_type": "ip"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["investigation_id"] == "test-inv-123"
            assert data["status"] == "completed"
            assert "Report" in data["report"]

    @pytest.mark.asyncio
    async def test_investigate_async_endpoint(self):
        """Test POST /investigate/async returns immediately with ID."""
        from src.osint_platform.api.routes.agent import router
        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        client = TestClient(app)

        with patch(
            "src.osint_platform.api.routes.agent.get_agent_service"
        ) as mock_get_service:
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service

            async def mock_investigate_async(target, target_type, context):
                return "async-inv-456"

            mock_service.investigate_async = mock_investigate_async

            response = client.post(
                "/api/v1/agent/investigate/async",
                json={"target": "example.com"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["investigation_id"] == "async-inv-456"
            assert data["status"] == "running"

    @pytest.mark.asyncio
    async def test_get_status_found(self):
        """Test GET /status returns investigation result."""
        from src.osint_platform.api.routes.agent import router
        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        client = TestClient(app)

        with patch(
            "src.osint_platform.api.routes.agent.get_agent_service"
        ) as mock_get_service:
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service
            mock_service.get_result.return_value = {
                "investigation_id": "test-id",
                "status": "completed",
                "report": "# Report",
                "error": None,
            }

            response = client.get("/api/v1/agent/status/test-id")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "completed"
            assert data["report"] == "# Report"

    @pytest.mark.asyncio
    async def test_get_status_not_found(self):
        """Test GET /status returns 404 for unknown investigation."""
        from src.osint_platform.api.routes.agent import router
        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        client = TestClient(app)

        with patch(
            "src.osint_platform.api.routes.agent.get_agent_service"
        ) as mock_get_service:
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service
            mock_service.get_result.return_value = None

            response = client.get("/api/v1/agent/status/nonexistent")
            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_history_endpoint(self):
        """Test GET /history returns investigation history."""
        from src.osint_platform.api.routes.agent import router
        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        client = TestClient(app)

        with patch(
            "src.osint_platform.api.routes.agent.get_agent_service"
        ) as mock_get_service:
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service
            mock_service.get_history.return_value = [
                {"target": "1.1.1.1", "status": "completed"},
            ]

            response = client.get("/api/v1/agent/history")
            assert response.status_code == 200
            data = response.json()
            assert data["total"] == 1
            assert len(data["investigations"]) == 1

    @pytest.mark.asyncio
    async def test_tools_endpoint(self):
        """Test GET /tools returns available tools."""
        from src.osint_platform.api.routes.agent import router
        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        client = TestClient(app)

        response = client.get("/api/v1/agent/tools")
        assert response.status_code == 200
        data = response.json()
        assert data["tool_count"] == 8
        assert len(data["tools"]) == 8

    @pytest.mark.asyncio
    async def test_cancel_endpoint_not_found(self):
        """Test POST /cancel returns 404 for unknown investigation."""
        from src.osint_platform.api.routes.agent import router
        from fastapi.testclient import TestClient
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)

        client = TestClient(app)

        with patch(
            "src.osint_platform.api.routes.agent.get_agent_service"
        ) as mock_get_service:
            mock_service = MagicMock()
            mock_get_service.return_value = mock_service
            mock_service.cancel_investigation.return_value = False
            mock_service.get_result.return_value = None

            response = client.post("/api/v1/agent/cancel/nonexistent")
            assert response.status_code == 404


# ─── Module-Level Exports Tests ──────────────────────────────────────────────


class TestAgentModule:
    """Tests for agent module __init__ exports."""

    def test_module_exports(self):
        """Test all expected exports are available."""
        from src.osint_platform.agent import (
            HermesCrew,
            create_hermes_crew,
            AgentService,
            get_agent_tools,
            get_tool_descriptions,
            TOOL_LIST,
        )

        assert HermesCrew is not None
        assert callable(create_hermes_crew)
        assert AgentService is not None
        assert callable(get_agent_tools)
        assert callable(get_tool_descriptions)
        assert isinstance(TOOL_LIST, list)
        assert len(TOOL_LIST) > 0


# ─── Module-level config tests ───────────────────────────────────────────────


class TestLLMConfig:
    """Tests for LLM configuration resolution."""

    @patch("src.osint_platform.agent.crew.get_config")
    def test_ollama_preferred_when_enabled(self, mock_get_config):
        """Test Ollama is used when enabled in config."""
        mock_get_config.return_value = {
            "ollama": {
                "enabled": True,
                "model": "qwen2.5-coder:32b",
                "fallback_to_claude": True,
            },
            "claude": {
                "api_key": "test-key",
                "model": "claude-3-5-sonnet-20241022",
            },
        }

        from src.osint_platform.agent.crew import _get_llm

        llm = _get_llm("investigator")
        assert "ollama/" in llm
        assert "qwen2.5-coder" in llm

    @patch("src.osint_platform.agent.crew.get_config")
    def test_claude_fallback_when_ollama_disabled(self, mock_get_config):
        """Test Claude is used when Ollama is disabled."""
        mock_get_config.return_value = {
            "ollama": {
                "enabled": False,
                "model": "qwen2.5-coder:32b",
                "fallback_to_claude": True,
            },
            "claude": {
                "api_key": "test-key",
                "model": "claude-3-5-sonnet-20241022",
            },
        }

        from src.osint_platform.agent.crew import _get_llm

        llm = _get_llm("analyst")
        assert "claude/" in llm

    @patch("src.osint_platform.agent.crew.get_config")
    def test_default_when_no_llm_configured(self, mock_get_config):
        """Test default Ollama fallback when no LLM is configured."""
        mock_get_config.return_value = {
            "ollama": {
                "enabled": False,
                "fallback_to_claude": False,
            },
            "claude": {},
        }

        from src.osint_platform.agent.crew import _get_llm

        llm = _get_llm("reporter")
        assert "ollama/" in llm


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
