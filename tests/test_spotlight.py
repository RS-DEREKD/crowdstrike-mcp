"""Tests for Spotlight evaluation logic module."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def spotlight_module(mock_client):
    """Create SpotlightModule with mocked API."""
    with patch("crowdstrike_mcp.modules.spotlight.SpotlightEvaluationLogic") as MockSEL:
        mock_sel = MagicMock()
        MockSEL.return_value = mock_sel
        from crowdstrike_mcp.modules.spotlight import SpotlightModule

        module = SpotlightModule(mock_client)
        module._service = lambda cls: mock_sel
        # Expose the mock for tests that configure return values via module.falcon
        module.falcon = mock_sel
        return module


class TestSpotlightSupportedEvaluations:
    """Test spotlight_supported_evaluations tool."""

    def test_returns_evaluation_data(self, spotlight_module):
        spotlight_module.falcon.combined_supported_evaluation.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "eval-001",
                        "name": "Windows Kernel Vulnerability",
                        "platforms": ["Windows"],
                        "cve_ids": ["CVE-2024-1234"],
                    }
                ]
            },
        }
        result = asyncio.run(spotlight_module.spotlight_supported_evaluations())
        assert "Windows Kernel Vulnerability" in result
        assert "eval-001" in result

    def test_handles_empty_results(self, spotlight_module):
        spotlight_module.falcon.combined_supported_evaluation.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        result = asyncio.run(spotlight_module.spotlight_supported_evaluations())
        assert "no evaluation" in result.lower() or "0" in result

    def test_handles_api_error(self, spotlight_module):
        spotlight_module.falcon.combined_supported_evaluation.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(spotlight_module.spotlight_supported_evaluations())
        assert "failed" in result.lower()

    def test_passes_filter_parameter(self, spotlight_module):
        spotlight_module.falcon.combined_supported_evaluation.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(spotlight_module.spotlight_supported_evaluations(filter="platform:'Windows'"))
        spotlight_module.falcon.combined_supported_evaluation.assert_called_once_with(filter="platform:'Windows'")


class TestSpotlightToolRegistration:
    """Verify spotlight tool registers correctly."""

    def test_tool_registers_as_read(self, spotlight_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        spotlight_module.register_tools(server)
        assert "spotlight_supported_evaluations" in spotlight_module.tools


class TestSpotlightVulnScopes:
    """Scope mappings for new operations exist in api_scopes."""

    def test_query_vulnerabilities_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("query_vulnerabilities") == ["spotlight-vulnerabilities:read"]

    def test_get_vulnerabilities_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("get_vulnerabilities") == ["spotlight-vulnerabilities:read"]

    def test_combined_vulnerabilities_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("query_vulnerabilities_combined") == ["spotlight-vulnerabilities:read"]

    def test_remediations_v2_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("get_remediations_v2") == ["spotlight-vulnerabilities:read"]


@pytest.fixture
def spotlight_vuln_module(mock_client):
    """Create SpotlightModule with both Spotlight APIs mocked."""
    with patch("crowdstrike_mcp.modules.spotlight.SpotlightEvaluationLogic") as MockEval, \
         patch("crowdstrike_mcp.modules.spotlight.SpotlightVulnerabilities") as MockVulns:
        mock_eval = MagicMock()
        mock_vulns = MagicMock()
        MockEval.return_value = mock_eval
        MockVulns.return_value = mock_vulns
        from crowdstrike_mcp.modules.spotlight import SpotlightModule

        module = SpotlightModule(mock_client)
        # route _service(cls) to the right mock based on class name
        def _fake_service(cls):
            return mock_vulns if cls.__name__ == "SpotlightVulnerabilities" else mock_eval
        module._service = _fake_service
        module.falcon_eval = mock_eval
        module.falcon_vulns = mock_vulns
        return module


class TestSpotlightQueryVulnerabilities:
    def test_returns_vuln_ids(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": ["vuln-1", "vuln-2", "vuln-3"]},
        }
        result = asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(filter="status:'open'")
        )
        assert "vuln-1" in result
        assert "3" in result  # count

    def test_passes_filter_and_limit(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(
                filter="cve.id:'CVE-2024-1234'", limit=25
            )
        )
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.assert_called_once()
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities.call_args.kwargs
        assert kwargs["filter"] == "cve.id:'CVE-2024-1234'"
        assert kwargs["limit"] == 25

    def test_caps_limit_at_500(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(
                filter="status:'open'", limit=9999
            )
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities.call_args.kwargs
        assert kwargs["limit"] == 500

    def test_requires_filter(self, spotlight_vuln_module):
        result = asyncio.run(spotlight_vuln_module.spotlight_query_vulnerabilities(filter=""))
        assert "filter" in result.lower()

    def test_passes_after_token(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(
                filter="status:'open'", after="token-xyz"
            )
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities.call_args.kwargs
        assert kwargs["after"] == "token-xyz"

    def test_handles_api_error(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(filter="status:'open'")
        )
        assert "failed" in result.lower()


class TestSpotlightGetVulnerabilities:
    def test_returns_vuln_details(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.get_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {
                    "id": "vuln-1",
                    "cve": {"id": "CVE-2024-1234", "severity": "CRITICAL", "base_score": 9.8},
                    "host_info": {"hostname": "web-01", "platform_name": "Linux"},
                    "status": "open",
                    "created_timestamp": "2026-04-01T00:00:00Z",
                }
            ]},
        }
        result = asyncio.run(
            spotlight_vuln_module.spotlight_get_vulnerabilities(ids=["vuln-1"])
        )
        assert "CVE-2024-1234" in result
        assert "CRITICAL" in result
        assert "web-01" in result

    def test_requires_ids(self, spotlight_vuln_module):
        result = asyncio.run(spotlight_vuln_module.spotlight_get_vulnerabilities(ids=[]))
        assert "ids" in result.lower() or "required" in result.lower()

    def test_passes_ids_to_falconpy(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.get_vulnerabilities.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(spotlight_vuln_module.spotlight_get_vulnerabilities(ids=["a", "b"]))
        spotlight_vuln_module.falcon_vulns.get_vulnerabilities.assert_called_once_with(ids=["a", "b"])

    def test_handles_api_error(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.get_vulnerabilities.return_value = {
            "status_code": 500, "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(spotlight_vuln_module.spotlight_get_vulnerabilities(ids=["x"]))
        assert "failed" in result.lower()
