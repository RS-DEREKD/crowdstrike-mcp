"""Tests for correlation rule template tools added in FalconPy v1.6.1."""

import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


MOCK_TEMPLATE = {
    "id": "template-uuid-001",
    "name": "Lateral Movement - RDP Brute Force",
    "description": "Detects repeated RDP login failures indicating brute force attempts.",
    "severity": 60,
    "search": {
        "filter": "#event_simpleName=UserLogonFailed2 LogonType=10 | groupBy([aid, UserName], function=count()) | count > 10",
    },
    "created_on": "2026-01-15T00:00:00Z",
    "updated_on": "2026-03-20T00:00:00Z",
}


@pytest.fixture
def correlation_module(mock_client):
    """Create CorrelationModule with mocked API."""
    with patch("modules.correlation.CorrelationRules") as MockCR:
        mock_cr = MagicMock()
        MockCR.return_value = mock_cr
        from modules.correlation import CorrelationModule

        module = CorrelationModule(mock_client)
        module.falcon = mock_cr
        return module


class TestCorrelationListTemplates:
    """Test correlation_list_templates tool."""

    def test_returns_template_ids(self, correlation_module):
        correlation_module.falcon.query_templates.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["template-uuid-001", "template-uuid-002"],
                "meta": {"pagination": {"total": 2}},
            },
        }
        result = asyncio.run(correlation_module.correlation_list_templates())
        assert "template-uuid-001" in result
        assert "template-uuid-002" in result

    def test_handles_empty_results(self, correlation_module):
        correlation_module.falcon.query_templates.return_value = {
            "status_code": 200,
            "body": {
                "resources": [],
                "meta": {"pagination": {"total": 0}},
            },
        }
        result = asyncio.run(correlation_module.correlation_list_templates())
        assert "no templates" in result.lower() or "0" in result

    def test_handles_api_error(self, correlation_module):
        correlation_module.falcon.query_templates.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(correlation_module.correlation_list_templates())
        assert "failed" in result.lower()


class TestCorrelationGetTemplate:
    """Test correlation_get_template tool."""

    def test_returns_template_details(self, correlation_module):
        correlation_module.falcon.get_templates.return_value = {
            "status_code": 200,
            "body": {"resources": [MOCK_TEMPLATE]},
        }
        result = asyncio.run(correlation_module.correlation_get_template(template_ids=["template-uuid-001"]))
        assert "Lateral Movement" in result
        assert "template-uuid-001" in result
        assert "RDP" in result

    def test_handles_not_found(self, correlation_module):
        correlation_module.falcon.get_templates.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        result = asyncio.run(correlation_module.correlation_get_template(template_ids=["bad-id"]))
        assert "no templates found" in result.lower()

    def test_handles_api_error(self, correlation_module):
        correlation_module.falcon.get_templates.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Internal error"}]},
        }
        result = asyncio.run(correlation_module.correlation_get_template(template_ids=["template-uuid-001"]))
        assert "failed" in result.lower()


class TestTemplateToolRegistration:
    """Verify template tools register correctly."""

    def test_template_tools_register_as_read(self, correlation_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        correlation_module.register_tools(server)
        assert "correlation_list_templates" in correlation_module.tools
        assert "correlation_get_template" in correlation_module.tools
