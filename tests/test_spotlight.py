"""Tests for Spotlight evaluation logic module."""

import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def spotlight_module(mock_client):
    """Create SpotlightModule with mocked API."""
    with patch("modules.spotlight.SpotlightEvaluationLogic") as MockSEL:
        mock_sel = MagicMock()
        MockSEL.return_value = mock_sel
        from modules.spotlight import SpotlightModule

        module = SpotlightModule(mock_client)
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
        result = asyncio.run(
            spotlight_module.spotlight_supported_evaluations()
        )
        assert "Windows Kernel Vulnerability" in result
        assert "eval-001" in result

    def test_handles_empty_results(self, spotlight_module):
        spotlight_module.falcon.combined_supported_evaluation.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        result = asyncio.run(
            spotlight_module.spotlight_supported_evaluations()
        )
        assert "no evaluation" in result.lower() or "0" in result

    def test_handles_api_error(self, spotlight_module):
        spotlight_module.falcon.combined_supported_evaluation.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(
            spotlight_module.spotlight_supported_evaluations()
        )
        assert "failed" in result.lower()

    def test_passes_filter_parameter(self, spotlight_module):
        spotlight_module.falcon.combined_supported_evaluation.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            spotlight_module.spotlight_supported_evaluations(filter="platform:'Windows'")
        )
        spotlight_module.falcon.combined_supported_evaluation.assert_called_once_with(
            filter="platform:'Windows'"
        )


class TestSpotlightToolRegistration:
    """Verify spotlight tool registers correctly."""

    def test_tool_registers_as_read(self, spotlight_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        spotlight_module.register_tools(server)
        assert "spotlight_supported_evaluations" in spotlight_module.tools
