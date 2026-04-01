"""Tests for new case management tools added in FalconPy v1.6.1."""

import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def case_module(mock_client):
    """Create CaseManagementModule with mocked API."""
    with patch("modules.case_management.CaseManagement") as MockCM:
        mock_cm = MagicMock()
        MockCM.return_value = mock_cm
        from modules.case_management import CaseManagementModule

        module = CaseManagementModule(mock_client)
        module.falcon = mock_cm
        return module


class TestCaseQueryAccessTags:
    """Test case_query_access_tags tool."""

    def test_returns_tag_ids(self, case_module):
        case_module.falcon.query_access_tags.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["tag-001", "tag-002"],
                "meta": {"pagination": {"total": 2}},
            },
        }
        result = asyncio.get_event_loop().run_until_complete(
            case_module.case_query_access_tags()
        )
        assert "tag-001" in result
        assert "tag-002" in result

    def test_handles_empty_results(self, case_module):
        case_module.falcon.query_access_tags.return_value = {
            "status_code": 200,
            "body": {
                "resources": [],
                "meta": {"pagination": {"total": 0}},
            },
        }
        result = asyncio.get_event_loop().run_until_complete(
            case_module.case_query_access_tags()
        )
        assert "no access tags" in result.lower() or "0" in result

    def test_handles_api_error(self, case_module):
        case_module.falcon.query_access_tags.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.get_event_loop().run_until_complete(
            case_module.case_query_access_tags()
        )
        assert "failed" in result.lower()


class TestCaseGetAccessTags:
    """Test case_get_access_tags tool."""

    def test_returns_tag_details(self, case_module):
        case_module.falcon.get_access_tags.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "tag-001", "name": "SOC-Team", "description": "SOC team access"}
                ]
            },
        }
        result = asyncio.get_event_loop().run_until_complete(
            case_module.case_get_access_tags(tag_ids=["tag-001"])
        )
        assert "SOC-Team" in result
        assert "tag-001" in result

    def test_handles_api_error(self, case_module):
        case_module.falcon.get_access_tags.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.get_event_loop().run_until_complete(
            case_module.case_get_access_tags(tag_ids=["bad-id"])
        )
        assert "failed" in result.lower()


class TestCaseAggregateAccessTags:
    """Test case_aggregate_access_tags tool."""

    def test_returns_aggregation_data(self, case_module):
        case_module.falcon.aggregate_access_tags.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"name": "tag_count", "buckets": [{"label": "SOC", "count": 5}]}
                ]
            },
        }
        result = asyncio.get_event_loop().run_until_complete(
            case_module.case_aggregate_access_tags(
                date_ranges=[],
                field="name",
                filter="",
                name="tag_count",
                type="terms",
            )
        )
        assert "tag_count" in result or "SOC" in result

    def test_handles_api_error(self, case_module):
        case_module.falcon.aggregate_access_tags.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Internal error"}]},
        }
        result = asyncio.get_event_loop().run_until_complete(
            case_module.case_aggregate_access_tags(
                date_ranges=[],
                field="name",
                filter="",
                name="tag_count",
                type="terms",
            )
        )
        assert "failed" in result.lower()


class TestToolRegistration:
    """Verify new tools register correctly."""

    def test_access_tag_tools_register_as_read(self, case_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        case_module.register_tools(server)
        assert "case_query_access_tags" in case_module.tools
        assert "case_get_access_tags" in case_module.tools
        assert "case_aggregate_access_tags" in case_module.tools
