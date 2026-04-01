"""Tests for CAOHuntingModule — intelligence queries and hunting guides."""

import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def cao_module(mock_client):
    """Create a CAOHuntingModule with mocked CAOHunting service."""
    with patch("modules.cao_hunting.CAOHunting"):
        from modules.cao_hunting import CAOHuntingModule

        module = CAOHuntingModule(mock_client)
        module._cao_hunting = MagicMock()
        return module


# ------------------------------------------------------------------
# Search Queries
# ------------------------------------------------------------------


class TestSearchQueries:
    """Test cao_search_queries tool."""

    def test_returns_queries_with_hydration(self, cao_module):
        """Search returns IDs, then hydrates with full details."""
        cao_module._cao_hunting.search_queries.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["q1", "q2"],
                "meta": {"pagination": {"total": 50}},
            },
        }
        cao_module._cao_hunting.get_queries.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "q1", "name": "Ransomware Hunt", "description": "Detect ransomware", "tags": ["ransomware"]},
                    {"id": "q2", "name": "Lateral Movement", "description": "Detect lateral movement", "tags": ["lateral"]},
                ],
            },
        }

        result = asyncio.run(cao_module.cao_search_queries())
        assert "Ransomware Hunt" in result
        assert "Lateral Movement" in result
        assert "50 total" in result

    def test_empty_results(self, cao_module):
        """No matching queries returns empty message."""
        cao_module._cao_hunting.search_queries.return_value = {
            "status_code": 200,
            "body": {
                "resources": [],
                "meta": {"pagination": {"total": 0}},
            },
        }

        result = asyncio.run(cao_module.cao_search_queries(filter="tags:'nonexistent'"))
        assert "No intelligence queries found" in result

    def test_passes_filter_and_q(self, cao_module):
        """Filter and q parameters are forwarded to the API."""
        cao_module._cao_hunting.search_queries.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        asyncio.run(cao_module.cao_search_queries(filter="tags:'apt'", q="ransomware", sort="created_on|desc"))
        cao_module._cao_hunting.search_queries.assert_called_once_with(limit=20, filter="tags:'apt'", q="ransomware", sort="created_on|desc")

    def test_search_api_error(self, cao_module):
        """403 error includes scope guidance."""
        cao_module._cao_hunting.search_queries.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Insufficient permissions"}]},
        }

        result = asyncio.run(cao_module.cao_search_queries())
        assert "Failed to search intelligence queries" in result
        assert "403" in result

    def test_translated_content(self, cao_module):
        """Include translated content when requested."""
        cao_module._cao_hunting.search_queries.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["q1"],
                "meta": {"pagination": {"total": 1}},
            },
        }
        cao_module._cao_hunting.get_queries.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "q1",
                        "name": "Test Query",
                        "translated_content": {"SPL": "index=main sourcetype=..."},
                    },
                ],
            },
        }

        result = asyncio.run(cao_module.cao_search_queries(include_translated_content=True))
        assert "SPL" in result
        cao_module._cao_hunting.get_queries.assert_called_once_with(ids=["q1"], include_translated_content="__all__")


# ------------------------------------------------------------------
# Get Queries
# ------------------------------------------------------------------


class TestGetQueries:
    """Test cao_get_queries tool."""

    def test_get_by_ids(self, cao_module):
        """Direct get by comma-separated IDs."""
        cao_module._cao_hunting.get_queries.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "q1", "name": "Query One", "tags": ["tag1"]},
                ],
            },
        }

        result = asyncio.run(cao_module.cao_get_queries(ids="q1"))
        assert "Query One" in result

    def test_empty_ids(self, cao_module):
        """Empty IDs string returns error."""
        result = asyncio.run(cao_module.cao_get_queries(ids=""))
        assert "No valid IDs" in result

    def test_multiple_ids(self, cao_module):
        """Comma-separated IDs are parsed correctly."""
        cao_module._cao_hunting.get_queries.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }

        asyncio.run(cao_module.cao_get_queries(ids="q1, q2, q3"))
        cao_module._cao_hunting.get_queries.assert_called_once_with(ids=["q1", "q2", "q3"])


# ------------------------------------------------------------------
# Search Guides
# ------------------------------------------------------------------


class TestSearchGuides:
    """Test cao_search_guides tool."""

    def test_returns_guides_with_hydration(self, cao_module):
        """Search returns IDs, then hydrates with full details."""
        cao_module._cao_hunting.search_guides.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["g1"],
                "meta": {"pagination": {"total": 10}},
            },
        }
        cao_module._cao_hunting.get_guides.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "g1", "name": "APT Hunting Guide", "description": "How to hunt APTs"},
                ],
            },
        }

        result = asyncio.run(cao_module.cao_search_guides())
        assert "APT Hunting Guide" in result
        assert "10 total" in result

    def test_empty_results(self, cao_module):
        """No matching guides returns empty message."""
        cao_module._cao_hunting.search_guides.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        result = asyncio.run(cao_module.cao_search_guides())
        assert "No hunting guides found" in result

    def test_search_api_error(self, cao_module):
        """API error is reported."""
        cao_module._cao_hunting.search_guides.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Internal error"}]},
        }

        result = asyncio.run(cao_module.cao_search_guides())
        assert "Failed to search hunting guides" in result


# ------------------------------------------------------------------
# Get Guides
# ------------------------------------------------------------------


class TestGetGuides:
    """Test cao_get_guides tool."""

    def test_get_by_ids(self, cao_module):
        """Direct get by IDs."""
        cao_module._cao_hunting.get_guides.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "g1", "name": "Guide One", "content": "Step 1: ..."},
                ],
            },
        }

        result = asyncio.run(cao_module.cao_get_guides(ids="g1"))
        assert "Guide One" in result

    def test_empty_ids(self, cao_module):
        """Empty IDs string returns error."""
        result = asyncio.run(cao_module.cao_get_guides(ids="  "))
        assert "No valid IDs" in result


# ------------------------------------------------------------------
# Aggregate
# ------------------------------------------------------------------


class TestAggregate:
    """Test cao_aggregate tool."""

    def test_terms_aggregation_queries(self, cao_module):
        """Terms aggregation on intelligence queries."""
        cao_module._cao_hunting.aggregate_queries.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "buckets": [
                            {"key": "high", "label": "high", "count": 42},
                            {"key": "medium", "label": "medium", "count": 18},
                        ],
                    },
                ],
            },
        }

        result = asyncio.run(cao_module.cao_aggregate(field="severity"))
        assert "high: 42" in result
        assert "medium: 18" in result

    def test_aggregation_guides(self, cao_module):
        """Aggregation routes to guides when resource_type=guides."""
        cao_module._cao_hunting.aggregate_guides.return_value = {
            "status_code": 200,
            "body": {"resources": [{"buckets": []}]},
        }

        asyncio.run(cao_module.cao_aggregate(field="tags", resource_type="guides"))
        cao_module._cao_hunting.aggregate_guides.assert_called_once()
        cao_module._cao_hunting.aggregate_queries.assert_not_called()

    def test_invalid_resource_type(self, cao_module):
        """Invalid resource_type returns error."""
        result = asyncio.run(cao_module.cao_aggregate(field="severity", resource_type="invalid"))
        assert "Invalid resource_type" in result

    def test_aggregation_with_filter(self, cao_module):
        """Filter is included in aggregation body."""
        cao_module._cao_hunting.aggregate_queries.return_value = {
            "status_code": 200,
            "body": {"resources": [{"buckets": []}]},
        }

        asyncio.run(cao_module.cao_aggregate(field="tags", filter="severity:'high'", size=5))
        call_kwargs = cao_module._cao_hunting.aggregate_queries.call_args
        body = call_kwargs.kwargs.get("body")
        assert body[0]["filter"] == "severity:'high'"
        assert body[0]["size"] == 5

    def test_aggregation_api_error(self, cao_module):
        """API error is reported."""
        cao_module._cao_hunting.aggregate_queries.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Access denied"}]},
        }

        result = asyncio.run(cao_module.cao_aggregate(field="severity"))
        assert "Failed to aggregate queries" in result


# ------------------------------------------------------------------
# Tool Registration
# ------------------------------------------------------------------


class TestToolRegistration:
    """Verify tool registration."""

    def test_all_tools_registered(self, cao_module):
        """All 5 tools should be registered."""
        mock_server = MagicMock()
        mock_server.tool.return_value = lambda fn: fn

        cao_module.register_tools(mock_server)

        expected = {
            "cao_search_queries",
            "cao_get_queries",
            "cao_search_guides",
            "cao_get_guides",
            "cao_aggregate",
        }
        assert set(cao_module.tools) == expected

    def test_all_tools_are_read_tier(self, cao_module):
        """All tools should register even with allow_writes=False."""
        cao_module.allow_writes = False
        mock_server = MagicMock()
        mock_server.tool.return_value = lambda fn: fn

        cao_module.register_tools(mock_server)
        assert len(cao_module.tools) == 5
