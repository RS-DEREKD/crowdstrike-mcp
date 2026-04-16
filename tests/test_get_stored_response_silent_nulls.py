"""Tests for get_stored_response silent-null bug fixes.

Covers three fixes:
  1. Metadata overview surfaces available fields (top-level + one level of nesting).
  2. All-null field extraction emits a warning with discovered top-level keys.
  3. Tool description notes field-path differences between alert_analysis and ngsiem_query.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def module(mock_client):
    """Create ResponseStoreModule (no FalconPy services needed)."""
    return ResponseStoreModule(mock_client)


def _store_alert_analysis_shaped() -> str:
    """Store an alert_analysis-shaped record (nested under Ngsiem.event)."""
    data = {
        "records": [
            {
                "@timestamp": "2026-04-10T12:00:00Z",
                "source": {"ip": "10.1.75.3"},
                "user": {"name": "alice"},
                "Ngsiem": {
                    "event": {
                        "usernames": ["alice"],
                        "source_ips": ["10.1.75.3"],
                        "action": "login",
                    }
                },
            },
            {
                "@timestamp": "2026-04-10T12:05:00Z",
                "source": {"ip": "10.1.75.4"},
                "user": {"name": "bob"},
                "Ngsiem": {
                    "event": {
                        "usernames": ["bob"],
                        "source_ips": ["10.1.75.4"],
                        "action": "logout",
                    }
                },
            },
        ]
    }
    return ResponseStore.store(data, tool_name="alert_analysis", metadata={"detection_id": "ngsiem:abc"})


def _store_ngsiem_flat() -> str:
    """Store an ngsiem_query-shaped record (flat dotted keys)."""
    data = {
        "events": [
            {"source.ip": "10.1.75.3", "Vendor.userIdentity.arn": "arn:aws:iam::123:user/alice"},
            {"source.ip": "10.1.75.4", "Vendor.userIdentity.arn": "arn:aws:iam::123:user/bob"},
        ]
    }
    return ResponseStore.store(data, tool_name="ngsiem_query")


# ---------------------------------------------------------------------------
# Fix 1: Metadata overview surfaces available fields
# ---------------------------------------------------------------------------


class TestMetadataOverviewSurfacesFields:
    def test_metadata_includes_top_level_keys(self, module):
        ref_id = _store_alert_analysis_shaped()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id))
        # Should mention top-level keys from the records
        for key in ("@timestamp", "source", "user", "Ngsiem"):
            assert key in result, f"Expected top-level key {key!r} in metadata overview; got: {result}"

    def test_metadata_includes_nested_subkeys(self, module):
        ref_id = _store_alert_analysis_shaped()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id))
        # Should surface one level of nesting for dicts: e.g., source.ip, user.name, Ngsiem.event
        assert "source.ip" in result
        assert "user.name" in result
        assert "Ngsiem.event" in result

    def test_metadata_flat_dotted_keys_surface_as_is(self, module):
        ref_id = _store_ngsiem_flat()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id))
        assert "source.ip" in result
        assert "Vendor.userIdentity.arn" in result

    def test_metadata_not_shown_when_filters_applied(self, module):
        """Schema hint only appears on unfiltered metadata calls."""
        ref_id = _store_ngsiem_flat()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id, record_index=0))
        # Should be the record JSON, not a schema hint section
        parsed = json.loads(result)
        assert parsed["source.ip"] == "10.1.75.3"

    def test_metadata_dedupes_across_records(self, module):
        """Top-level keys should be unioned across all records without duplication."""
        data = {
            "records": [
                {"a": 1, "b": {"x": 1}},
                {"a": 2, "c": 3},
            ]
        }
        ref_id = ResponseStore.store(data, tool_name="test")
        result = asyncio.run(module.get_stored_response(ref_id=ref_id))
        # All top-level keys from any record should appear
        assert "a" in result
        assert "b" in result
        assert "c" in result
        # And nested sub-key for the dict-valued field
        assert "b.x" in result


# ---------------------------------------------------------------------------
# Fix 3: Tool description documents field path differences
# ---------------------------------------------------------------------------


class TestToolDescriptionDocumentsFieldPaths:
    def test_description_mentions_alert_analysis_vs_ngsiem_paths(self, mock_client):
        """register_tools should pass a description covering field-path differences."""
        module = ResponseStoreModule(mock_client)
        server = MagicMock()
        captured = {}

        def fake_tool(**kwargs):
            # Capture whichever tool registration we care about
            if kwargs.get("name") == "get_stored_response":
                captured["description"] = kwargs.get("description", "")

            def decorator(fn):
                return fn

            return decorator

        server.tool.side_effect = fake_tool
        module.register_tools(server)

        desc = captured.get("description", "")
        # Description should mention differing field paths between tools
        assert "alert_analysis" in desc
        assert "ngsiem_query" in desc

    def test_description_recommends_record_index_for_schema_discovery(self, mock_client):
        module = ResponseStoreModule(mock_client)
        server = MagicMock()
        captured = {}

        def fake_tool(**kwargs):
            if kwargs.get("name") == "get_stored_response":
                captured["description"] = kwargs.get("description", "")

            def decorator(fn):
                return fn

            return decorator

        server.tool.side_effect = fake_tool
        module.register_tools(server)

        desc = captured.get("description", "")
        assert "record_index" in desc
