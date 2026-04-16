"""Tests for get_stored_response silent-null bug fixes.

Covers three fixes:
  1. Metadata overview surfaces available fields (top-level + one level of nesting).
  2. All-null field extraction emits a warning with discovered top-level keys.
  3. Tool description notes field-path differences between alert_analysis and ngsiem_query.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from crowdstrike_mcp.modules.response_store import ResponseStoreModule

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
