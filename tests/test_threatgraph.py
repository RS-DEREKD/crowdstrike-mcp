"""Tests for Threat Graph module."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


class TestThreatGraphScopes:
    """Scope mappings for Threat Graph operations exist in api_scopes."""

    def test_entities_vertices_getv2_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("entities_vertices_getv2") == ["threatgraph:read"]

    def test_combined_edges_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("combined_edges_get") == ["threatgraph:read"]

    def test_combined_ran_on_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("combined_ran_on_get") == ["threatgraph:read"]

    def test_combined_summary_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("combined_summary_get") == ["threatgraph:read"]

    def test_queries_edgetypes_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("queries_edgetypes_get") == ["threatgraph:read"]
