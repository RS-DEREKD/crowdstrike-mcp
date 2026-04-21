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


class TestEdgeTypeCache:
    """ThreatGraphEdgeTypeCache behavior: fetch-on-first-read, cache, invalidate."""

    def test_first_read_calls_fetcher_and_caches(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        fetch_calls = []

        def fake_fetcher():
            fetch_calls.append(1)
            return {"status_code": 200, "body": {"resources": ["accessed_by_session", "wrote_file"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        body = cache.read()
        assert "accessed_by_session" in body
        assert "wrote_file" in body
        assert len(fetch_calls) == 1

    def test_second_read_uses_cache(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        fetch_calls = []

        def fake_fetcher():
            fetch_calls.append(1)
            return {"status_code": 200, "body": {"resources": ["x"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        cache.read()
        cache.read()
        assert len(fetch_calls) == 1

    def test_fetch_failure_does_not_poison_cache(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        state = {"calls": 0, "fail": True}

        def fake_fetcher():
            state["calls"] += 1
            if state["fail"]:
                return {"status_code": 500, "body": {"errors": [{"message": "boom"}]}}
            return {"status_code": 200, "body": {"resources": ["ok"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        first = cache.read()
        assert "500" in first or "error" in first.lower()

        state["fail"] = False
        second = cache.read()
        assert "ok" in second
        assert state["calls"] == 2

    def test_invalidate_forces_refetch(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        state = {"calls": 0, "payload": ["v1"]}

        def fake_fetcher():
            state["calls"] += 1
            return {"status_code": 200, "body": {"resources": list(state["payload"])}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        first = cache.read()
        assert "v1" in first

        state["payload"] = ["v2"]
        cache.invalidate()
        second = cache.read()
        assert "v2" in second
        assert state["calls"] == 2


@pytest.fixture
def threatgraph_module(mock_client):
    """ThreatGraphModule with ThreatGraph service mocked."""
    with patch("crowdstrike_mcp.modules.threat_graph.ThreatGraph") as MockTG:
        mock_tg = MagicMock()
        MockTG.return_value = mock_tg
        from crowdstrike_mcp.modules.threat_graph import ThreatGraphModule

        module = ThreatGraphModule(mock_client)
        module._service = lambda cls: mock_tg
        module.falcon = mock_tg
        return module


class TestThreatGraphModuleScaffold:
    """Module loads, registers expected resource URI, inherits BaseModule."""

    def test_module_subclasses_base(self, threatgraph_module):
        from crowdstrike_mcp.modules.base import BaseModule

        assert isinstance(threatgraph_module, BaseModule)

    def test_registers_edge_types_resource(self, threatgraph_module):
        server = MagicMock()
        server.resource.return_value = lambda fn: fn
        threatgraph_module.register_resources(server)
        assert "falcon://reference/threatgraph-edge-types" in threatgraph_module.resources

    def test_auto_discovery_finds_class(self):
        from crowdstrike_mcp.registry import discover_module_classes

        names = [c.__name__ for c in discover_module_classes()]
        assert "ThreatGraphModule" in names


class TestThreatGraphGetEdgeTypes:
    def test_returns_edge_types(self, threatgraph_module):
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 200,
            "body": {"resources": ["wrote_file", "accessed_by_session"]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_edge_types())
        assert "wrote_file" in result
        assert "accessed_by_session" in result

    def test_invalidates_resource_cache(self, threatgraph_module):
        # Seed the cache
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 200,
            "body": {"resources": ["old"]},
        }
        first_body = threatgraph_module._edge_type_cache.read()
        assert "old" in first_body

        # Change API response, then call the tool
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 200,
            "body": {"resources": ["new"]},
        }
        asyncio.run(threatgraph_module.threatgraph_get_edge_types())

        # The cache should now reflect the new list on next resource read
        second_body = threatgraph_module._edge_type_cache.read()
        assert "new" in second_body
        assert "old" not in second_body

    def test_handles_api_error(self, threatgraph_module):
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_edge_types())
        assert "failed" in result.lower() or "forbidden" in result.lower()
