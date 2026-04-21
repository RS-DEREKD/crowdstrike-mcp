"""Tests for FR 07 NGSIEM read-expansion tools."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def ngsiem_module(mock_client):
    """NGSIEMModule with the falconpy NGSIEM client mocked."""
    with patch("crowdstrike_mcp.modules.ngsiem.NGSIEM") as MockNGSIEM:
        mock_falcon = MagicMock()
        MockNGSIEM.return_value = mock_falcon
        from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

        module = NGSIEMModule(mock_client)
        module._service = lambda cls: mock_falcon
        module.falcon = mock_falcon
        return module


class TestCallAndUnwrap:
    """The shared helper used by all 12 new tools."""

    def test_success_path_returns_resources(self, ngsiem_module):
        fake_method = MagicMock(return_value={
            "status_code": 200,
            "body": {"resources": [{"id": "a"}, {"id": "b"}]},
        })
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name", filter="x")
        assert result["success"] is True
        assert result["resources"] == [{"id": "a"}, {"id": "b"}]
        fake_method.assert_called_once_with(filter="x")

    def test_http_error_surfaces_body_message(self, ngsiem_module):
        fake_method = MagicMock(return_value={
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        })
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name")
        assert result["success"] is False
        assert "Forbidden" in result["error"]
        assert "403" in result["error"]

    def test_empty_resources_is_success(self, ngsiem_module):
        fake_method = MagicMock(return_value={
            "status_code": 200,
            "body": {"resources": []},
        })
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name")
        assert result["success"] is True
        assert result["resources"] == []

    def test_exception_is_captured(self, ngsiem_module):
        fake_method = MagicMock(side_effect=RuntimeError("boom"))
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name")
        assert result["success"] is False
        assert "boom" in result["error"]


class TestListSavedQueries:
    def test_returns_compact_projection_by_default(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "q1", "name": "enrich_users", "last_modified": "2026-04-01",
                 "query": "..." * 100, "extra": "ignored"},
                {"id": "q2", "name": "enrich_hosts", "last_modified": "2026-04-02"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries())
        assert "q1" in result and "enrich_users" in result
        assert "q2" in result and "enrich_hosts" in result
        # Bulk body fields must not leak in compact mode
        assert "extra" not in result

    def test_detail_true_returns_full_records(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "q1", "name": "x", "last_modified": "t", "extra": "keep_me"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries(detail=True))
        assert "keep_me" in result

    def test_passes_filter_and_limit(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_saved_queries(filter="name:'enrich_*'", limit=25))
        kwargs = ngsiem_module.falcon.list_saved_queries.call_args.kwargs
        assert kwargs["filter"] == "name:'enrich_*'"
        assert kwargs["limit"] == 25

    def test_caps_limit_at_1000(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_saved_queries(limit=9999))
        kwargs = ngsiem_module.falcon.list_saved_queries.call_args.kwargs
        assert kwargs["limit"] == 1000

    def test_empty_result_message(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries())
        assert "no" in result.lower() or "0" in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 403, "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries())
        assert "failed" in result.lower()


class TestGetSavedQueryTemplate:
    def test_returns_full_template(self, ngsiem_module):
        ngsiem_module.falcon.get_saved_query_template.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "q1", "name": "enrich_users", "query_string": "#repo=all | ..."},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="q1"))
        assert "q1" in result
        assert "enrich_users" in result
        assert "#repo=all" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_saved_query_template.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="abc"))
        kwargs = ngsiem_module.falcon.get_saved_query_template.call_args.kwargs
        assert kwargs["ids"] == "abc" or kwargs["ids"] == ["abc"]

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_saved_query_template.return_value = {
            "status_code": 404, "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="missing"))
        assert "failed" in result.lower()
