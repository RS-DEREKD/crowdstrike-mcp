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


class TestListLookupFiles:
    def test_returns_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_lookup_files.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "l1", "name": "blocked_domains.csv", "last_modified": "t1",
                 "row_count": 400, "schema": "..." * 20},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_lookup_files())
        assert "l1" in result and "blocked_domains.csv" in result
        assert "row_count" not in result  # not in compact field set

    def test_detail_true_returns_full(self, ngsiem_module):
        ngsiem_module.falcon.list_lookup_files.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "l1", "name": "x", "row_count": 42},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_lookup_files(detail=True))
        assert "row_count" in result
        assert "42" in result

    def test_caps_limit(self, ngsiem_module):
        ngsiem_module.falcon.list_lookup_files.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_lookup_files(limit=9999))
        assert ngsiem_module.falcon.list_lookup_files.call_args.kwargs["limit"] == 1000


class TestGetLookupFile:
    FULL_RECORD = {
        "id": "l1",
        "name": "blocked_domains.csv",
        "row_count": 385,
        "schema": [{"name": "domain", "type": "string"}],
        "content": "domain\nfoo.example\nbar.example\n",
        "last_modified": "2026-04-10T00:00:00Z",
    }

    def test_metadata_only_by_default(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = {
            "status_code": 200, "body": {"resources": [self.FULL_RECORD]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_lookup_file(id="l1"))
        assert "blocked_domains.csv" in result
        assert "385" in result
        assert "foo.example" not in result  # content stripped
        assert "bar.example" not in result

    def test_include_content_true_returns_content(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = {
            "status_code": 200, "body": {"resources": [self.FULL_RECORD]},
        }
        result = asyncio.run(
            ngsiem_module.ngsiem_get_lookup_file(id="l1", include_content=True)
        )
        assert "foo.example" in result
        assert "bar.example" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_lookup_file(id="abc"))
        kwargs = ngsiem_module.falcon.get_lookup_file.call_args.kwargs
        assert kwargs["ids"] == "abc" or kwargs["ids"] == ["abc"]

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = {
            "status_code": 404, "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_lookup_file(id="missing"))
        assert "failed" in result.lower()


class TestListDashboards:
    def test_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_dashboards.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "d1", "name": "Ingestion Overview", "last_modified": "t1",
                 "widgets": ["..." * 50]},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_dashboards())
        assert "Ingestion Overview" in result
        assert "widgets" not in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_dashboards.return_value = {
            "status_code": 500, "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_dashboards())
        assert "failed" in result.lower()


class TestListParsers:
    def test_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_parsers.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "p1", "name": "box-parser", "last_modified": "t",
                 "script": "#" * 1000},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_parsers())
        assert "box-parser" in result
        assert "script" not in result

    def test_detail_true_returns_script(self, ngsiem_module):
        ngsiem_module.falcon.list_parsers.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "p1", "name": "box-parser", "script": "MARKER_STRING"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_parsers(detail=True))
        assert "MARKER_STRING" in result


class TestGetParser:
    def test_returns_parser_detail(self, ngsiem_module):
        ngsiem_module.falcon.get_parser.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "p1", "name": "box-parser", "script": "MARKER_STRING"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_parser(id="p1"))
        assert "p1" in result
        assert "MARKER_STRING" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_parser.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_parser(id="p1"))
        kwargs = ngsiem_module.falcon.get_parser.call_args.kwargs
        assert kwargs["ids"] == "p1" or kwargs["ids"] == ["p1"]

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_parser.return_value = {
            "status_code": 404, "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_parser(id="missing"))
        assert "failed" in result.lower()
