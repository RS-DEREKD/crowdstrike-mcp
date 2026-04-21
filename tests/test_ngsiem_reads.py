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
