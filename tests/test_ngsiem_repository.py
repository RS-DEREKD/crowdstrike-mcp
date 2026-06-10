"""Tests for NGSIEM repository selection and configurable poll/timeout.

ngsiem_query historically searched only the ``search-all`` repository with a
hardcoded 120s timeout and 2s poll interval. These tests cover:

* a new ``repository`` parameter (default ``search-all`` — back-compatible)
  threaded through start_search / get_search_status / stop_search, and
* ``FALCON_MCP_NGSIEM_TIMEOUT`` / ``FALCON_MCP_NGSIEM_POLL_INTERVAL`` env
  overrides (matching the upstream falcon-mcp variable names).
"""

import asyncio
import inspect
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def ngsiem_module(mock_client):
    with patch("crowdstrike_mcp.modules.ngsiem.NGSIEM") as MockNGSIEM:
        mock_falcon = MagicMock()
        MockNGSIEM.return_value = mock_falcon
        from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

        module = NGSIEMModule(mock_client)
        module._service = lambda cls: mock_falcon
        module.falcon = mock_falcon
        return module


def _wire_search(mock_falcon, events=None):
    """Make start_search/get_search_status return an immediately-completed search."""
    mock_falcon.start_search.return_value = {
        "status_code": 200,
        "resources": {"id": "SID-1"},
    }
    mock_falcon.get_search_status.return_value = {
        "status_code": 200,
        "body": {"done": True, "cancelled": False, "events": events or []},
    }


def _wire_never_done(mock_falcon):
    """Make a search that starts but never completes (always done=False)."""
    mock_falcon.start_search.return_value = {
        "status_code": 200,
        "resources": {"id": "SID-1"},
    }
    mock_falcon.get_search_status.return_value = {
        "status_code": 200,
        "body": {"done": False, "cancelled": False, "events": []},
    }


class TestRepositoryParameter:
    def test_ngsiem_query_exposes_repository_param(self, ngsiem_module):
        params = inspect.signature(ngsiem_module.ngsiem_query).parameters
        assert "repository" in params

    def test_repository_defaults_to_search_all(self, ngsiem_module):
        params = inspect.signature(ngsiem_module.ngsiem_query).parameters
        assert params["repository"].default == "search-all"

    def test_default_repository_sent_to_start_search(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon)
        asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)"))
        _, kwargs = ngsiem_module.falcon.start_search.call_args
        assert kwargs["repository"] == "search-all"

    def test_custom_repository_sent_to_start_search(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon)
        asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)", repository="forensics_view"))
        _, kwargs = ngsiem_module.falcon.start_search.call_args
        assert kwargs["repository"] == "forensics_view"

    def test_custom_repository_used_for_status_polling(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon)
        asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)", repository="investigate_view"))
        _, kwargs = ngsiem_module.falcon.get_search_status.call_args
        assert kwargs["repository"] == "investigate_view"

    def test_execute_query_defaults_repository_to_instance_value(self, ngsiem_module):
        """Internal callers that omit repository keep the instance default (back-compat)."""
        _wire_search(ngsiem_module.falcon)
        ngsiem_module._execute_query("#repo=x | head(1)")
        _, kwargs = ngsiem_module.falcon.start_search.call_args
        assert kwargs["repository"] == "search-all"


class TestConfigurableTimeout:
    def test_timeout_env_var_triggers_fast_timeout_and_stops_search(self, ngsiem_module):
        _wire_never_done(ngsiem_module.falcon)
        with patch.dict("os.environ", {"FALCON_MCP_NGSIEM_TIMEOUT": "0"}):
            out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)", repository="forensics_view"))
        assert "timed out" in out.lower()
        # cleanup stop_search must target the same repository
        _, kwargs = ngsiem_module.falcon.stop_search.call_args
        assert kwargs["repository"] == "forensics_view"


class TestConfigurablePollInterval:
    def test_poll_interval_env_var_controls_sleep_between_polls(self, ngsiem_module):
        ngsiem_module.falcon.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "SID-1"},
        }
        # First poll: not done. Second poll: done.
        ngsiem_module.falcon.get_search_status.side_effect = [
            {"status_code": 200, "body": {"done": False, "cancelled": False, "events": []}},
            {"status_code": 200, "body": {"done": True, "cancelled": False, "events": []}},
        ]
        with patch.dict("os.environ", {"FALCON_MCP_NGSIEM_POLL_INTERVAL": "3"}):
            with patch("crowdstrike_mcp.modules.ngsiem.time.sleep") as mock_sleep:
                asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)"))
        mock_sleep.assert_called_once_with(3)
