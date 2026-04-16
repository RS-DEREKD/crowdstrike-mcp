"""Tests for NGSIEM alert_analysis timeout fix — deadline, cache, parallel queries, graceful fallback."""

import time as _time
from unittest.mock import MagicMock, patch

import pytest

from crowdstrike_mcp.modules.alerts import AlertsModule


@pytest.fixture
def alerts_module(mock_client):
    """AlertsModule with NGSIEM available and APIs mocked."""
    with patch("crowdstrike_mcp.modules.alerts.Alerts"), patch(
        "crowdstrike_mcp.modules.alerts._NGSIEM_AVAILABLE", True
    ):
        module = AlertsModule(mock_client)
        mock_ngsiem = MagicMock()
        module._service = lambda cls: mock_ngsiem
        module._mock_ngsiem = mock_ngsiem
        return module


class TestExecuteNgsiemQueryDeadline:
    """_execute_ngsiem_query respects the deadline param and returns timed_out on expiry."""

    def test_expired_deadline_returns_timed_out_without_polling(self, alerts_module):
        """An already-expired deadline aborts before the poll loop starts."""
        alerts_module._mock_ngsiem.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        # Return status as not-done so the poll loop would normally keep running
        alerts_module._mock_ngsiem.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": False},
        }
        # Deadline already in the past
        expired_deadline = _time.time() - 1.0
        result = alerts_module._execute_ngsiem_query(
            "test query", "1d", 10, deadline=expired_deadline
        )
        assert result["success"] is False
        assert result.get("timed_out") is True
        # stop_search should have been called to clean up
        alerts_module._mock_ngsiem.stop_search.assert_called_once()

    def test_default_deadline_is_inf_existing_callers_unaffected(self, alerts_module):
        """Calling without deadline= still works — default is float('inf')."""
        alerts_module._mock_ngsiem.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        alerts_module._mock_ngsiem.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": [{"field": "value"}]},
        }
        # No deadline arg — should succeed normally
        result = alerts_module._execute_ngsiem_query("SELECT 1", "1d", 5)
        assert result["success"] is True
        assert result["events_matched"] == 1

    def test_queries_executed_list_populated(self, alerts_module):
        """CQL string is appended to queries_executed before start_search."""
        alerts_module._mock_ngsiem.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        alerts_module._mock_ngsiem.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": []},
        }
        queries_executed = []
        alerts_module._execute_ngsiem_query(
            "my CQL query", "1d", 5, queries_executed=queries_executed
        )
        assert len(queries_executed) == 1
        assert "my CQL query" in queries_executed[0]

    def test_queries_executed_none_does_not_crash(self, alerts_module):
        """queries_executed=None (default) causes no crash."""
        alerts_module._mock_ngsiem.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        alerts_module._mock_ngsiem.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": []},
        }
        # Should not raise
        result = alerts_module._execute_ngsiem_query("SELECT 1", "1d", 5)
        assert result["success"] is True


class TestNgsiemEventCache:
    """_ngsiem_event_cache is instance-level and only caches successes."""

    def test_cache_initialized_on_module(self, alerts_module):
        assert hasattr(alerts_module, "_ngsiem_event_cache")
        assert isinstance(alerts_module._ngsiem_event_cache, dict)
        assert len(alerts_module._ngsiem_event_cache) == 0

    def test_two_instances_have_separate_caches(self, mock_client):
        with patch("crowdstrike_mcp.modules.alerts.Alerts"), patch(
            "crowdstrike_mcp.modules.alerts._NGSIEM_AVAILABLE", True
        ):
            m1 = AlertsModule(mock_client)
            m2 = AlertsModule(mock_client)
            m1._ngsiem_event_cache[("key", "1d")] = {"success": True}
            assert ("key", "1d") not in m2._ngsiem_event_cache
