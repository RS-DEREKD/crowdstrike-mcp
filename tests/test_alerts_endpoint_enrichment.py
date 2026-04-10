"""Tests for AlertsModule endpoint enrichment via NGSIEM (replaces dead Detects API)."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def alerts_module(mock_client):
    """Create AlertsModule with mocked APIs."""
    with patch("modules.alerts.Alerts"), patch("modules.alerts._NGSIEM_AVAILABLE", True), patch("modules.alerts.NGSIEM") as MockNGSIEM:
        mock_ngsiem_instance = MagicMock()
        MockNGSIEM.return_value = mock_ngsiem_instance
        module = __import__("modules.alerts", fromlist=["AlertsModule"]).AlertsModule(mock_client)
        module._get_ngsiem_service = lambda: mock_ngsiem_instance
        return module


class TestEndpointEnrichmentViaNGSIEM:
    """Verify endpoint alert enrichment uses NGSIEM instead of dead Detects API."""

    def test_enrichment_queries_ngsiem_with_device_id(self, alerts_module):
        alert = {
            "composite_id": "cust:ind:device123:det456",
            "device": {"device_id": "device123"},
        }
        # Mock NGSIEM search flow — _get_ngsiem_service returns the mock;
        # _execute_ngsiem_query calls start_search / get_search_status on it.
        ngsiem_mock = alerts_module._get_ngsiem_service()
        ngsiem_mock.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        ngsiem_mock.get_search_status.return_value = {
            "status_code": 200,
            "body": {
                "done": True,
                "events": [
                    {
                        "#event_simpleName": "ProcessRollup2",
                        "aid": "device123",
                        "CommandLine": "cmd.exe /c whoami",
                        "ImageFileName": "\\Device\\HarddiskVolume2\\Windows\\System32\\cmd.exe",
                    }
                ],
            },
        }

        result = alerts_module._get_behaviors_for_alert(alert)
        assert result["success"] is True
        assert len(result["behaviors"]) == 1
        assert result["behaviors"][0]["#event_simpleName"] == "ProcessRollup2"

    def test_enrichment_fails_gracefully_without_ngsiem(self, alerts_module):
        alerts_module._get_ngsiem_service = lambda: None
        alert = {
            "composite_id": "cust:ind:device123:det456",
            "device": {"device_id": "device123"},
        }
        result = alerts_module._get_behaviors_for_alert(alert)
        assert result["success"] is False
        assert "not available" in result["error"]

    def test_enrichment_fails_gracefully_without_device_id(self, alerts_module):
        alert = {
            "composite_id": "cust:ind:device123:det456",
            "device": {},
        }
        result = alerts_module._get_behaviors_for_alert(alert)
        assert result["success"] is False
        assert "device_id" in result["error"]

    def test_enrichment_returns_empty_on_no_events(self, alerts_module):
        alert = {
            "composite_id": "cust:ind:device123:det456",
            "device": {"device_id": "device123"},
        }
        ngsiem_mock = alerts_module._get_ngsiem_service()
        ngsiem_mock.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        ngsiem_mock.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": []},
        }

        result = alerts_module._get_behaviors_for_alert(alert)
        assert result["success"] is True
        assert result["behaviors"] == []

    def test_detects_api_is_not_initialized(self, alerts_module):
        """Confirm the Detects client is not used."""
        assert not hasattr(alerts_module, "_detects") or alerts_module._detects is None
