"""Tests for _analyze_alert triggering-record mapping on endpoint alerts."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def alerts_module(mock_client):
    """Create AlertsModule with mocked APIs for endpoint enrichment testing."""
    with (
        patch("crowdstrike_mcp.modules.alerts.Alerts"),
        patch("crowdstrike_mcp.modules.alerts._NGSIEM_AVAILABLE", True),
    ):
        module = __import__(
            "crowdstrike_mcp.modules.alerts", fromlist=["AlertsModule"]
        ).AlertsModule(mock_client)
        mock_ngsiem = MagicMock()
        module._service = lambda cls: mock_ngsiem
        module._mock_ngsiem = mock_ngsiem
        return module


def _make_behavior(pid, image, cmdline, timestamp):
    """Helper: make a minimal ProcessRollup2-style record."""
    return {
        "TargetProcessId": pid,
        "ImageFileName": image,
        "CommandLine": cmdline,
        "@timestamp": timestamp,
    }


class TestBehaviorSorting:
    """Behaviors are sorted by @timestamp ascending."""

    def test_behaviors_sorted_by_timestamp(self, alerts_module):
        behaviors = [
            _make_behavior("111", "\\b.exe", "b.exe", "2026-04-15T10:02:00Z"),
            _make_behavior("222", "\\a.exe", "a.exe", "2026-04-15T10:01:00Z"),
        ]
        alerts_module._get_behaviors_for_alert = MagicMock(
            return_value={"success": True, "behaviors": behaviors}
        )
        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {
                    "composite_id": "cust:ind:sub:111-0-trigger1",
                    "device": {"device_id": "dev1"},
                },
            }
        )

        result = alerts_module._analyze_alert("cust:ind:sub:111-0-trigger1", max_events=5)
        sorted_behaviors = result["behaviors"]
        assert sorted_behaviors[0]["@timestamp"] == "2026-04-15T10:01:00Z"
        assert sorted_behaviors[1]["@timestamp"] == "2026-04-15T10:02:00Z"

    def test_missing_timestamp_sorts_to_front_without_error(self, alerts_module):
        """Records without @timestamp get empty-string key — no TypeError."""
        behaviors = [
            _make_behavior("111", "\\b.exe", "b.exe", "2026-04-15T10:02:00Z"),
            {"TargetProcessId": "222", "ImageFileName": "\\c.exe"},  # no @timestamp
        ]
        alerts_module._get_behaviors_for_alert = MagicMock(
            return_value={"success": True, "behaviors": behaviors}
        )
        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {
                    "composite_id": "cust:ind:sub:111-0-trigger1",
                    "device": {"device_id": "dev1"},
                },
            }
        )
        # Should not raise
        result = alerts_module._analyze_alert("cust:ind:sub:111-0-trigger1", max_events=5)
        assert result["success"] is True


class TestTriggeringProcessPopulation:
    """triggering_process is populated when PID matches a behavior record."""

    def test_triggering_process_populated(self, alerts_module):
        behaviors = [
            _make_behavior("999", "\\other.exe", "other.exe", "2026-04-15T10:01:00Z"),
            _make_behavior(
                "288700987",
                "\\SearchIndexer.exe",
                "SearchIndexer.exe /Embedding",
                "2026-04-15T10:02:00Z",
            ),
        ]
        alerts_module._get_behaviors_for_alert = MagicMock(
            return_value={"success": True, "behaviors": behaviors}
        )
        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {
                    "composite_id": "cust:ind:sub:288700987-10357-1549328",
                    "device": {"device_id": "dev1"},
                },
            }
        )

        result = alerts_module._analyze_alert(
            "cust:ind:sub:288700987-10357-1549328", max_events=5
        )
        assert result["triggering_pid"] == "288700987"
        assert result["triggering_record_index"] == 1  # after sorting, it's second (later timestamp)
        tp = result["triggering_process"]
        assert tp is not None
        assert tp["ImageFileName"] == "\\SearchIndexer.exe"
        assert tp["CommandLine"] == "SearchIndexer.exe /Embedding"
        assert tp["TargetProcessId"] == "288700987"
        assert tp["record_index"] == 1

    def test_pid_not_found_returns_none_gracefully(self, alerts_module):
        """If PID from composite ID doesn't match any behavior, fields are None — no crash."""
        behaviors = [
            _make_behavior("111", "\\other.exe", "other.exe", "2026-04-15T10:01:00Z"),
        ]
        alerts_module._get_behaviors_for_alert = MagicMock(
            return_value={"success": True, "behaviors": behaviors}
        )
        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {
                    "composite_id": "cust:ind:sub:999999-0-trigger1",
                    "device": {"device_id": "dev1"},
                },
            }
        )

        result = alerts_module._analyze_alert("cust:ind:sub:999999-0-trigger1", max_events=5)
        assert result["triggering_pid"] == "999999"
        assert result["triggering_process"] is None
        assert result["triggering_record_index"] is None

    def test_empty_behaviors_returns_none_gracefully(self, alerts_module):
        alerts_module._get_behaviors_for_alert = MagicMock(
            return_value={"success": True, "behaviors": []}
        )
        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {
                    "composite_id": "cust:ind:sub:288700987-10357-1549328",
                    "device": {"device_id": "dev1"},
                },
            }
        )

        result = alerts_module._analyze_alert(
            "cust:ind:sub:288700987-10357-1549328", max_events=5
        )
        assert result["triggering_process"] is None

    def test_non_endpoint_alert_has_no_triggering_process(self, alerts_module):
        """ngsiem: and thirdparty: alerts don't populate triggering_process."""
        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {
                    "composite_id": "cust:thirdparty:cust:alert-uuid",
                },
            }
        )

        result = alerts_module._analyze_alert("cust:thirdparty:cust:alert-uuid", max_events=5)
        assert result.get("triggering_process") is None
        assert result.get("triggering_pid") is None


class TestTriggeringProcessBlock:
    """Triggering Process block appears in formatter output when triggering_process is set."""

    def _make_analysis(self, triggering_process=None):
        """Minimal analysis result dict for formatter testing."""
        return {
            "alert": {
                "name": "GenericMasqueradingDefenseEvasion",
                "composite_id": "cust:ind:sub:288700987-10357-1549328",
                "severity_name": "High",
                "severity": 70,
                "status": "new",
                "type": "ind",
                "product": {},
                "created_timestamp": "2026-04-15T10:00:00Z",
                "updated_timestamp": "2026-04-15T10:00:00Z",
            },
            "product_type": "endpoint",
            "product_name": "Endpoint",
            "enrichment_type": "endpoint_behaviors",
            "events": None,
            "behaviors": [],
            "enrichment_note": None,
            "triggering_pid": "288700987" if triggering_process else None,
            "triggering_record_index": 4 if triggering_process else None,
            "triggering_process": triggering_process,
        }

    def test_full_formatter_includes_triggering_block(self, alerts_module):
        tp = {
            "ImageFileName": "\\Device\\SearchIndexer.exe",
            "CommandLine": "SearchIndexer.exe /Embedding",
            "TargetProcessId": "288700987",
            "record_index": 4,
        }
        analysis = self._make_analysis(triggering_process=tp)
        output = alerts_module._format_alert_analysis_response(analysis, summary_mode=False)
        assert "### Triggering Process" in output
        assert "SearchIndexer.exe" in output
        assert "SearchIndexer.exe /Embedding" in output
        assert "288700987" in output
        assert "record_index" in output.lower() or "Record index" in output

    def test_full_formatter_triggering_block_before_behaviors(self, alerts_module):
        """Triggering block must appear before the behaviors section."""
        tp = {
            "ImageFileName": "\\Device\\SearchIndexer.exe",
            "CommandLine": "SearchIndexer.exe /Embedding",
            "TargetProcessId": "288700987",
            "record_index": 4,
        }
        analysis = self._make_analysis(triggering_process=tp)
        analysis["behaviors"] = [{"tactic": "Defense Evasion"}]
        output = alerts_module._format_alert_analysis_response(analysis, summary_mode=False)
        trigger_pos = output.index("### Triggering Process")
        behaviors_pos = output.index("### Endpoint Behaviors")
        assert trigger_pos < behaviors_pos

    def test_full_formatter_no_block_when_triggering_process_none(self, alerts_module):
        analysis = self._make_analysis(triggering_process=None)
        output = alerts_module._format_alert_analysis_response(analysis, summary_mode=False)
        assert "### Triggering Process" not in output

    def test_summary_formatter_includes_triggering_block(self, alerts_module):
        tp = {
            "ImageFileName": "\\Device\\SearchIndexer.exe",
            "CommandLine": "SearchIndexer.exe /Embedding",
            "TargetProcessId": "288700987",
            "record_index": 4,
        }
        analysis = self._make_analysis(triggering_process=tp)
        output = alerts_module._format_alert_analysis_response(analysis, summary_mode=True)
        assert "### Triggering Process" in output
        assert "SearchIndexer.exe" in output

    def test_summary_formatter_no_block_when_triggering_process_none(self, alerts_module):
        analysis = self._make_analysis(triggering_process=None)
        output = alerts_module._format_alert_analysis_response(analysis, summary_mode=True)
        assert "### Triggering Process" not in output
