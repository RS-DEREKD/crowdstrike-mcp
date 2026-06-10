"""Regression tests for NGSIEM time-parameter handling (issues #20, #22).

Root cause: the NGSIEM/LogScale start_search API rejects ISO-8601 timestamps
with HTTP 400 "No content was received for this request". It accepts only
relative durations ('1d') or epoch milliseconds. ngsiem_query previously
passed the raw value straight through, so any absolute timestamp 400'd, and
there was no end_time parameter at all.
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
    """Make start_search/get_search_status return a completed search."""
    mock_falcon.start_search.return_value = {
        "status_code": 200,
        "resources": {"id": "SID-1"},
    }
    mock_falcon.get_search_status.return_value = {
        "status_code": 200,
        "body": {"done": True, "cancelled": False, "events": events or []},
    }


class TestToEpochMs:
    def test_iso8601_with_z_converts_to_epoch_ms(self, ngsiem_module):
        # 2026-05-15T13:00:00Z == 1778850000 s == 1778850000000 ms
        assert ngsiem_module._to_epoch_ms("2026-05-15T13:00:00Z") == "1778850000000"

    def test_epoch_seconds_promoted_to_millis(self, ngsiem_module):
        assert ngsiem_module._to_epoch_ms("1747314000") == "1747314000000"

    def test_epoch_millis_passed_through(self, ngsiem_module):
        assert ngsiem_module._to_epoch_ms("1747314000000") == "1747314000000"


class TestExecuteQueryTimeParams:
    def test_iso_start_time_sent_as_epoch_ms_not_iso(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon)
        ngsiem_module._execute_query("#repo=x | head(1)", start_time="2026-05-15T13:00:00Z")
        _, kwargs = ngsiem_module.falcon.start_search.call_args
        assert kwargs["start"] == "1778850000000"

    def test_end_time_sent_as_epoch_ms(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon)
        ngsiem_module._execute_query(
            "#repo=x | head(1)",
            start_time="2026-05-15T13:00:00Z",
            end_time="2026-05-15T15:00:00Z",
        )
        _, kwargs = ngsiem_module.falcon.start_search.call_args
        assert kwargs["start"] == "1778850000000"
        assert kwargs["end"] == "1778857200000"

    def test_relative_time_range_passed_through_without_end(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon)
        ngsiem_module._execute_query("#repo=x | head(1)", time_range="7d")
        _, kwargs = ngsiem_module.falcon.start_search.call_args
        assert kwargs["start"] == "7d"
        assert kwargs.get("end") is None


class TestNgsiemQueryDisplay:
    def test_display_reflects_relative_time_range(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon)
        out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x | head(1)", time_range="7d"))
        assert "Time Range: 7d" in out

    def test_display_reflects_absolute_window(self, ngsiem_module):
        _wire_search(ngsiem_module.falcon)
        out = asyncio.run(
            ngsiem_module.ngsiem_query(
                "#repo=x | head(1)",
                start_time="2026-05-15T13:00:00Z",
                end_time="2026-05-15T15:00:00Z",
            )
        )
        assert "2026-05-15T13:00:00Z" in out
        assert "2026-05-15T15:00:00Z" in out


class TestSignature:
    def test_ngsiem_query_exposes_time_range_start_end(self, ngsiem_module):
        params = inspect.signature(ngsiem_module.ngsiem_query).parameters
        assert "time_range" in params
        assert "start_time" in params
        assert "end_time" in params
