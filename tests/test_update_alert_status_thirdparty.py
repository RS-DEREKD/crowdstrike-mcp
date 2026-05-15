"""Issue #21: update_alert_status must not fire an opaque HTTP 500 at the
CrowdStrike API for thirdparty composite IDs.

The CrowdStrike update_alerts_v3 backend returns HTTP 500 for any
product=thirdparty composite ID (confirmed platform-side defect, see issue
#21). Until CrowdStrike support resolves it, the tool proactively skips
thirdparty IDs with an actionable message and still processes the rest of
a mixed batch.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

NG = "bf7f666a6cb8419ea851663ecef09c24:ngsiem:bf7f666a6cb8419ea851663ecef09c24:aaaa"
TP = "bf7f666a6cb8419ea851663ecef09c24:thirdparty:bf7f666a6cb8419ea851663ecef09c24:bbbb"
TP2 = "bf7f666a6cb8419ea851663ecef09c24:thirdparty:bf7f666a6cb8419ea851663ecef09c24:cccc"


@pytest.fixture
def alerts_module(mock_client):
    with patch("crowdstrike_mcp.modules.alerts.Alerts"):
        from crowdstrike_mcp.modules.alerts import AlertsModule

        module = AlertsModule(mock_client)
        mock_alerts = MagicMock()
        mock_alerts.update_alerts_v3.return_value = {
            "status_code": 200,
            "body": {"meta": {"writes": {"resources_affected": 1}}},
        }
        module._service = lambda cls: mock_alerts
        module._mock_alerts = mock_alerts
        return module


def test_all_thirdparty_does_not_call_api(alerts_module):
    out = asyncio.run(alerts_module.update_alert_status([TP, TP2], "closed"))
    alerts_module._mock_alerts.update_alerts_v3.assert_not_called()
    assert "thirdparty" in out.lower()
    assert "#21" in out  # references the tracking issue
    assert "console" in out.lower()  # tells analyst where to close it


def test_mixed_batch_updates_only_non_thirdparty(alerts_module):
    out = asyncio.run(alerts_module.update_alert_status([NG, TP], "closed"))
    alerts_module._mock_alerts.update_alerts_v3.assert_called_once()
    _, kwargs = alerts_module._mock_alerts.update_alerts_v3.call_args
    assert kwargs["composite_ids"] == [NG]
    assert "1" in out  # one updated
    assert "thirdparty" in out.lower()  # one skipped, surfaced


def test_non_thirdparty_only_unchanged(alerts_module):
    out = asyncio.run(alerts_module.update_alert_status([NG], "closed"))
    _, kwargs = alerts_module._mock_alerts.update_alerts_v3.call_args
    assert kwargs["composite_ids"] == [NG]
    assert "Successfully updated 1" in out
    assert "thirdparty" not in out.lower()
