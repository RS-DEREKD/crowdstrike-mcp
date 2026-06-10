"""Issue #21: CrowdStrike's update_alerts_v3 returns a SPURIOUS HTTP 500 for
product=thirdparty composite IDs — but the write is actually applied
server-side (confirmed live: status changes stick despite the 500).

So the tool must NOT report failure or skip thirdparty IDs. On a 500 for
thirdparty IDs it re-fetches the alert and, if the requested status was
applied, reports success. Non-thirdparty 500s are still genuine failures
and must not be masked by a verification re-fetch.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

NG = "bf7f666a6cb8419ea851663ecef09c24:ngsiem:bf7f666a6cb8419ea851663ecef09c24:aaaa"
TP = "bf7f666a6cb8419ea851663ecef09c24:thirdparty:bf7f666a6cb8419ea851663ecef09c24:bbbb"


@pytest.fixture
def alerts_module(mock_client):
    with patch("crowdstrike_mcp.modules.alerts.Alerts"):
        from crowdstrike_mcp.modules.alerts import AlertsModule

        module = AlertsModule(mock_client)
        mock_alerts = MagicMock()
        module._service = lambda cls: mock_alerts
        module._mock_alerts = mock_alerts
        return module


def _resp(code, body=None):
    return {"status_code": code, "body": body or {}}


def test_thirdparty_spurious_500_but_status_applied_is_success(alerts_module):
    m = alerts_module._mock_alerts
    m.update_alerts_v3.return_value = _resp(500, {"errors": [{"code": 500, "message": "Internal Server Error"}]})
    # Re-fetch shows the status DID change despite the 500.
    m.get_alerts_v2.return_value = _resp(200, {"resources": [{"status": "closed"}]})

    out = asyncio.run(alerts_module.update_alert_status([TP], "closed"))

    m.get_alerts_v2.assert_called_once()
    assert "Successfully updated 1" in out
    assert "thirdparty" in out.lower()  # surfaces the spurious-500/verified caveat


def test_thirdparty_500_and_status_not_applied_is_failure(alerts_module):
    m = alerts_module._mock_alerts
    m.update_alerts_v3.return_value = _resp(500, {"errors": [{"code": 500, "message": "Internal Server Error"}]})
    # Re-fetch shows the status did NOT change — a real failure.
    m.get_alerts_v2.return_value = _resp(200, {"resources": [{"status": "new"}]})

    out = asyncio.run(alerts_module.update_alert_status([TP], "closed"))

    assert "Failed to update" in out


def test_non_thirdparty_500_is_failure_without_masking(alerts_module):
    m = alerts_module._mock_alerts
    m.update_alerts_v3.return_value = _resp(500, {"errors": [{"code": 500, "message": "Internal Server Error"}]})

    out = asyncio.run(alerts_module.update_alert_status([NG], "closed"))

    assert "Failed to update" in out
    m.get_alerts_v2.assert_not_called()  # do not verify-mask real errors for other products


def test_http_200_success_unchanged(alerts_module):
    m = alerts_module._mock_alerts
    m.update_alerts_v3.return_value = _resp(200, {"meta": {"writes": {"resources_affected": 1}}})

    out = asyncio.run(alerts_module.update_alert_status([NG], "closed"))

    assert "Successfully updated 1" in out
    m.get_alerts_v2.assert_not_called()
