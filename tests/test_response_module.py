"""Tests for ResponseModule — host containment with safety model."""

import sys
import os
import json
import asyncio
import tempfile
from unittest.mock import MagicMock, patch, mock_open

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


MOCK_DEVICE = {
    "device_id": "abc123",
    "hostname": "PROD-WEB-03",
    "platform_name": "Windows",
    "os_version": "Windows Server 2022",
    "last_seen": "2026-03-26T14:00:00Z",
    "containment_status": "normal",
    "status": "normal",
    "tags": ["SensorGroupingTags/Production", "SensorGroupingTags/Web-Tier"],
}

MOCK_CONTAINED_DEVICE = {
    **MOCK_DEVICE,
    "containment_status": "contained",
}

MOCK_DNC_DEVICE = {
    **MOCK_DEVICE,
    "hostname": "DC-PRIMARY",
    "tags": ["SensorGroupingTags/Critical-Infrastructure"],
}


@pytest.fixture
def response_module(mock_client):
    """Create ResponseModule with mocked Hosts API."""
    with patch("modules.response.Hosts") as MockHosts:
        mock_hosts = MagicMock()
        MockHosts.return_value = mock_hosts
        from modules.response import ResponseModule
        module = ResponseModule(mock_client)
        module.hosts = mock_hosts
        return module


def _mock_device_lookup(hosts_mock, device_data):
    """Configure mock to return a device from get_device_details."""
    hosts_mock.get_device_details.return_value = {
        "status_code": 200,
        "body": {"resources": [device_data]},
    }


class TestHostContainPreFlight:
    """Pre-flight validation before containment."""

    def test_preview_returns_device_details(self, response_module):
        _mock_device_lookup(response_module.hosts, MOCK_DEVICE)
        result = asyncio.get_event_loop().run_until_complete(
            response_module.host_contain(
                device_id="abc123",
                reason="Cryptominer confirmed",
                confirm=False,
            )
        )
        assert "CONTAINMENT REQUEST" in result
        assert "PROD-WEB-03" in result
        assert "abc123" in result
        assert "confirm=True" in result.lower() or "confirm" in result.lower()

    def test_already_contained_returns_noop(self, response_module):
        _mock_device_lookup(response_module.hosts, MOCK_CONTAINED_DEVICE)
        result = asyncio.get_event_loop().run_until_complete(
            response_module.host_contain(
                device_id="abc123",
                reason="Cryptominer confirmed",
                confirm=False,
            )
        )
        assert "already contained" in result.lower()

    def test_excluded_tag_blocks_containment(self, response_module):
        _mock_device_lookup(response_module.hosts, MOCK_DNC_DEVICE)
        result = asyncio.get_event_loop().run_until_complete(
            response_module.host_contain(
                device_id="abc123",
                reason="Test",
                confirm=True,
            )
        )
        assert "excluded" in result.lower() or "refused" in result.lower()

    def test_device_not_found_returns_error(self, response_module):
        response_module.hosts.get_device_details.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        result = asyncio.get_event_loop().run_until_complete(
            response_module.host_contain(
                device_id="nonexistent",
                reason="Test",
                confirm=False,
            )
        )
        assert "not found" in result.lower() or "error" in result.lower()


class TestHostContainExecution:
    """Actual containment execution with confirm=True."""

    def test_contain_succeeds_with_confirm(self, response_module):
        _mock_device_lookup(response_module.hosts, MOCK_DEVICE)
        response_module.hosts.perform_action.return_value = {
            "status_code": 202,
            "body": {"resources": [{"id": "abc123"}]},
        }
        result = asyncio.get_event_loop().run_until_complete(
            response_module.host_contain(
                device_id="abc123",
                reason="Cryptominer confirmed",
                confirm=True,
            )
        )
        assert "contained" in result.lower() or "success" in result.lower()
        response_module.hosts.perform_action.assert_called_once()
        call_kwargs = response_module.hosts.perform_action.call_args
        assert call_kwargs[1]["action_name"] == "contain" or \
               call_kwargs.kwargs.get("action_name") == "contain"

    def test_contain_api_failure(self, response_module):
        _mock_device_lookup(response_module.hosts, MOCK_DEVICE)
        response_module.hosts.perform_action.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Insufficient permissions"}]},
        }
        result = asyncio.get_event_loop().run_until_complete(
            response_module.host_contain(
                device_id="abc123",
                reason="Test",
                confirm=True,
            )
        )
        assert "fail" in result.lower() or "error" in result.lower()


class TestHostLiftContainment:
    """Lift containment flow."""

    def test_preview_shows_contained_device(self, response_module):
        _mock_device_lookup(response_module.hosts, MOCK_CONTAINED_DEVICE)
        result = asyncio.get_event_loop().run_until_complete(
            response_module.host_lift_containment(
                device_id="abc123",
                reason="Investigation complete",
                confirm=False,
            )
        )
        assert "LIFT CONTAINMENT" in result
        assert "PROD-WEB-03" in result

    def test_not_contained_returns_noop(self, response_module):
        _mock_device_lookup(response_module.hosts, MOCK_DEVICE)
        result = asyncio.get_event_loop().run_until_complete(
            response_module.host_lift_containment(
                device_id="abc123",
                reason="Test",
                confirm=False,
            )
        )
        assert "not contained" in result.lower()

    def test_lift_succeeds_with_confirm(self, response_module):
        _mock_device_lookup(response_module.hosts, MOCK_CONTAINED_DEVICE)
        response_module.hosts.perform_action.return_value = {
            "status_code": 202,
            "body": {"resources": [{"id": "abc123"}]},
        }
        result = asyncio.get_event_loop().run_until_complete(
            response_module.host_lift_containment(
                device_id="abc123",
                reason="Investigation complete",
                confirm=True,
            )
        )
        assert "lifted" in result.lower() or "success" in result.lower()


class TestContainmentAuditLog:
    """Verify containment actions are logged."""

    def test_contain_writes_audit_entry(self, response_module, tmp_path):
        log_file = tmp_path / "containment_audit.log"
        response_module._audit_log_path = str(log_file)

        _mock_device_lookup(response_module.hosts, MOCK_DEVICE)
        response_module.hosts.perform_action.return_value = {
            "status_code": 202,
            "body": {"resources": [{"id": "abc123"}]},
        }
        asyncio.get_event_loop().run_until_complete(
            response_module.host_contain(
                device_id="abc123",
                reason="Cryptominer confirmed",
                confirm=True,
            )
        )
        assert log_file.exists()
        log_content = log_file.read_text()
        entry = json.loads(log_content.strip().split("\n")[-1])
        assert entry["action"] == "contain"
        assert entry["target"]["device_id"] == "abc123"
        assert entry["reason"] == "Cryptominer confirmed"


class TestToolRegistration:
    """Verify tools register correctly."""

    def test_registers_both_tools(self, response_module):
        server = MagicMock()
        response_module.register_tools(server)
        assert "host_contain" in response_module.tools
        assert "host_lift_containment" in response_module.tools
