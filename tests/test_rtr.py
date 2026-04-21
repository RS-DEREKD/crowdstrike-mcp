"""Tests for Real-Time Response (read-only) module."""

import asyncio
import json
import os
from unittest.mock import MagicMock, patch

import pytest


class TestRTRScopes:
    """Scope mappings for the 7 RTR operations exist in api_scopes."""

    @pytest.mark.parametrize(
        "op, scope",
        [
            ("RTR_InitSession", "real-time-response:write"),
            ("RTR_ListSessions", "real-time-response:read"),
            ("RTR_PulseSession", "real-time-response:write"),
            ("RTR_ExecuteActiveResponderCommand", "real-time-response:write"),
            ("RTR_CheckActiveResponderCommandStatus", "real-time-response:read"),
            ("RTR_GetExtractedFileContents", "real-time-response:read"),
            ("RTR_ListFilesV2", "real-time-response:read"),
        ],
    )
    def test_operation_has_expected_scope(self, op, scope):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes

        assert get_required_scopes(op) == [scope]


class TestRTRModuleImport:
    def test_module_imports(self):
        from crowdstrike_mcp.modules.rtr import RTRModule
        assert RTRModule is not None

    def test_module_uses_real_time_response(self, mock_client):
        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse") as MockRTR:
            MockRTR.return_value = MagicMock()
            from crowdstrike_mcp.modules.rtr import RTRModule

            module = RTRModule(mock_client)
            assert module is not None
            assert module.tools == []  # nothing registered yet


@pytest.fixture
def rtr_module(mock_client, tmp_path):
    """Create RTRModule with RealTimeResponse mocked. Audit log + download dir redirected to tmp."""
    with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse") as MockRTR:
        mock_rtr = MagicMock()
        MockRTR.return_value = mock_rtr
        from crowdstrike_mcp.modules.rtr import RTRModule

        module = RTRModule(mock_client)
        module._service = lambda cls: mock_rtr
        module.falcon = mock_rtr
        # redirect side-effect paths into tmp so tests don't touch the real user config
        module._audit_log_path = str(tmp_path / "rtr_audit.log")
        module._download_dir = str(tmp_path / "rtr_downloads")
        return module


class TestRTRAllowlist:
    def test_default_allowlist_contains_read_only_verbs(self, rtr_module):
        for verb in ["ls", "ps", "reg query", "getfile", "cat", "pwd"]:
            assert verb in rtr_module._allowlist

    def test_default_allowlist_excludes_hard_denied(self, rtr_module):
        for verb in ["cp", "mv", "rm", "put", "runscript", "kill", "mkdir"]:
            assert verb not in rtr_module._allowlist

    def test_extras_env_var_adds_commands(self, mock_client, monkeypatch, tmp_path):
        monkeypatch.setenv("CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED", "tasklist, whoami")
        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse"):
            from crowdstrike_mcp.modules.rtr import RTRModule
            m = RTRModule(mock_client)
            assert "tasklist" in m._allowlist
            assert "whoami" in m._allowlist

    def test_extras_cannot_bypass_hard_deny(self, mock_client, monkeypatch):
        monkeypatch.setenv("CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED", "rm, put, runscript")
        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse"):
            from crowdstrike_mcp.modules.rtr import RTRModule
            m = RTRModule(mock_client)
            assert "rm" not in m._allowlist
            assert "put" not in m._allowlist
            assert "runscript" not in m._allowlist

    def test_validate_command_accepts_allowed(self, rtr_module):
        assert rtr_module._validate_command("ls", "ls C:\\Users") is None

    def test_validate_command_rejects_unlisted(self, rtr_module):
        err = rtr_module._validate_command("tasklist", "tasklist")
        assert err is not None
        assert "allowlist" in err.lower()

    def test_validate_command_rejects_hard_denied(self, rtr_module):
        err = rtr_module._validate_command("rm", "rm -rf /")
        assert err is not None
        assert "hard-denied" in err.lower()

    def test_validate_command_requires_matching_prefix(self, rtr_module):
        err = rtr_module._validate_command("ls", "ps aux")
        assert err is not None
        assert "start with" in err.lower()


class TestRTRInitSession:
    def test_returns_session_id(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 201,
            "body": {
                "resources": [
                    {"session_id": "sess-abc", "device_id": "dev-123", "pwd": "/"}
                ]
            },
        }
        result = asyncio.run(rtr_module.rtr_init_session(device_id="dev-123"))
        assert "sess-abc" in result
        assert "dev-123" in result

    def test_passes_device_id_and_queue_offline(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "s", "device_id": "dev-123"}]},
        }
        asyncio.run(
            rtr_module.rtr_init_session(device_id="dev-123", queue_offline=True)
        )
        rtr_module.falcon.init_session.assert_called_once_with(
            device_id="dev-123", queue_offline=True
        )

    def test_default_queue_offline_false(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "s", "device_id": "dev-123"}]},
        }
        asyncio.run(rtr_module.rtr_init_session(device_id="dev-123"))
        kwargs = rtr_module.falcon.init_session.call_args.kwargs
        assert kwargs["queue_offline"] is False

    def test_requires_device_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_init_session(device_id=""))
        assert "device_id" in result.lower()

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(rtr_module.rtr_init_session(device_id="dev-123"))
        assert "failed" in result.lower()


class TestRTRListSessions:
    def test_returns_session_metadata(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "sess-1",
                        "device_id": "dev-1",
                        "created_at": "2026-04-20T00:00:00Z",
                        "updated_at": "2026-04-20T00:01:00Z",
                        "pwd": "C:\\Users",
                    }
                ]
            },
        }
        result = asyncio.run(rtr_module.rtr_list_sessions(ids=["sess-1"]))
        assert "sess-1" in result
        assert "dev-1" in result

    def test_passes_ids_to_falconpy(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(rtr_module.rtr_list_sessions(ids=["a", "b", "c"]))
        rtr_module.falcon.list_sessions.assert_called_once_with(ids=["a", "b", "c"])

    def test_requires_ids(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_list_sessions(ids=[]))
        assert "ids" in result.lower()

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(rtr_module.rtr_list_sessions(ids=["sess-1"]))
        assert "failed" in result.lower()
