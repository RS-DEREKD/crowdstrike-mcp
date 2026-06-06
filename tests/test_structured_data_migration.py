"""Regression tests ensuring large-response tools use the in-memory structured
data path (ref_id via ResponseStore) instead of the legacy temp-file fallback.

The legacy fallback path writes response text to disk under
`$TMPDIR/crowdstrike-mcp/`, which tripped CodeQL alert
`py/clear-text-storage-sensitive-data` for PII-adjacent fields (MAC address,
IP, hostname) returned by host/spotlight/RTR/etc. tools.

Each test forces a response large enough to exceed
`LARGE_RESPONSE_THRESHOLD` and asserts that:
  - output contains the structured ref_id marker ("resp_" / "Structured data stored as")
  - output does NOT contain the legacy temp-file marker ("Full output saved to:")
"""

from __future__ import annotations

import json

from crowdstrike_mcp.response_store import ResponseStore
from crowdstrike_mcp.utils import LARGE_RESPONSE_THRESHOLD

STRUCTURED_MARKER = "Structured data stored as"
LEGACY_MARKER = "Full output saved to:"


def _bulky_resource(idx: int) -> dict:
    """A single fake resource big enough that a handful overflow the threshold."""
    return {
        "id": f"vertex-{idx}",
        "type": "device",
        "properties": {
            "hostname": f"HOST-{idx}",
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "local_ip": "10.0.0.1",
            "notes": "x" * 2000,
        },
    }


def _large_resources(count: int = 20) -> list[dict]:
    resources = [_bulky_resource(i) for i in range(count)]
    # Sanity: make sure the rendered JSON comfortably exceeds the threshold.
    assert len(json.dumps(resources)) > LARGE_RESPONSE_THRESHOLD
    return resources


class TestLegacyFallbackRemoved:
    """format_text_response must never write to disk, even without structured_data.

    The legacy temp-file fallback (writing $TMPDIR/crowdstrike-mcp/*.txt) was the
    source of CodeQL alert py/clear-text-storage-sensitive-data. All known callers
    now pass structured_data, so the fallback is removed. A large response without
    structured_data must still be handled gracefully — truncated, not written out.
    """

    def test_large_text_without_structured_data_does_not_write_file(self):
        import crowdstrike_mcp.utils as utils_mod
        from crowdstrike_mcp.utils import format_text_response

        # The legacy fallback machinery must be gone entirely.
        assert not hasattr(utils_mod, "_write_response_file")
        assert not hasattr(utils_mod, "_cleanup_old_files")
        assert not hasattr(utils_mod, "MCP_OUTPUT_DIR")

        large_text = "x" * (LARGE_RESPONSE_THRESHOLD + 1)
        result = format_text_response(large_text, raw=True)

        # No temp-file path leaked into output.
        assert LEGACY_MARKER not in result
        assert "/tmp/" not in result
        # Response is still usable — truncation is communicated.
        assert "TRUNCATED" in result


class TestIdentityInvestigateEntityStructuredData:
    """idp.identity_investigate_entity(include_raw=True) must route large graphs through ResponseStore."""

    def test_include_raw_large_result_populates_response_store(self):
        import asyncio
        from unittest.mock import MagicMock, patch

        with patch("crowdstrike_mcp.modules.idp.IdentityProtection"):
            from crowdstrike_mcp.modules.idp import IDPModule

            module = IDPModule(MagicMock())

        # Stub resolution and investigation to return a large payload.
        module._resolve_entities = lambda kwargs: ["ent-1", "ent-2"]
        big_timeline = [
            {
                "eventId": f"evt-{i}",
                "timestamp": "2026-04-20T00:00:00Z",
                "eventType": "LOGIN",
                "eventSeverity": "MEDIUM",
                "detail": "x" * 500,
            }
            for i in range(80)
        ]
        module._execute_investigation = lambda inv_type, resolved, params: {
            "timelines": [{"entity_id": resolved[0], "timeline": big_timeline}],
        }

        output = asyncio.run(
            module.identity_investigate_entity(
                entity_names=["Administrator"],
                investigation_types=["timeline_analysis"],
                include_raw=True,
            )
        )
        assert STRUCTURED_MARKER in output
        assert LEGACY_MARKER not in output
        assert ResponseStore.list_refs()


class TestCloudRiskTimelineStructuredData:
    """cloud_security.cloud_get_risk_timeline(full=True) must route large JSON through ResponseStore."""

    def test_full_mode_large_timeline_populates_response_store(self):
        import asyncio
        from unittest.mock import MagicMock, patch

        with patch("crowdstrike_mcp.modules.cloud_security.CloudSecurity"):
            from crowdstrike_mcp.modules.cloud_security import CloudSecurityModule

            module = CloudSecurityModule(MagicMock())

        risks = [
            {
                "id": f"risk-{i}",
                "severity": "high",
                "rule_name": f"rule-{i}",
                "current_status": "open",
                "first_seen": "2026-04-01T00:00:00Z",
                "last_seen": "2026-04-20T00:00:00Z",
                "reason": "x" * 1500,
            }
            for i in range(40)
        ]
        module._get_risk_timeline = lambda **kwargs: {
            "success": True,
            "asset": {"id": kwargs["asset_id"], "type": "ec2", "cloud_provider": "aws"},
            "risks": risks,
            "changes": [],
            "total_risks": len(risks),
        }

        output = asyncio.run(module.cloud_get_risk_timeline(asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-abc", full=True))
        assert STRUCTURED_MARKER in output
        assert LEGACY_MARKER not in output
        assert ResponseStore.list_refs()


class TestHostsHistoryStructuredData:
    """hosts.host_login_history / host_network_history must route large results through ResponseStore."""

    def _make_module(self):
        from unittest.mock import MagicMock, patch

        with patch("crowdstrike_mcp.modules.hosts.Hosts"):
            from crowdstrike_mcp.modules.hosts import HostsModule

            return HostsModule(MagicMock())

    def _history_entries(self, count: int) -> list[dict]:
        return [
            {
                "device_id": "dev-1",
                "user_name": f"user-{i}",
                "login_time": f"2026-04-{i % 28 + 1:02d}T12:00:00Z",
                "local_ip": "10.0.0.1",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "notes": "x" * 500,
            }
            for i in range(count)
        ]

    def test_login_history_large_populates_response_store(self):
        import asyncio

        module = self._make_module()
        entries = self._history_entries(60)
        module._get_login_history = lambda device_id: {
            "success": True,
            "device_id": device_id,
            "count": len(entries),
            "login_history": entries,
        }

        output = asyncio.run(module.host_login_history(device_id="dev-1"))
        assert STRUCTURED_MARKER in output
        assert LEGACY_MARKER not in output
        refs = ResponseStore.list_refs()
        assert refs and refs[0]["record_count"] == len(entries)

    def test_network_history_large_populates_response_store(self):
        import asyncio

        module = self._make_module()
        entries = self._history_entries(60)
        module._get_network_history = lambda device_id: {
            "success": True,
            "device_id": device_id,
            "count": len(entries),
            "network_history": entries,
        }

        output = asyncio.run(module.host_network_history(device_id="dev-1"))
        assert STRUCTURED_MARKER in output
        assert LEGACY_MARKER not in output
        refs = ResponseStore.list_refs()
        assert refs and refs[0]["record_count"] == len(entries)


class TestSpotlightVulnListStructuredData:
    """spotlight._format_vuln_list must route large vuln lists through ResponseStore."""

    def test_large_vuln_list_populates_response_store(self):
        from unittest.mock import MagicMock, patch

        with patch("crowdstrike_mcp.modules.spotlight.SpotlightVulnerabilities"):
            from crowdstrike_mcp.modules.spotlight import SpotlightModule

            module = SpotlightModule(MagicMock())

        vulns = [
            {
                "id": f"vuln-{i}",
                "cve_id": f"CVE-2025-{i:04d}",
                "severity": "HIGH",
                "base_score": 8.1,
                "exploit_status": 60,
                "status": "open",
                "hostname": f"HOST-{i}",
                "platform": "Windows",
                "created_timestamp": "2026-04-01T00:00:00Z",
                "apps": [f"app-{j}" for j in range(5)],
                "remediation_ids": [],
            }
            for i in range(120)
        ]
        result = {"vulns": vulns, "total": len(vulns), "after": None}

        output = module._format_vuln_list(result, header="Test header")
        assert len(output) >= 0  # sanity
        assert STRUCTURED_MARKER in output
        assert LEGACY_MARKER not in output
        refs = ResponseStore.list_refs()
        assert refs and refs[0]["record_count"] == len(vulns)


class TestRtrCheckCommandStatusStructuredData:
    """rtr_check_command_status must route large stdout/stderr through ResponseStore."""

    def test_large_command_output_populates_response_store(self, monkeypatch):
        import asyncio
        from unittest.mock import MagicMock, patch

        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse") as MockRTR:
            MockRTR.return_value = MagicMock()
            from crowdstrike_mcp.modules.rtr import RTRModule

            module = RTRModule(MagicMock())

        # Force a multi-KB stdout so the response overflows the threshold.
        large_stdout = "x" * (LARGE_RESPONSE_THRESHOLD + 1)
        module._check_command_status = lambda cloud_request_id, session_id: {
            "success": True,
            "resource": {
                "complete": True,
                "stdout": large_stdout,
                "stderr": "",
                "cloud_request_id": cloud_request_id,
                "session_id": session_id,
            },
        }

        result = asyncio.run(module.rtr_check_command_status(cloud_request_id="req-1", session_id="sess-1"))
        assert STRUCTURED_MARKER in result
        assert LEGACY_MARKER not in result
        assert ResponseStore.list_refs()


class TestThreatGraphStructuredData:
    """threat_graph._handle_list_response must route large responses through ResponseStore."""

    def test_large_list_response_populates_response_store(self):
        from crowdstrike_mcp.modules.threat_graph import _handle_list_response

        fake_response = {
            "status_code": 200,
            "body": {"resources": _large_resources(), "meta": {"pagination": {"total": 20}}},
        }
        result = _handle_list_response(fake_response, "get vertices", "entities_vertices_getv2", "Threat Graph Vertices")

        assert STRUCTURED_MARKER in result
        assert LEGACY_MARKER not in result
        # A record was actually stored and is retrievable.
        refs = ResponseStore.list_refs()
        assert len(refs) == 1
        assert refs[0]["record_count"] == 20
