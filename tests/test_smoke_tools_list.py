"""Smoke tests for MCP tool registration — verifies tool visibility with and without allow_writes."""

import os
import sys
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# FalconPy service classes that modules import and instantiate in __init__.
# We patch these so no real auth is required.
_FALCONPY_PATCHES = [
    "modules.alerts.Alerts",
    "modules.cao_hunting.CAOHunting",
    "modules.case_management.CaseManagement",
    "modules.cloud_registration.CSPMRegistration",
    "modules.cloud_security.CloudSecurity",
    "modules.cloud_security.CloudSecurityDetections",
    "modules.cloud_security.CloudSecurityAssets",
    "modules.correlation.CorrelationRules",
    "modules.correlation.APIHarnessV2",
    "modules.hosts.Hosts",
    "modules.ngsiem.NGSIEM",
    "modules.response.Hosts",
]

# Expected tool sets — update these when adding/removing tools
EXPECTED_READ_TOOLS = {
    "get_alerts",
    "alert_analysis",
    "ngsiem_alert_analysis",
    "ngsiem_query",
    "host_lookup",
    "host_login_history",
    "host_network_history",
    "correlation_list_rules",
    "correlation_get_rule",
    "correlation_export_rule",
    "case_query",
    "case_get",
    "case_get_fields",
    "cao_search_queries",
    "cao_get_queries",
    "cao_search_guides",
    "cao_get_guides",
    "cao_aggregate",
    "cloud_list_accounts",
    "cloud_policy_settings",
    "cloud_get_risks",
    "cloud_get_iom_detections",
    "cloud_query_assets",
    "cloud_compliance_by_account",
}

EXPECTED_WRITE_TOOLS = {
    "update_alert_status",
    "correlation_update_rule",
    "correlation_import_to_iac",
    "host_contain",
    "host_lift_containment",
    "case_create",
    "case_update",
    "case_add_alert_evidence",
    "case_add_event_evidence",
    "case_add_tags",
    "case_delete_tags",
    "case_upload_file",
}


@contextmanager
def _patch_falconpy():
    """Patch all FalconPy service classes to MagicMock so no real auth is needed."""
    with (
        patch.multiple("modules.alerts", Alerts=MagicMock()),
        patch.multiple("modules.cao_hunting", CAOHunting=MagicMock()),
        patch.multiple("modules.case_management", CaseManagement=MagicMock()),
        patch.multiple("modules.cloud_registration", CSPMRegistration=MagicMock()),
        patch.multiple("modules.cloud_security", CloudSecurity=MagicMock(), CloudSecurityDetections=MagicMock(), CloudSecurityAssets=MagicMock()),
        patch.multiple("modules.correlation", CorrelationRules=MagicMock(), APIHarnessV2=MagicMock()),
        patch.multiple("modules.hosts", Hosts=MagicMock()),
        patch.multiple("modules.ngsiem", NGSIEM=MagicMock()),
        patch.multiple("modules.response", Hosts=MagicMock()),
    ):
        yield


def _collect_tools(mock_client, allow_writes: bool) -> set[str]:
    """Instantiate all modules and collect registered tool names."""
    from registry import get_available_modules

    with _patch_falconpy():
        modules = get_available_modules(mock_client, allow_writes=allow_writes)

    mock_server = MagicMock()
    mock_server.tool.return_value = lambda fn: fn

    for mod in modules:
        mod.register_tools(mock_server)

    return {name for mod in modules for name in mod.tools}


class TestToolsListSmoke:
    """Verify tool registration matches expected sets."""

    def test_readonly_mode_registers_only_read_tools(self, mock_client):
        """Default mode: only read tools visible, zero write tools."""
        tools = _collect_tools(mock_client, allow_writes=False)

        # All read tools should be present
        missing_read = EXPECTED_READ_TOOLS - tools
        assert not missing_read, f"Read tools missing in readonly mode: {missing_read}"

        # No write tools should be present
        leaked_write = EXPECTED_WRITE_TOOLS & tools
        assert not leaked_write, f"Write tools leaked in readonly mode: {leaked_write}"

    def test_write_mode_registers_all_tools(self, mock_client):
        """With allow_writes=True: all read + write tools visible."""
        tools = _collect_tools(mock_client, allow_writes=True)

        # All read tools should be present
        missing_read = EXPECTED_READ_TOOLS - tools
        assert not missing_read, f"Read tools missing in write mode: {missing_read}"

        # All write tools should be present
        missing_write = EXPECTED_WRITE_TOOLS - tools
        assert not missing_write, f"Write tools missing in write mode: {missing_write}"

    def test_no_unexpected_tools(self, mock_client):
        """No tools exist that aren't in either expected set (catches untracked tools)."""
        tools = _collect_tools(mock_client, allow_writes=True)
        all_expected = EXPECTED_READ_TOOLS | EXPECTED_WRITE_TOOLS
        unexpected = tools - all_expected
        assert not unexpected, f"Unexpected tools registered (add to expected sets): {unexpected}"

    def test_write_tools_not_in_read_set(self):
        """Sanity: no overlap between read and write expected sets."""
        overlap = EXPECTED_READ_TOOLS & EXPECTED_WRITE_TOOLS
        assert not overlap, f"Tool in both read and write sets: {overlap}"
