"""Tests for tool-level read/write permission gating."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_server():
    """Create a mock FastMCP server."""
    server = MagicMock()
    # server.tool() returns a decorator, which is called with the method
    server.tool.return_value = lambda fn: fn
    return server


@pytest.fixture
def base_module(mock_client):
    """Create a concrete BaseModule subclass for testing."""
    from crowdstrike_mcp.modules.base import BaseModule

    class TestModule(BaseModule):
        def register_tools(self, server):
            pass

    module = TestModule(mock_client)
    return module


class TestToolTierGating:
    """Verify _add_tool() respects tier and allow_writes."""

    def test_read_tool_registers_when_writes_disabled(self, base_module, mock_server):
        """Read tools always register regardless of allow_writes."""
        base_module.allow_writes = False
        base_module._add_tool(mock_server, lambda: None, name="get_alerts", tier="read")
        assert "get_alerts" in base_module.tools
        mock_server.tool.assert_called_once()

    def test_read_tool_registers_when_writes_enabled(self, base_module, mock_server):
        """Read tools register when writes are enabled too."""
        base_module.allow_writes = True
        base_module._add_tool(mock_server, lambda: None, name="get_alerts", tier="read")
        assert "get_alerts" in base_module.tools

    def test_write_tool_skipped_when_writes_disabled(self, base_module, mock_server):
        """Write tools are NOT registered when allow_writes is False."""
        base_module.allow_writes = False
        base_module._add_tool(mock_server, lambda: None, name="update_alert_status", tier="write")
        assert "update_alert_status" not in base_module.tools
        mock_server.tool.assert_not_called()

    def test_write_tool_registers_when_writes_enabled(self, base_module, mock_server):
        """Write tools register when allow_writes is True."""
        base_module.allow_writes = True
        base_module._add_tool(mock_server, lambda: None, name="update_alert_status", tier="write")
        assert "update_alert_status" in base_module.tools
        mock_server.tool.assert_called_once()

    def test_default_tier_is_read(self, base_module, mock_server):
        """Tools without explicit tier default to read (always register)."""
        base_module.allow_writes = False
        base_module._add_tool(mock_server, lambda: None, name="ngsiem_query")
        assert "ngsiem_query" in base_module.tools

    def test_invalid_tier_raises_error(self, base_module, mock_server):
        """Typos in tier value raise ValueError immediately."""
        with pytest.raises(ValueError, match="Invalid tier"):
            base_module._add_tool(mock_server, lambda: None, name="bad_tool", tier="writ")

    def test_allow_writes_defaults_to_false(self, base_module):
        """BaseModule.allow_writes defaults to False."""
        assert base_module.allow_writes is False


class TestRegistryAllowWrites:
    """Verify registry passes allow_writes to module instances."""

    def test_allow_writes_false_by_default(self, mock_client):
        """Modules get allow_writes=False when not specified."""
        with patch("crowdstrike_mcp.registry.discover_module_classes") as mock_discover:
            from crowdstrike_mcp.modules.base import BaseModule

            class FakeModule(BaseModule):
                def register_tools(self, server):
                    pass

            mock_discover.return_value = [FakeModule]

            from crowdstrike_mcp.registry import get_available_modules

            modules = get_available_modules(mock_client, allow_writes=False)
            assert len(modules) == 1
            assert modules[0].allow_writes is False

    def test_allow_writes_true_propagates(self, mock_client):
        """Modules get allow_writes=True when specified."""
        with patch("crowdstrike_mcp.registry.discover_module_classes") as mock_discover:
            from crowdstrike_mcp.modules.base import BaseModule

            class FakeModule(BaseModule):
                def register_tools(self, server):
                    pass

            mock_discover.return_value = [FakeModule]

            from crowdstrike_mcp.registry import get_available_modules

            modules = get_available_modules(mock_client, allow_writes=True)
            assert len(modules) == 1
            assert modules[0].allow_writes is True
