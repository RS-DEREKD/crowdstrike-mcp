"""Tests for endpoint_get_behaviors deprecation wrapper."""

import sys
import os
import asyncio
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def endpoint_module(mock_client):
    """Create EndpointModule with mocked Detects API."""
    with patch("modules.endpoint.Detects"):
        from modules.endpoint import EndpointModule
        return EndpointModule(mock_client)


class TestEndpointDeprecation:
    """Verify endpoint_get_behaviors returns deprecation guidance."""

    def test_returns_deprecation_message(self, endpoint_module):
        result = asyncio.get_event_loop().run_until_complete(
            endpoint_module.endpoint_get_behaviors(
                detection_ids=["cid:ind:cid:detect123"]
            )
        )
        assert "DEPRECATED" in result
        assert "Detects API" in result
        assert "ngsiem_query" in result

    def test_extracts_device_id_from_composite(self, endpoint_module):
        result = asyncio.get_event_loop().run_until_complete(
            endpoint_module.endpoint_get_behaviors(
                detection_ids=["cust123:ind:device456:detect789"]
            )
        )
        assert "DEPRECATED" in result
        assert "device456" in result

    def test_handles_multiple_ids(self, endpoint_module):
        result = asyncio.get_event_loop().run_until_complete(
            endpoint_module.endpoint_get_behaviors(
                detection_ids=[
                    "cust123:ind:devA:det1",
                    "cust123:ind:devB:det2",
                ]
            )
        )
        assert "devA" in result
        assert "devB" in result

    def test_handles_non_composite_ids(self, endpoint_module):
        """Non-composite IDs should not crash, just show deprecation."""
        result = asyncio.get_event_loop().run_until_complete(
            endpoint_module.endpoint_get_behaviors(
                detection_ids=["just-a-plain-id"]
            )
        )
        assert "DEPRECATED" in result

    def test_does_not_call_detects_api(self, endpoint_module):
        """The deprecated tool should NOT make any API calls."""
        asyncio.get_event_loop().run_until_complete(
            endpoint_module.endpoint_get_behaviors(
                detection_ids=["cid:ind:cid:det1"]
            )
        )
        endpoint_module.detects.get_detect_summaries.assert_not_called()

    def test_tool_is_still_registered(self, endpoint_module):
        """The tool should still register so callers get guidance."""
        server = MagicMock()
        endpoint_module.register_tools(server)
        assert "endpoint_get_behaviors" in endpoint_module.tools
