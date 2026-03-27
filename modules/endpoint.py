"""
Endpoint Module — EDR behavior enrichment via the Detects API.

Tools:
  endpoint_get_behaviors — Get detailed EDR behaviors for endpoint detections
"""

from __future__ import annotations

import json
from typing import Annotated, TYPE_CHECKING

from modules.base import BaseModule
from common.errors import format_api_error
from utils import format_text_response, extract_detection_id, parse_composite_id

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

try:
    from falconpy import Detects
    DETECTS_AVAILABLE = True
except ImportError:
    DETECTS_AVAILABLE = False


class EndpointModule(BaseModule):
    """Endpoint detection behavior details via the Detects API."""

    def __init__(self, client):
        super().__init__(client)
        if not DETECTS_AVAILABLE:
            raise ImportError(
                "falconpy.Detects not available. "
                "Ensure crowdstrike-falconpy >= 1.6.0 is installed."
            )
        self.detects = Detects(auth_object=self.client.auth_object)
        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server, self.endpoint_get_behaviors, name="endpoint_get_behaviors",
            description=(
                "Get detailed EDR behaviors for endpoint detections: process trees, "
                "command lines, parent/child processes, MITRE ATT&CK techniques."
            ),
        )

    async def endpoint_get_behaviors(
        self,
        detection_ids: Annotated[list[str], "List of endpoint detection IDs (composite or detect IDs)"],
    ) -> str:
        """DEPRECATED: The Detects API was decommissioned in March 2026."""
        device_ids = []
        for did in detection_ids:
            parsed = parse_composite_id(did)
            parts = parsed.get("parts", [])
            # Composite format: cust_id:ind:device_id:detect_id
            if len(parts) >= 4 and parts[1] == "ind":
                device_ids.append(parts[2])

        guidance = [
            "## endpoint_get_behaviors is DEPRECATED",
            "",
            "The CrowdStrike Detects API was decommissioned in March 2026.",
            "This tool no longer returns data.",
            "",
            "### Alternative: Query raw EDR telemetry via ngsiem_query",
            "",
            "Use `ngsiem_query` to get the same process tree and behavior data:",
            "",
            "```",
            'ngsiem_query(query="#event_simpleName=ProcessRollup2 aid=<device_id> | head(20)", start_time="1d")',
            "```",
            "",
            "For specific event types:",
            "```",
            "# Process execution",
            '#event_simpleName=ProcessRollup2 aid=<device_id> | head(20)',
            "",
            "# DNS requests",
            '#event_simpleName=DnsRequest aid=<device_id> | head(20)',
            "",
            "# Network connections",
            '#event_simpleName=NetworkConnectIP4 aid=<device_id> | head(20)',
            "```",
        ]

        if device_ids:
            guidance.append("")
            guidance.append("### Device IDs extracted from your input")
            guidance.append("")
            for did in device_ids:
                guidance.append(f"- `aid={did}`")

        return format_text_response("\n".join(guidance), raw=True)

    @staticmethod
    def _extract_device_info(device):
        return {
            "device_id": device.get("device_id", ""),
            "hostname": device.get("hostname", ""),
            "platform_name": device.get("platform_name", ""),
            "os_version": device.get("os_version", ""),
            "local_ip": device.get("local_ip", ""),
            "external_ip": device.get("external_ip", ""),
            "machine_domain": device.get("machine_domain", ""),
        }
