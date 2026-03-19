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
from utils import format_text_response, extract_detection_id

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
        """Get detailed behavior summaries for endpoint detections."""
        cleaned_ids = [extract_detection_id(did) for did in detection_ids]
        result = self._get_behaviors(cleaned_ids)

        if not result.get("success"):
            return format_text_response(
                f"Failed to get behaviors: {result.get('error')}", raw=True,
            )

        detections = result.get("detections", [])
        lines = [f"Endpoint Detection Behaviors ({result['count']} detections)", ""]

        for detection in detections:
            lines.append(f"### Detection: {detection['detection_id']}")
            lines.append(f"- Status: {detection['status']}")
            lines.append(f"- Max Severity: {detection['max_severity_displayname']}")
            device = detection.get("device", {})
            if device:
                lines.append(
                    f"- Device: {device.get('hostname', 'N/A')} "
                    f"({device.get('platform_name', 'N/A')})"
                )
            lines.append("")

            for j, behavior in enumerate(detection.get("behaviors", []), 1):
                lines.append(f"#### Behavior {j}: {behavior.get('display_name', 'N/A')}")
                lines.append(f"- File: {behavior.get('filename', 'N/A')}")
                lines.append(f"- Path: {behavior.get('filepath', 'N/A')}")
                cmdline = behavior.get("cmdline", "")
                if cmdline:
                    lines.append(f"- Command: `{cmdline}`")
                parent_cmd = behavior.get("parent_details", {}).get("parent_cmdline", "")
                if parent_cmd:
                    lines.append(f"- Parent Command: `{parent_cmd}`")
                lines.append(
                    f"- MITRE: {behavior.get('tactic', 'N/A')} / "
                    f"{behavior.get('technique', 'N/A')} "
                    f"({behavior.get('technique_id', '')})"
                )
                lines.append(f"- Severity: {behavior.get('severity', 'N/A')}")
                if behavior.get("description"):
                    lines.append(f"- Description: {behavior['description']}")
                if behavior.get("sha256"):
                    lines.append(f"- SHA256: {behavior['sha256']}")
                lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    # ------------------------------------------------------------------
    # Internal methods (logic from handlers/endpoint_detections.py)
    # ------------------------------------------------------------------

    def _get_behaviors(self, detection_ids):
        try:
            response = self.detects.get_detect_summaries(ids=detection_ids)
            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to get detection summaries", operation="get_detect_summaries")}

            resources = response.get("body", {}).get("resources", [])
            if not resources:
                return {"success": False, "error": f"No detection summaries found for IDs: {detection_ids}"}

            summaries = []
            for detection in resources:
                summary = {
                    "detection_id": detection.get("detection_id", ""),
                    "status": detection.get("status", ""),
                    "max_severity_displayname": detection.get("max_severity_displayname", ""),
                    "max_confidence": detection.get("max_confidence", 0),
                    "first_behavior": detection.get("first_behavior", ""),
                    "last_behavior": detection.get("last_behavior", ""),
                    "device": self._extract_device_info(detection.get("device", {})),
                    "behaviors": [],
                }

                for behavior in detection.get("behaviors", []):
                    summary["behaviors"].append({
                        "behavior_id": behavior.get("behavior_id", ""),
                        "filename": behavior.get("filename", ""),
                        "filepath": behavior.get("filepath", ""),
                        "cmdline": behavior.get("cmdline", ""),
                        "parent_details": {
                            "parent_cmdline": behavior.get("parent_details", {}).get("parent_cmdline", ""),
                            "parent_process_graph_id": behavior.get("parent_details", {}).get("parent_process_graph_id", ""),
                        },
                        "pattern_disposition_details": behavior.get("pattern_disposition_details", {}),
                        "severity": behavior.get("severity", 0),
                        "confidence": behavior.get("confidence", 0),
                        "tactic": behavior.get("tactic", ""),
                        "tactic_id": behavior.get("tactic_id", ""),
                        "technique": behavior.get("technique", ""),
                        "technique_id": behavior.get("technique_id", ""),
                        "display_name": behavior.get("display_name", ""),
                        "description": behavior.get("description", ""),
                        "scenario": behavior.get("scenario", ""),
                        "objective": behavior.get("objective", ""),
                        "sha256": behavior.get("sha256", ""),
                        "md5": behavior.get("md5", ""),
                        "user_name": behavior.get("user_name", ""),
                        "timestamp": behavior.get("timestamp", ""),
                    })

                summaries.append(summary)

            return {"success": True, "detections": summaries, "count": len(summaries)}
        except Exception as e:
            return {"success": False, "error": f"Error getting behaviors: {str(e)}"}

    def get_behaviors_for_alert(self, alert):
        """Get behaviors for an alert (used by AlertsModule for endpoint enrichment)."""
        composite_id = alert.get("composite_id", "")
        if not composite_id:
            return {"success": False, "error": "No composite_id in alert data"}

        result = self._get_behaviors([composite_id])
        if result.get("success") and result.get("detections"):
            all_behaviors = []
            for detection in result["detections"]:
                all_behaviors.extend(detection.get("behaviors", []))
            return {"success": True, "behaviors": all_behaviors}

        parts = composite_id.split(":")
        if len(parts) >= 4 and parts[1] == "ind":
            detect_id = parts[-1]
            result = self._get_behaviors([detect_id])
            if result.get("success") and result.get("detections"):
                all_behaviors = []
                for detection in result["detections"]:
                    all_behaviors.extend(detection.get("behaviors", []))
                return {"success": True, "behaviors": all_behaviors}

        return {"success": False, "error": f"Could not retrieve behaviors for alert {composite_id}"}

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
