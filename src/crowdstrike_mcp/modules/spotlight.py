"""
Spotlight Module — vulnerability evaluation logic via the SpotlightEvaluationLogic API.

Tools:
  spotlight_supported_evaluations — Get supported vulnerability evaluation logic
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Optional

from falconpy import SpotlightEvaluationLogic

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


class SpotlightModule(BaseModule):
    """Spotlight vulnerability evaluation logic queries."""

    def __init__(self, client):
        super().__init__(client)
        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.spotlight_supported_evaluations,
            name="spotlight_supported_evaluations",
            description=(
                "Get supported vulnerability evaluation logic — assessment methods, "
                "OS/platform coverage, and evaluation criteria. Use to check if Spotlight "
                "can evaluate a specific CVE or what platforms are covered."
            ),
        )

    async def spotlight_supported_evaluations(
        self,
        filter: Annotated[Optional[str], "FQL filter expression (e.g. platform:'Windows')"] = None,
    ) -> str:
        """Get combined supported evaluation logic."""
        try:
            kwargs = {}
            if filter:
                kwargs["filter"] = filter

            falcon = self._service(SpotlightEvaluationLogic)
            response = falcon.combined_supported_evaluation(**kwargs)

            if response["status_code"] != 200:
                err = format_api_error(response, "Failed to get evaluations", operation="combinedSupportedEvaluationExt")
                return format_text_response(f"Failed to get supported evaluations: {err}", raw=True)

            resources = response.get("body", {}).get("resources", [])
            lines = [f"Spotlight Supported Evaluations ({len(resources)} results)", ""]

            if not resources:
                lines.append("No evaluation logic found matching the filter.")
            else:
                for i, ev in enumerate(resources, 1):
                    lines.append(f"{i}. **{ev.get('name', 'Unknown')}**")
                    lines.append(f"   - ID: {ev.get('id', 'N/A')}")
                    if ev.get("platforms"):
                        lines.append(f"   - Platforms: {', '.join(ev['platforms'])}")
                    if ev.get("cve_ids"):
                        lines.append(f"   - CVEs: {', '.join(ev['cve_ids'][:10])}")
                    lines.append("")

            lines.append("```json")
            lines.append(json.dumps(resources, indent=2, default=str))
            lines.append("```")

            return format_text_response("\n".join(lines), raw=True)
        except Exception as e:
            return format_text_response(f"Failed to get supported evaluations: {e}", raw=True)
