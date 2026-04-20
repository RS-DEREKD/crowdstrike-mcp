"""
Spotlight Module — vulnerability evaluation logic via the SpotlightEvaluationLogic API.

Tools:
  spotlight_supported_evaluations — Get supported vulnerability evaluation logic
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Optional

try:
    from falconpy import SpotlightEvaluationLogic

    SPOTLIGHT_EVAL_AVAILABLE = True
except ImportError:
    SPOTLIGHT_EVAL_AVAILABLE = False

try:
    from falconpy import SpotlightVulnerabilities

    SPOTLIGHT_VULNS_AVAILABLE = True
except ImportError:
    SPOTLIGHT_VULNS_AVAILABLE = False

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


class SpotlightModule(BaseModule):
    """Spotlight vulnerability evaluation logic queries."""

    def __init__(self, client):
        super().__init__(client)
        if not SPOTLIGHT_EVAL_AVAILABLE and not SPOTLIGHT_VULNS_AVAILABLE:
            raise ImportError(
                "Neither SpotlightEvaluationLogic nor SpotlightVulnerabilities available. "
                "Ensure crowdstrike-falconpy >= 1.6.1 is installed."
            )
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
        self._add_tool(
            server,
            self.spotlight_query_vulnerabilities,
            name="spotlight_query_vulnerabilities",
            description=(
                "Find vulnerability IDs matching an FQL filter. Use to locate open "
                "CVEs by host (`aid`), CVE ID, severity, or age. Returns IDs only — "
                "use spotlight_get_vulnerabilities or spotlight_vulnerabilities_combined "
                "for full records."
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

    async def spotlight_query_vulnerabilities(
        self,
        filter: Annotated[str, "FQL filter expression (required). See falcon://fql/spotlight-vulnerabilities."],
        limit: Annotated[int, "Max IDs to return (default 50, max 500)"] = 50,
        after: Annotated[Optional[str], "Pagination token from a prior call"] = None,
        sort: Annotated[Optional[str], "Sort expression (e.g. 'created_timestamp|desc')"] = None,
    ) -> str:
        """Find vulnerability IDs matching an FQL filter."""
        result = self._query_vulnerabilities(filter=filter, limit=limit, after=after, sort=sort)

        if not result.get("success"):
            return format_text_response(f"Failed to query vulnerabilities: {result.get('error')}", raw=True)

        ids = result["ids"]
        lines = [
            f"Spotlight Vulnerability IDs: {len(ids)} returned (total={result.get('total', 'unknown')})",
            "",
        ]
        if result.get("after"):
            lines.append(f"Next page token: `{result['after']}`")
            lines.append("")
        if not ids:
            lines.append("No vulnerabilities matched the filter.")
        else:
            for i, vid in enumerate(ids, 1):
                lines.append(f"{i}. {vid}")
        return format_text_response("\n".join(lines), raw=True)

    def _query_vulnerabilities(self, filter, limit=50, after=None, sort=None):
        if not SPOTLIGHT_VULNS_AVAILABLE:
            return {"success": False, "error": "SpotlightVulnerabilities client not available"}
        if not filter:
            return {"success": False, "error": "filter is required (e.g. status:'open')"}
        try:
            svc = self._service(SpotlightVulnerabilities)
            kwargs = {"filter": filter, "limit": min(limit, 500)}
            if after:
                kwargs["after"] = after
            if sort:
                kwargs["sort"] = sort
            r = svc.query_vulnerabilities(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to query vulnerabilities", operation="query_vulnerabilities")}
            body = r.get("body", {})
            ids = body.get("resources", [])
            meta = body.get("meta", {}).get("pagination", {})
            return {
                "success": True,
                "ids": ids,
                "total": meta.get("total", len(ids)),
                "after": meta.get("after"),
            }
        except Exception as e:
            return {"success": False, "error": f"Error querying vulnerabilities: {e}"}
