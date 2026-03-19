"""
Correlation Module — detection engineering via the CorrelationRules API.

Tools:
  correlation_list_rules   — List detection/correlation rules
  correlation_get_rule     — Get full rule details
  correlation_update_rule  — Enable/disable rules with audit comment
  correlation_export_rule  — Export rule in structured format
"""

from __future__ import annotations

import json
from typing import Annotated, Optional, TYPE_CHECKING

from modules.base import BaseModule
from common.errors import format_api_error
from utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

try:
    from falconpy import CorrelationRules
    CORRELATION_AVAILABLE = True
except ImportError:
    CORRELATION_AVAILABLE = False

try:
    from falconpy import APIHarnessV2
    HARNESS_AVAILABLE = True
except ImportError:
    HARNESS_AVAILABLE = False


class CorrelationModule(BaseModule):
    """Correlation rule management for detection engineering."""

    def __init__(self, client):
        super().__init__(client)
        self._use_harness = False

        if CORRELATION_AVAILABLE:
            try:
                self.falcon = CorrelationRules(auth_object=self.client.auth_object)
                self._log("Initialized with CorrelationRules service class")
            except Exception:
                self._init_harness()
        elif HARNESS_AVAILABLE:
            self._init_harness()
        else:
            raise ImportError(
                "Neither falconpy.CorrelationRules nor falconpy.APIHarnessV2 available. "
                "Ensure crowdstrike-falconpy >= 1.6.0 is installed."
            )

    def _init_harness(self):
        self.falcon = APIHarnessV2(auth_object=self.client.auth_object)
        self._use_harness = True
        self._log("Initialized with APIHarnessV2 (Uber class)")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server, self.correlation_list_rules, name="correlation_list_rules",
            description=(
                "List NGSIEM correlation/detection rules with optional filtering "
                "by enabled status and name search."
            ),
        )
        self._add_tool(
            server, self.correlation_get_rule, name="correlation_get_rule",
            description=(
                "Get full details for correlation rules: CQL filter, severity, "
                "MITRE mapping, notification settings."
            ),
        )
        self._add_tool(
            server, self.correlation_update_rule, name="correlation_update_rule",
            description="Enable or disable a correlation rule with an audit comment.",
        )
        self._add_tool(
            server, self.correlation_export_rule, name="correlation_export_rule",
            description="Export a correlation rule in structured format for review.",
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def correlation_list_rules(
        self,
        enabled: Annotated[Optional[bool], "Filter by enabled status (omit for all rules)"] = None,
        search: Annotated[Optional[str], "Wildcard search on rule name/description"] = None,
        max_results: Annotated[int, "Maximum rules to return (default: 100)"] = 100,
    ) -> str:
        """List correlation/detection rules with optional filtering."""
        result = self._list_rules(enabled=enabled, search=search, max_results=max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to list rules: {result.get('error')}", raw=True)

        rules = result.get("rules", [])
        lines = [
            f"Correlation Rules: {result['count']} returned (of {result['total']} total)",
            "",
        ]

        for i, rule in enumerate(rules, 1):
            enabled_str = "ENABLED" if rule.get("enabled") else "DISABLED"
            lines.append(f"{i}. [{enabled_str}] {rule['name']}")
            lines.append(f"   ID: {rule['id']}")
            if rule.get("severity"):
                lines.append(f"   Severity: {rule['severity']}")
            if rule.get("description"):
                lines.append(f"   Description: {rule['description']}")
            lines.append(f"   Updated: {rule.get('updated_on', 'N/A')}")
            lines.append("")

        if not rules:
            lines.append("No rules found matching the filters.")

        return format_text_response("\n".join(lines), raw=True)

    async def correlation_get_rule(
        self,
        rule_ids: Annotated[list[str], "List of rule IDs to retrieve"],
    ) -> str:
        """Get full details for specific correlation rules."""
        result = self._get_rules(rule_ids)

        if not result.get("success"):
            return format_text_response(f"Failed to get rules: {result.get('error')}", raw=True)

        lines = [f"Correlation Rule Details ({result['count']} rules)", ""]

        for rule in result.get("rules", []):
            lines.append(f"### {rule.get('name', 'Unknown')}")
            lines.append(f"- ID: {rule.get('id', 'N/A')}")
            lines.append(f"- Enabled: {rule.get('enabled', False)}")
            lines.append(f"- Status: {rule.get('status', 'N/A')}")
            lines.append(f"- Severity: {rule.get('severity', 'N/A')}")
            lines.append(f"- Created: {rule.get('created_on', 'N/A')}")
            lines.append(f"- Updated: {rule.get('updated_on', 'N/A')}")
            if rule.get("description"):
                lines.append(f"- Description: {rule['description']}")

            search = rule.get("search", {})
            if search and search.get("filter"):
                lines.append(f"\n**CQL Filter:**")
                lines.append("```")
                lines.append(search["filter"])
                lines.append("```")

            lines.append("")
            lines.append("**Full Rule JSON:**")
            lines.append("```json")
            lines.append(json.dumps(rule, indent=2, default=str))
            lines.append("```")
            lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    async def correlation_update_rule(
        self,
        rule_id: Annotated[str, "Rule ID to update"],
        enabled: Annotated[bool, "True to enable, False to disable"],
        comment: Annotated[Optional[str], "Audit comment explaining the change"] = None,
    ) -> str:
        """Enable or disable a correlation rule with an audit comment."""
        result = self._update_rule(rule_id, enabled, comment)

        if not result.get("success"):
            return format_text_response(f"Failed to update rule: {result.get('error')}", raw=True)

        action = "enabled" if result["enabled"] else "disabled"
        lines = [f"Successfully {action} rule: {result['rule_id']}"]
        if result.get("comment"):
            lines.append(f"Comment: {result['comment']}")

        return format_text_response("\n".join(lines), raw=True)

    async def correlation_export_rule(
        self,
        rule_id: Annotated[str, "Rule ID to export"],
    ) -> str:
        """Export a correlation rule in structured format for review."""
        result = self._export_rule(rule_id)

        if not result.get("success"):
            return format_text_response(f"Failed to export rule: {result.get('error')}", raw=True)

        export = result["export"]
        lines = [
            f"## Correlation Rule Export: {export['metadata']['name']}",
            "",
            "### Metadata",
        ]
        for k, v in export["metadata"].items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")

        if export.get("search", {}).get("filter"):
            lines.append("### CQL Filter")
            lines.append("```")
            lines.append(export["search"]["filter"])
            lines.append("```")
            lines.append("")

        lines.append("### Full Export")
        lines.append("```json")
        lines.append(json.dumps(export, indent=2, default=str))
        lines.append("```")

        return format_text_response("\n".join(lines), raw=True)

    # ------------------------------------------------------------------
    # Internal methods (logic from handlers/correlation_rules.py)
    # ------------------------------------------------------------------

    def _list_rules(self, enabled=None, search=None, max_results=100):
        try:
            all_rule_ids = []
            offset = 0
            batch_limit = 500
            while True:
                if self._use_harness:
                    response = self.falcon.command("queries_rules_get_v1", limit=batch_limit, offset=offset)
                else:
                    response = self.falcon.query_rules(limit=batch_limit, offset=offset)

                if response["status_code"] != 200:
                    return {"success": False, "error": format_api_error(response, "Failed to query rules", operation="query_rules")}

                batch_ids = response.get("body", {}).get("resources", [])
                all_rule_ids.extend(batch_ids)

                total_api = (
                    response.get("body", {})
                    .get("meta", {})
                    .get("pagination", {})
                    .get("total", 0)
                )
                if len(all_rule_ids) >= total_api or not batch_ids:
                    break
                offset += batch_limit

            if not all_rule_ids:
                return {"success": True, "rules": [], "count": 0, "total": 0}

            all_rules = []
            batch_size = 100
            for i in range(0, len(all_rule_ids), batch_size):
                batch = all_rule_ids[i:i + batch_size]
                if self._use_harness:
                    details = self.falcon.command("entities_rules_get_v1", ids=batch)
                else:
                    details = self.falcon.get_rules(ids=batch)

                if details["status_code"] != 200:
                    self._log(f"Failed to get details for batch {i // batch_size + 1}")
                    continue
                all_rules.extend(details.get("body", {}).get("resources", []))

            filtered = all_rules
            if enabled is not None:
                filtered = [r for r in filtered if r.get("enabled", False) is enabled]
            if search:
                search_lower = search.lower()
                filtered = [
                    r for r in filtered
                    if search_lower in r.get("name", "").lower()
                    or search_lower in r.get("description", "").lower()
                ]

            total_matched = len(filtered)
            filtered = filtered[:max_results]

            summaries = []
            for rule in filtered:
                summaries.append({
                    "id": rule.get("id", ""),
                    "name": rule.get("name", ""),
                    "description": rule.get("description", "")[:200],
                    "enabled": rule.get("enabled", False),
                    "status": rule.get("status", ""),
                    "severity": rule.get("severity", ""),
                    "created_on": rule.get("created_on", ""),
                    "updated_on": rule.get("updated_on", ""),
                    "created_by": rule.get("created_by", ""),
                })

            return {"success": True, "rules": summaries, "count": len(summaries), "total": total_matched}
        except Exception as e:
            return {"success": False, "error": f"Error listing rules: {str(e)}"}

    def _get_rules(self, rule_ids):
        try:
            if self._use_harness:
                response = self.falcon.command("entities_rules_get_v1", ids=rule_ids)
            else:
                response = self.falcon.get_rules(ids=rule_ids)

            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to get rule details", operation="get_rules")}

            resources = response.get("body", {}).get("resources", [])
            if not resources:
                return {"success": False, "error": f"No rules found for IDs: {rule_ids}"}

            return {"success": True, "rules": resources, "count": len(resources)}
        except Exception as e:
            return {"success": False, "error": f"Error getting rules: {str(e)}"}

    def _update_rule(self, rule_id, enabled, comment=None):
        try:
            update_payload = [{"id": rule_id, "enabled": enabled}]
            if comment:
                update_payload[0]["comment"] = comment

            if self._use_harness:
                response = self.falcon.command("entities_rules_patch_v1", body=update_payload)
            else:
                response = self.falcon.update_rules(body=update_payload)

            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to update rule", operation="update_rules")}

            return {"success": True, "rule_id": rule_id, "enabled": enabled, "comment": comment}
        except Exception as e:
            return {"success": False, "error": f"Error updating rule: {str(e)}"}

    def _export_rule(self, rule_id):
        result = self._get_rules([rule_id])
        if not result.get("success"):
            return result

        rules = result.get("rules", [])
        if not rules:
            return {"success": False, "error": f"Rule not found: {rule_id}"}

        rule = rules[0]
        export = {
            "metadata": {
                "rule_id": rule.get("id", ""),
                "name": rule.get("name", ""),
                "description": rule.get("description", ""),
                "enabled": rule.get("enabled", False),
                "status": rule.get("status", ""),
                "severity": rule.get("severity", ""),
                "created_on": rule.get("created_on", ""),
                "updated_on": rule.get("updated_on", ""),
                "created_by": rule.get("created_by", ""),
                "updated_by": rule.get("updated_by", ""),
            },
            "search": rule.get("search", {}),
            "notification": rule.get("notification", {}),
            "trigger": rule.get("trigger", {}),
            "full_rule": rule,
        }

        return {"success": True, "export": export}
