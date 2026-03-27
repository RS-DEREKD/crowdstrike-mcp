"""
Alerts Module — unified alert retrieval and analysis across all detection types.

Tools:
  get_alerts             — Retrieve alerts across all detection types with filtering
  alert_analysis         — Deep-dive alert analysis with type-specific enrichment
  ngsiem_alert_analysis  — Alias for alert_analysis (backward compat)
  update_alert_status    — Update alert status, comments, and tags

Cross-module dependency: AlertsModule creates its own NGSIEM service
instance using ``self.client.auth_object`` instead of depending on other modules.
They all share the same OAuth2 token.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Optional

from falconpy import Alerts

from common.errors import format_api_error
from modules.base import BaseModule
from utils import (
    PRODUCT_FQL_MAP,
    extract_detection_id,
    format_text_response,
    parse_composite_id,
)

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

# Optional imports for cross-module enrichment
try:
    from falconpy import NGSIEM

    _NGSIEM_AVAILABLE = True
except ImportError:
    _NGSIEM_AVAILABLE = False


class AlertsModule(BaseModule):
    """Alert retrieval, analysis, and status management across all detection types."""

    def __init__(self, client):
        super().__init__(client)
        self.alerts = Alerts(auth_object=self.client.auth_object)

        # Create internal NGSIEM instance for enrichment
        self._ngsiem = None

        if _NGSIEM_AVAILABLE:
            try:
                self._ngsiem = NGSIEM(auth_object=self.client.auth_object)
            except Exception as e:
                self._log(f"NGSIEM enrichment not available: {e}")

        self._log("Initialized")

    def register_resources(self, server: FastMCP) -> None:
        from resources.fql_guides import ALERT_FQL

        def _alert_fql():
            return ALERT_FQL

        server.resource(
            "falcon://fql/alerts",
            name="Alert FQL Syntax Guide",
            description="Documentation: Alert FQL filter syntax",
        )(_alert_fql)
        self.resources.append("falcon://fql/alerts")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.get_alerts,
            name="get_alerts",
            description=(
                "Retrieve CrowdStrike alerts across ALL detection types (endpoint, NGSIEM, cloud security, identity, third-party) with filtering"
            ),
        )
        self._add_tool(
            server,
            self.alert_analysis,
            name="alert_analysis",
            description=(
                "Retrieve detailed alert metadata and type-specific enrichment "
                "by composite detection ID. Supports endpoint (ind), NGSIEM (ngsiem), "
                "cloud security (fcs), identity (ldt), and third-party (thirdparty) detections."
            ),
        )
        self._add_tool(
            server,
            self.alert_analysis,
            name="ngsiem_alert_analysis",
            description=("[ALIAS for alert_analysis] Retrieve detailed alert metadata and related security events by composite detection ID."),
        )
        self._add_tool(
            server,
            self.update_alert_status,
            name="update_alert_status",
            description=("Update CrowdStrike alert status after triage/investigation. Supports status changes, comments for audit trail, and tags."),
            tier="write",
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def get_alerts(
        self,
        severity: Annotated[str, "Minimum severity level"] = "ALL",
        time_range: Annotated[str, "Time range (e.g. '1h', '6h', '12h', '1d', '7d', '30d')"] = "1d",
        status: Annotated[str, "Filter by alert status"] = "all",
        pattern_name: Annotated[Optional[str], "Wildcard match on detection/alert name"] = None,
        product: Annotated[str, "Filter by detection source/product type"] = "all",
        max_results: Annotated[int, "Maximum alerts to return (default: 50, max: 200)"] = 50,
    ) -> str:
        """Retrieve alerts with flexible filtering across all detection types."""
        result = self._get_alerts(
            severity=severity,
            time_range=time_range,
            status=status,
            pattern_name=pattern_name,
            product=product,
            max_results=max_results,
        )

        if not result.get("success"):
            return format_text_response(
                f"Failed to retrieve alerts: {result.get('error')}",
                raw=True,
            )

        alerts_list = result["alerts"]
        lines = [
            f"Alerts Retrieved: {result['count']} (of {result['total_available']} total)",
            f"Filter: severity={severity}, time_range={time_range}, status={status}, product={product}",
        ]
        if pattern_name:
            lines.append(f"Pattern: {pattern_name}")
        lines.append("")

        if not alerts_list:
            lines.append("No alerts found matching the filters.")
        else:
            for i, a in enumerate(alerts_list, 1):
                tags_str = f" [{', '.join(a['tags'])}]" if a.get("tags") else ""
                assigned = f" -> {a['assigned_to']}" if a.get("assigned_to") else ""
                product_tag = f" ({a['product_name']})" if a.get("product_name") else ""
                lines.append(f"{i}. [{a['severity']}] {a['name']}{product_tag} (status: {a['status']}{assigned}{tags_str})")
                lines.append(f"   ID: {a['composite_id']}")
                lines.append(f"   Created: {a['created_timestamp']}")
                if a.get("description"):
                    lines.append(f"   Description: {a['description']}")
                lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    async def alert_analysis(
        self,
        detection_id: Annotated[str, "The composite detection ID to analyze"],
        max_events: Annotated[int, "Maximum related events to retrieve (for NGSIEM)"] = 10,
    ) -> str:
        """Analyze an alert with type-specific enrichment."""
        detection_id = extract_detection_id(detection_id)
        result = await asyncio.to_thread(self._analyze_alert, detection_id, max_events)

        if not result.get("success"):
            return format_text_response(
                f"Failed to analyze alert: {result.get('error', 'Unknown error')}",
                raw=True,
            )

        response_text = self._format_alert_analysis_response(result)
        return format_text_response(response_text, raw=True)

    async def update_alert_status(
        self,
        composite_ids: Annotated[list[str], "List of composite alert IDs to update"],
        status: Annotated[str, "New alert status ('new', 'in_progress', 'closed', 'reopened')"],
        comment: Annotated[Optional[str], "Comment for audit trail"] = None,
        tags: Annotated[Optional[list[str]], "Tags to add"] = None,
    ) -> str:
        """Update alert status, add comments and tags."""
        cleaned_ids = [extract_detection_id(cid) for cid in composite_ids]
        result = self._update_alert_status(cleaned_ids, status, comment, tags)

        if not result.get("success"):
            return format_text_response(
                f"Failed to update alerts: {result.get('error')}",
                raw=True,
            )

        lines = [
            f"Successfully updated {result['updated_count']} alert(s)",
            f"New status: {result['new_status']}",
        ]
        if result.get("comment_added"):
            lines.append(f"Comment added: {comment}")
        if result.get("tags_added"):
            lines.append(f"Tags added: {', '.join(result['tags_added'])}")

        return format_text_response("\n".join(lines), raw=True)

    # ------------------------------------------------------------------
    # Internal methods (logic from handlers/alerts.py)
    # ------------------------------------------------------------------

    def _get_alert_details(self, detection_id):
        try:
            response = self.alerts.get_alerts_v2(composite_ids=[detection_id])
            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to get alert", operation="get_alerts_v2")}
            resources = response.get("body", {}).get("resources", [])
            if not resources:
                return {"success": False, "error": f"Alert not found: {detection_id}"}
            return {"success": True, "alert": resources[0]}
        except Exception as e:
            return {"success": False, "error": f"Error retrieving alert: {str(e)}"}

    # Alerts v2 API severity uses 10/20/30/40/50, not 1-5.
    _SEVERITY_MAP = {
        "CRITICAL": 50,
        "HIGH": 40,
        "MEDIUM": 30,
        "LOW": 20,
        "INFORMATIONAL": 10,
    }

    def _get_alerts(self, severity="ALL", time_range="1d", status="all", pattern_name=None, product="all", max_results=50):
        try:
            time_units = {"h": "hours", "d": "days"}
            unit = time_range[-1]
            value = int(time_range[:-1])
            if unit not in time_units:
                return {"success": False, "error": f"Invalid time_range unit: {unit}. Use 'h' or 'd'."}

            start_dt = datetime.now() - timedelta(**{time_units[unit]: value})
            date_from = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

            filter_parts = [f"created_timestamp:>='{date_from}'"]

            if severity.upper() != "ALL":
                sev_value = self._SEVERITY_MAP.get(severity.upper())
                if sev_value is not None:
                    filter_parts.append(f"severity:>={sev_value}")

            if status.lower() != "all":
                filter_parts.append(f"status:'{status.lower()}'")

            # NOTE: `name` is NOT a valid FQL filter field for query_alerts_v2.
            # pattern_name is applied as a client-side post-filter after fetching details.

            if product.lower() != "all":
                fql_values = PRODUCT_FQL_MAP.get(product.lower())
                if fql_values:
                    product_list = ",".join(f"'{v}'" for v in fql_values)
                    filter_parts.append(f"product:[{product_list}]")

            filter_query = "+".join(filter_parts)

            # When post-filtering by name, fetch more to compensate for filtering loss.
            fetch_limit = min(max_results * 4, 200) if pattern_name else min(max_results, 200)

            response = self.alerts.query_alerts_v2(
                filter=filter_query,
                limit=fetch_limit,
                sort="created_timestamp.desc",
            )

            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to query alerts", operation="query_alerts_v2")}

            alert_ids = response.get("body", {}).get("resources", [])
            total_available = response.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(alert_ids))

            if not alert_ids:
                return {
                    "success": True,
                    "alerts": [],
                    "count": 0,
                    "total_available": 0,
                    "filter": filter_query,
                    "time_range": time_range,
                }

            details_response = self.alerts.get_alerts_v2(composite_ids=alert_ids)
            if details_response["status_code"] != 200:
                return {"success": False, "error": format_api_error(details_response, "Failed to get alert details", operation="get_alerts_v2")}

            alerts_data = details_response.get("body", {}).get("resources", [])

            alert_summaries = []
            for a in alerts_data:
                composite_id = a.get("composite_id", "")
                id_info = parse_composite_id(composite_id)

                raw_product = a.get("product", {})
                if isinstance(raw_product, dict):
                    api_product_name = raw_product.get("name", "")
                else:
                    api_product_name = str(raw_product) if raw_product else ""

                alert_summaries.append(
                    {
                        "composite_id": composite_id,
                        "name": a.get("name", "Unknown"),
                        "severity": a.get("severity_name", "Unknown"),
                        "severity_value": a.get("severity", 0),
                        "status": a.get("status", "unknown"),
                        "created_timestamp": a.get("created_timestamp", ""),
                        "updated_timestamp": a.get("updated_timestamp", ""),
                        "assigned_to": a.get("assigned_to_name", ""),
                        "type": a.get("type", ""),
                        "product": id_info["product_type"],
                        "product_name": id_info["product_name"],
                        "api_product": api_product_name,
                        "tags": a.get("tags", []),
                        "description": a.get("description", "")[:200],
                    }
                )

            # Client-side post-filter by pattern_name (not supported in FQL).
            if pattern_name:
                pattern_lower = pattern_name.lower()
                alert_summaries = [a for a in alert_summaries if pattern_lower in a["name"].lower()]

            # Trim to requested max_results after any post-filtering.
            alert_summaries = alert_summaries[:max_results]

            return {
                "success": True,
                "alerts": alert_summaries,
                "count": len(alert_summaries),
                "total_available": total_available,
                "filter": filter_query,
                "time_range": time_range,
            }
        except Exception as e:
            return {"success": False, "error": f"Error retrieving alerts: {str(e)}"}

    def _update_alert_status(self, composite_ids, status, comment=None, tags=None):
        try:
            valid_statuses = ["new", "in_progress", "closed", "reopened"]
            if status.lower() not in valid_statuses:
                return {"success": False, "error": f"Invalid status: {status}. Must be one of: {valid_statuses}"}

            action_params = [{"name": "update_status", "value": status.lower()}]
            if comment:
                action_params.append({"name": "append_comment", "value": comment})
            if tags:
                action_params.extend({"name": "add_tag", "value": tag} for tag in tags)

            response = self.alerts.update_alerts_v3(
                composite_ids=composite_ids,
                action_parameters=action_params,
            )

            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to update alerts", operation="update_alerts_v3")}

            return {
                "success": True,
                "updated_count": len(composite_ids),
                "new_status": status.lower(),
                "comment_added": comment is not None,
                "tags_added": tags or [],
            }
        except Exception as e:
            return {"success": False, "error": f"Error updating alerts: {str(e)}"}

    # ------------------------------------------------------------------
    # Multi-type alert analysis with enrichment routing
    # ------------------------------------------------------------------

    def _get_related_ngsiem_events(self, composite_id, time_range="1d", max_events=10):
        """Get events related to an NGSIEM alert using CQL queries."""
        if not self._ngsiem:
            return {"success": False, "error": "NGSIEM enrichment not available"}

        try:
            parts = composite_id.split(":")
            indicator_id = parts[-1] if len(parts) >= 4 else composite_id

            indicator_queries = [
                f'Ngsiem.indicator.id = "{indicator_id}"',
                f'@id = "{indicator_id}"',
                f'indicator.id = "{indicator_id}"',
            ]

            detection_id_from_event = None
            indicator_event = None

            for query in indicator_queries:
                result = self._execute_ngsiem_query(query, time_range, 1)
                if result.get("success") and result.get("events_matched", 0) > 0:
                    events = result.get("events", [])
                    if events:
                        indicator_event = events[0]
                        detection_id_from_event = indicator_event.get("Ngsiem.detection.id") or indicator_event.get("detection.id")
                        self._log(f"Found indicator event, detection ID: {detection_id_from_event}")
                        break

            if not detection_id_from_event:
                return {
                    "success": False,
                    "error": f"Could not find indicator event or extract detection ID. Tried queries: {indicator_queries}",
                    "events_matched": 0,
                }

            detection_queries = [
                f'Ngsiem.detection.id = "{detection_id_from_event}"',
                f'detection.id = "{detection_id_from_event}"',
            ]

            for query in detection_queries:
                result = self._execute_ngsiem_query(query, time_range, max_events)
                if result.get("success") and result.get("events_matched", 0) > 0:
                    return {
                        "success": True,
                        "events": result.get("events", []),
                        "events_matched": result.get("events_matched", 0),
                        "detection_id_used": detection_id_from_event,
                        "query_used": query,
                    }

            if indicator_event:
                return {
                    "success": True,
                    "events": [indicator_event],
                    "events_matched": 1,
                    "detection_id_used": detection_id_from_event,
                    "note": "Only found the indicator event, no additional related events",
                }

            return {
                "success": False,
                "error": f"Found detection ID {detection_id_from_event} but no related events.",
                "events_matched": 0,
            }
        except Exception as e:
            return {"success": False, "error": f"Error getting related events: {str(e)}"}

    def _execute_ngsiem_query(self, query, start_time="1d", max_results=10):
        """Execute a CQL query using the internal NGSIEM client."""
        import time as _time

        timestamped_query = f"// MCP Query - {datetime.now().isoformat()}\n{query}"

        try:
            response = self._ngsiem.start_search(
                repository="search-all",
                query_string=timestamped_query,
                start=start_time,
                is_live=False,
            )

            if response["status_code"] != 200:
                return {"success": False, "error": f"Search start failed: HTTP {response['status_code']}"}

            search_id = response.get("resources", {}).get("id")

            start = _time.time()
            timeout = 60

            while _time.time() - start < timeout:
                status_response = self._ngsiem.get_search_status(
                    repository="search-all",
                    search_id=search_id,
                )

                if status_response["status_code"] != 200:
                    return {"success": False, "error": f"Status check failed: HTTP {status_response['status_code']}"}

                body = status_response.get("body", {})
                done = body.get("done", False)
                cancelled = body.get("cancelled", False)

                if done or cancelled:
                    events = body.get("events", [])
                    events_matched = len(events)
                    if len(events) > max_results:
                        events = events[:max_results]
                    return {
                        "success": True,
                        "events_matched": events_matched,
                        "events_returned": len(events),
                        "events": events,
                    }

                if body.get("state") == "error":
                    return {"success": False, "error": f"Search error: {body.get('messages', [])}"}

                _time.sleep(2)

            self._ngsiem.stop_search(repository="search-all", id=search_id)
            return {"success": False, "error": f"Query timed out after {timeout} seconds"}

        except Exception as e:
            return {"success": False, "error": f"Query execution error: {str(e)}"}

    def _get_behaviors_for_alert(self, alert):
        """Get endpoint context via NGSIEM raw telemetry (replaces deprecated Detects API).

        The Detects API was decommissioned in March 2026. This method now queries
        NGSIEM for raw EDR events (ProcessRollup2) around the alert's device.
        """
        if not self._ngsiem:
            return {"success": False, "error": "NGSIEM enrichment not available — cannot enrich endpoint alert"}

        device_id = alert.get("device", {}).get("device_id", "")
        if not device_id:
            return {"success": False, "error": "No device_id in alert — cannot query endpoint telemetry"}

        query = f'#event_simpleName=ProcessRollup2 aid="{device_id}" | head(20)'

        try:
            result = self._execute_ngsiem_query(query, start_time="24h", max_results=20)
            if not result.get("success"):
                return {
                    "success": False,
                    "error": f"NGSIEM endpoint enrichment failed: {result.get('error', 'Unknown')}",
                }

            events = result.get("events", [])
            return {"success": True, "behaviors": events}
        except Exception as e:
            return {"success": False, "error": f"NGSIEM endpoint enrichment error: {str(e)}"}

    def _analyze_alert(self, detection_id, max_events=10):
        """Analyze an alert with type-specific enrichment routing."""
        alert_result = self._get_alert_details(detection_id)
        if not alert_result.get("success"):
            return alert_result

        alert = alert_result["alert"]
        id_info = parse_composite_id(detection_id)
        product_type = id_info["product_type"]
        product_name = id_info["product_name"]

        result = {
            "success": True,
            "alert": alert,
            "product_type": product_type,
            "product_name": product_name,
            "enrichment_type": None,
            "events": None,
            "behaviors": None,
            "enrichment_note": None,
        }

        if product_type == "ngsiem" and self._ngsiem:
            result["enrichment_type"] = "ngsiem_events"
            events_result = self._get_related_ngsiem_events(
                detection_id,
                time_range="7d",
                max_events=max_events,
            )
            if events_result.get("success"):
                result["events"] = events_result.get("events", [])
                result["events_matched"] = events_result.get("events_matched", 0)
                result["query_used"] = events_result.get("query_used", "")
            else:
                result["enrichment_note"] = f"NGSIEM event retrieval failed: {events_result.get('error', 'Unknown')}"

        elif product_type == "cloud_security":
            result["enrichment_type"] = "cloud_security_raw"
            result["enrichment_note"] = (
                "Cloud security alert — full raw alert payload included for inspection. Automated cloud event enrichment will be added in a future update."
            )

        elif product_type == "endpoint":
            result["enrichment_type"] = "endpoint_behaviors"
            try:
                behaviors_result = self._get_behaviors_for_alert(alert)
                if behaviors_result.get("success"):
                    result["behaviors"] = behaviors_result.get("behaviors", [])
                else:
                    result["enrichment_note"] = f"Endpoint behavior retrieval failed: {behaviors_result.get('error', 'Unknown')}"
            except Exception as e:
                result["enrichment_note"] = f"Endpoint enrichment error: {str(e)}"

        elif product_type == "identity":
            result["enrichment_type"] = "identity_metadata_only"
            result["enrichment_note"] = "Identity Protection alert — enrichment via GraphQL API planned for future update."

        elif product_type == "thirdparty":
            result["enrichment_type"] = "thirdparty_metadata_only"
            result["enrichment_note"] = (
                "Third-party integration alert — generated by an external connector "
                "(e.g., EntraID, Cato VPN, or other third-party source). "
                "These alerts are NOT tunable within CrowdStrike NGSIEM; "
                "tuning must be done in the originating third-party platform."
            )

        else:
            result["enrichment_type"] = "metadata_only"
            result["enrichment_note"] = f"Unknown product type '{id_info['product_prefix']}' — returning alert metadata only."

        return result

    def _format_alert_analysis_response(self, analysis):
        """Format the analyze_alert result into a readable text response."""
        alert = analysis["alert"]
        parts = []

        parts.append(f"## Alert Analysis ({analysis['product_name']})")
        parts.append("")

        parts.append("### Alert Metadata")
        parts.append(f"- **Name**: {alert.get('name', 'Unknown')}")
        parts.append(f"- **Composite ID**: {alert.get('composite_id', 'N/A')}")
        parts.append(f"- **Severity**: {alert.get('severity_name', 'Unknown')} ({alert.get('severity', 'N/A')})")
        parts.append(f"- **Status**: {alert.get('status', 'unknown')}")
        parts.append(f"- **Type**: {alert.get('type', 'N/A')}")
        parts.append(f"- **Product Type**: {analysis['product_name']} (`{analysis['product_type']}`)")

        raw_product = alert.get("product", {})
        if isinstance(raw_product, dict):
            api_product = raw_product.get("name", "N/A")
        else:
            api_product = str(raw_product) if raw_product else "N/A"
        parts.append(f"- **API Product**: {api_product}")

        pattern = alert.get("pattern", {})
        if isinstance(pattern, dict) and pattern:
            parts.append(f"- **Pattern**: {pattern.get('name', 'N/A')} (ID: {pattern.get('id', 'N/A')})")

        parts.append(f"- **Created**: {alert.get('created_timestamp', 'N/A')}")
        parts.append(f"- **Updated**: {alert.get('updated_timestamp', 'N/A')}")

        description = alert.get("description", "")
        if description:
            parts.append(f"- **Description**: {description}")

        tags = alert.get("tags", [])
        if tags:
            parts.append(f"- **Tags**: {', '.join(tags)}")

        assigned = alert.get("assigned_to_name", "")
        if assigned:
            parts.append(f"- **Assigned To**: {assigned}")
        parts.append("")

        behaviors = alert.get("behaviors", [])
        if behaviors and isinstance(behaviors, list):
            parts.append("### MITRE ATT&CK Mapping")
            for behavior in behaviors[:5]:
                if isinstance(behavior, dict):
                    parts.append(f"- **{behavior.get('tactic', 'N/A')}**: {behavior.get('technique', 'N/A')}")
            parts.append("")

        device = alert.get("device")
        if device and isinstance(device, dict):
            parts.append("### Affected Device")
            parts.append(f"- Hostname: {device.get('hostname', 'N/A')}")
            parts.append(f"- User: {device.get('user_name', 'N/A')}")
            parts.append(f"- Platform: {device.get('platform_name', 'N/A')}")
            device_id = device.get("device_id", "")
            if device_id:
                parts.append(f"- Device ID: {device_id}")
            parts.append("")

        if analysis.get("enrichment_note"):
            parts.append("### Enrichment Note")
            parts.append(f"> {analysis['enrichment_note']}")
            parts.append("")

        events = analysis.get("events")
        if events:
            parts.append(f"### Related Events ({len(events)} events)")
            parts.append("")
            for i, event in enumerate(events, 1):
                parts.append(f"#### Event {i}")
                summary_fields = []
                for key in ["event.action", "@timestamp", "cloud.account.id", "source.ip", "Vendor.userIdentity.arn", "#event.outcome"]:
                    val = event.get(key)
                    if val:
                        short_key = key.lstrip("#").split(".")[-1]
                        summary_fields.append(f"{short_key}={val}")
                if summary_fields:
                    parts.append(f"  {' | '.join(summary_fields)}")
                parts.append("```json")
                parts.append(json.dumps(event, indent=2, default=str))
                parts.append("```")
                parts.append("")

        behaviors_data = analysis.get("behaviors")
        if behaviors_data:
            parts.append(f"### Endpoint Behaviors ({len(behaviors_data)} behaviors)")
            parts.append("")
            for i, behavior in enumerate(behaviors_data, 1):
                parts.append(f"#### Behavior {i}")
                summary_fields = []
                for key in ["tactic", "technique", "filename", "cmdline", "severity"]:
                    val = behavior.get(key)
                    if val:
                        val_str = str(val)[:80]
                        summary_fields.append(f"{key}={val_str}")
                if summary_fields:
                    parts.append(f"  {' | '.join(summary_fields)}")
                parts.append("```json")
                parts.append(json.dumps(behavior, indent=2, default=str))
                parts.append("```")
                parts.append("")

        if analysis.get("enrichment_type") == "cloud_security_raw":
            parts.append("### Raw Alert Payload (Cloud Security)")
            parts.append("```json")
            parts.append(json.dumps(alert, indent=2, default=str))
            parts.append("```")
            parts.append("")

        if analysis.get("enrichment_type") == "thirdparty_metadata_only":
            parts.append("### Raw Alert Payload (Third-Party)")
            parts.append("```json")
            parts.append(json.dumps(alert, indent=2, default=str))
            parts.append("```")
            parts.append("")

        has_raw_payload = analysis.get("enrichment_type") in ("cloud_security_raw", "thirdparty_metadata_only")
        if not events and not behaviors_data and not has_raw_payload:
            parts.append("### Related Events")
            parts.append("No related events found for this alert.")
            parts.append("")

        return "\n".join(parts)
