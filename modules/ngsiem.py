"""
NGSIEM Module — executes CQL queries against the search-all repository.

Tools:
  ngsiem_query — Execute NGSIEM/CQL query across all CrowdStrike logs
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING, Annotated

from falconpy import NGSIEM

from modules.base import BaseModule
from utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


class NGSIEMModule(BaseModule):
    """NGSIEM query module for global search-all repository."""

    def __init__(self, client):
        super().__init__(client)
        self.falcon = NGSIEM(auth_object=self.client.auth_object)
        self.repository = "search-all"
        self._log(f"Initialized with global repository: {self.repository}")

    def register_resources(self, server: FastMCP) -> None:
        from resources.fql_guides import CQL_SYNTAX

        def _cql_syntax():
            return CQL_SYNTAX

        server.resource(
            "falcon://cql/syntax",
            name="CQL Query Syntax Reference",
            description="Documentation: CQL query language syntax for NGSIEM",
        )(_cql_syntax)
        self.resources.append("falcon://cql/syntax")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.ngsiem_query,
            name="ngsiem_query",
            description=("Execute NGSIEM/CQL query across all CrowdStrike logs using search-all repository"),
        )

    async def ngsiem_query(
        self,
        query: Annotated[str, "The NGSIEM/CQL query to execute"],
        start_time: Annotated[str, "Time range (e.g. '1h', '1d', '7d', '30d')"] = "1d",
        max_results: Annotated[int, "Maximum results to return (default: 100, max: 1000)"] = 100,
    ) -> str:
        """Execute a CQL query on the search-all repository."""
        max_results = min(max(max_results, 1), 1000)

        result = self._execute_query(query, start_time, max_results)

        if result.get("success"):
            events = result.get("events", [])
            lines = [
                "NGSIEM Query Results (All Logs):",
                f"Query: {result['query']}",
                f"Time Range: {result['time_range']}",
                "Repository: search-all (global)",
                f"Events Processed: {result['events_processed']:,}",
                f"Events Matched: {result['events_matched']:,}",
                f"Events Returned: {result['events_returned']}",
            ]
            if result.get("results_truncated"):
                lines.append(f"Results limited to {max_results} events out of {result['events_matched']} total matches")
            lines.append("")

            if events:
                lines.append("Results:")
                for i, event in enumerate(events[:10]):
                    lines.append(f"\n#{i + 1}:")
                    for key, value in event.items():
                        str_value = str(value)
                        if len(str_value) > 200:
                            str_value = str_value[:200] + "..."
                        lines.append(f"  {key}: {str_value}")
                if len(events) > 10:
                    lines.append(f"\n... and {len(events) - 10} more results")
            else:
                lines.append("No events found matching the query.")
                lines.append("\nTips:")
                lines.append("- Try longer time ranges like '7d' or '30d'")
                lines.append("- Use broader queries like '*' to see available data")

            return format_text_response("\n".join(lines), raw=True)
        else:
            error_text = (
                f"NGSIEM Query Failed:\nError: {result.get('error', 'Unknown error')}\n"
                f"\nPlease ensure:\n1. Query syntax is valid CQL\n"
                f"2. Time range is reasonable\n3. Try simpler queries first"
            )
            return format_text_response(error_text, raw=True)

    # ------------------------------------------------------------------
    # Internal query execution (also called by AlertsModule)
    # ------------------------------------------------------------------

    def _execute_query(
        self,
        query: str,
        start_time: str = "1d",
        max_results: int = 100,
    ) -> dict:
        """Execute a complete NGSIEM query. Returns result dict."""
        # Add MCP identifier comment for audit/tracking
        timestamped_query = f"// MCP Query - {datetime.now().isoformat()}\n{query}"

        # Start search
        try:
            response = self.falcon.start_search(
                repository=self.repository,
                query_string=timestamped_query,
                start=start_time,
                is_live=False,
            )

            if response["status_code"] != 200:
                error_details = []

                resources = response.get("resources", {})
                if "errors" in resources:
                    for error in resources["errors"]:
                        if isinstance(error, dict) and "message" in error:
                            error_details.append(error["message"])
                        else:
                            error_details.append(str(error))

                body = response.get("body", {})
                if "errors" in body:
                    for error in body["errors"]:
                        if isinstance(error, dict) and "message" in error:
                            error_details.append(error["message"])
                        else:
                            error_details.append(str(error))

                if not error_details:
                    error_details = [f"HTTP {response['status_code']} error"]

                error_msg = "; ".join(error_details)
                return {
                    "success": False,
                    "error": f"Failed to start search (HTTP {response['status_code']}): {error_msg}",
                }

            search_id = response.get("resources", {}).get("id")

        except Exception as e:
            return {"success": False, "error": f"Search start error: {str(e)}"}

        # Wait for completion
        try:
            start = time.time()
            timeout = 120  # 2 minute timeout

            while time.time() - start < timeout:
                status_response = self.falcon.get_search_status(
                    repository=self.repository,
                    search_id=search_id,
                )

                if status_response["status_code"] != 200:
                    error_msg = f"HTTP {status_response['status_code']}"
                    body = status_response.get("body", {})
                    if "errors" in body:
                        error_msg += f": {body['errors']}"
                    return {"success": False, "error": f"Status check failed: {error_msg}"}

                body = status_response.get("body", {})
                done = body.get("done", False)
                cancelled = body.get("cancelled", False)
                state = body.get("state", "unknown")

                if done or cancelled:
                    events = body.get("events", [])
                    events_matched = len(events)
                    events_processed = events_matched

                    if len(events) > max_results:
                        events = events[:max_results]
                        truncated = True
                    else:
                        truncated = False

                    return {
                        "success": True,
                        "events_processed": events_processed,
                        "events_matched": events_matched,
                        "events_returned": len(events),
                        "results_truncated": truncated,
                        "query": query,  # Original query without MCP comment
                        "time_range": start_time,
                        "events": events,
                    }

                if state == "error":
                    messages = body.get("messages", [])
                    return {"success": False, "error": f"Search error: {messages}"}

                time.sleep(2)

            # Timeout
            self.falcon.stop_search(repository=self.repository, id=search_id)
            return {"success": False, "error": f"Query timed out after {timeout} seconds"}

        except Exception as e:
            try:
                self.falcon.stop_search(repository=self.repository, id=search_id)
            except Exception:
                pass
            return {"success": False, "error": f"Query execution error: {str(e)}"}
