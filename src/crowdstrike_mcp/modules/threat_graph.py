"""
Threat Graph Module — CrowdStrike Threat Graph read surface (process/file/network/identity edges).

Tools:
  threatgraph_get_vertices      — Fetch vertex metadata by composite ID
  threatgraph_get_edges         — Walk outgoing/incoming edges of one edge type
  threatgraph_get_ran_on        — Find hosts/processes where an indicator was observed
  threatgraph_get_summary       — Short triage-ready summary for vertex IDs
  threatgraph_get_edge_types    — Refresh (and return) the edge-type catalog

Resources:
  falcon://reference/threatgraph-edge-types
    Lazily populated from get_edge_types() on first read. Invalidated when
    the threatgraph_get_edge_types tool is called. First module in this repo
    with a *dynamic* MCP resource; static-content resources live in
    resources/fql_guides.py.

Vertex IDs are composite strings. The most common form is:
  pid:<aid>:<offset_ns>
where <aid> is the Falcon agent ID and <offset_ns> is a nanosecond-precision
offset from the alert / process payload. Every tool docstring includes the
recipe.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal, Optional  # noqa: F401 — used by tool methods added in later tasks

try:
    from falconpy import ThreatGraph

    THREATGRAPH_AVAILABLE = True
except ImportError:
    THREATGRAPH_AVAILABLE = False

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


EDGE_TYPES_RESOURCE_URI = "falcon://reference/threatgraph-edge-types"


class ThreatGraphModule(BaseModule):
    """Threat Graph read-only pivots (vertices, edges, ran-on, summary)."""

    def __init__(self, client):
        super().__init__(client)
        if not THREATGRAPH_AVAILABLE:
            raise ImportError("ThreatGraph not available. Ensure crowdstrike-falconpy >= 1.6.1 is installed.")
        self._edge_type_cache = ThreatGraphEdgeTypeCache(self._fetch_edge_types)
        self._log("Initialized")

    def register_resources(self, server: FastMCP) -> None:
        def _edge_types_body():
            return self._edge_type_cache.read()

        server.resource(
            EDGE_TYPES_RESOURCE_URI,
            name="Threat Graph Edge Types",
            description="Live list of Threat Graph edge types (cached in-process).",
        )(_edge_types_body)
        self.resources.append(EDGE_TYPES_RESOURCE_URI)

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.threatgraph_get_edge_types,
            name="threatgraph_get_edge_types",
            description=(
                "Refresh and return the live list of Threat Graph edge types. "
                "Also invalidates the falcon://reference/threatgraph-edge-types "
                "cache so the next resource read re-fetches. Use sparingly; "
                "prefer reading the resource."
            ),
        )

    async def threatgraph_get_edge_types(self) -> str:
        """Refresh the edge-type cache and return the current list."""
        try:
            response = self._fetch_edge_types()
            if response.get("status_code") != 200:
                err = format_api_error(
                    response,
                    "Failed to get edge types",
                    operation="queries_edgetypes_get",
                )
                return format_text_response(f"Failed to get edge types: {err}", raw=True)
            # Invalidate then re-read so the cache picks up the fresh response
            self._edge_type_cache.invalidate()
            body = self._edge_type_cache.read()
            return format_text_response(body, raw=True)
        except Exception as e:
            return format_text_response(f"Failed to get edge types: {e}", raw=True)

    # -------- internal helpers --------

    def _fetch_edge_types(self) -> dict:
        """Invoke ThreatGraph.get_edge_types(); used as the cache fetcher."""
        falcon = self._service(ThreatGraph)
        return falcon.get_edge_types()
