"""
Threat Graph edge-type reference — lazily populated from the live API.

Unlike the static FQL guides in fql_guides.py, the Threat Graph edge-type
catalog evolves with CrowdStrike releases. We fetch it on first resource
read, cache in process memory, and let callers invalidate via the
threatgraph_get_edge_types tool.
"""

from __future__ import annotations

from typing import Callable

FETCH_FAILURE_BODY = (
    "# Threat Graph — Edge Types\n\n"
    "Failed to fetch the live edge-type list. Call `threatgraph_get_edge_types` "
    "directly or retry this resource read.\n\n"
    "API error: {detail}\n"
)


class ThreatGraphEdgeTypeCache:
    """Lazy, process-lifetime cache for Threat Graph edge types."""

    def __init__(self, fetcher: Callable[[], dict]):
        """
        Args:
            fetcher: zero-arg callable returning the falconpy response dict
                     from get_edge_types() (keys: status_code, body).
        """
        self._fetcher = fetcher
        self._cached: str | None = None

    def read(self) -> str:
        """Return the formatted edge-type reference, fetching if needed."""
        if self._cached is not None:
            return self._cached
        response = self._fetcher()
        status = response.get("status_code")
        if status != 200:
            errors = (response.get("body") or {}).get("errors") or []
            detail = errors[0].get("message") if errors else f"HTTP {status}"
            return FETCH_FAILURE_BODY.format(detail=detail)
        resources = (response.get("body") or {}).get("resources") or []
        self._cached = self._format(resources)
        return self._cached

    def invalidate(self) -> None:
        """Drop the cached response so the next read re-fetches."""
        self._cached = None

    @staticmethod
    def _format(resources: list) -> str:
        # Resources may be a list of strings (edge names) or a list of dicts
        # with a "name" key. Support both; fall back to repr.
        lines = ["# Threat Graph — Edge Types", ""]
        lines.append(f"{len(resources)} edge types available.")
        lines.append("")
        for item in resources:
            if isinstance(item, str):
                lines.append(f"- `{item}`")
            elif isinstance(item, dict):
                name = item.get("name") or item.get("type") or repr(item)
                lines.append(f"- `{name}`")
            else:
                lines.append(f"- `{item!r}`")
        lines.append("")
        lines.append("Pass any of these as the `edge_type` argument to `threatgraph_get_edges`.")
        return "\n".join(lines)
