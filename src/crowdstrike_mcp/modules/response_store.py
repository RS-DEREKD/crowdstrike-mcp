"""
Response Store Module — structured data retrieval for truncated MCP responses.

Tools:
  get_stored_response    — Query stored structured data by ref_id with field extraction
  list_stored_responses  — List all stored response references
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Optional

from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.response_store import ResponseStore
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

# Common key fields for record_key lookup, in priority order
_KEY_FIELDS = [
    "composite_id",
    "@id",
    "detection_id",
    "id",
    "TargetProcessId",  # endpoint behavior records (ProcessRollup2)
    "user.name",
    "UserName",
    "user_name",
    "ComputerName",
    "hostname",
    "source.ip",
]


def _get_nested(d: dict, dot_path: str):
    """Navigate a nested dict by dot-separated path. Returns None on miss."""
    keys = dot_path.split(".")
    current = d
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
    return current


def _stringify_record(record) -> str:
    """Recursively stringify a record for text search."""
    if isinstance(record, dict):
        return " ".join(_stringify_record(v) for v in record.values())
    if isinstance(record, list):
        return " ".join(_stringify_record(v) for v in record)
    return str(record)


class ResponseStoreModule(BaseModule):
    """Provides tools to query stored structured data from truncated responses."""

    def __init__(self, client):
        super().__init__(client)
        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.get_stored_response,
            name="get_stored_response",
            description=(
                "Query stored structured data from a previous tool response. "
                "Use ref_id from truncation notices to extract fields, search records, "
                "or retrieve specific records without leaving the MCP tool loop."
            ),
        )
        self._add_tool(
            server,
            self.list_stored_responses,
            name="list_stored_responses",
            description="List all stored response references with metadata summaries.",
        )

    async def get_stored_response(
        self,
        ref_id: Annotated[str, "Reference ID from truncation notice (e.g., 'resp_001')"],
        record_index: Annotated[Optional[int], "Return specific record by 0-based index"] = None,
        record_key: Annotated[Optional[str], "Find record by natural key (scans common ID fields)"] = None,
        fields: Annotated[Optional[str], "Comma-separated dot-path fields to extract"] = None,
        search: Annotated[Optional[str], "Case-insensitive text search across record values"] = None,
        max_results: Annotated[int, "Cap returned records (default: 20)"] = 20,
    ) -> str:
        """Query stored structured data by reference ID."""
        stored = ResponseStore.get(ref_id)
        if not stored:
            available = ResponseStore.list_refs()
            if available:
                ref_list = ", ".join(r["ref_id"] for r in available)
                return format_text_response(
                    f"Reference '{ref_id}' not found. Available: {ref_list}",
                    raw=True,
                )
            return format_text_response(
                f"Reference '{ref_id}' not found. No stored responses available.",
                raw=True,
            )

        data = stored.data
        records = self._find_record_lists(data)

        # ref_id only → metadata overview
        if record_index is None and record_key is None and fields is None and search is None:
            return format_text_response(self._format_metadata(stored), raw=True)

        # record_index → specific record
        if record_index is not None:
            if not records:
                return format_text_response(f"No record lists found in {ref_id}.", raw=True)
            flat = [r for lst in records.values() for r in lst]
            if record_index < 0 or record_index >= len(flat):
                return format_text_response(
                    f"Index {record_index} out of range (0-{len(flat) - 1}).",
                    raw=True,
                )
            record = flat[record_index]
            if fields:
                record = self._project_fields(record, fields)
            return format_text_response(
                json.dumps(record, indent=2, default=str),
                raw=True,
            )

        # record_key → find by natural key
        if record_key is not None:
            flat = [r for lst in records.values() for r in lst]
            match = self._find_by_key(flat, record_key)
            if match is None:
                available_keys = self._available_keys(flat[0] if flat else {})
                return format_text_response(
                    f"No record matching key '{record_key}'. Available key fields: {available_keys}",
                    raw=True,
                )
            if fields:
                match = self._project_fields(match, fields)
            return format_text_response(
                json.dumps(match, indent=2, default=str),
                raw=True,
            )

        # search → text search
        if search is not None:
            flat = [r for lst in records.values() for r in lst]
            matches = [r for r in flat if search.lower() in _stringify_record(r).lower()][:max_results]
            if fields:
                matches = [self._project_fields(m, fields) for m in matches]
            if not matches:
                return format_text_response(
                    f"No records matching '{search}' in {ref_id}.",
                    raw=True,
                )
            return format_text_response(
                json.dumps(matches, indent=2, default=str),
                raw=True,
            )

        # fields only → extract from all records
        if fields:
            flat = [r for lst in records.values() for r in lst][:max_results]
            projected = [self._project_fields(r, fields) for r in flat]
            return format_text_response(
                json.dumps(projected, indent=2, default=str),
                raw=True,
            )

        return format_text_response(self._format_metadata(stored), raw=True)

    async def list_stored_responses(self) -> str:
        """List all stored response references."""
        refs = ResponseStore.list_refs()
        if not refs:
            return format_text_response("No stored responses.", raw=True)

        lines = ["Stored Responses:", ""]
        for r in refs:
            meta_str = ""
            if r.get("metadata"):
                meta_parts = [f"{k}={v}" for k, v in r["metadata"].items() if v]
                meta_str = f" ({', '.join(meta_parts)})" if meta_parts else ""
            lines.append(f"  {r['ref_id']}: {r['tool_name']} | {r['record_count']} records | {r['timestamp']}{meta_str}")
        return format_text_response("\n".join(lines), raw=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_record_lists(data: dict) -> dict[str, list]:
        """Find all top-level list values in data."""
        return {k: v for k, v in data.items() if isinstance(v, list)}

    @staticmethod
    def _format_metadata(stored) -> str:
        """Format metadata overview for a stored response."""
        lines = [
            f"Stored Response: {stored.ref_id}",
            f"Tool: {stored.tool_name}",
            f"Timestamp: {stored.timestamp.isoformat()}",
            f"Records: {stored.record_count}",
        ]
        if stored.metadata:
            for k, v in stored.metadata.items():
                if v:
                    lines.append(f"{k}: {v}")
        lines.extend(
            [
                "",
                "Use parameters to query this data:",
                f'  get_stored_response(ref_id="{stored.ref_id}", fields="field1,field2")',
                f'  get_stored_response(ref_id="{stored.ref_id}", search="keyword")',
                f'  get_stored_response(ref_id="{stored.ref_id}", record_index=0)',
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _project_fields(record: dict, fields_str: str) -> dict:
        """Extract dot-path fields from a record."""
        field_list = [f.strip() for f in fields_str.split(",") if f.strip()]
        result = {}
        for f in field_list:
            result[f] = _get_nested(record, f)
        return result

    @staticmethod
    def _find_by_key(records: list[dict], key_value: str) -> dict | None:
        """Find a record where any common key field matches the value."""
        for record in records:
            for kf in _KEY_FIELDS:
                val = _get_nested(record, kf)
                if val is not None and str(val) == key_value:
                    return record
        return None

    @staticmethod
    def _available_keys(record: dict) -> str:
        """List key fields available in a record."""
        found = []
        for kf in _KEY_FIELDS:
            val = _get_nested(record, kf)
            if val is not None:
                found.append(f"{kf}={val}")
        return ", ".join(found) if found else "(none)"
