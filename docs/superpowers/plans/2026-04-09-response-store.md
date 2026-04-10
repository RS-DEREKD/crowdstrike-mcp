# Response Store Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `ResponseStore` singleton and `get_stored_response` MCP tool so the SOC triage agent can query truncated response data within the MCP tool loop — no Bash/grep fallback needed.

**Architecture:** Root-level `response_store.py` holds the `ResponseStore` class (singleton with classmethods). `modules/response_store.py` holds the `ResponseStoreModule` that registers `get_stored_response` and `list_stored_responses` MCP tools. `utils.py` gains `structured_data` and `metadata` params on `format_text_response()` — opt-in tools pass their raw result dicts through this path. Non-opted-in tools are unchanged (temp file fallback).

**Tech Stack:** Python 3.11, FastMCP, pytest, unittest.mock

**Spec:** `docs/superpowers/specs/2026-04-09-response-store-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `response_store.py` | Create | `ResponseStore` singleton class + `StoredResponse` dataclass |
| `modules/response_store.py` | Create | `ResponseStoreModule` — registers `get_stored_response` and `list_stored_responses` tools |
| `utils.py` | Modify | Add `structured_data` and `metadata` params to `format_text_response()` |
| `modules/alerts.py` | Modify | Pass `structured_data` + `tool_name` + `metadata` from `alert_analysis()` and `get_alerts()` |
| `modules/ngsiem.py` | Modify | Pass `structured_data` + `tool_name` + `metadata` from `ngsiem_query()` |
| `tests/conftest.py` | Modify | Add `ResponseStore._reset()` fixture |
| `tests/test_response_store.py` | Create | Unit tests for `ResponseStore` class |
| `tests/test_get_stored_response.py` | Create | Unit tests for `get_stored_response` tool |
| `tests/test_store_integration.py` | Create | Integration tests for truncation → store flow |

---

## Chunk 1: ResponseStore Class + Unit Tests

### Task 1: Write failing tests for ResponseStore

**Files:**
- Create: `tests/test_response_store.py`
- Modify: `tests/conftest.py`

- [ ] **Step 1: Add ResponseStore reset fixture to conftest.py**

Add after the existing `mock_ngsiem_api` fixture in `tests/conftest.py`:

```python
@pytest.fixture(autouse=True)
def reset_response_store():
    """Reset ResponseStore between tests to prevent state leakage."""
    from response_store import ResponseStore
    ResponseStore._reset()
    yield
    ResponseStore._reset()
```

- [ ] **Step 2: Write failing tests for store, retrieve, counter, eviction, and record counting**

```python
"""Tests for ResponseStore singleton — store, retrieve, eviction, record counting."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from response_store import ResponseStore, StoredResponse


class TestStoreAndRetrieve:
    """Basic store/get operations."""

    def test_store_returns_ref_id(self):
        """store() returns a ref_id like 'resp_001'."""
        ref_id = ResponseStore.store({"events": [{"a": 1}]}, tool_name="test_tool")
        assert ref_id == "resp_001"

    def test_retrieve_stored_data(self):
        """get() returns the stored data unchanged."""
        data = {"events": [{"source.ip": "1.2.3.4"}], "success": True}
        ref_id = ResponseStore.store(data, tool_name="alert_analysis")
        result = ResponseStore.get(ref_id)
        assert isinstance(result, StoredResponse)
        assert result.data == data
        assert result.tool_name == "alert_analysis"

    def test_get_nonexistent_returns_none(self):
        """get() returns None for unknown ref_id."""
        assert ResponseStore.get("resp_999") is None


class TestRefIdIncrementing:
    """ref_ids increment sequentially."""

    def test_sequential_ids(self):
        """Multiple stores produce resp_001, resp_002, resp_003."""
        id1 = ResponseStore.store({"events": []})
        id2 = ResponseStore.store({"events": []})
        id3 = ResponseStore.store({"events": []})
        assert id1 == "resp_001"
        assert id2 == "resp_002"
        assert id3 == "resp_003"


class TestRingBufferEviction:
    """FIFO eviction when max_entries exceeded."""

    def test_oldest_evicted_at_limit(self):
        """First entry is evicted when 51st is stored (max_entries=50)."""
        for i in range(50):
            ResponseStore.store({"events": [{"i": i}]})
        # resp_001 should exist
        assert ResponseStore.get("resp_001") is not None
        # Store one more — resp_001 should be evicted
        ResponseStore.store({"events": [{"i": 50}]})
        assert ResponseStore.get("resp_001") is None
        # resp_002 should still exist
        assert ResponseStore.get("resp_002") is not None


class TestRecordCountGeneric:
    """record_count sums all top-level list values."""

    def test_events_list(self):
        """Counts events list."""
        ref_id = ResponseStore.store({"events": [{"a": 1}, {"a": 2}], "success": True})
        result = ResponseStore.get(ref_id)
        assert result.record_count == 2

    def test_multiple_lists(self):
        """Counts events + behaviors."""
        ref_id = ResponseStore.store({
            "events": [{"a": 1}],
            "behaviors": [{"b": 1}, {"b": 2}],
            "success": True,
        })
        result = ResponseStore.get(ref_id)
        assert result.record_count == 3

    def test_alerts_list(self):
        """Counts alerts from get_alerts result shape."""
        ref_id = ResponseStore.store({
            "alerts": [{"id": "a1"}, {"id": "a2"}, {"id": "a3"}],
            "count": 3,
            "total_available": 100,
        })
        result = ResponseStore.get(ref_id)
        assert result.record_count == 3

    def test_no_lists_zero_count(self):
        """No top-level lists → record_count is 0."""
        ref_id = ResponseStore.store({"success": True, "error": None})
        result = ResponseStore.get(ref_id)
        assert result.record_count == 0

    def test_results_key(self):
        """Counts results list (ngsiem_query alternative shape)."""
        ref_id = ResponseStore.store({"results": [{"x": 1}], "success": True})
        result = ResponseStore.get(ref_id)
        assert result.record_count == 1


class TestListRefs:
    """list_refs() returns summary of all stored responses."""

    def test_list_refs_format(self):
        """list_refs returns dicts with ref_id, tool_name, record_count."""
        ResponseStore.store({"events": [{"a": 1}]}, tool_name="alert_analysis", metadata={"detection_id": "abc"})
        ResponseStore.store({"alerts": [{"id": "x"}]}, tool_name="get_alerts")
        refs = ResponseStore.list_refs()
        assert len(refs) == 2
        assert refs[0]["ref_id"] == "resp_001"
        assert refs[0]["tool_name"] == "alert_analysis"
        assert refs[0]["record_count"] == 1
        assert refs[0]["metadata"] == {"detection_id": "abc"}
        assert refs[1]["ref_id"] == "resp_002"

    def test_list_refs_empty(self):
        """list_refs returns empty list when no responses stored."""
        assert ResponseStore.list_refs() == []
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_response_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'response_store'`

### Task 2: Implement ResponseStore class

**Files:**
- Create: `response_store.py`

- [ ] **Step 1: Write the ResponseStore implementation**

```python
"""
ResponseStore — in-memory structured data store for large MCP tool responses.

Stores raw Python dicts from tool output (before text formatting) so the
get_stored_response MCP tool can do field-level extraction without Bash/grep.

This file lives at the root level (peer to utils.py) to keep the dependency
direction clean: utils.py imports from here, modules import from utils.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class StoredResponse:
    """A stored structured response from an MCP tool."""

    ref_id: str
    tool_name: str
    timestamp: datetime
    data: dict
    metadata: dict
    record_count: int


class ResponseStore:
    """Singleton in-memory store for structured MCP tool responses.

    All methods are classmethods — no instantiation needed.
    Ring buffer with FIFO eviction at _max_entries.
    """

    _store: dict[str, StoredResponse] = {}
    _counter: int = 0
    _max_entries: int = 50

    @classmethod
    def store(
        cls,
        data: dict,
        tool_name: str = "",
        metadata: dict | None = None,
    ) -> str:
        """Store structured data and return a ref_id (e.g., 'resp_001')."""
        cls._counter += 1
        ref_id = f"resp_{cls._counter:03d}"

        if len(cls._store) >= cls._max_entries:
            cls._evict_oldest()

        record_count = cls._count_records(data)

        cls._store[ref_id] = StoredResponse(
            ref_id=ref_id,
            tool_name=tool_name,
            timestamp=datetime.now(),
            data=data,
            metadata=metadata or {},
            record_count=record_count,
        )

        return ref_id

    @classmethod
    def get(cls, ref_id: str) -> StoredResponse | None:
        """Retrieve a stored response by ref_id."""
        return cls._store.get(ref_id)

    @classmethod
    def list_refs(cls) -> list[dict]:
        """Return summary of all stored responses."""
        return [
            {
                "ref_id": sr.ref_id,
                "tool_name": sr.tool_name,
                "timestamp": sr.timestamp.isoformat(),
                "record_count": sr.record_count,
                "metadata": sr.metadata,
            }
            for sr in cls._store.values()
        ]

    @classmethod
    def _count_records(cls, data: dict) -> int:
        """Count records generically: sum lengths of all top-level list values."""
        return sum(len(v) for v in data.values() if isinstance(v, list))

    @classmethod
    def _evict_oldest(cls) -> None:
        """Remove the oldest entry (FIFO)."""
        if cls._store:
            oldest_key = next(iter(cls._store))
            del cls._store[oldest_key]

    @classmethod
    def _reset(cls) -> None:
        """Clear all stored responses and reset counter. For testing only."""
        cls._store.clear()
        cls._counter = 0
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_response_store.py -v`
Expected: All PASS

- [ ] **Step 3: Run full test suite to check for regressions**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All existing tests still pass

- [ ] **Step 4: Commit**

```bash
git add response_store.py tests/test_response_store.py tests/conftest.py
git commit -m "feat: add ResponseStore class with ring buffer and generic record counting"
```

---

## Chunk 2: get_stored_response + list_stored_responses Tools

### Task 3: Write failing tests for get_stored_response tool

**Files:**
- Create: `tests/test_get_stored_response.py`

- [ ] **Step 1: Write failing tests for all get_stored_response behaviors**

```python
"""Tests for get_stored_response and list_stored_responses MCP tools."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from response_store import ResponseStore


# --- Sample data fixtures ---

@pytest.fixture
def stored_alert_analysis():
    """Store an alert_analysis result and return the ref_id."""
    data = {
        "success": True,
        "alert": {
            "name": "Suspicious Login",
            "composite_id": "cid:ngsiem:cid:alert123",
            "severity_name": "High",
            "status": "new",
        },
        "product_type": "ngsiem",
        "product_name": "NG-SIEM",
        "enrichment_type": "ngsiem_events",
        "events": [
            {
                "@timestamp": "2026-04-09T10:00:00Z",
                "event.action": "ConsoleLogin",
                "source": {"ip": "198.51.100.1"},
                "user": {"name": "andy@roadrunnerwm.com"},
                "Vendor": {
                    "properties": {
                        "status": {"errorCode": 0},
                    },
                    "initiatedBy": {
                        "app": {"servicePrincipalId": "sp-22df6a91"},
                    },
                },
                "ComputerName": "RR-9L15TW3",
            },
            {
                "@timestamp": "2026-04-09T10:05:00Z",
                "event.action": "UserLogin",
                "source": {"ip": "203.0.113.50"},
                "user": {"name": "bob@roadrunnerwm.com"},
                "Vendor": {
                    "properties": {
                        "status": {"errorCode": 50126},
                    },
                },
                "ComputerName": "RR-ABC123",
            },
            {
                "@timestamp": "2026-04-09T10:10:00Z",
                "event.action": "ServicePrincipalLogin",
                "source": {"ip": "198.51.100.1"},
                "user": {"name": "svc-backup@roadrunnerwm.com"},
                "Vendor": {
                    "properties": {
                        "status": {"errorCode": 0},
                    },
                },
                "ComputerName": "RR-9L15TW3",
            },
        ],
        "events_matched": 3,
    }
    ref_id = ResponseStore.store(
        data,
        tool_name="alert_analysis",
        metadata={"detection_id": "cid:ngsiem:cid:alert123"},
    )
    return ref_id, data


@pytest.fixture
def stored_ngsiem_query():
    """Store an ngsiem_query result and return the ref_id."""
    data = {
        "success": True,
        "events": [
            {"@timestamp": f"2026-04-09T{10+i}:00:00Z", "DomainName": f"domain{i}.com", "ComputerName": f"host{i}"}
            for i in range(25)
        ],
        "events_matched": 25,
        "events_returned": 25,
        "query": '#event_simpleName=DnsRequest ComputerName="RR-9L15TW3"',
        "time_range": "1d",
    }
    ref_id = ResponseStore.store(
        data,
        tool_name="ngsiem_query",
        metadata={"query": data["query"], "time_range": "1d"},
    )
    return ref_id, data


# --- Helper to invoke the tool method directly ---

@pytest.fixture
def response_store_module(mock_client):
    """Create a ResponseStoreModule instance."""
    from modules.response_store import ResponseStoreModule
    return ResponseStoreModule(mock_client)


# --- Tests ---

class TestRefOnlyReturnsMetadata:
    """ref_id only → metadata overview, no record data."""

    def test_metadata_only(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(ref_id=ref_id)
        assert "alert_analysis" in result
        assert "3 records" in result or "3 events" in result
        assert "cid:ngsiem:cid:alert123" in result
        # Should NOT contain full event data
        assert "198.51.100.1" not in result


class TestRecordIndex:
    """record_index returns a specific record."""

    def test_returns_specific_record(self, response_store_module, stored_alert_analysis):
        ref_id, data = stored_alert_analysis
        result = response_store_module._get_stored_response(ref_id=ref_id, record_index=0)
        parsed = json.loads(result)
        assert parsed["@timestamp"] == "2026-04-09T10:00:00Z"
        assert parsed["source"]["ip"] == "198.51.100.1"

    def test_index_out_of_range(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(ref_id=ref_id, record_index=99)
        assert "out of range" in result.lower() or "invalid" in result.lower()


class TestRecordKeyLookup:
    """record_key finds a record by natural key field."""

    def test_find_by_user_name(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(
            ref_id=ref_id, record_key="bob@roadrunnerwm.com",
        )
        parsed = json.loads(result)
        assert parsed["user"]["name"] == "bob@roadrunnerwm.com"

    def test_find_by_computer_name(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(
            ref_id=ref_id, record_key="RR-ABC123",
        )
        parsed = json.loads(result)
        assert parsed["ComputerName"] == "RR-ABC123"

    def test_key_not_found(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(
            ref_id=ref_id, record_key="nonexistent@example.com",
        )
        assert "not found" in result.lower()


class TestFieldsExtraction:
    """fields parameter extracts dot-path fields."""

    def test_dot_path_extraction(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(
            ref_id=ref_id, fields="source.ip,Vendor.properties.status.errorCode",
        )
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert len(parsed) == 3
        assert parsed[0]["source.ip"] == "198.51.100.1"
        assert parsed[0]["Vendor.properties.status.errorCode"] == 0
        assert parsed[1]["source.ip"] == "203.0.113.50"
        assert parsed[1]["Vendor.properties.status.errorCode"] == 50126

    def test_missing_field_returns_null(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(
            ref_id=ref_id, fields="nonexistent.field",
        )
        parsed = json.loads(result)
        assert parsed[0]["nonexistent.field"] is None

    def test_fields_with_record_index(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(
            ref_id=ref_id, record_index=1, fields="source.ip,user.name",
        )
        parsed = json.loads(result)
        # Single record, not a list
        assert parsed["source.ip"] == "203.0.113.50"
        assert parsed["user.name"] == "bob@roadrunnerwm.com"


class TestSearch:
    """search parameter does case-insensitive substring match."""

    def test_search_case_insensitive(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(
            ref_id=ref_id, search="BOB@",
        )
        parsed = json.loads(result)
        assert len(parsed) == 1
        assert parsed[0]["user"]["name"] == "bob@roadrunnerwm.com"

    def test_search_with_fields(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(
            ref_id=ref_id, search="22df6a91", fields="source.ip,Vendor.initiatedBy.app.servicePrincipalId",
        )
        parsed = json.loads(result)
        assert len(parsed) == 1
        assert parsed[0]["source.ip"] == "198.51.100.1"
        assert parsed[0]["Vendor.initiatedBy.app.servicePrincipalId"] == "sp-22df6a91"

    def test_search_no_match(self, response_store_module, stored_alert_analysis):
        ref_id, _ = stored_alert_analysis
        result = response_store_module._get_stored_response(
            ref_id=ref_id, search="zzz_no_match_zzz",
        )
        assert "no records" in result.lower() or "0 match" in result.lower()

    def test_max_results_cap(self, response_store_module, stored_ngsiem_query):
        ref_id, _ = stored_ngsiem_query
        result = response_store_module._get_stored_response(
            ref_id=ref_id, search="domain", max_results=5,
        )
        parsed = json.loads(result)
        assert len(parsed) == 5


class TestInvalidRefId:
    """Clean error for nonexistent ref_id."""

    def test_invalid_ref_id(self, response_store_module):
        result = response_store_module._get_stored_response(ref_id="resp_999")
        assert "not found" in result.lower()


class TestListStoredResponses:
    """list_stored_responses tool."""

    def test_lists_all_stored(self, response_store_module, stored_alert_analysis, stored_ngsiem_query):
        result = response_store_module._list_stored_responses()
        assert "resp_001" in result
        assert "resp_002" in result
        assert "alert_analysis" in result
        assert "ngsiem_query" in result

    def test_empty_store(self, response_store_module):
        result = response_store_module._list_stored_responses()
        assert "no stored responses" in result.lower() or "empty" in result.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_get_stored_response.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'modules.response_store'`

### Task 4: Implement ResponseStoreModule with get_stored_response tool

**Files:**
- Create: `modules/response_store.py`

- [ ] **Step 1: Write the ResponseStoreModule implementation**

```python
"""
ResponseStore Module — MCP tools for querying stored structured responses.

Tools:
  get_stored_response    — Query stored response data by ref_id with field extraction,
                           search, and record key lookup
  list_stored_responses  — List all stored responses with metadata summaries
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Optional

from modules.base import BaseModule
from response_store import ResponseStore

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

# Key fields scanned for record_key lookup, in priority order
_KEY_FIELDS = [
    "composite_id", "@id", "detection_id", "id",
    "user.name", "UserName", "user_name",
    "ComputerName", "hostname",
    "source.ip",
]


def _get_nested(data: dict, dot_path: str):
    """Navigate a nested dict by dot-separated path. Returns None if missing."""
    keys = dot_path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
    return current


def _stringify_values(obj, _depth: int = 0) -> str:
    """Recursively stringify all values in a dict/list for search matching."""
    if _depth > 10:
        return str(obj)
    if isinstance(obj, dict):
        return " ".join(_stringify_values(v, _depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_stringify_values(item, _depth + 1) for item in obj)
    return str(obj)


def _get_records(data: dict) -> list:
    """Extract the record list(s) from stored data.

    Looks for top-level list values. If multiple lists exist, concatenates
    them (events + behaviors for alert_analysis). Skips non-record lists
    like 'tags'.
    """
    records = []
    for key, value in data.items():
        if isinstance(value, list) and value and isinstance(value[0], dict):
            records.extend(value)
    return records


class ResponseStoreModule(BaseModule):
    """MCP tools for querying the in-memory response store."""

    def __init__(self, client):
        super().__init__(client)
        self._log("Initialized (no API client needed)")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.get_stored_response,
            name="get_stored_response",
            description=(
                "Query stored structured data from a previous tool response that was "
                "truncated or stored for later access. Supports field extraction, "
                "search, and record key lookup — no Bash/grep needed."
            ),
        )
        self._add_tool(
            server,
            self.list_stored_responses,
            name="list_stored_responses",
            description="List all stored responses with ref_id, tool name, record count, and metadata.",
        )

    async def get_stored_response(
        self,
        ref_id: Annotated[str, "Reference ID from a previous tool response (e.g., 'resp_001')"],
        record_index: Annotated[Optional[int], "Return specific record by 0-based index"] = None,
        record_key: Annotated[Optional[str], "Find record by natural key (scans composite_id, user.name, ComputerName, source.ip, etc.)"] = None,
        fields: Annotated[Optional[str], "Comma-separated dot-path fields to extract (e.g., 'source.ip,Vendor.properties.status.errorCode')"] = None,
        search: Annotated[Optional[str], "Case-insensitive text search across all record values"] = None,
        max_results: Annotated[int, "Maximum records to return from search (default: 20)"] = 20,
    ) -> str:
        """Query stored structured data from a previous response."""
        return self._get_stored_response(
            ref_id=ref_id,
            record_index=record_index,
            record_key=record_key,
            fields=fields,
            search=search,
            max_results=max_results,
        )

    async def list_stored_responses(self) -> str:
        """List all stored responses."""
        return self._list_stored_responses()

    # ------------------------------------------------------------------
    # Internal methods (sync, testable without async)
    # ------------------------------------------------------------------

    def _get_stored_response(
        self,
        *,
        ref_id: str,
        record_index: int | None = None,
        record_key: str | None = None,
        fields: str | None = None,
        search: str | None = None,
        max_results: int = 20,
    ) -> str:
        stored = ResponseStore.get(ref_id)
        if stored is None:
            available = [sr["ref_id"] for sr in ResponseStore.list_refs()]
            if available:
                return f"Error: ref_id '{ref_id}' not found. Available: {', '.join(available)}"
            return f"Error: ref_id '{ref_id}' not found. No stored responses available."

        records = _get_records(stored.data)

        # --- ref_id only: metadata overview ---
        if record_index is None and record_key is None and fields is None and search is None:
            lines = [
                f"Stored Response: {stored.ref_id}",
                f"Tool: {stored.tool_name}",
                f"Timestamp: {stored.timestamp.isoformat()}",
                f"Records: {stored.record_count}",
            ]
            if stored.metadata:
                for k, v in stored.metadata.items():
                    lines.append(f"  {k}: {v}")
            # List available record key fields from first record
            if records:
                available_keys = []
                for kf in _KEY_FIELDS:
                    val = _get_nested(records[0], kf)
                    if val is not None:
                        available_keys.append(f"{kf}={val}")
                if available_keys:
                    lines.append(f"Key fields (first record): {', '.join(available_keys)}")
            return "\n".join(lines)

        # --- record_key lookup ---
        if record_key is not None:
            for record in records:
                for kf in _KEY_FIELDS:
                    val = _get_nested(record, kf)
                    if val is not None and str(val) == record_key:
                        if fields:
                            projected = self._project_fields(record, fields)
                            return json.dumps(projected, indent=2, default=str)
                        return json.dumps(record, indent=2, default=str)
            # Not found — show available keys
            if records:
                available_keys = set()
                for record in records[:5]:
                    for kf in _KEY_FIELDS:
                        val = _get_nested(record, kf)
                        if val is not None:
                            available_keys.add(f"{kf}={val}")
                return f"Error: record_key '{record_key}' not found. Available keys (first 5 records): {', '.join(sorted(available_keys))}"
            return f"Error: record_key '{record_key}' not found. No records in stored response."

        # --- record_index ---
        if record_index is not None:
            if record_index < 0 or record_index >= len(records):
                return f"Error: record_index {record_index} out of range. Valid range: 0-{len(records) - 1}"
            record = records[record_index]
            if fields:
                projected = self._project_fields(record, fields)
                return json.dumps(projected, indent=2, default=str)
            return json.dumps(record, indent=2, default=str)

        # --- search ---
        if search is not None:
            search_lower = search.lower()
            matches = []
            for record in records:
                if search_lower in _stringify_values(record).lower():
                    matches.append(record)
                    if len(matches) >= max_results:
                        break

            if not matches:
                return f"No records matching '{search}' in {stored.ref_id} ({len(records)} records searched)."

            if fields:
                projected = [self._project_fields(r, fields) for r in matches]
                return json.dumps(projected, indent=2, default=str)
            return json.dumps(matches, indent=2, default=str)

        # --- fields only (extract from all records) ---
        if fields is not None:
            projected = [self._project_fields(r, fields) for r in records[:max_results]]
            return json.dumps(projected, indent=2, default=str)

        return json.dumps(records[:max_results], indent=2, default=str)

    def _list_stored_responses(self) -> str:
        refs = ResponseStore.list_refs()
        if not refs:
            return "No stored responses available."

        lines = [f"Stored Responses ({len(refs)}):"]
        lines.append("")
        for ref in refs:
            meta_parts = []
            if ref.get("metadata"):
                for k, v in ref["metadata"].items():
                    meta_parts.append(f"{k}={v}")
            meta_str = f" | {', '.join(meta_parts)}" if meta_parts else ""
            lines.append(
                f"  {ref['ref_id']}: {ref['tool_name']} — "
                f"{ref['record_count']} records — "
                f"{ref['timestamp']}{meta_str}"
            )
        return "\n".join(lines)

    @staticmethod
    def _project_fields(record: dict, fields_str: str) -> dict:
        """Extract dot-path fields from a record."""
        field_names = [f.strip() for f in fields_str.split(",") if f.strip()]
        return {name: _get_nested(record, name) for name in field_names}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_get_stored_response.py -v`
Expected: All PASS

- [ ] **Step 3: Run full test suite**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add modules/response_store.py tests/test_get_stored_response.py
git commit -m "feat: add get_stored_response and list_stored_responses MCP tools"
```

---

## Chunk 3: Integrate with utils.py and Opt-In Tools

### Task 5: Write failing integration tests

**Files:**
- Create: `tests/test_store_integration.py`

- [ ] **Step 1: Write failing integration tests for the truncation → store flow**

```python
"""Integration tests for structured data storage through format_text_response."""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from response_store import ResponseStore
from utils import LARGE_RESPONSE_THRESHOLD, format_text_response


class TestAlertAnalysisStoresOnTruncation:
    """Large response with structured_data → stored with ref_id in notice."""

    def test_truncated_response_includes_ref_id(self):
        large_text = "x" * (LARGE_RESPONSE_THRESHOLD + 1000)
        data = {"events": [{"source.ip": "1.2.3.4"}], "success": True}

        result = format_text_response(
            large_text,
            tool_name="alert_analysis",
            raw=True,
            structured_data=data,
            metadata={"detection_id": "cid:ngsiem:cid:abc123"},
        )

        assert "resp_001" in result
        assert "get_stored_response" in result
        assert "alert_analysis" in result
        assert "cid:ngsiem:cid:abc123" in result
        # Old temp file path should NOT appear
        assert "crowdstrike-mcp" not in result or "get_stored_response" in result

    def test_structured_data_is_queryable(self):
        large_text = "x" * (LARGE_RESPONSE_THRESHOLD + 1000)
        data = {
            "events": [{"source": {"ip": "198.51.100.1"}, "user": {"name": "andy"}}],
            "success": True,
        }

        format_text_response(
            large_text,
            tool_name="alert_analysis",
            raw=True,
            structured_data=data,
        )

        stored = ResponseStore.get("resp_001")
        assert stored is not None
        assert stored.data["events"][0]["source"]["ip"] == "198.51.100.1"


class TestNonOptInToolNoStoreWhenFits:
    """Tool without structured_data + small response → no storage."""

    def test_no_store_no_ref(self):
        small_text = "Host: RR-9L15TW3\nPlatform: Windows"
        result = format_text_response(small_text, raw=True)
        assert "resp_" not in result
        assert ResponseStore.list_refs() == []


class TestOptInToolsAlwaysStore:
    """Opt-in tools pass structured_data even for small responses → always stored."""

    def test_small_response_still_stored(self):
        small_text = "Alert: test (1 event)"
        data = {"events": [{"a": 1}], "success": True}

        result = format_text_response(
            small_text,
            tool_name="alert_analysis",
            raw=True,
            structured_data=data,
        )

        # Response fits inline — returned as-is (with footer)
        assert "test" in result
        # But structured data was stored
        stored = ResponseStore.get("resp_001")
        assert stored is not None
        assert stored.data == data

    def test_inline_response_has_ref_footer(self):
        small_text = "Alert: test"
        data = {"events": [{"a": 1}], "success": True}

        result = format_text_response(
            small_text,
            tool_name="alert_analysis",
            raw=True,
            structured_data=data,
        )

        assert "resp_001" in result


class TestTruncationNoticeIncludesContext:
    """Truncation notice surfaces tool name and key metadata."""

    def test_context_line_with_detection_id(self):
        large_text = "x" * (LARGE_RESPONSE_THRESHOLD + 1000)
        data = {"events": [], "success": True}

        result = format_text_response(
            large_text,
            tool_name="alert_analysis",
            raw=True,
            structured_data=data,
            metadata={"detection_id": "cid:ngsiem:cid:xyz789"},
        )

        assert "alert_analysis" in result
        assert "cid:ngsiem:cid:xyz789" in result

    def test_context_line_with_query(self):
        large_text = "x" * (LARGE_RESPONSE_THRESHOLD + 1000)
        data = {"events": [], "success": True}

        result = format_text_response(
            large_text,
            tool_name="ngsiem_query",
            raw=True,
            structured_data=data,
            metadata={"query": '#event_simpleName=DnsRequest ComputerName="RR-9L15TW3"'},
        )

        assert "ngsiem_query" in result
        assert "DnsRequest" in result


class TestAlertAnalysisEndToEndWiring:
    """End-to-end: alert_analysis actually passes structured_data through."""

    def test_alert_analysis_stores_structured_data(self):
        """Calling alert_analysis with a mocked backend stores data in ResponseStore."""
        from unittest.mock import MagicMock, patch

        with patch("modules.alerts.Alerts") as MockAlerts, \
             patch("modules.alerts.NGSIEM", create=True):
            mock_alerts_api = MagicMock()
            MockAlerts.return_value = mock_alerts_api
            mock_client = MagicMock()
            mock_client.auth_object = MagicMock()

            from modules.alerts import AlertsModule
            module = AlertsModule(mock_client)
            module.alerts = mock_alerts_api

            # Mock _analyze_alert to return a small result
            small_result = {
                "success": True,
                "alert": {
                    "name": "Test",
                    "composite_id": "cid:ngsiem:cid:test1",
                    "severity_name": "Low",
                    "severity": 20,
                    "status": "new",
                    "type": "detection",
                    "product": {"name": "ngsiem"},
                },
                "product_type": "ngsiem",
                "product_name": "NG-SIEM",
                "enrichment_type": "ngsiem_events",
                "events": [{"@timestamp": "2026-04-09T00:00:00Z", "source": {"ip": "1.2.3.4"}}],
                "events_matched": 1,
            }
            module._analyze_alert = MagicMock(return_value=small_result)

            import asyncio
            asyncio.run(module.alert_analysis(detection_id="cid:ngsiem:cid:test1"))

            # Verify structured data was stored
            refs = ResponseStore.list_refs()
            assert len(refs) >= 1
            stored = ResponseStore.get(refs[-1]["ref_id"])
            assert stored is not None
            assert stored.tool_name == "alert_analysis"
            assert stored.data["events"][0]["source"]["ip"] == "1.2.3.4"


class TestBackwardCompatNoStructuredData:
    """Tool without structured_data → existing temp file fallback on truncation."""

    def test_temp_file_fallback(self):
        large_text = "x" * (LARGE_RESPONSE_THRESHOLD + 1000)

        result = format_text_response(large_text, tool_name="host_lookup", raw=True)

        # Should use old temp file path behavior
        assert "Full output saved to:" in result
        assert "cat " in result
        # Should NOT have ref_id
        assert "resp_" not in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_store_integration.py -v`
Expected: FAIL — `format_text_response()` doesn't accept `structured_data` yet

### Task 6: Modify format_text_response in utils.py

**Files:**
- Modify: `utils.py:75-110`

- [ ] **Step 1: Update format_text_response to accept structured_data and metadata**

In `utils.py`, make two changes:

**First**, add a top-level import near the other imports at the top of `utils.py`:

```python
from response_store import ResponseStore
```

**Second**, modify the `format_text_response` function. The change is:
1. Add `structured_data` and `metadata` keyword params
2. When `structured_data` is provided, always store via `ResponseStore.store()`
3. On truncation with structured_data: replace temp file notice with ref_id notice
4. On inline with structured_data: append ref_id footer
5. Without structured_data: existing temp file behavior unchanged

Replace `format_text_response` (lines 75-110) with:

```python
def format_text_response(
    text: str,
    *,
    tool_name: str = "",
    raw: bool = False,
    structured_data: dict | None = None,
    metadata: dict | None = None,
) -> Union[str, List[Dict[str, str]]]:
    """Format a text string as an MCP-compatible response.

    If the response exceeds LARGE_RESPONSE_THRESHOLD:
      - With structured_data: stores in ResponseStore, returns truncated text + ref_id
      - Without structured_data: writes to temp file (backward compat)

    When structured_data is provided, always stores regardless of text size
    (opt-in tools always store for later field-level access).
    """
    ref_id = None

    # Opt-in tools: always store structured data
    if structured_data is not None:
        ref_id = ResponseStore.store(structured_data, tool_name or _current_tool_name, metadata)

    if len(text) <= LARGE_RESPONSE_THRESHOLD:
        # Text fits inline
        if ref_id:
            text = f"{text}\n\n[Structured data available: {ref_id}]"
        return text if raw else [{"type": "text", "text": text}]

    # Text exceeds threshold — truncate
    if ref_id:
        # Structured data path — use ref_id notice
        summary = _extract_summary(text)
        record_count = sum(
            len(v) for v in structured_data.values() if isinstance(v, list)
        ) if structured_data else 0

        # Build context line from metadata
        context_parts = [f"Tool: {tool_name or _current_tool_name}"]
        if metadata:
            for key in ("detection_id", "query", "filter"):
                val = metadata.get(key)
                if val:
                    display_val = str(val)[:100]
                    context_parts.append(f"{key}: {display_val}")
                    break

        parts = [
            summary,
            "",
            f"--- RESPONSE TRUNCATED ({len(text):,} chars) ---",
            f"Structured data stored as: {ref_id} ({record_count} records)",
            " | ".join(context_parts),
            "",
            "To query this data use the get_stored_response tool:",
            f'  get_stored_response(ref_id="{ref_id}")                                → metadata overview',
            f'  get_stored_response(ref_id="{ref_id}", fields="source.ip,user.name")  → extract fields',
            f'  get_stored_response(ref_id="{ref_id}", search="keyword")              → search records',
            f'  get_stored_response(ref_id="{ref_id}", record_index=0)                → full first record',
        ]
        result = "\n".join(parts)
        return result if raw else [{"type": "text", "text": result}]

    # No structured data — temp file fallback (backward compat)
    file_path = _write_response_file(text, tool_name or _current_tool_name)
    summary = _extract_summary(text)

    parts = [
        summary,
        "",
        f"--- RESPONSE TRUNCATED ({len(text):,} chars) ---",
        f"Full output saved to: {file_path}",
        "",
        "To inspect the full data, use bash:",
        f"  cat '{file_path}' | head -200",
        f"  python3 -c \"import json; print(open('{file_path}').read()[:5000])\"",
        f"  grep -i 'keyword' '{file_path}'",
    ]

    result = "\n".join(parts)
    return result if raw else [{"type": "text", "text": result}]
```

**Important**: this changes `tool_name` and `raw` from positional-or-keyword to keyword-only (after `*`). All existing callers already use `raw=True` as a keyword. No breakage.

- [ ] **Step 2: Update all existing callers to use keyword arguments**

All callers in the codebase already use `format_text_response(text, raw=True)` or `format_text_response(f"Error: ...", raw=True)`. The only caller that passes `tool_name` positionally is in `utils.py` itself (the old temp file path inside the function). Grep to confirm:

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && grep -rn "format_text_response" modules/ utils.py --include="*.py"`

Check that no caller passes positional args beyond `text`. If any do, update them to keyword.

- [ ] **Step 3: Run integration tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_store_integration.py -v`
Expected: All PASS

- [ ] **Step 4: Run full test suite**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All pass — existing callers unaffected

- [ ] **Step 5: Commit**

```bash
git add utils.py tests/test_store_integration.py
git commit -m "feat: integrate ResponseStore with format_text_response truncation path"
```

### Task 7: Wire up alert_analysis and get_alerts

**Files:**
- Modify: `modules/alerts.py:174-191` (alert_analysis)
- Modify: `modules/alerts.py:114-172` (get_alerts)

- [ ] **Step 1: Update alert_analysis to pass structured_data**

In `modules/alerts.py`, modify the `alert_analysis` method (around line 174-191). Change the return statement to pass `tool_name`, `structured_data`, and `metadata`:

Replace:
```python
        response_text = self._format_alert_analysis_response(result, summary_mode=summary_mode)
        return format_text_response(response_text, raw=True)
```

With:
```python
        response_text = self._format_alert_analysis_response(result, summary_mode=summary_mode)
        return format_text_response(
            response_text,
            tool_name="alert_analysis",
            raw=True,
            structured_data=result,
            metadata={"detection_id": detection_id},
        )
```

- [ ] **Step 2: Update get_alerts to pass structured_data**

In `modules/alerts.py`, modify the `get_alerts` method (around line 114-172). Capture the result dict and pass it through. Change the final return:

Replace:
```python
        return format_text_response("\n".join(lines), raw=True)
```

With:
```python
        return format_text_response(
            "\n".join(lines),
            tool_name="get_alerts",
            raw=True,
            structured_data=result,
            metadata={"filter": result.get("filter"), "q": q, "time_range": time_range},
        )
```

**Note**: The `result` variable from `self._get_alerts()` is already available in scope — it's used to build `alerts_list = result["alerts"]` at the top of the method.

- [ ] **Step 3: Run full test suite**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add modules/alerts.py
git commit -m "feat: wire alert_analysis and get_alerts to ResponseStore"
```

### Task 8: Wire up ngsiem_query

**Files:**
- Modify: `modules/ngsiem.py:54-100`

- [ ] **Step 1: Update ngsiem_query to pass structured_data**

In `modules/ngsiem.py`, modify the `ngsiem_query` method (around line 54-100). Capture the `result` dict and pass it through on success. Change the success return:

Replace:
```python
            return format_text_response("\n".join(lines), raw=True)
```

With:
```python
            return format_text_response(
                "\n".join(lines),
                tool_name="ngsiem_query",
                raw=True,
                structured_data=result,
                metadata={"query": result.get("query"), "time_range": start_time},
            )
```

The error path (`else` branch) remains unchanged — no structured_data on error.

- [ ] **Step 2: Run full test suite**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add modules/ngsiem.py
git commit -m "feat: wire ngsiem_query to ResponseStore"
```

---

## Chunk 4: Final Validation + Docs

### Task 9: Full regression test and smoke test

- [ ] **Step 1: Run full test suite**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests pass (existing + new)

- [ ] **Step 2: Verify module auto-discovery includes ResponseStoreModule**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -c "from registry import get_module_names; print(get_module_names())"`
Expected: Output includes `'responsestore'` alongside existing modules

- [ ] **Step 3: Verify tool count increased by 2**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -c "
from unittest.mock import MagicMock
from registry import get_available_modules
client = MagicMock()
client.auth_object = MagicMock()
modules = get_available_modules(client, allow_writes=True)
tools = [t for m in modules for t in m.tools]
print(f'Total tools: {len(tools)}')
print('New tools:', [t for t in tools if 'stored' in t or 'store' in t])
"`
Expected: `get_stored_response` and `list_stored_responses` in tool list

### Task 10: Update README with response store docs

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add response store section to README**

Find the tools table or tool documentation section in README.md and add entries for the two new tools. Also add a section explaining the structured data storage behavior:

Add to the tools table:
```markdown
| `get_stored_response` | Query stored structured data from truncated responses — field extraction, search, key lookup |
| `list_stored_responses` | List all stored responses with metadata summaries |
```

Add a new section:
```markdown
### Structured Data Storage

When tools like `alert_analysis`, `ngsiem_query`, or `get_alerts` produce responses that exceed
the MCP context limit (20KB default), the structured data is stored in memory and a reference ID
is returned. Use `get_stored_response` to query this data without leaving the MCP tool loop:

```
get_stored_response(ref_id="resp_001")                                → metadata overview
get_stored_response(ref_id="resp_001", fields="source.ip,user.name")  → extract specific fields
get_stored_response(ref_id="resp_001", search="keyword")              → search across records
get_stored_response(ref_id="resp_001", record_key="user@example.com") → find record by key
get_stored_response(ref_id="resp_001", record_index=0)                → full first record
```

Opt-in tools always store structured data, even when the response fits inline. The `[Structured data available: resp_001]` footer on inline responses indicates stored data is available for later drill-down.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add response store tools and structured data storage to README"
```
