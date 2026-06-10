# Response Store: Structured Data Retrieval for Truncated MCP Responses

**Date**: 2026-04-09
**Status**: Approved
**Author**: SOC AI Agent + Will Webster

---

## Problem

When MCP tool responses exceed 20KB, `format_text_response()` writes the full output to a temp file and returns a truncated summary with the file path. The SOC triage agent must then break out of the MCP tool loop and use `Read`/`grep` via Bash to access the data. This kills autonomous operation.

The `summary_mode` improvements shipped in PR #3 reduce truncation frequency, but during real triage the agent often needs full event-level fields (e.g., `source.ip`, `Vendor.properties.status.errorCode`, `Vendor.initiatedBy.app.servicePrincipalId`) that only exist in the raw event payloads — which are exactly what gets truncated.

**Root cause**: structured data from tools like `_analyze_alert()` is serialized to formatted text *before* the truncation decision. Once truncated, the structured data is lost — the agent can only grep over text.

## Solution

Add a `ResponseStore` singleton that holds structured tool output (Python dicts) in memory, queryable via a new `get_stored_response` MCP tool. The triage agent stays in the MCP tool loop — no Bash, no file reads.

### Design Principles

1. **Store structured data before text formatting** — field extraction is dict access, not regex
2. **Opt-in per tool** — chronic offenders (`alert_analysis`, `ngsiem_query`, `get_alerts`) always store; everything else only stores on truncation
3. **Backward compatible** — tools that don't pass `structured_data` get the existing temp file fallback
4. **Clean dependency direction** — `utils.py` imports `ResponseStore`; `ResponseStore` does not import from `utils.py`

## Architecture

### Data Flow

```
_analyze_alert() → structured dict (events, behaviors, alert)
    ↓
format_text_response(text, structured_data=result)
    ↓
    ├── text fits inline + structured_data provided → return text, store structured data
    ├── text exceeds threshold + structured_data provided → store structured data, return truncated text with ref_id
    └── text exceeds threshold + no structured_data → existing temp file fallback
```

### Dependency Direction

The `ResponseStore` class (dataclass + singleton logic) lives in a root-level file `response_store.py`, peer to `utils.py`. The `ResponseStoreModule` (MCP tool registration) lives in `modules/response_store.py` and imports from the root-level file. This keeps the natural dependency direction: modules import from root-level utilities, never the reverse.

```
response_store.py (root-level, peer to utils.py)
    └── ResponseStore class (classmethods)
    └── StoredResponse dataclass

utils.py ──imports──→ response_store.py (peer import, same level)
modules/alerts.py ──imports──→ utils.py
modules/ngsiem.py ──imports──→ utils.py

modules/response_store.py (ResponseStoreModule)
    ├── imports ResponseStore from root-level response_store.py
    ├── registers get_stored_response tool
    └── registers list_stored_responses tool
```

No circular imports. No utility-to-module dependency inversion.

## Components

### 1. ResponseStore class

Location: `response_store.py` (root-level, peer to `utils.py`)

Singleton with classmethods — no instantiation needed by callers.

```python
@dataclass
class StoredResponse:
    ref_id: str
    tool_name: str
    timestamp: datetime
    data: dict            # raw structured dict from the tool
    metadata: dict        # query context, filters, alert ID, etc.
    record_count: int     # count of top-level list values in data

class ResponseStore:
    _store: dict[str, StoredResponse] = {}
    _counter: int = 0
    _max_entries: int = 50

    @classmethod
    def store(cls, data: dict, tool_name: str = "", metadata: dict | None = None) -> str:
        """Store structured data, return ref_id (e.g., 'resp_001')."""

    @classmethod
    def get(cls, ref_id: str) -> StoredResponse | None:
        """Retrieve by ref_id."""

    @classmethod
    def list_refs(cls) -> list[dict]:
        """Return summary of all stored refs (id, tool, timestamp, record_count, metadata)."""

    @classmethod
    def _count_records(cls, data: dict) -> int:
        """Count records generically: sum lengths of all top-level list values in data."""

    @classmethod
    def _evict_oldest(cls) -> None:
        """FIFO eviction when _max_entries exceeded."""

    @classmethod
    def _reset(cls) -> None:
        """Clear all stored responses and reset counter. For testing only."""
```

**Test isolation**: `_reset()` is called in a pytest fixture (`conftest.py`) to prevent state leakage between test cases.

**record_count derivation**: scans all top-level values in `data`, sums the length of any that are lists. Handles `events`, `behaviors`, `alerts`, `results`, and any future list keys without hardcoding.

**Ring buffer**: 50 entries, FIFO eviction. MCP server is single-session; 50 is generous for any triage session.

### 2. get_stored_response tool

Location: `modules/response_store.py`, registered via `ResponseStoreModule`

**Note**: `ResponseStoreModule` extends `BaseModule` which requires a `FalconClient` in `__init__`. The module doesn't use the client — this is an accepted tradeoff to stay consistent with the module auto-discovery pattern. The `client` parameter is ignored.

**Parameters:**

| Param | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ref_id` | str | yes | — | Reference ID (e.g., `resp_001`) |
| `record_index` | int | no | None | Return specific record by 0-based index |
| `record_key` | str | no | None | Find record by natural key (scans common ID fields) |
| `fields` | str | no | None | Comma-separated dot-path fields to extract |
| `search` | str | no | None | Case-insensitive text search across record values |
| `max_results` | int | no | 20 | Cap returned records |

**Behavior matrix:**

| Params | Result |
|--------|--------|
| `ref_id` only | Metadata overview: tool, timestamp, record count, stored query/filters. No record data. |
| `+ record_index` | Full record at that index |
| `+ record_key` | Find record where a common key field matches the value |
| `+ fields` | Extract dot-path fields from all records as compact list |
| `+ search` | Return records containing substring match (capped at `max_results`) |
| `+ record_index + fields` | Extract specific fields from one record |
| `+ search + fields` | Search, then project fields from matches |

**record_key lookup**: scans a prioritized list of common key fields in each record:
- `composite_id`, `@id`, `detection_id`, `id`
- `user.name`, `UserName`, `user_name`
- `ComputerName`, `hostname`
- `source.ip`

Returns the first record where any of these fields matches `record_key`. If no match, returns a clear error listing available key fields found in the first record.

**Dot-path field extraction**: `fields="source.ip,Vendor.properties.status.errorCode"` navigates nested dicts. Missing fields return `null`, not errors.

**Search**: stringifies each record value recursively and does case-insensitive substring match.

### 3. list_stored_responses tool

Location: `modules/response_store.py`

No parameters. Returns the output of `ResponseStore.list_refs()` — a summary table of all stored responses with ref_id, tool name, timestamp, record count, and key metadata. Useful when the agent needs to find a ref_id from a prior call.

### 4. Changes to utils.py

`format_text_response()` gains two optional parameters:

```python
def format_text_response(
    text: str,
    tool_name: str = "",
    raw: bool = False,
    structured_data: dict | None = None,  # NEW — raw structured dict from tool
    metadata: dict | None = None,         # NEW — query context, filters, alert ID
) -> Union[str, List[Dict[str, str]]]:
```

**Important**: opt-in tools must pass `tool_name` explicitly. Currently no module passes it — all call `format_text_response(text, raw=True)`. The opt-in tools must change to pass `tool_name` so the store can label responses meaningfully.

**Logic when `structured_data` is provided:**
- Always store: `ref_id = ResponseStore.store(structured_data, tool_name, metadata)` — opt-in tools always store regardless of text size (enables field extraction even on non-truncated responses)
- If text fits inline: return text with a small footer: `[Structured data available: resp_001]`
- If text exceeds threshold: return truncated summary with ref_id and context in notice

**Logic when `structured_data` is NOT provided:**
- Existing behavior unchanged — temp file fallback on truncation

**Truncation notice format (with structured data):**

```
--- RESPONSE TRUNCATED (145,230 chars) ---
Structured data stored as: resp_001 (10 events)
Tool: alert_analysis | Alert: cust_id:ngsiem:cust_id:abc123def456

To query this data use the get_stored_response tool:
  get_stored_response(ref_id="resp_001")                                → metadata overview
  get_stored_response(ref_id="resp_001", fields="source.ip,user.name")  → extract fields
  get_stored_response(ref_id="resp_001", search="keyword")              → search records
  get_stored_response(ref_id="resp_001", record_index=0)                → full first record
```

The context line (e.g., `Alert: cust_id:ngsiem:...`) is derived from the `metadata` parameter — surface the first useful identifier so the agent can distinguish multiple stored responses without an extra tool call. `format_text_response` scans `metadata` for keys like `detection_id`, `query`, `filter` and picks the first non-empty value for the context line.

### 5. Changes to modules/alerts.py

**`alert_analysis()`** — pass structured result, tool_name, and metadata:

```python
async def alert_analysis(self, detection_id, max_events=10, summary_mode=False):
    detection_id = extract_detection_id(detection_id)
    result = await asyncio.to_thread(self._analyze_alert, detection_id, max_events)

    if not result.get("success"):
        return format_text_response(...)

    response_text = self._format_alert_analysis_response(result, summary_mode=summary_mode)
    return format_text_response(
        response_text,
        tool_name="alert_analysis",
        raw=True,
        structured_data=result,
        metadata={"detection_id": detection_id},
    )
```

**`get_alerts()`** — pass the `result` dict from `_get_alerts()` as structured_data:

```python
async def get_alerts(self, severity, time_range, status, pattern_name, product, max_results, offset, q, summary_mode):
    result = self._get_alerts(...)

    if not result.get("success"):
        return format_text_response(...)

    # ... build text lines from result["alerts"] ...

    return format_text_response(
        "\n".join(lines),
        tool_name="get_alerts",
        raw=True,
        structured_data=result,
        metadata={"filter": result.get("filter"), "q": q, "time_range": time_range},
    )
```

The `result` dict from `_get_alerts()` contains `alerts` (list of dicts), `count`, `total_available`, `offset`, `next_offset` — all structured and directly queryable.

### 6. Changes to modules/ngsiem.py

**`ngsiem_query()`** — pass the `result` dict from `_execute_query()` as structured_data:

```python
async def ngsiem_query(self, query, start_time, max_results, fields):
    max_results = min(max(max_results, 1), 1000)
    result = self._execute_query(query, start_time, max_results, fields=fields)

    if result.get("success"):
        # ... build text lines from result ...

        return format_text_response(
            "\n".join(lines),
            tool_name="ngsiem_query",
            raw=True,
            structured_data=result,
            metadata={"query": result.get("query"), "time_range": start_time},
        )
    else:
        return format_text_response(error_text, raw=True)  # no structured_data on error
```

The `result` dict from `_execute_query()` contains `events` (list of dicts), `events_matched`, `events_processed`, `events_returned`, `query`, `time_range`, `field_projection` — all structured and directly queryable.

## What Does NOT Change

- All other tools (`host_lookup`, `case_query`, `correlation_*`, `host_login_history`, etc.) — no changes, existing temp file fallback preserved
- `_extract_summary()` — still used for the truncated text portion
- `_write_response_file()` — still used when `structured_data` is not provided
- `_cleanup_old_files()` — still manages temp files for non-opted-in tools
- Module auto-discovery, `BaseModule`, `_add_tool()` — no changes

## Testing

TDD approach — write failing tests first, then implement.

### Unit: ResponseStore

| Test | Validates |
|------|-----------|
| `test_store_and_retrieve` | Store a dict, get it back by ref_id |
| `test_ref_id_incrementing` | Sequential IDs: resp_001, resp_002, ... |
| `test_ring_buffer_eviction` | Store 51 entries, first is evicted |
| `test_record_count_generic` | Counts top-level lists from various tool shapes |
| `test_list_refs` | Returns correct summaries |

### Unit: get_stored_response tool

| Test | Validates |
|------|-----------|
| `test_ref_only_returns_metadata` | No record data, just counts and context |
| `test_record_index` | Returns specific record |
| `test_record_key_lookup` | Finds record by natural key (composite_id, user.name, etc.) |
| `test_record_key_not_found` | Clear error with available key fields |
| `test_fields_extraction` | Dot-path field extraction from nested dicts |
| `test_fields_missing_gracefully` | Missing field returns null, not error |
| `test_search_case_insensitive` | Substring match across record values |
| `test_search_with_fields` | Search + field projection combined |
| `test_max_results_cap` | Search results capped |
| `test_invalid_ref_id` | Clean error for nonexistent ref |

### Integration: truncation → store flow

| Test | Validates |
|------|-----------|
| `test_alert_analysis_stores_on_truncation` | Large response → structured data stored, ref_id in truncation notice |
| `test_non_opt_in_tool_no_store_when_fits` | Tool without structured_data + small response → no storage, no ref_id |
| `test_store_opt_in_tools_always_store` | alert_analysis passes structured_data even for small responses (regression guard) |
| `test_truncation_notice_includes_context` | ref_id + tool name + alert ID in notice |
| `test_backward_compat_no_structured_data` | Tool without structured_data → temp file fallback |

## Out of Scope

- TTL-based eviction (FIFO is sufficient for single-session MCP)
- Persisting store to disk across server restarts
- Global `prefer_summary_mode` config toggle
- Auto-detecting which tools should opt in (explicit is better)
- Streaming/chunked responses via MCP protocol
