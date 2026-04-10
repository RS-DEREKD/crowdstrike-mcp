# MCP Tool Improvements Design Spec

**Date**: 2026-04-07
**Origin**: [SOC AI Agent handoff — 2026-04-03](../../handoffs/mcp-improvements.md)
**Approach**: Per-tool parameters (Approach A) — no new abstractions or middleware
**Branch**: `feat/mcp-enhancements-v2`

---

## Overview

Three improvements to reduce SOC agent friction observed during the 2026-04-03 triage session:

1. **`get_alerts` pagination** — add `offset` and server-side `q` search
2. **Auto-summary mode** — compact key-fields responses for `get_alerts` and `alert_analysis`
3. **`ngsiem_query` field projection** — server-side `select()` via a `fields` parameter

All changes are backward compatible — new parameters have defaults matching current behavior. One behavioral nuance: `pattern_name` moves from client-side substring matching to server-side FQL wildcard. Results should be equivalent in practice (validated via live API), but edge cases around tokenization could differ. `total_available` will now reflect the post-filter count when `pattern_name` is used (more useful than the previous pre-filter count).

**Side item**: Update the FQL syntax guide with missing operators discovered during design validation.

---

## Feature 1: `get_alerts` Pagination + Server-Side Search

### Problem

`get_alerts` fetches up to 200 alerts with no offset. Bulk operations on large queues (229+ alerts observed) require N/50 round-trips. The `pattern_name` parameter uses client-side filtering with a 4x over-fetch hack, which breaks with pagination.

### Validated Findings (Live API Testing)

| Test | Result |
|------|--------|
| `query_alerts_v2(offset=...)` | Natively supported, max limit 10,000 |
| `query_alerts_v2(q='MCP Server')` | 265 hits — free-text search across all alert metadata |
| FQL `name:'RunningAsRootContainer'` (exact) | 7,299 hits — `name` IS a valid FQL field |
| FQL `name:*'*MCP*'` (wildcard) | 3 hits — wildcard matching works |
| FQL `name:~*'*mcp*'` (case-insensitive wildcard) | 3 hits — works |
| FQL `name:~'MCP Server'` (text match) | 0 hits — tokenization mismatch, unreliable |

### Design

**Parameter changes to `get_alerts`:**

| Parameter | Change | Details |
|-----------|--------|---------|
| `offset` | **New** | `int`, default `0`. Passed to `query_alerts_v2(offset=...)` |
| `q` | **New** | `Optional[str]`, default `None`. Passed to `query_alerts_v2(q=...)` for server-side free-text search across all alert metadata |
| `pattern_name` | **Reimplement** | Keep parameter name (no breaking change). Switch from client-side substring filter to server-side FQL `name:~*'*{value}*'` (case-insensitive wildcard). Value must be sanitized: strip/escape single quotes via existing `sanitize_input()` in `utils.py` before FQL interpolation |
| `max_results` | **Raise cap** | Max from 200 to 1000. API supports 10,000 but 1000 is a reasonable agent ceiling. Default stays 50 |

**How pagination works:**
- `offset` passed directly to `query_alerts_v2(offset=...)`
- `pattern_name` now server-side via FQL, so it composes correctly with `offset`
- `q` is also server-side, composes with `offset`
- `pattern_name` and `q` can be used together (FQL filter + free-text are independent API parameters). `pattern_name` targets the alert name field specifically; `q` searches all metadata fields broadly. When both are provided, results must match both constraints.

**Input validation:**
- `offset` < 0 → clamp to 0
- `q` empty string → treat as `None`
- `pattern_name` → sanitize via `sanitize_input()` before FQL interpolation

**Response additions:**

```json
{
  "success": true,
  "alerts": [...],
  "count": 50,
  "total_available": 229,
  "offset": 0,
  "next_offset": 50,
  "filter": "created_timestamp:>='...'",
  "q": "SetUIDBitFoundInImage",
  "time_range": "1d"
}
```

- `offset`: echoed back for caller reference
- `next_offset`: `offset + count` if more results exist, `null` on last page
- `q`: echoed back if provided

**Code changes:**
- `modules/alerts.py` — `get_alerts()` signature: add `offset`, `q` params
- `modules/alerts.py` — `_get_alerts()`: pass `offset` and `q` to `query_alerts_v2()`, add `name:~*'*{pattern_name}*'` to FQL filter_parts (sanitize value first), remove client-side filtering block and 4x over-fetch multiplier. Update `Annotated` description for `max_results` to say "max: 1000"
- `modules/alerts.py` — response dict: add `offset`, `next_offset`, `q` fields

**What gets removed:**
- Client-side name filtering (lines 327-330)
- 4x over-fetch multiplier (line 267)

---

## Feature 2: Auto-Summary Mode for Large Responses

### Problem

Tool responses exceeding 20KB are written to temp files. The agent receives a truncated stub with a file path, requiring Bash `Read`/`grep` fallback. This breaks the tool-only workflow.

### Validated Findings (Live API Testing)

Alert field availability varies by product type:

| Field | NGSIEM | CWPP | Endpoint |
|-------|--------|------|----------|
| `name` | Yes | Yes | Yes |
| `severity_name` | Yes | Yes | Yes |
| `status` | Yes | Yes | Yes |
| `product` | `"ngsiem"` | `"cwpp"` | `"ind"` |
| `tactic` / `technique` | Yes (`"Discovery"` / `"T1518.001"`) | Missing | Present |
| `host_names` | List | Missing | Missing (use `device`) |
| `user_names` | List | Missing | Missing |
| `tags` | Missing on tested | Missing on tested | Present |
| `assigned_to_name` | Missing on tested | Missing on tested | Present |

### Design

**New parameter on `get_alerts` and `alert_analysis`:**

```python
summary_mode: Annotated[bool, "Return compact key-fields only (default: false)"] = False
```

**`get_alerts` summary schema:**

When `summary_mode=true`, each alert is trimmed to:

```python
{
    "composite_id": str,
    "name": str,
    "severity": str,        # severity_name
    "status": str,
    "product": str,          # product_name (human-readable, e.g. "NG-SIEM")
    "created_timestamp": str,
    "tactic": str | None,   # .get(), absent on CWPP
    "technique": str | None, # .get(), absent on CWPP
    "host_names": list | None,
    "user_names": list | None,
    "tags": list | None,
}
```

All fields accessed with `.get()` — missing fields return `null`. This is a subset of the current full response, not a new object.

**`alert_analysis` summary schema:**

When `summary_mode=true`:
- Alert metadata: id, name, severity, status, tags, tactic, technique, product
- Top 5 related events: timestamp, event type, 3-4 key fields per event type
- `total_events` count
- Truncation notice: `"Showing 5 of {N} related events. Use summary_mode=false for full details."`

**Interaction with existing truncation:**
- Summary mode reduces payload *before* serialization, avoiding the 20KB threshold in most cases
- Temp-file fallback remains as a safety net and still applies to summary mode output — at ~150 bytes per alert, 1000 alerts in summary could reach ~150KB, which exceeds the 20KB threshold. The truncation mechanism handles this gracefully.
- Summary mode's value is that it makes the *truncated* output useful (key fields only) rather than cutting off mid-JSON-blob

**`alert_analysis` summary — key fields per event type:**

| Event Type | Summary Fields |
|-----------|---------------|
| NGSIEM events | `@timestamp`, `#event_simpleName` or `event.action`, `ComputerName`, `UserName`, `source.ip` |
| Endpoint behaviors | `timestamp`, `tactic`, `technique`, `filename`, `cmdline` (first 200 chars) |
| Cloud/Identity/Other | `timestamp`, `event.action`, `source.ip`, `user.name` |

Fields accessed with `.get()` — missing fields omitted from output rather than showing `null`.

**Code changes:**
- `modules/alerts.py` — `get_alerts()` and `_get_alerts()`: add `summary_mode` param, apply field trimming before response formatting
- `modules/alerts.py` — `alert_analysis()` and `_analyze_alert()`: add `summary_mode` param, cap related events at 5 and project key fields
- `modules/alerts.py` — `_format_alert_analysis_response()`: summary-aware formatting branch

---

## Feature 3: `ngsiem_query` Field Projection

### Problem

Raw event queries return full payloads that frequently exceed 20KB. The workaround is manually appending `| table([...], limit=N)` to every query.

### Validated Findings (Live API Testing)

| Test | Result |
|------|--------|
| `select([@timestamp, DomainName, ComputerName])` | Works — returns only requested fields, server-side |
| Query with existing pipe + select | Works — select appends cleanly |

### Design

**Parameter changes to `ngsiem_query`:**

| Parameter | Change | Details |
|-----------|--------|---------|
| `fields` | **New** | `Optional[str]`, comma-separated field names. Appended as `\| select([f1, f2, ...])` to query before execution |
| `max_results` | **Keep** | Cap stays at 1000, default stays at 100 |

**How `fields` works:**
- If provided, the server appends `| select([field1, field2, ...])` to the CQL query before sending to LogScale
- Projection happens server-side, reducing payload at the source
- If the query already contains a pipe-stage `select(` or `table(`, the `fields` parameter is **ignored** with a note in the response: `"field_projection_skipped": "query already contains select() or table()"`. Detection uses regex `\|\s*(?:select|table)\s*\(` to avoid false positives from field values or comments containing those strings.
- CQL `select()` takes bare field references (not quoted strings), so field names like `@timestamp`, `#event.outcome`, `Vendor.properties.status.errorCode` pass through unmodified. Invalid field names produce `null` values silently — no validation needed.

**Response addition:**

```json
{
  "success": true,
  "events_returned": 50,
  "events_matched": 4382,
  "results_truncated": true,
  "field_projection": ["@timestamp", "DomainName", "ComputerName"],
  "query": "...",
  "time_range": "1d",
  "events": [...]
}
```

- `field_projection`: echoed field list when projection applied, `null` otherwise

**Code changes:**
- `modules/ngsiem.py` — `ngsiem_query()`: add `fields` param, parse comma-separated string (split on `,`, strip whitespace, drop empty segments), append `| select([...])` to query if no existing projection detected
- `modules/ngsiem.py` — response dict: add `field_projection` field

**Input validation for `fields`:**
- Empty string or whitespace-only → treat as `None` (no projection)
- Trailing/leading commas → ignored (empty segments dropped after split)

---

## Side Item: FQL Syntax Guide Update

### Problem

`resources/fql_guides.py` documents only basic comparison operators. The full FQL spec includes wildcard and text match operators that are useful across all modules.

### Missing Operators

| Operator | Name | Description |
|----------|------|-------------|
| `~` | Text match | Tokenizes string, ignores spaces/case/punctuation |
| `!~` | Not text match | Negated text match |
| `*` | Wildcard | Wildcard matching (operator `*` + value wildcards `*`) |
| `~*` | Case-insensitive wildcard | Case-insensitive wildcard text contains |
| `~*!` | Case-insensitive not wildcard | Case-insensitive wildcard text does not contain |

### Changes

- `resources/fql_guides.py` — Add operators section to `ALERT_FQL` with examples
- `resources/fql_guides.py` — Add operators section to `HOST_FQL` (wildcard hostname matching is documented in CrowdStrike FQL docs)
- `resources/fql_guides.py` — Update `ALERT_FQL` "NOT Supported" section: remove the note about `name` not being filterable, replace with examples of `name:~*'*pattern*'`
- `modules/alerts.py` — Remove the inline comment at line 255-256 (`# NOTE: name IS NOT a valid FQL filter field`) which is now incorrect
- `resources/fql_guides.py` — Add `now` keyword for timestamp filters (e.g., `created_timestamp:>='now-15d'`)

---

## Files Changed

| File | Changes |
|------|---------|
| `modules/alerts.py` | `get_alerts`: add `offset`, `q`, `summary_mode`; reimplement `pattern_name` as FQL; add `next_offset` to response. `alert_analysis`: add `summary_mode`. Remove client-side filtering. |
| `modules/ngsiem.py` | `ngsiem_query`: add `fields` param, append `select()` to query |
| `resources/fql_guides.py` | Add wildcard/text match operators, fix `name` field docs, add `now` keyword |
| `tests/test_smoke_tools_list.py` | Update expected tool parameter schemas |
| `README.md` | Update tool parameter docs for `get_alerts` and `ngsiem_query` |

---

## Out of Scope

- Global `prefer_summary_mode` config toggle — can be layered on later as default overrides
- `POST /alerts/combined/alerts/v1` cursor-based pagination — overkill for sub-10k results
- `ngsiem_query` summary_mode — `fields` gives explicit control, better for a query tool
- Changes to the temp-file truncation mechanism — stays as safety net

---

## Test Plan

**Unit tests:**
- `offset` + `pattern_name` FQL generation (verify `name:~*'*...*'` in filter string)
- `pattern_name` sanitization (single quotes, FQL metacharacters stripped)
- `q` parameter passthrough to `query_alerts_v2(q=...)`
- `next_offset` calculation: mid-page, last page (null), empty results
- `summary_mode` field trimming: NGSIEM alert (has tactic/technique), CWPP alert (missing fields)
- `alert_analysis` summary: event cap at 5, per-type field projection
- `fields` → `| select([...])` query rewriting
- `fields` ignored when query matches `\|\s*(?:select|table)\s*\(` regex
- `fields` edge cases: empty string, trailing commas, whitespace
- `max_results` clamped to [1, 1000] for get_alerts, [1, 1000] for ngsiem_query

**Smoke tests:**
- Verify new parameters appear in tool schemas
- Verify `offset`, `q`, `summary_mode` params on get_alerts
- Verify `fields` param on ngsiem_query

**Manual integration tests (live API):**
- Paginate through 100+ alerts: `get_alerts(max_results=50, offset=0)` then `offset=50`, verify `next_offset` and `total_available` consistency
- `pattern_name` + `offset` together: verify server-side filtering composes with pagination
- `q` + `pattern_name` together: verify both constraints apply
- `summary_mode=true` on alert_analysis for a large NGSIEM alert: verify output stays compact
- `fields` projection on a DnsRequest query: verify only requested fields returned
