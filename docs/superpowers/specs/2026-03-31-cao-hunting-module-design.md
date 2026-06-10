# CAO Hunting Module Design

## Context

CrowdStrike's CAO (Custom Assessment Operations) Hunting API provides access to curated intelligence queries and hunting guides. The FalconPy SDK (`>= 1.6.0`) already ships a `CAOHunting` service class with 7 operations. This module exposes 5 of those as MCP tools, following the established patterns in this project.

## Tools (5, all read-tier)

### `cao_search_queries`
Search and retrieve intelligence queries. Combines `search_queries` (returns IDs) + `get_queries` (hydrates details) — same pattern as `cloud_security._query_assets`.

**Parameters:**
- `filter: Optional[str]` — FQL filter expression
- `q: Optional[str]` — Free-text search
- `sort: Optional[str]` — Sort field and direction (e.g. `created_on|desc`)
- `include_translated_content: bool = False` — Include AI-translated content (SPL, etc.)
- `max_results: int = 20` — Max queries to return

### `cao_get_queries`
Retrieve intelligence queries by known IDs.

**Parameters:**
- `ids: str` — Comma-separated intelligence query IDs
- `include_translated_content: bool = False`

### `cao_search_guides`
Search and retrieve hunting guides. Same search+hydrate pattern.

**Parameters:**
- `filter: Optional[str]` — FQL filter expression
- `q: Optional[str]` — Free-text search
- `sort: Optional[str]` — Sort field and direction
- `max_results: int = 20`

### `cao_get_guides`
Retrieve hunting guides by known IDs.

**Parameters:**
- `ids: str` — Comma-separated hunting guide IDs

### `cao_aggregate`
Aggregate intelligence queries or hunting guides. Decomposes the aggregation body into explicit parameters for MCP usability.

**Parameters:**
- `field: str` — Field to aggregate on (e.g. `severity`, `tags`, `created_on`)
- `type: str = "terms"` — Aggregation type (`terms`, `date_range`, `range`, `cardinality`)
- `resource_type: str = "queries"` — What to aggregate: `queries` or `guides`
- `filter: Optional[str]` — FQL filter to scope the aggregation
- `size: int = 10` — Number of buckets to return

## Dropped

- **`cao_export_archive`** — Binary file export. Unusual pattern for this project; deferred to a future PR.

## Files

### New: `modules/cao_hunting.py`

```
CAOHuntingModule(BaseModule)
├── __init__(client)          → CAOHunting(auth_object=...)
├── register_tools(server)    → 5 × _add_tool(..., tier="read")
├── cao_search_queries(...)   → _search_queries()
├── cao_get_queries(...)      → _get_queries_by_ids()
├── cao_search_guides(...)    → _search_guides()
├── cao_get_guides(...)       → _get_guides_by_ids()
├── cao_aggregate(...)        → _aggregate()
├── _search_queries()         → search_queries + get_queries
├── _get_queries_by_ids()     → get_queries
├── _search_guides()          → search_guides + get_guides
├── _get_guides_by_ids()      → get_guides
└── _aggregate()              → aggregate_queries | aggregate_guides
```

### Modify: `common/api_scopes.py`

Add 7 operation→scope mappings (all `cao-hunting:read`):

```python
"search_queries": ["cao-hunting:read"],
"get_queries": ["cao-hunting:read"],
"aggregate_queries": ["cao-hunting:read"],
"search_guides": ["cao-hunting:read"],
"get_guides": ["cao-hunting:read"],
"aggregate_guides": ["cao-hunting:read"],
"create_export_archive": ["cao-hunting:read"],
```

### New: `tests/test_cao_hunting.py`

Test classes:
- `TestSearchQueries` — search+hydrate flow, empty results, API errors (403 with scope message)
- `TestGetQueries` — direct get by IDs
- `TestSearchGuides` — search+hydrate flow
- `TestGetGuides` — direct get by IDs
- `TestAggregate` — terms aggregation, guides vs queries routing
- `TestToolRegistration` — all 5 tools register, all are read-tier

### Modify: `tests/test_smoke_tools_list.py`

- Add `"modules.cao_hunting.CAOHunting"` to `_FALCONPY_PATCHES`
- Add `patch.multiple("modules.cao_hunting", CAOHunting=MagicMock())` to `_patch_falconpy()`
- Add 5 tool names to `EXPECTED_READ_TOOLS`

## Verification

1. `pytest tests/test_cao_hunting.py` — unit tests pass
2. `pytest tests/test_smoke_tools_list.py` — smoke tests pass (new tools in expected sets)
3. `pytest tests/` — full test suite passes
4. `ruff check modules/cao_hunting.py tests/test_cao_hunting.py` — lint clean
