# FR 07 — NGSIEM Read Expansion Design

> **Status:** Draft
> **Date:** 2026-04-21
> **FR:** `docs/FRs/07-ngsiem-read-expansion.md`
> **Branch:** `feature/fr07-ngsiem-read-expansion`

## Goal

Add 12 read-only MCP tools that expose NGSIEM's introspection surface (saved
queries, lookup files, dashboards, parsers) and ingestion-pipeline state (data
connections, connectors, provisioning status). Writes remain out of scope —
`talonctl` owns the IaC write path.

After this work the NGSIEM module exposes 13 tools total: the existing
`ngsiem_query` plus the 12 new reads.

## Why

Two gaps the existing single-tool surface leaves open:

1. **Detection engineering: no live-state verification.** When authoring or
   reviewing a saved-search enrichment, the only way to answer "is this
   deployed and what does its current body look like?" is console or
   talonctl state. The MCP can't live-confirm.
2. **Triage: no ingestion-pipeline visibility.** When a query returns
   unexpectedly empty, the analyst can't ask via MCP "is the connector
   healthy? when did it last ingest?"

## Non-Goals

- **No writes.** Every falconpy write method (`create_saved_query`,
  `update_lookup_file`, `delete_*`, `install_parser`,
  `update_*_connection_status`, `regenerate_ingest_token`, etc.) stays
  unwrapped.
- **No `get_ingest_token`.** Technically read-only, but an ingest token is a
  secret; exposing it through an LLM-mediated tool is a credential-leak
  risk. Operators pull it from the console.
- **No composite tools.** The FR floated `ngsiem_ingestion_health()` as a
  roll-up of `get_provisioning_status` + failed `list_data_connections`.
  Deferred — agents compose when needed. Re-evaluate after usage data.
- **No changes to `ngsiem_query`.** The FR's `time_range` vs `start_time`
  canonicalization is tracked separately and out of scope here.
- **No new falconpy service classes.** Everything routes through the
  existing `NGSIEM` client.

## Architecture

### Module location

Extend `src/crowdstrike_mcp/modules/ngsiem.py`. Same `NGSIEMModule` class,
same `_service(NGSIEM)` pattern already established for `ngsiem_query`.
One module per falconpy service class matches the repo convention (cf.
`alerts.py` at 955 lines, `case_management.py` at 998, `idp.py` at 791).
Expected post-FR size: ~750–900 lines.

### Registration

Each new tool registered in `register_tools` via:

```python
self._add_tool(
    server,
    self.ngsiem_<tool>,
    name="ngsiem_<tool>",
    description="...",
    tier="read",
)
```

### Shared call helper

Factor a small internal helper so each tool stays ~15–25 lines:

```python
def _call_and_unwrap(self, method, tool_name: str, **kwargs) -> dict:
    """Call a falconpy method and unwrap to {success, resources|error}.

    Mirrors the HTTP-status / body-errors unwrap logic already in
    _execute_query. Returns:
      {"success": True,  "resources": <list or dict>, "meta": <dict>}
      {"success": False, "error": <str>}
    """
```

All 12 new tools call `_call_and_unwrap` and then do type-specific
projection before returning `format_text_response(..., raw=True,
structured_data=...)`.

### Output formatting

Match the existing `ngsiem_query` pattern:

- Human-readable text body with a header block (tool name, filter/limit
  used, record count), then the records.
- `structured_data=<dict>` for downstream tooling.
- `raw=True` to bypass response-store caching for these small reads.

## Tool Surface

### Saved searches

| Tool | Args | Falconpy |
|---|---|---|
| `ngsiem_list_saved_queries` | `filter: Optional[str]=None`, `limit: int=100`, `detail: bool=False` | `list_saved_queries()` |
| `ngsiem_get_saved_query_template` | `id: str` | `get_saved_query_template()` |

### Lookup files

| Tool | Args | Falconpy |
|---|---|---|
| `ngsiem_list_lookup_files` | `filter: Optional[str]=None`, `limit: int=100`, `detail: bool=False` | `list_lookup_files()` |
| `ngsiem_get_lookup_file` | `id: str`, `include_content: bool=False` | `get_lookup_file()` |

### Dashboards & parsers

| Tool | Args | Falconpy |
|---|---|---|
| `ngsiem_list_dashboards` | `filter: Optional[str]=None`, `limit: int=100`, `detail: bool=False` | `list_dashboards()` |
| `ngsiem_list_parsers` | `filter: Optional[str]=None`, `limit: int=100`, `detail: bool=False` | `list_parsers()` |
| `ngsiem_get_parser` | `id: str` | `get_parser()` |

### Ingestion / connectors

| Tool | Args | Falconpy |
|---|---|---|
| `ngsiem_list_data_connections` | `filter: Optional[str]=None`, `limit: int=100`, `detail: bool=False` | `list_data_connections()` |
| `ngsiem_get_data_connection` | `id: str` | `get_connection_by_id()` |
| `ngsiem_get_provisioning_status` | — | `get_provisioning_status()` |
| `ngsiem_list_data_connectors` | — | `list_data_connectors()` |
| `ngsiem_list_connector_configs` | `filter: Optional[str]=None`, `limit: int=100`, `detail: bool=False` | `list_connector_configs()` |

## Shaping Conventions

### Compact-by-default for all `list_*` tools

Default projection is `[id, name, last_modified]` plus `state` / `status`
where the type has one (e.g., data_connections). `detail=True` returns the
full falconpy record.

Projection is done in-process after the falconpy call — no server-side
`select()` since these are REST endpoints, not CQL.

### Lookup file content

`ngsiem_get_lookup_file(id, include_content=False)`:

- `include_content=False` (default): strip content / rows fields from the
  response, keep metadata (id, name, row count, schema, last_modified).
- `include_content=True`: pass the content field through.

If falconpy returns content always, strip client-side. If falconpy has a
native metadata-only mode, use it.

### Limits

`limit: int=100` on every `list_*` tool. Capped at 1000 (same cap as
`ngsiem_query`). `limit=0` is not a valid value — if the caller wants
everything, they pass `limit=1000` explicitly. No offset / pagination
surfaced in this FR; add when a real use case demands it.

### Filters

The `filter` parameter passes through to falconpy's `filter=` kwarg (FQL
string). The module does not parse or validate the FQL — invalid filters
surface as a 400 from the API and are reported via the existing
`error` unwrap path.

## Safety

- **Read-only tier.** Every new tool registers with `tier="read"`.
- **No write methods imported.** The module only calls read methods on the
  falconpy `NGSIEM` client. A short comment at the top of the new
  registration block enumerates the excluded methods so future readers see
  the deliberate omission.
- **`get_ingest_token` explicitly excluded** with a comment citing the
  credential-leak rationale.
- **No secrets in logs.** Existing `_log` pattern used; no request bodies
  or response payloads written to logs.

## Testing

### Unit tests

Extend `tests/test_ngsiem_*.py` (follow the existing file-per-concern
convention). For each new tool:

- Happy path: mock `_service(NGSIEM)`, assert the correct falconpy method
  and kwargs are called, assert the formatted response includes expected
  fields.
- HTTP error unwrap: falconpy returns `status_code >= 400` with body
  errors; tool returns `success=False` and surfaces the error message.
- Empty-list path (for `list_*` tools): falconpy returns 200 with empty
  resources; tool formats "no records" cleanly.
- `detail=True` vs default: assert the projected record shape changes as
  designed.
- `include_content=True` vs `False` (lookup file): content field present
  / absent.

### Scope exclusions

- No integration tests against a live tenant — matches repo convention for
  FR-scoped additions.
- No perf tests — read-path ceiling is bounded by `limit`.

## Docs

- Update `README.md` tool-list / module enumeration to reference the new
  tools (likely a table near the NGSIEM section).
- Update `docs/FRs/README.md` status table to mark FR 07 as implemented.
- Append a brief "Implemented: <date> — see `<branch>/<commit>`" note to
  `docs/FRs/07-ngsiem-read-expansion.md`.
- Any per-module tool docs in `docs/features/` — audit in the plan; update
  only if they already enumerate NGSIEM tools.

## Risks & Open Items

- **Falconpy method signature drift.** We're on `crowdstrike-falconpy
  >= 1.6.1`. Verify each of the 12 method signatures against the installed
  version during the plan's first task; adjust if any method expects
  different kwargs than the FR assumes.
- **Lookup-file content shape.** Confirm whether `get_lookup_file` returns
  content by default. If not, `include_content=True` may need a separate
  endpoint (e.g., `get_lookup_from_package_with_namespace`). First plan
  task verifies.
- **`get_connection_by_id` vs `get_data_connection`.** The FR maps
  `ngsiem_get_data_connection` to `get_connection_by_id()` — confirm this
  is the current falconpy spelling and not a renamed method.

## Rollout

Single PR off `feature/fr07-ngsiem-read-expansion`. No staged rollout,
feature flag, or gradual enablement — tools are additive and read-only.
Implementation plan will sequence the 12 tools into logical batches (likely
by category) with a shared-helper task first.
