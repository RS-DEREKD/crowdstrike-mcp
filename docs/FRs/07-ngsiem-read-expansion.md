# FR 07: NGSIEM Read Expansion

**Requested**: 2026-04-17
**Lens**: Detection engineering (IaC) + triage (ingestion health)
**Falconpy**: `ngsiem` (read subset)
**Posture**: Read-only

## Problem

The MCP today exposes a single NGSIEM tool: `ngsiem_query`. Falconpy's
`ngsiem.py` surfaces ~47 methods including reads for every resource type
managed by talonctl (saved searches, lookup files, dashboards, parsers) plus
the data-connector/ingestion surface.

This leaves two gaps:

1. **Detection engineering: no live-state verification.** When authoring or
   reviewing a saved-search enrichment function, the only way to answer "is
   this deployed and what does its current body look like?" is through
   talonctl state or the console. The MCP can't live-confirm.
2. **Triage: no ingestion-pipeline visibility.** When a detection doesn't
   fire that should have, or a hunt returns unexpectedly empty, the analyst
   can't ask "is the connector healthy? when did it last ingest?" via MCP.
   This is a blind spot for the "why is this query silent?" class of issue.

Write operations (create/update/delete) are explicitly excluded — `talonctl`
owns the IaC write path. This FR is purely about **observing live NGSIEM
state**.

## Impact

### IaC / detection engineering

- Before editing a saved-search, live-confirm the current body and metadata
- Verify a lookup file's row count and schema post-deploy without console work
- Reviewing drift across a PR — compare talonctl state to live NGSIEM state
- Useful handoff to the existing `docs/features/talonctl-validate-disparity.md`
  issue: live parse-via-API would give a path to confirm a query is valid
  in production even when `validate-query` can't

### Triage / hunting

- Ingestion-health triage one-liner: "list_data_connections → any failed?"
- Connector-specific investigation: "why are we missing Cato events? show me
  the connector status and last ingest token"
- Silent-query diagnosis: "the #Vendor=box detection returned nothing for
  the last hour — is the Box ingestion connector healthy?"

## Proposed MCP Tools

### Saved searches

| Tool | Purpose | Key args |
|---|---|---|
| `ngsiem_list_saved_queries` | Enumerate saved searches (our enrichment functions) | optional `filter`, `limit` |
| `ngsiem_get_saved_query_template` | Get a saved search's live body + metadata | `id: str` |

### Lookup files

| Tool | Purpose | Key args |
|---|---|---|
| `ngsiem_list_lookup_files` | Enumerate lookup files | optional `filter`, `limit` |
| `ngsiem_get_lookup_file` | Get a lookup file's metadata (and optionally contents) | `id: str`, optional `include_content: bool` |

### Dashboards & parsers

| Tool | Purpose | Key args |
|---|---|---|
| `ngsiem_list_dashboards` | Enumerate dashboards | optional filter |
| `ngsiem_list_parsers` | Enumerate parsers | optional filter |
| `ngsiem_get_parser` | Get a parser's live config | `id: str` |

### Ingestion / connectors (the "why is my query empty?" surface)

| Tool | Purpose | Key args |
|---|---|---|
| `ngsiem_list_data_connections` | Enumerate data connections | optional filter |
| `ngsiem_get_data_connection` | Get connection state for one ID | `id: str` |
| `ngsiem_get_provisioning_status` | Get provisioning / health status | — |
| `ngsiem_list_data_connectors` | Enumerate data connectors (connector types available) | — |
| `ngsiem_list_connector_configs` | Enumerate connector configuration instances | optional filter |

## Falconpy Methods Used

From `src/falconpy/ngsiem.py`:

| MCP tool | Falconpy method |
|---|---|
| `ngsiem_list_saved_queries` | `list_saved_queries()` |
| `ngsiem_get_saved_query_template` | `get_saved_query_template()` |
| `ngsiem_list_lookup_files` | `list_lookup_files()` |
| `ngsiem_get_lookup_file` | `get_lookup_file()` |
| `ngsiem_list_dashboards` | `list_dashboards()` |
| `ngsiem_list_parsers` | `list_parsers()` |
| `ngsiem_get_parser` | `get_parser()` |
| `ngsiem_list_data_connections` | `list_data_connections()` |
| `ngsiem_get_data_connection` | `get_connection_by_id()` |
| `ngsiem_get_provisioning_status` | `get_provisioning_status()` |
| `ngsiem_list_data_connectors` | `list_data_connectors()` |
| `ngsiem_list_connector_configs` | `list_connector_configs()` |

## Safety & Scope

- **Read-only. No exceptions.** Every listed falconpy write method
  (`create_saved_query`, `update_lookup_file`, `delete_*`, `install_parser`,
  `update_*_connection_status`, `regenerate_ingest_token`, etc.) is out of
  scope. talonctl owns the IaC write path and its drift-detection flow should
  not be confused by a separate MCP write surface.
- **`get_ingest_token` excluded.** While technically read-only, an ingest token
  is a secret. Exposing it through an agent-accessible tool is a credential-
  leak risk. Operators who need the token should pull it from the console or
  via a dedicated admin script, not through an LLM-mediated tool.
- **Output shaping.** `get_saved_query_template` returns the full query body;
  large enrichment functions are multi-KB. No special shaping needed, but
  `list_*` calls should default to compact projections (id, name, last_modified)
  with a `detail=true` flag for full records.
- **Consistency with existing `ngsiem_query`.** Prefer `time_range` over
  `start_time` for any time-windowed parameters (see the documented
  `ngsiem_query` parameter-mismatch bug — this FR is a chance to establish
  the canonical name for the whole module).

## Open Questions

1. **Connector-health composite tool?** A single
   `ngsiem_ingestion_health()` that returns `get_provisioning_status` plus a
   roll-up of failed connections would cover the "is ingestion healthy right
   now?" triage question in one call. Strong recommendation to include.
2. **Do we need `ngsiem_query` itself to surface active connector warnings?**
   When a query returns zero events, the MCP could optionally cross-check
   recent ingestion health and include "note: Box connector last ingest was
   6h ago" in the narrative. Cross-tool concern; separate follow-up.
3. **Lookup file contents via `get_lookup_file`.** Content can be large (e.g.,
   the 385-entry `generative_ai_domains.csv`). Default to metadata only, opt
   in via `include_content=true`. Worth confirming falconpy's native behavior.
