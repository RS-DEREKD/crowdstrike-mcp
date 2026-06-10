# FR 06: Threat Graph — Design

**Date:** 2026-04-21
**Spec source:** `docs/FRs/06-threat-graph.md`
**Branch:** `feature/fr06-threat-graph` (worktree `.worktrees/fr06-threat-graph`)
**Posture:** Read-only

## Summary

Add a `ThreatGraphModule` that exposes five thin, read-only MCP tools mapping 1:1
to falconpy's `ThreatGraph` service collection, plus one lazily-populated MCP
resource listing Threat Graph edge types.

The design favors a thin mapping over composition. Spec open question #1
(composed `threatgraph_get_process_tree` helper) is explicitly deferred to a
v1.1 once we have real agent traces showing the friction. Spec open question #3
(edge-type drift) is resolved by serving the type list from a dynamic cache of
`get_edge_types()` rather than a baked-in constant.

## Architecture

One new module. One falconpy client class. No cross-module dependencies.

```
src/crowdstrike_mcp/
  modules/
    threat_graph.py            # ThreatGraphModule: 5 tools + 1 resource
  resources/
    threatgraph_reference.py   # Lazy edge-type cache + formatter

tests/
  test_threatgraph.py          # ~13 tests, no live API

docs/
  modules/threat-graph.md      # Tool reference + composite-ID recipe
```

The module is registered in `server.py` alongside the existing modules, using
whatever module-enable pattern the repo already uses (to be verified in the
implementation plan). Registered tier: `read` for all five tools.

## Tool surface

All parameters use `Annotated[Type, "description"]`. Defaults match the spec's
Safety section. No synthetic time-range arg — see the note below on time
scoping.

| Tool | Required args | Optional args | Defaults & caps |
|---|---|---|---|
| `threatgraph_get_vertices` | `ids: list[str]`, `vertex_type: str` | `scope: str`, `nano: bool` | `scope="device"`. Uses `get_vertices_v2` (falconpy `entities_vertices_getv2`). |
| `threatgraph_get_edges` | `ids: list[str]`, `edge_type: str` | `direction: Literal["primary","secondary"] \| None`, `scope: str`, `limit: int`, `offset: str`, `nano: bool` | `direction=None` (API returns both), `scope="device"`, `limit=100`, hard cap `limit<=1000`. |
| `threatgraph_get_ran_on` | `value: str`, `type: str` | `scope: str`, `limit: int`, `offset: str`, `nano: bool` | `scope="device"`, `limit=100`, cap `1000`. `type` mirrors falconpy's `type` arg (`hash_md5`, `hash_sha256`, `domain`, `ip_address`). |
| `threatgraph_get_summary` | `ids: list[str]`, `vertex_type: str` | `scope: str`, `nano: bool` | `scope="device"`. |
| `threatgraph_get_edge_types` | — | — | Thin pass-through; also invalidates the resource cache. |

**Vertex IDs.** Tools accept raw Threat Graph composite IDs only. Each tool's
docstring documents the format (`pid:<aid>:<offset_ns>` and variants) and
includes a one-line recipe for assembling an ID from an alert payload's
`aid` / `pid` / `timestamp` fields. No auto-resolution — spec Safety #2 left
this as a future nice-to-have, and cross-module coupling to Alerts would hide
failure modes (stale vertices, missing alerts).

**Time-range scoping.** Falconpy's `get_edges`/`get_ran_on` don't take a
`time_range` kwarg at the collection level; the Threat Graph API applies its
own server-side defaults. This module does **not** synthesize a client-side
time filter. The tool docstrings call this out, and the default `limit=100`
prevents runaway neighborhoods on long-lived hosts. If agent traces show this
is a real problem, we'll add a client-side filter in a follow-up.

**Output format.** All responses go through `format_text_response(..., raw=True)`
so the agent sees the falconpy JSON verbatim (pattern from FR 01, FR 02).

## Edge-type resource

URI: `falcon://reference/threatgraph-edge-types`

| Event | Behavior |
|---|---|
| Module init | Resource registered. No API call. |
| First resource read | Call `get_edge_types()`, format, cache in module state, return body. |
| Subsequent reads | Serve from cache. |
| First-read failure | Return a short error body pointing at the live tool; leave cache empty so next read retries. |
| `threatgraph_get_edge_types` tool called | Pass-through to falconpy **and** invalidate the cache so the next resource read re-fetches. |

This is the first module in the repo with a *dynamic* resource —
`fql_guides.py` resources are static strings. The module docstring documents
the pattern so it's discoverable next time.

## Error handling

Shared via `crowdstrike_mcp.common.errors.format_api_error`:

- **403** — scope-guidance footer: `Threat Graph: Read`.
- **400 on `get_edges` with bad `edge_type`** — detect the falconpy error shape
  and append: "Call `threatgraph_get_edge_types` or read
  `falcon://reference/threatgraph-edge-types` for the valid list."
- **404 on vertex lookup** — pass through; docstring already documents the
  composite-ID format.
- **`limit > 1000`** — `ValueError` before calling falconpy, message directs
  agent to page via `offset`.
- **Unknown falconpy exception** — bubble up via `format_api_error`.

## Testing

`tests/test_threatgraph.py`, patterned on `tests/test_spotlight.py`. Same
mocking approach (no live API). Coverage:

- Happy path per tool (5)
- `get_edges` invalid `edge_type` → 400 → hint appended (1)
- `get_vertices` 403 → scope-guidance appended (1)
- `limit=1001` → `ValueError` before API call (1)
- Resource first-read fetches + caches (1)
- Resource second read serves from cache (1)
- Resource first-read failure returns error without poisoning cache (1)
- `threatgraph_get_edge_types` tool invalidates cache (1)
- Module registers exactly 5 tools + 1 resource at `tier="read"` (1)

Target: ~13 tests.

## Documentation

- `docs/modules/threat-graph.md` — user-facing tool reference, composite-ID
  recipe, edge-type resource URL, worked triage example (detection PID →
  `get_vertices` → `get_edges direction=both` → narrative).
- Module-level docstring in `threat_graph.py` listing tool names + one-line
  purposes (matches every other module).
- Repo-level module index update if one exists.

## Out of scope

- **`threatgraph_get_process_tree` composed helper** — spec open question #1;
  add in a v1.1 once triage traces show demand.
- **NGSIEM ↔ Threat Graph cross-reference** — spec open question #2; long-horizon.
- **Auto-resolution of alert IDs → vertex IDs** — deferred; agent assembles
  composite IDs from documented format.
- **Admin / write paths** — Threat Graph is read-only in falconpy; nothing to
  exclude beyond that.
- **v1 fallback for `get_vertices`** — we use v2 unconditionally; if the
  tenant is stuck on v1-era data, revisit.

## Open questions

None at design time. All spec-level open questions are either resolved above or
explicitly deferred.
