# FR 06: Threat Graph

**Requested**: 2026-04-17
**Lens**: Triage (EDR pivot) + hunting (process-chain traversal)
**Falconpy**: `threatgraph`
**Posture**: Read-only

## Problem

When a detection fires on a process, the MCP has no way to pivot from that
process to its EDR context — what launched it, what it launched, what it
talked to, what files it touched. Today this requires the Falcon Process
Explorer console (US-2 deep-link), which is outside the agent loop.

`ngsiem_query` gets us close for some pivots (query by `aid` + time window,
stitch together process events), but:
- It's expensive on large time windows
- It doesn't know about Threat Graph's normalized edge types
- It can't walk a process tree across restart boundaries reliably

Threat Graph is CrowdStrike's canonical graph of all sensor-observed edges —
the authoritative source for "what ran on this host and what else touched it."

## Impact

Two workflow patterns:

1. **Triage pivot**: given a detection on a process, one call returns the
   full process tree (parents, children) and another returns network/file
   edges. Agent can describe "rclone.exe spawned by explorer.exe, which
   connected to cloudflare.com and read from C:\Users\X\Documents" in a
   single triage turn.
2. **Indicator-on-host traversal**: given a hash/IP, return all hosts where
   it was observed, with the surrounding process context at each observation.
   Supports hunt pivots from an IOC back to affected-process chains.

Directly useful for the existing CrowdStrike endpoint detections in this repo
(92 of them), especially the shadow-IT detections where context ("was this
installed by an admin tool or user-initiated?") is the triage question.

## Proposed MCP Tools

| Tool | Purpose | Key args |
|---|---|---|
| `threatgraph_get_vertices` | Look up a specific vertex (process, file, network, user, etc.) by ID | `vertex_type: str`, `ids: list[str]`, optional `scope: str` |
| `threatgraph_get_edges` | Get outgoing/incoming edges from a vertex (process → children, file → processes, etc.) | `vertex_id: str`, `edge_type: str`, optional `direction`, `limit` |
| `threatgraph_get_ran_on` | Given an indicator (hash/IP/domain), return the set of hosts/processes where it was observed | `indicator_type: str`, `indicator_value: str`, optional `time_range` |
| `threatgraph_get_summary` | Short summary of a vertex for quick triage context | `vertex_ids: list[str]` |
| `threatgraph_get_edge_types` | Enumerate supported edge types (`responsible_process`, `wrote_to_file`, `established_connection`, etc.) — introspection | — |

## Falconpy Methods Used

From `src/falconpy/threatgraph.py`:

| MCP tool | Falconpy method |
|---|---|
| `threatgraph_get_vertices` | `get_vertices()` (prefer v2 over `get_vertices_v1`) |
| `threatgraph_get_edges` | `get_edges()` |
| `threatgraph_get_ran_on` | `get_ran_on()` |
| `threatgraph_get_summary` | `get_summary()` |
| `threatgraph_get_edge_types` | `get_edge_types()` |

## Safety & Scope

- **Read-only.** Threat Graph is a read surface in falconpy.
- **Vertex ID handling.** Threat Graph vertex IDs are composite strings
  (`pid:aid:offset` and similar). MCP should document the accepted formats
  and provide helper resolution where possible — e.g., accept an alert
  composite ID and resolve to the implicated vertex internally.
- **Edge-type introspection.** `get_edge_types` should populate a local
  reference the agent can consult before calling `get_edges` with an invalid
  type.
- **Result size.** Vertex neighborhoods can be enormous on long-lived hosts
  (a shell process may have thousands of children). Enforce a default
  `limit=100`, max `limit=1000`, with paging via falconpy's `after`/`next`
  token mechanism.
- **Time-range scoping.** Mandate a default time range (e.g., 24h) to prevent
  accidental multi-year traversals; require explicit expansion.

## Open Questions

1. **Composite "process tree" helper.** Triage almost always wants the full
   tree rooted at a specific PID, not individual edge calls. A composed
   `threatgraph_get_process_tree(vertex_id, depth=N)` wrapping multiple
   `get_edges` calls would save turns. Add as a v1.1 after watching usage.
2. **NGSIEM correlation.** Could the MCP internally cross-reference a Threat
   Graph vertex back to the NGSIEM composite alert ID? That composability is
   a long-horizon goal; treat as out-of-scope for this FR.
3. **Edge-type consistency.** Threat Graph edge types have evolved over
   versions — confirm `get_edge_types` returns the current live schema, not
   a baked-in constant list.
