# Threat Graph

Read-only pivots against CrowdStrike's Threat Graph — the canonical graph of
sensor-observed edges (process trees, file writes, network connections,
identity events).

## Tools

### `threatgraph_get_vertices`

Fetch vertex metadata by composite ID. Uses `get_vertices_v2` under the hood.

Args:
- `ids: list[str]` — composite vertex IDs
- `vertex_type: str` — `process`, `file`, `domain`, `ip_address`, `user`, `module`, ...
- `scope: str` — `device` (default), `customer`, `global`, `cspm`, `cwpp`
- `nano: bool` — return nano-precision timestamps

Composite ID format (most common): `pid:<aid>:<offset_ns>`.
Recipe from an alert payload:
`pid:<alert.device.device_id>:<alert.pattern_disposition_details.process_timestamp_ns>`.

### `threatgraph_get_edges`

Walk one edge type out of (or into) a set of vertex IDs.

Args:
- `ids: list[str]`
- `edge_type: str` — e.g. `wrote_file`, `accessed_by_session`. See
  `falcon://reference/threatgraph-edge-types` for the full live list.
- `direction: "primary" | "secondary" | None` — `primary` is outgoing from the
  vertex; `secondary` is incoming. Omit for both.
- `scope: str` — default `device`
- `limit: int` — default 100, max 1000 (page with `offset`)
- `offset: str` — pagination token from a prior call
- `nano: bool`

On invalid `edge_type` (400 response), the tool appends a hint pointing to the
edge-type tool and resource.

### `threatgraph_get_ran_on`

Look up where an indicator (hash / domain / IP) was observed. Starting point
for IOC → affected-host pivots.

Args:
- `value: str` — the indicator
- `type: "hash_md5" | "hash_sha256" | "domain" | "ip_address"`
- `scope, limit, offset, nano` — as above

### `threatgraph_get_summary`

One-line-per-vertex triage summaries. Use after `threatgraph_get_vertices`
when you want overview rather than full properties.

### `threatgraph_get_edge_types`

Refresh and return the live edge-type list. Also invalidates the
`falcon://reference/threatgraph-edge-types` resource cache.

## Resource

`falcon://reference/threatgraph-edge-types` — current edge-type catalog,
lazily fetched on first read and cached for the server's lifetime.

## Scopes

All operations require `threatgraph:read`.

## Worked example

Detection fires on a `rclone.exe` process. Triage pivot:

1. Assemble the vertex ID: `pid:<device.device_id>:<process_timestamp_ns>`.
2. `threatgraph_get_vertices(ids=[...], vertex_type="process")` — confirm
   name, command line, hash.
3. `threatgraph_get_edges(ids=[...], edge_type="wrote_file")` — what it
   touched on disk.
4. `threatgraph_get_edges(ids=[...], edge_type="established_connection",
   direction="primary")` — where it phoned out.
5. `threatgraph_get_edges(ids=[...], edge_type="responsible_process",
   direction="secondary")` — what spawned it.

## Quirks

- Vertex IDs are composite; the tool docstrings show how to assemble them from
  alert payloads. No auto-resolution (yet).
- Threat Graph has no client-side time-range argument. The API applies its
  own server-side defaults; the `limit` cap (100 default, 1000 max) prevents
  runaway neighborhoods.
- The edge-type list is dynamic and fetched live. If the
  `threatgraph_get_edge_types` tool returns a different set than the resource,
  the resource is serving a stale cache — calling the tool invalidates it.
