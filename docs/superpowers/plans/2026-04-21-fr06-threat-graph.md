# FR 06: Threat Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `ThreatGraphModule` — five thin, read-only MCP tools that map 1:1 to falconpy's `ThreatGraph` service collection, plus one lazily-cached MCP resource listing edge types.

**Architecture:** New module under `src/crowdstrike_mcp/modules/threat_graph.py` subclassing `BaseModule`. Auto-discovered by `registry.py` (no `server.py` edit needed — registration happens via `pkgutil.iter_modules` scanning for `*Module` subclasses). Edge-type list cached in module state, populated on first resource read, invalidated by the `threatgraph_get_edge_types` tool. No cross-module dependencies.

**Tech Stack:** Python 3.11+, `crowdstrike-falconpy>=1.6.1` (`ThreatGraph`), `mcp>=1.12.1` (FastMCP), pytest.

**Spec:** `docs/superpowers/specs/2026-04-21-fr06-threat-graph-design.md`

---

## File Structure

- **Create:** `src/crowdstrike_mcp/modules/threat_graph.py` — `ThreatGraphModule`, 5 tools, resource registration
- **Create:** `src/crowdstrike_mcp/resources/threatgraph_reference.py` — lazy edge-type cache + formatter
- **Modify:** `src/crowdstrike_mcp/common/api_scopes.py` — add 5 Threat Graph operation → scope entries
- **Create:** `tests/test_threatgraph.py` — ~13 tests, all mocked
- **Create:** `docs/modules/threat-graph.md` — user-facing tool reference

Auto-discovery: the module class name **must** end in `Module` (i.e. `ThreatGraphModule`) — `registry.py:45` filters on this suffix. Registry derives the CLI/config module name as `threatgraph` (class name minus `Module`, lowercased).

---

## Task 1: Add Threat Graph scopes to api_scopes

**Files:**
- Modify: `src/crowdstrike_mcp/common/api_scopes.py` (add entries to `OPERATION_SCOPES`)
- Test: `tests/test_threatgraph.py` (new file)

- [ ] **Step 1: Write the failing test**

Create `tests/test_threatgraph.py`:

```python
"""Tests for Threat Graph module."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


class TestThreatGraphScopes:
    """Scope mappings for Threat Graph operations exist in api_scopes."""

    def test_entities_vertices_getv2_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("entities_vertices_getv2") == ["threatgraph:read"]

    def test_combined_edges_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("combined_edges_get") == ["threatgraph:read"]

    def test_combined_ran_on_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("combined_ran_on_get") == ["threatgraph:read"]

    def test_combined_summary_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("combined_summary_get") == ["threatgraph:read"]

    def test_queries_edgetypes_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("queries_edgetypes_get") == ["threatgraph:read"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphScopes -v`
Expected: 5 failures, each asserting `[] == ["threatgraph:read"]` (operation unknown → empty list).

- [ ] **Step 3: Add the scope entries**

In `src/crowdstrike_mcp/common/api_scopes.py`, before the closing `}` of `OPERATION_SCOPES` (after the CAO Hunting block around line 74), insert:

```python
    # Threat Graph
    "entities_vertices_getv2": ["threatgraph:read"],
    "combined_edges_get": ["threatgraph:read"],
    "combined_ran_on_get": ["threatgraph:read"],
    "combined_summary_get": ["threatgraph:read"],
    "queries_edgetypes_get": ["threatgraph:read"],
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphScopes -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/common/api_scopes.py tests/test_threatgraph.py
git commit -m "feat(threatgraph): add api_scopes entries for Threat Graph ops"
```

---

## Task 2: Edge-type lazy-cache reference module

**Files:**
- Create: `src/crowdstrike_mcp/resources/threatgraph_reference.py`
- Modify: `tests/test_threatgraph.py`

The cache is a small helper with two responsibilities: fetch+format on demand, and allow explicit invalidation. Kept outside the module class so it's easy to test in isolation and matches the `resources/` directory convention (see `fql_guides.py`).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_threatgraph.py`:

```python
class TestEdgeTypeCache:
    """ThreatGraphEdgeTypeCache behavior: fetch-on-first-read, cache, invalidate."""

    def test_first_read_calls_fetcher_and_caches(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        fetch_calls = []

        def fake_fetcher():
            fetch_calls.append(1)
            return {"status_code": 200, "body": {"resources": ["accessed_by_session", "wrote_file"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        body = cache.read()
        assert "accessed_by_session" in body
        assert "wrote_file" in body
        assert len(fetch_calls) == 1

    def test_second_read_uses_cache(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        fetch_calls = []

        def fake_fetcher():
            fetch_calls.append(1)
            return {"status_code": 200, "body": {"resources": ["x"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        cache.read()
        cache.read()
        assert len(fetch_calls) == 1

    def test_fetch_failure_does_not_poison_cache(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        state = {"calls": 0, "fail": True}

        def fake_fetcher():
            state["calls"] += 1
            if state["fail"]:
                return {"status_code": 500, "body": {"errors": [{"message": "boom"}]}}
            return {"status_code": 200, "body": {"resources": ["ok"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        first = cache.read()
        assert "500" in first or "error" in first.lower()

        state["fail"] = False
        second = cache.read()
        assert "ok" in second
        assert state["calls"] == 2

    def test_invalidate_forces_refetch(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        state = {"calls": 0, "payload": ["v1"]}

        def fake_fetcher():
            state["calls"] += 1
            return {"status_code": 200, "body": {"resources": list(state["payload"])}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        first = cache.read()
        assert "v1" in first

        state["payload"] = ["v2"]
        cache.invalidate()
        second = cache.read()
        assert "v2" in second
        assert state["calls"] == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_threatgraph.py::TestEdgeTypeCache -v`
Expected: 4 failures — `ModuleNotFoundError: No module named 'crowdstrike_mcp.resources.threatgraph_reference'`.

- [ ] **Step 3: Create the cache module**

Create `src/crowdstrike_mcp/resources/threatgraph_reference.py`:

```python
"""
Threat Graph edge-type reference — lazily populated from the live API.

Unlike the static FQL guides in fql_guides.py, the Threat Graph edge-type
catalog evolves with CrowdStrike releases. We fetch it on first resource
read, cache in process memory, and let callers invalidate via the
threatgraph_get_edge_types tool.
"""

from __future__ import annotations

from typing import Callable

FETCH_FAILURE_BODY = (
    "# Threat Graph — Edge Types\n\n"
    "Failed to fetch the live edge-type list. Call `threatgraph_get_edge_types` "
    "directly or retry this resource read.\n\n"
    "API error: {detail}\n"
)


class ThreatGraphEdgeTypeCache:
    """Lazy, process-lifetime cache for Threat Graph edge types."""

    def __init__(self, fetcher: Callable[[], dict]):
        """
        Args:
            fetcher: zero-arg callable returning the falconpy response dict
                     from get_edge_types() (keys: status_code, body).
        """
        self._fetcher = fetcher
        self._cached: str | None = None

    def read(self) -> str:
        """Return the formatted edge-type reference, fetching if needed."""
        if self._cached is not None:
            return self._cached
        response = self._fetcher()
        status = response.get("status_code")
        if status != 200:
            errors = (response.get("body") or {}).get("errors") or []
            detail = (errors[0].get("message") if errors else f"HTTP {status}")
            return FETCH_FAILURE_BODY.format(detail=detail)
        resources = (response.get("body") or {}).get("resources") or []
        self._cached = self._format(resources)
        return self._cached

    def invalidate(self) -> None:
        """Drop the cached response so the next read re-fetches."""
        self._cached = None

    @staticmethod
    def _format(resources: list) -> str:
        # Resources may be a list of strings (edge names) or a list of dicts
        # with a "name" key. Support both; fall back to repr.
        lines = ["# Threat Graph — Edge Types", ""]
        lines.append(f"{len(resources)} edge types available.")
        lines.append("")
        for item in resources:
            if isinstance(item, str):
                lines.append(f"- `{item}`")
            elif isinstance(item, dict):
                name = item.get("name") or item.get("type") or repr(item)
                lines.append(f"- `{name}`")
            else:
                lines.append(f"- `{item!r}`")
        lines.append("")
        lines.append(
            "Pass any of these as the `edge_type` argument to `threatgraph_get_edges`."
        )
        return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_threatgraph.py::TestEdgeTypeCache -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/resources/threatgraph_reference.py tests/test_threatgraph.py
git commit -m "feat(threatgraph): add lazy edge-type reference cache"
```

---

## Task 3: Module scaffold + registration

Set up `ThreatGraphModule` with imports, init, empty `register_tools`, and the resource registration. No tools yet; this task only proves the module loads cleanly and the resource URI is registered.

**Files:**
- Create: `src/crowdstrike_mcp/modules/threat_graph.py`
- Modify: `tests/test_threatgraph.py`

- [ ] **Step 1: Write the failing test**

Note: `mock_client` is already provided by `tests/conftest.py`. Reuse it — do **not** redefine it locally.

Append to `tests/test_threatgraph.py`:

```python
@pytest.fixture
def threatgraph_module(mock_client):
    """ThreatGraphModule with ThreatGraph service mocked."""
    with patch("crowdstrike_mcp.modules.threat_graph.ThreatGraph") as MockTG:
        mock_tg = MagicMock()
        MockTG.return_value = mock_tg
        from crowdstrike_mcp.modules.threat_graph import ThreatGraphModule

        module = ThreatGraphModule(mock_client)
        module._service = lambda cls: mock_tg
        module.falcon = mock_tg
        return module


class TestThreatGraphModuleScaffold:
    """Module loads, registers expected resource URI, inherits BaseModule."""

    def test_module_subclasses_base(self, threatgraph_module):
        from crowdstrike_mcp.modules.base import BaseModule
        assert isinstance(threatgraph_module, BaseModule)

    def test_registers_edge_types_resource(self, threatgraph_module):
        server = MagicMock()
        server.resource.return_value = lambda fn: fn
        threatgraph_module.register_resources(server)
        assert "falcon://reference/threatgraph-edge-types" in threatgraph_module.resources

    def test_auto_discovery_finds_class(self):
        from crowdstrike_mcp.registry import discover_module_classes
        names = [c.__name__ for c in discover_module_classes()]
        assert "ThreatGraphModule" in names
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphModuleScaffold -v`
Expected: 3 failures — `ModuleNotFoundError: No module named 'crowdstrike_mcp.modules.threat_graph'`.

- [ ] **Step 3: Create the module scaffold**

Create `src/crowdstrike_mcp/modules/threat_graph.py`:

```python
"""
Threat Graph Module — CrowdStrike Threat Graph read surface (process/file/network/identity edges).

Tools:
  threatgraph_get_vertices      — Fetch vertex metadata by composite ID
  threatgraph_get_edges         — Walk outgoing/incoming edges of one edge type
  threatgraph_get_ran_on        — Find hosts/processes where an indicator was observed
  threatgraph_get_summary       — Short triage-ready summary for vertex IDs
  threatgraph_get_edge_types    — Refresh (and return) the edge-type catalog

Resources:
  falcon://reference/threatgraph-edge-types
    Lazily populated from get_edge_types() on first read. Invalidated when
    the threatgraph_get_edge_types tool is called. First module in this repo
    with a *dynamic* MCP resource; static-content resources live in
    resources/fql_guides.py.

Vertex IDs are composite strings. The most common form is:
  pid:<aid>:<offset_ns>
where <aid> is the Falcon agent ID and <offset_ns> is a nanosecond-precision
offset from the alert / process payload. Every tool docstring includes the
recipe.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal, Optional

try:
    from falconpy import ThreatGraph

    THREATGRAPH_AVAILABLE = True
except ImportError:
    THREATGRAPH_AVAILABLE = False

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


EDGE_TYPES_RESOURCE_URI = "falcon://reference/threatgraph-edge-types"


class ThreatGraphModule(BaseModule):
    """Threat Graph read-only pivots (vertices, edges, ran-on, summary)."""

    def __init__(self, client):
        super().__init__(client)
        if not THREATGRAPH_AVAILABLE:
            raise ImportError(
                "ThreatGraph not available. Ensure crowdstrike-falconpy >= 1.6.1 is installed."
            )
        self._edge_type_cache = ThreatGraphEdgeTypeCache(self._fetch_edge_types)
        self._log("Initialized")

    def register_resources(self, server: FastMCP) -> None:
        def _edge_types_body():
            return self._edge_type_cache.read()

        server.resource(
            EDGE_TYPES_RESOURCE_URI,
            name="Threat Graph Edge Types",
            description="Live list of Threat Graph edge types (cached in-process).",
        )(_edge_types_body)
        self.resources.append(EDGE_TYPES_RESOURCE_URI)

    def register_tools(self, server: FastMCP) -> None:
        # Tools added in later tasks.
        pass

    # -------- internal helpers --------

    def _fetch_edge_types(self) -> dict:
        """Invoke ThreatGraph.get_edge_types(); used as the cache fetcher."""
        falcon = self._service(ThreatGraph)
        return falcon.get_edge_types()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphModuleScaffold -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/threat_graph.py tests/test_threatgraph.py
git commit -m "feat(threatgraph): add ThreatGraphModule scaffold + edge-type resource"
```

---

## Task 4: `threatgraph_get_edge_types` tool (smallest tool + cache invalidation)

**Files:**
- Modify: `src/crowdstrike_mcp/modules/threat_graph.py`
- Modify: `tests/test_threatgraph.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_threatgraph.py`:

```python
class TestThreatGraphGetEdgeTypes:
    def test_returns_edge_types(self, threatgraph_module):
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 200,
            "body": {"resources": ["wrote_file", "accessed_by_session"]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_edge_types())
        assert "wrote_file" in result
        assert "accessed_by_session" in result

    def test_invalidates_resource_cache(self, threatgraph_module):
        # Seed the cache
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 200,
            "body": {"resources": ["old"]},
        }
        first_body = threatgraph_module._edge_type_cache.read()
        assert "old" in first_body

        # Change API response, then call the tool
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 200,
            "body": {"resources": ["new"]},
        }
        asyncio.run(threatgraph_module.threatgraph_get_edge_types())

        # The cache should now reflect the new list on next resource read
        second_body = threatgraph_module._edge_type_cache.read()
        assert "new" in second_body
        assert "old" not in second_body

    def test_handles_api_error(self, threatgraph_module):
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_edge_types())
        assert "failed" in result.lower() or "forbidden" in result.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetEdgeTypes -v`
Expected: 3 failures — `AttributeError: 'ThreatGraphModule' object has no attribute 'threatgraph_get_edge_types'`.

- [ ] **Step 3: Add the tool**

In `src/crowdstrike_mcp/modules/threat_graph.py`, replace the `register_tools` body:

```python
    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.threatgraph_get_edge_types,
            name="threatgraph_get_edge_types",
            description=(
                "Refresh and return the live list of Threat Graph edge types. "
                "Also invalidates the falcon://reference/threatgraph-edge-types "
                "cache so the next resource read re-fetches. Use sparingly; "
                "prefer reading the resource."
            ),
        )
```

Append the tool method to the class:

```python
    async def threatgraph_get_edge_types(self) -> str:
        """Refresh the edge-type cache and return the current list."""
        try:
            response = self._fetch_edge_types()
            if response.get("status_code") != 200:
                err = format_api_error(
                    response,
                    "Failed to get edge types",
                    operation="queries_edgetypes_get",
                )
                return format_text_response(f"Failed to get edge types: {err}", raw=True)
            # Invalidate then re-read so the cache picks up the fresh response
            self._edge_type_cache.invalidate()
            body = self._edge_type_cache.read()
            return format_text_response(body, raw=True)
        except Exception as e:
            return format_text_response(f"Failed to get edge types: {e}", raw=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetEdgeTypes -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/threat_graph.py tests/test_threatgraph.py
git commit -m "feat(threatgraph): add threatgraph_get_edge_types tool"
```

---

## Task 5: `threatgraph_get_vertices` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/threat_graph.py`
- Modify: `tests/test_threatgraph.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_threatgraph.py`:

```python
class TestThreatGraphGetVertices:
    def test_returns_vertex_metadata(self, threatgraph_module):
        threatgraph_module.falcon.get_vertices_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "pid:aaa:111", "vertex_type": "process", "properties": {"name": "rclone.exe"}}
            ]},
        }
        result = asyncio.run(
            threatgraph_module.threatgraph_get_vertices(
                ids=["pid:aaa:111"], vertex_type="process"
            )
        )
        assert "pid:aaa:111" in result
        assert "rclone.exe" in result

    def test_passes_args_to_falconpy(self, threatgraph_module):
        threatgraph_module.falcon.get_vertices_v2.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_vertices(
                ids=["pid:aaa:111"], vertex_type="process", scope="customer", nano=True
            )
        )
        kwargs = threatgraph_module.falcon.get_vertices_v2.call_args.kwargs
        assert kwargs["ids"] == ["pid:aaa:111"]
        assert kwargs["vertex_type"] == "process"
        assert kwargs["scope"] == "customer"
        assert kwargs["nano"] is True

    def test_default_scope_is_device(self, threatgraph_module):
        threatgraph_module.falcon.get_vertices_v2.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_vertices(
                ids=["x"], vertex_type="process"
            )
        )
        kwargs = threatgraph_module.falcon.get_vertices_v2.call_args.kwargs
        assert kwargs["scope"] == "device"

    def test_requires_ids(self, threatgraph_module):
        result = asyncio.run(
            threatgraph_module.threatgraph_get_vertices(ids=[], vertex_type="process")
        )
        assert "ids" in result.lower() or "required" in result.lower()

    def test_403_includes_scope_guidance(self, threatgraph_module):
        threatgraph_module.falcon.get_vertices_v2.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(
            threatgraph_module.threatgraph_get_vertices(
                ids=["pid:aaa:111"], vertex_type="process"
            )
        )
        assert "threatgraph:read" in result.lower() or "threatgraph" in result.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetVertices -v`
Expected: 5 failures — `AttributeError: ... threatgraph_get_vertices`.

- [ ] **Step 3: Add the tool**

In `src/crowdstrike_mcp/modules/threat_graph.py` inside `register_tools`, append:

```python
        self._add_tool(
            server,
            self.threatgraph_get_vertices,
            name="threatgraph_get_vertices",
            description=(
                "Fetch Threat Graph vertex metadata by composite ID. Vertex IDs "
                "take the form pid:<aid>:<offset_ns> for processes; other shapes "
                "exist for files, users, etc. Recipe: from an alert payload, "
                "assemble pid:<alert.device.device_id>:<alert.pattern_disposition_details.process_timestamp_ns>. "
                "Use vertex_type=process|file|domain|ip_address|user|module|... ; "
                "scope defaults to 'device' (per-host)."
            ),
        )
```

Append the tool method:

```python
    async def threatgraph_get_vertices(
        self,
        ids: Annotated[list[str], "Composite vertex IDs (e.g. ['pid:<aid>:<offset_ns>'])"],
        vertex_type: Annotated[str, "Vertex type: process, file, domain, ip_address, user, module, etc."],
        scope: Annotated[Literal["device", "customer", "global", "cspm", "cwpp"], "Query scope"] = "device",
        nano: Annotated[bool, "Return nano-precision timestamps"] = False,
    ) -> str:
        """Fetch vertex metadata by composite ID (uses get_vertices_v2)."""
        if not ids:
            return format_text_response("Failed: ids is required", raw=True)
        try:
            falcon = self._service(ThreatGraph)
            response = falcon.get_vertices_v2(
                ids=ids, vertex_type=vertex_type, scope=scope, nano=nano,
            )
            if response.get("status_code") != 200:
                err = format_api_error(
                    response,
                    "Failed to get vertices",
                    operation="entities_vertices_getv2",
                )
                return format_text_response(f"Failed to get vertices: {err}", raw=True)
            return format_text_response(
                _render_resources("Threat Graph Vertices", response), raw=True
            )
        except Exception as e:
            return format_text_response(f"Failed to get vertices: {e}", raw=True)
```

At module scope (bottom of file), add a shared renderer:

```python
import json  # add to existing imports at top of file, not here


def _render_resources(header: str, response: dict) -> str:
    body = response.get("body") or {}
    resources = body.get("resources") or []
    meta = body.get("meta") or {}
    pagination = meta.get("pagination") or {}
    lines = [f"{header}: {len(resources)} returned"]
    if pagination.get("total") is not None:
        lines[-1] += f" (total={pagination['total']})"
    if pagination.get("offset"):
        lines.append(f"Next offset: `{pagination['offset']}`")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(resources, indent=2, default=str))
    lines.append("```")
    return "\n".join(lines)
```

Make sure `import json` is at the top of the file with the other imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetVertices -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/threat_graph.py tests/test_threatgraph.py
git commit -m "feat(threatgraph): add threatgraph_get_vertices tool"
```

---

## Task 6: `threatgraph_get_edges` tool (includes invalid-edge_type hint)

**Files:**
- Modify: `src/crowdstrike_mcp/modules/threat_graph.py`
- Modify: `tests/test_threatgraph.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_threatgraph.py`:

```python
class TestThreatGraphGetEdges:
    def test_returns_edges(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"source_vertex_id": "pid:aaa:111", "target_vertex_id": "pid:bbb:222"}
            ]},
        }
        result = asyncio.run(
            threatgraph_module.threatgraph_get_edges(
                ids=["pid:aaa:111"], edge_type="wrote_file"
            )
        )
        assert "pid:aaa:111" in result
        assert "pid:bbb:222" in result

    def test_passes_args_to_falconpy(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_edges(
                ids=["x"], edge_type="wrote_file", direction="primary",
                scope="customer", limit=50, offset="tok", nano=True,
            )
        )
        kwargs = threatgraph_module.falcon.get_edges.call_args.kwargs
        assert kwargs["ids"] == ["x"]
        assert kwargs["edge_type"] == "wrote_file"
        assert kwargs["direction"] == "primary"
        assert kwargs["scope"] == "customer"
        assert kwargs["limit"] == 50
        assert kwargs["offset"] == "tok"
        assert kwargs["nano"] is True

    def test_default_limit_is_100(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_edges(ids=["x"], edge_type="wrote_file")
        )
        kwargs = threatgraph_module.falcon.get_edges.call_args.kwargs
        assert kwargs["limit"] == 100

    def test_limit_above_1000_rejected_before_api_call(self, threatgraph_module):
        result = asyncio.run(
            threatgraph_module.threatgraph_get_edges(
                ids=["x"], edge_type="wrote_file", limit=1001
            )
        )
        assert threatgraph_module.falcon.get_edges.call_count == 0
        assert "1000" in result or "limit" in result.lower()

    def test_direction_omitted_when_none(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_edges(ids=["x"], edge_type="wrote_file")
        )
        kwargs = threatgraph_module.falcon.get_edges.call_args.kwargs
        assert "direction" not in kwargs

    def test_400_invalid_edge_type_appends_hint(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "invalid edge_type 'bogus'"}]},
        }
        result = asyncio.run(
            threatgraph_module.threatgraph_get_edges(ids=["x"], edge_type="bogus")
        )
        assert "threatgraph_get_edge_types" in result or "threatgraph-edge-types" in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetEdges -v`
Expected: 6 failures.

- [ ] **Step 3: Add the tool**

In `register_tools` append:

```python
        self._add_tool(
            server,
            self.threatgraph_get_edges,
            name="threatgraph_get_edges",
            description=(
                "Walk edges of one type out of (or into) a set of vertex IDs. "
                "One edge_type per call; discover valid edge types via the "
                "falcon://reference/threatgraph-edge-types resource or "
                "threatgraph_get_edge_types tool. direction='primary' "
                "walks outgoing edges, 'secondary' walks incoming, "
                "None returns both. Defaults: limit=100, scope='device'; "
                "hard cap limit<=1000 (page via offset)."
            ),
        )
```

Append the tool method:

```python
    _MAX_LIMIT = 1000

    async def threatgraph_get_edges(
        self,
        ids: Annotated[list[str], "Source vertex IDs"],
        edge_type: Annotated[str, "Edge type (see falcon://reference/threatgraph-edge-types)"],
        direction: Annotated[Optional[Literal["primary", "secondary"]], "Edge direction: primary=outgoing, secondary=incoming, None=both"] = None,
        scope: Annotated[Literal["device", "customer", "global", "cspm", "cwpp"], "Query scope"] = "device",
        limit: Annotated[int, "Max edges per call (default 100, max 1000)"] = 100,
        offset: Annotated[Optional[str], "Pagination token from a prior call"] = None,
        nano: Annotated[bool, "Return nano-precision timestamps"] = False,
    ) -> str:
        """Walk edges of one edge_type out of/into the given vertex IDs."""
        if not ids:
            return format_text_response("Failed: ids is required", raw=True)
        if not edge_type:
            return format_text_response("Failed: edge_type is required", raw=True)
        if limit > self._MAX_LIMIT:
            return format_text_response(
                f"Failed: limit={limit} exceeds max {self._MAX_LIMIT}. "
                f"Page through results using the offset argument.",
                raw=True,
            )
        kwargs = {
            "ids": ids,
            "edge_type": edge_type,
            "scope": scope,
            "limit": limit,
            "nano": nano,
        }
        if direction is not None:
            kwargs["direction"] = direction
        if offset:
            kwargs["offset"] = offset
        try:
            falcon = self._service(ThreatGraph)
            response = falcon.get_edges(**kwargs)
            if response.get("status_code") != 200:
                err = format_api_error(
                    response,
                    "Failed to get edges",
                    operation="combined_edges_get",
                )
                hint = ""
                if response.get("status_code") == 400:
                    hint = (
                        "\n\nHint: call `threatgraph_get_edge_types` or read "
                        "`falcon://reference/threatgraph-edge-types` for the valid "
                        "edge_type values."
                    )
                return format_text_response(f"Failed to get edges: {err}{hint}", raw=True)
            return format_text_response(
                _render_resources("Threat Graph Edges", response), raw=True
            )
        except Exception as e:
            return format_text_response(f"Failed to get edges: {e}", raw=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetEdges -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/threat_graph.py tests/test_threatgraph.py
git commit -m "feat(threatgraph): add threatgraph_get_edges tool with edge-type hint"
```

---

## Task 7: `threatgraph_get_ran_on` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/threat_graph.py`
- Modify: `tests/test_threatgraph.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_threatgraph.py`:

```python
class TestThreatGraphGetRanOn:
    def test_returns_ran_on(self, threatgraph_module):
        threatgraph_module.falcon.get_ran_on.return_value = {
            "status_code": 200,
            "body": {"resources": [{"aid": "host-1", "id": "pid:host-1:123"}]},
        }
        result = asyncio.run(
            threatgraph_module.threatgraph_get_ran_on(
                value="1.2.3.4", type="ip_address"
            )
        )
        assert "host-1" in result

    def test_passes_args_to_falconpy(self, threatgraph_module):
        threatgraph_module.falcon.get_ran_on.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_ran_on(
                value="abc123", type="hash_sha256",
                scope="customer", limit=50, offset="tok", nano=True,
            )
        )
        kwargs = threatgraph_module.falcon.get_ran_on.call_args.kwargs
        assert kwargs["value"] == "abc123"
        assert kwargs["type"] == "hash_sha256"
        assert kwargs["scope"] == "customer"
        assert kwargs["limit"] == 50
        assert kwargs["offset"] == "tok"
        assert kwargs["nano"] is True

    def test_default_limit_and_scope(self, threatgraph_module):
        threatgraph_module.falcon.get_ran_on.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_ran_on(value="x", type="domain")
        )
        kwargs = threatgraph_module.falcon.get_ran_on.call_args.kwargs
        assert kwargs["limit"] == 100
        assert kwargs["scope"] == "device"

    def test_limit_above_1000_rejected(self, threatgraph_module):
        result = asyncio.run(
            threatgraph_module.threatgraph_get_ran_on(
                value="x", type="domain", limit=2000
            )
        )
        assert threatgraph_module.falcon.get_ran_on.call_count == 0
        assert "1000" in result or "limit" in result.lower()

    def test_requires_value_and_type(self, threatgraph_module):
        result = asyncio.run(
            threatgraph_module.threatgraph_get_ran_on(value="", type="domain")
        )
        assert "value" in result.lower() or "required" in result.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetRanOn -v`
Expected: 5 failures.

- [ ] **Step 3: Add the tool**

In `register_tools` append:

```python
        self._add_tool(
            server,
            self.threatgraph_get_ran_on,
            name="threatgraph_get_ran_on",
            description=(
                "Look up where an indicator (hash, domain, IP) was observed in "
                "the environment. type=hash_md5|hash_sha256|domain|ip_address. "
                "Returns a list of hosts/processes where the indicator was seen — "
                "the starting point for IOC → affected-process-chain pivots. "
                "Defaults: limit=100, scope='device'; cap limit<=1000."
            ),
        )
```

Append the tool method:

```python
    async def threatgraph_get_ran_on(
        self,
        value: Annotated[str, "Indicator value (e.g. a SHA256 hash, a domain, or an IP)"],
        type: Annotated[Literal["hash_md5", "hash_sha256", "domain", "ip_address"], "Indicator type"],
        scope: Annotated[Literal["device", "customer", "global", "cspm", "cwpp"], "Query scope"] = "device",
        limit: Annotated[int, "Max results (default 100, max 1000)"] = 100,
        offset: Annotated[Optional[str], "Pagination token from a prior call"] = None,
        nano: Annotated[bool, "Return nano-precision timestamps"] = False,
    ) -> str:
        """Find observations of an indicator across hosts/processes."""
        if not value:
            return format_text_response("Failed: value is required", raw=True)
        if not type:
            return format_text_response("Failed: type is required", raw=True)
        if limit > self._MAX_LIMIT:
            return format_text_response(
                f"Failed: limit={limit} exceeds max {self._MAX_LIMIT}. "
                f"Page through results using the offset argument.",
                raw=True,
            )
        kwargs = {
            "value": value, "type": type, "scope": scope,
            "limit": limit, "nano": nano,
        }
        if offset:
            kwargs["offset"] = offset
        try:
            falcon = self._service(ThreatGraph)
            response = falcon.get_ran_on(**kwargs)
            if response.get("status_code") != 200:
                err = format_api_error(
                    response,
                    "Failed to get ran_on",
                    operation="combined_ran_on_get",
                )
                return format_text_response(f"Failed to get ran_on: {err}", raw=True)
            return format_text_response(
                _render_resources("Threat Graph Ran-On", response), raw=True
            )
        except Exception as e:
            return format_text_response(f"Failed to get ran_on: {e}", raw=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetRanOn -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/threat_graph.py tests/test_threatgraph.py
git commit -m "feat(threatgraph): add threatgraph_get_ran_on tool"
```

---

## Task 8: `threatgraph_get_summary` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/threat_graph.py`
- Modify: `tests/test_threatgraph.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_threatgraph.py`:

```python
class TestThreatGraphGetSummary:
    def test_returns_summary(self, threatgraph_module):
        threatgraph_module.falcon.get_summary.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "pid:aaa:111", "summary": "rclone.exe -> cloudflare.com"}
            ]},
        }
        result = asyncio.run(
            threatgraph_module.threatgraph_get_summary(
                ids=["pid:aaa:111"], vertex_type="process"
            )
        )
        assert "pid:aaa:111" in result
        assert "rclone.exe" in result

    def test_passes_args_to_falconpy(self, threatgraph_module):
        threatgraph_module.falcon.get_summary.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_summary(
                ids=["x"], vertex_type="process", scope="customer", nano=True,
            )
        )
        kwargs = threatgraph_module.falcon.get_summary.call_args.kwargs
        assert kwargs["ids"] == ["x"]
        assert kwargs["vertex_type"] == "process"
        assert kwargs["scope"] == "customer"
        assert kwargs["nano"] is True

    def test_requires_ids(self, threatgraph_module):
        result = asyncio.run(
            threatgraph_module.threatgraph_get_summary(ids=[], vertex_type="process")
        )
        assert "ids" in result.lower() or "required" in result.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetSummary -v`
Expected: 3 failures.

- [ ] **Step 3: Add the tool**

In `register_tools` append:

```python
        self._add_tool(
            server,
            self.threatgraph_get_summary,
            name="threatgraph_get_summary",
            description=(
                "Short triage-ready summary for one or more vertex IDs. Use "
                "after threatgraph_get_vertices to get a one-line-per-vertex "
                "overview rather than full properties."
            ),
        )
```

Append the tool method:

```python
    async def threatgraph_get_summary(
        self,
        ids: Annotated[list[str], "Composite vertex IDs"],
        vertex_type: Annotated[str, "Vertex type (process, file, etc.)"],
        scope: Annotated[Literal["device", "customer", "global", "cspm", "cwpp"], "Query scope"] = "device",
        nano: Annotated[bool, "Return nano-precision timestamps"] = False,
    ) -> str:
        """Fetch triage-ready vertex summaries."""
        if not ids:
            return format_text_response("Failed: ids is required", raw=True)
        try:
            falcon = self._service(ThreatGraph)
            response = falcon.get_summary(
                ids=ids, vertex_type=vertex_type, scope=scope, nano=nano,
            )
            if response.get("status_code") != 200:
                err = format_api_error(
                    response,
                    "Failed to get summary",
                    operation="combined_summary_get",
                )
                return format_text_response(f"Failed to get summary: {err}", raw=True)
            return format_text_response(
                _render_resources("Threat Graph Summary", response), raw=True
            )
        except Exception as e:
            return format_text_response(f"Failed to get summary: {e}", raw=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphGetSummary -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/threat_graph.py tests/test_threatgraph.py
git commit -m "feat(threatgraph): add threatgraph_get_summary tool"
```

---

## Task 9: Tool-registration count + tier assertion

Verifies the module wires up exactly the expected surface and all tools land at `tier="read"`.

**Files:**
- Modify: `tests/test_threatgraph.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_threatgraph.py`:

```python
class TestThreatGraphRegistrationSurface:
    def test_registers_exactly_five_tools_at_read_tier(self, threatgraph_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        threatgraph_module.register_tools(server)
        expected = {
            "threatgraph_get_vertices",
            "threatgraph_get_edges",
            "threatgraph_get_ran_on",
            "threatgraph_get_summary",
            "threatgraph_get_edge_types",
        }
        assert set(threatgraph_module.tools) == expected

    def test_write_tools_not_registered_when_disabled(self, threatgraph_module):
        # ThreatGraph is read-only; this guards against accidentally adding a
        # write tool in the future without opting in explicitly.
        threatgraph_module.allow_writes = False
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        threatgraph_module.register_tools(server)
        # All tools remain read-tier; allow_writes flip must not add or drop any.
        assert len(threatgraph_module.tools) == 5
```

- [ ] **Step 2: Run tests**

Run: `python -m pytest tests/test_threatgraph.py::TestThreatGraphRegistrationSurface -v`
Expected: both pass (the tools are already registered at `tier="read"` via the default in `BaseModule._add_tool`).

- [ ] **Step 3: Commit**

```bash
git add tests/test_threatgraph.py
git commit -m "test(threatgraph): assert exact tool surface + read-only posture"
```

---

## Task 10: Full test suite + smoke check

- [ ] **Step 1: Run the full suite**

Run: `python -m pytest -q`
Expected: all previously-passing tests still pass; new Threat Graph tests all pass. Count should be baseline (185) + new tests.

- [ ] **Step 2: Smoke-check module auto-discovery at server startup**

Run:
```bash
python -c "from crowdstrike_mcp.registry import get_module_names; print(sorted(get_module_names()))"
```
Expected: output includes `threatgraph` alongside the other modules.

- [ ] **Step 3: Smoke-check the smoke-tools-list test still passes**

Run: `python -m pytest tests/test_smoke_tools_list.py -v`
Expected: pass (if it enumerates tools and there's no hardcoded count that would reject 5 new tools — if it does, update the expected count in that test as part of this step).

- [ ] **Step 4: Lint**

Run: `python -m ruff check src/crowdstrike_mcp/modules/threat_graph.py src/crowdstrike_mcp/resources/threatgraph_reference.py tests/test_threatgraph.py`
Expected: no errors. Fix any reported issues inline (unused imports, E501, etc.).

Run: `python -m ruff format src/crowdstrike_mcp/modules/threat_graph.py src/crowdstrike_mcp/resources/threatgraph_reference.py tests/test_threatgraph.py`

- [ ] **Step 5: Commit (only if the lint/format step changed files)**

```bash
git status
# If anything changed:
git add -u
git commit -m "style(threatgraph): ruff format"
```

---

## Task 11: User-facing documentation

**Files:**
- Create: `docs/modules/threat-graph.md`

- [ ] **Step 1: Create the module doc**

Write `docs/modules/threat-graph.md`:

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add docs/modules/threat-graph.md
git commit -m "docs(threatgraph): add user-facing module reference"
```

---

## Task 12: Final verification

- [ ] **Step 1: Re-run the full test suite**

Run: `python -m pytest -q`
Expected: 185 (baseline) + ~26 new Threat Graph tests = ~211 total, all passing. Count the new tests and note the final number in the commit summary.

- [ ] **Step 2: Verify module shows up in server startup**

Run:
```bash
python -c "from crowdstrike_mcp.registry import get_module_names; assert 'threatgraph' in get_module_names(); print('ok')"
```
Expected: `ok`.

- [ ] **Step 3: Verify scope lookup end-to-end**

Run:
```bash
python -c "from crowdstrike_mcp.common.api_scopes import get_required_scopes; print(get_required_scopes('combined_edges_get'))"
```
Expected: `['threatgraph:read']`.

- [ ] **Step 4: Final sanity — list tools the module registers**

Run:
```bash
python - <<'PY'
from unittest.mock import MagicMock, patch
with patch('crowdstrike_mcp.modules.threat_graph.ThreatGraph'):
    from crowdstrike_mcp.modules.threat_graph import ThreatGraphModule
    m = ThreatGraphModule(MagicMock())
    server = MagicMock(); server.tool.return_value = lambda fn: fn
    server.resource.return_value = lambda fn: fn
    m.register_tools(server); m.register_resources(server)
    print('tools:', sorted(m.tools))
    print('resources:', m.resources)
PY
```
Expected:
```
tools: ['threatgraph_get_edge_types', 'threatgraph_get_edges', 'threatgraph_get_ran_on', 'threatgraph_get_summary', 'threatgraph_get_vertices']
resources: ['falcon://reference/threatgraph-edge-types']
```

- [ ] **Step 5: Confirm branch state is clean**

Run: `git status`
Expected: `nothing to commit, working tree clean` on branch `feature/fr06-threat-graph`.

Feature is ready. The `finishing-a-development-branch` skill takes over from here (PR, merge, or cleanup).
