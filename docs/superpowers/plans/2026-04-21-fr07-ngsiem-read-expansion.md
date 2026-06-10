# FR 07: NGSIEM Read Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 12 read-only MCP tools to `NGSIEMModule` that expose live-state introspection (saved queries, lookup files, dashboards, parsers) and ingestion-pipeline visibility (data connections, connectors, provisioning status).

**Architecture:** Extend the existing `src/crowdstrike_mcp/modules/ngsiem.py` — one falconpy service class per module matches repo convention. All 12 tools call a new shared `_call_and_unwrap` helper that mirrors the HTTP-status / body-errors unwrap logic already in `_execute_query`. Compact-by-default projection for all `list_*` tools with a `detail=True` flag; `get_lookup_file` strips content unless `include_content=True`.

**Tech Stack:** Python 3.11+, `crowdstrike-falconpy>=1.6.1`, `mcp>=1.12.1`, FastMCP, pytest.

**Spec:** `docs/superpowers/specs/2026-04-21-fr07-ngsiem-read-expansion-design.md`

**FR:** `docs/FRs/07-ngsiem-read-expansion.md`

**Branch:** `feature/fr07-ngsiem-read-expansion` in `.worktrees/fr07-ngsiem-read-expansion/`

---

## File Structure

**Modify:**
- `src/crowdstrike_mcp/modules/ngsiem.py` — add helper + 12 tool methods + registrations
- `src/crowdstrike_mcp/common/api_scopes.py` — add 11 operation-to-scope entries
- `README.md` — extend the tool inventory near the NGSIEM section
- `docs/FRs/README.md` — flip FR 07 status to Implemented
- `docs/FRs/07-ngsiem-read-expansion.md` — append implementation note
- `tests/test_smoke_tools_list.py` — update expected tool count / list if the suite enumerates it

**Create:**
- `tests/test_ngsiem_reads.py` — new test file covering the 12 new tools

**Do not create:** new module files, new resources, new falconpy imports beyond the existing `NGSIEM`.

---

## Task 0: Environment baseline & falconpy signature verification

**Files:** none (read-only inspection + commands)

- [ ] **Step 1: Confirm working directory and branch**

Run:
```bash
pwd
git branch --show-current
```
Expected: inside `.worktrees/fr07-ngsiem-read-expansion`, branch `feature/fr07-ngsiem-read-expansion`.

- [ ] **Step 2: Install package in editable mode**

Run:
```bash
pip install -e '.[dev]'
```

If the install fails with `WinError 32` (file in use by another process), stop any other MCP server / worktree agent processes that may hold `crowdstrike-mcp.exe`, then retry. The package can also be considered usable if another worktree already has it installed in editable mode pointing at a different path — verify by running `python -c "import crowdstrike_mcp; print(crowdstrike_mcp.__file__)"` and confirming the import resolves.

- [ ] **Step 3: Run full baseline test suite**

Run:
```bash
python -m pytest tests/ -q
```
Expected: all tests pass. Record the count. If anything fails on master state, stop and report — do not proceed until baseline is green.

- [ ] **Step 4: Verify all 12 falconpy methods exist and have the expected signature**

Run:
```bash
python -c "
from falconpy import NGSIEM
import inspect
methods = [
    'list_saved_queries', 'get_saved_query_template',
    'list_lookup_files', 'get_lookup_file',
    'list_dashboards', 'list_parsers', 'get_parser',
    'list_data_connections', 'get_connection_by_id',
    'get_provisioning_status', 'list_data_connectors',
    'list_connector_configs',
]
for m in methods:
    assert hasattr(NGSIEM, m), f'MISSING: {m}'
    print(f'{m}: {inspect.signature(getattr(NGSIEM, m))}')"
```
Expected: all 12 method names print. If any are missing (renamed in falconpy), STOP — update the plan before proceeding.

- [ ] **Step 5: Probe `get_lookup_file` response shape (optional but informative)**

Document whether the method accepts `include_content=True` natively or always returns content. Run:
```bash
python -c "from falconpy import NGSIEM; import inspect; print(inspect.getdoc(NGSIEM.get_lookup_file))" 2>&1 | head -40
```

Expected: docstring output. The module implementation will strip content client-side if needed — this is a sanity check, not a blocker.

- [ ] **Step 6: No commit for Task 0** (read-only investigation).

---

## Task 1: Add API scope mappings

**Files:**
- Modify: `src/crowdstrike_mcp/common/api_scopes.py`
- Test: extend existing scope coverage in `tests/test_ngsiem_reads.py` (created in Task 2)

We add scope entries now so that 403 errors from any of the 12 new operations surface a useful "required scope: ngsiem:read" hint via the existing plumbing.

- [ ] **Step 1: Add 11 new NGSIEM entries to `OPERATION_SCOPES`**

Open `src/crowdstrike_mcp/common/api_scopes.py`. Find the NGSIEM section (currently has `start_search`, `get_search_status`, `stop_search`). Extend it to:

```python
    # NGSIEM
    "start_search": ["ngsiem:read"],
    "get_search_status": ["ngsiem:read"],
    "stop_search": ["ngsiem:write"],
    # NGSIEM — read-only introspection (FR 07)
    "list_saved_queries": ["ngsiem:read"],
    "get_saved_query_template": ["ngsiem:read"],
    "list_lookup_files": ["ngsiem:read"],
    "get_lookup_file": ["ngsiem:read"],
    "list_dashboards": ["ngsiem:read"],
    "list_parsers": ["ngsiem:read"],
    "get_parser": ["ngsiem:read"],
    "list_data_connections": ["ngsiem:read"],
    "get_connection_by_id": ["ngsiem:read"],
    "get_provisioning_status": ["ngsiem:read"],
    "list_data_connectors": ["ngsiem:read"],
    "list_connector_configs": ["ngsiem:read"],
```

- [ ] **Step 2: Verify module still imports cleanly**

Run:
```bash
python -c "from crowdstrike_mcp.common.api_scopes import get_required_scopes; print(get_required_scopes('list_saved_queries'))"
```
Expected: `['ngsiem:read']`

- [ ] **Step 3: Commit**

```bash
git add src/crowdstrike_mcp/common/api_scopes.py
git commit -m "feat(fr07): register ngsiem:read scopes for 11 new read operations"
```

---

## Task 2: Add `_call_and_unwrap` helper + test scaffolding

**Files:**
- Modify: `src/crowdstrike_mcp/modules/ngsiem.py`
- Create: `tests/test_ngsiem_reads.py`

This task lands the shared helper + fixture pattern the remaining tasks will reuse. It registers no tools yet — just wiring.

- [ ] **Step 1: Write the failing helper test**

Create `tests/test_ngsiem_reads.py`:

```python
"""Tests for FR 07 NGSIEM read-expansion tools."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def ngsiem_module(mock_client):
    """NGSIEMModule with the falconpy NGSIEM client mocked."""
    with patch("crowdstrike_mcp.modules.ngsiem.NGSIEM") as MockNGSIEM:
        mock_falcon = MagicMock()
        MockNGSIEM.return_value = mock_falcon
        from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

        module = NGSIEMModule(mock_client)
        module._service = lambda cls: mock_falcon
        module.falcon = mock_falcon
        return module


class TestCallAndUnwrap:
    """The shared helper used by all 12 new tools."""

    def test_success_path_returns_resources(self, ngsiem_module):
        fake_method = MagicMock(return_value={
            "status_code": 200,
            "body": {"resources": [{"id": "a"}, {"id": "b"}]},
        })
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name", filter="x")
        assert result["success"] is True
        assert result["resources"] == [{"id": "a"}, {"id": "b"}]
        fake_method.assert_called_once_with(filter="x")

    def test_http_error_surfaces_body_message(self, ngsiem_module):
        fake_method = MagicMock(return_value={
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        })
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name")
        assert result["success"] is False
        assert "Forbidden" in result["error"]
        assert "403" in result["error"]

    def test_empty_resources_is_success(self, ngsiem_module):
        fake_method = MagicMock(return_value={
            "status_code": 200,
            "body": {"resources": []},
        })
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name")
        assert result["success"] is True
        assert result["resources"] == []

    def test_exception_is_captured(self, ngsiem_module):
        fake_method = MagicMock(side_effect=RuntimeError("boom"))
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name")
        assert result["success"] is False
        assert "boom" in result["error"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py::TestCallAndUnwrap -v
```
Expected: FAIL with `AttributeError: 'NGSIEMModule' object has no attribute '_call_and_unwrap'`.

- [ ] **Step 3: Add the helper to `ngsiem.py`**

Open `src/crowdstrike_mcp/modules/ngsiem.py`. After the `_execute_query` method (around line 250, the last method in the class), add:

```python
    # ------------------------------------------------------------------
    # Shared unwrap helper (FR 07 read-expansion tools)
    # ------------------------------------------------------------------

    def _call_and_unwrap(self, method, operation: str, **kwargs) -> dict:
        """Call a falconpy method and normalize the response shape.

        Returns ``{"success": True, "resources": <list|dict>, "body": <dict>}``
        on HTTP 200, or ``{"success": False, "error": <str>}`` on any
        non-2xx or thrown exception. Errors are extracted from both the
        top-level ``resources.errors`` and ``body.errors`` shapes that
        falconpy may use, matching the pattern in ``_execute_query``.
        """
        try:
            response = method(**kwargs)
        except Exception as exc:
            return {"success": False, "error": f"{operation} call error: {exc}"}

        status = response.get("status_code", 0)
        body = response.get("body", {}) or {}

        if 200 <= status < 300:
            return {
                "success": True,
                "resources": body.get("resources", []),
                "body": body,
            }

        error_details: list[str] = []
        resources = response.get("resources", {}) or {}
        if isinstance(resources, dict) and "errors" in resources:
            for err in resources["errors"]:
                if isinstance(err, dict) and "message" in err:
                    error_details.append(err["message"])
                else:
                    error_details.append(str(err))
        if "errors" in body:
            for err in body["errors"]:
                if isinstance(err, dict) and "message" in err:
                    error_details.append(err["message"])
                else:
                    error_details.append(str(err))
        if not error_details:
            error_details = [f"HTTP {status} error"]

        return {
            "success": False,
            "error": f"{operation} failed (HTTP {status}): {'; '.join(error_details)}",
        }
```

- [ ] **Step 4: Run the test to verify it passes**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py::TestCallAndUnwrap -v
```
Expected: 4 passing.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem.py tests/test_ngsiem_reads.py
git commit -m "feat(fr07): add _call_and_unwrap helper + ngsiem read-tool test scaffold"
```

---

## Task 3: Saved-query tools (`ngsiem_list_saved_queries`, `ngsiem_get_saved_query_template`)

**Files:**
- Modify: `src/crowdstrike_mcp/modules/ngsiem.py`
- Test: `tests/test_ngsiem_reads.py`

Two tools. Both share a compact-vs-detail projection pattern; the list version also takes `filter` and `limit`.

- [ ] **Step 1: Write failing tests for both tools**

Append to `tests/test_ngsiem_reads.py`:

```python
class TestListSavedQueries:
    def test_returns_compact_projection_by_default(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "q1", "name": "enrich_users", "last_modified": "2026-04-01",
                 "query": "..." * 100, "extra": "ignored"},
                {"id": "q2", "name": "enrich_hosts", "last_modified": "2026-04-02"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries())
        assert "q1" in result and "enrich_users" in result
        assert "q2" in result and "enrich_hosts" in result
        # Bulk body fields must not leak in compact mode
        assert "extra" not in result

    def test_detail_true_returns_full_records(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "q1", "name": "x", "last_modified": "t", "extra": "keep_me"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries(detail=True))
        assert "keep_me" in result

    def test_passes_filter_and_limit(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_saved_queries(filter="name:'enrich_*'", limit=25))
        kwargs = ngsiem_module.falcon.list_saved_queries.call_args.kwargs
        assert kwargs["filter"] == "name:'enrich_*'"
        assert kwargs["limit"] == 25

    def test_caps_limit_at_1000(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_saved_queries(limit=9999))
        kwargs = ngsiem_module.falcon.list_saved_queries.call_args.kwargs
        assert kwargs["limit"] == 1000

    def test_empty_result_message(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries())
        assert "no" in result.lower() or "0" in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 403, "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries())
        assert "failed" in result.lower()


class TestGetSavedQueryTemplate:
    def test_returns_full_template(self, ngsiem_module):
        ngsiem_module.falcon.get_saved_query_template.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "q1", "name": "enrich_users", "query_string": "#repo=all | ..."},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="q1"))
        assert "q1" in result
        assert "enrich_users" in result
        assert "#repo=all" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_saved_query_template.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="abc"))
        kwargs = ngsiem_module.falcon.get_saved_query_template.call_args.kwargs
        assert kwargs["ids"] == "abc" or kwargs["ids"] == ["abc"]

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_saved_query_template.return_value = {
            "status_code": 404, "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="missing"))
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run the tests to verify failure**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py::TestListSavedQueries tests/test_ngsiem_reads.py::TestGetSavedQueryTemplate -v
```
Expected: FAIL with `AttributeError: ... has no attribute 'ngsiem_list_saved_queries'` (and similar).

- [ ] **Step 3: Add a small projection helper at class level**

In `src/crowdstrike_mcp/modules/ngsiem.py`, inside `NGSIEMModule`, just above `_call_and_unwrap`, add:

```python
    _COMPACT_LIST_FIELDS = ("id", "name", "last_modified", "state", "status")

    @classmethod
    def _project_compact(cls, records: list) -> list:
        """Return records filtered to the compact projection field set."""
        projected = []
        for rec in records:
            if not isinstance(rec, dict):
                projected.append(rec)
                continue
            projected.append({k: rec[k] for k in cls._COMPACT_LIST_FIELDS if k in rec})
        return projected

    def _format_list(
        self,
        result: dict,
        *,
        tool_name: str,
        label: str,
        filter_: str | None,
        limit: int,
        detail: bool,
        meta_extra: dict | None = None,
    ) -> str:
        """Shared formatter for the compact/detail list tools."""
        if not result.get("success"):
            return format_text_response(
                f"{tool_name} failed:\n{result.get('error', 'Unknown error')}",
                tool_name=tool_name,
                raw=True,
            )
        records = result["resources"] or []
        if not detail:
            records = self._project_compact(records)
        header = [
            f"{label} ({len(records)} result{'s' if len(records) != 1 else ''}):",
        ]
        if filter_:
            header.append(f"Filter: {filter_}")
        header.append(f"Limit: {limit}")
        header.append(f"Detail: {detail}")
        header.append("")
        if not records:
            header.append(f"No {label.lower()} found.")
            return format_text_response(
                "\n".join(header),
                tool_name=tool_name,
                raw=True,
                structured_data={"records": records, **(meta_extra or {})},
                metadata={"filter": filter_, "limit": limit},
            )
        for i, rec in enumerate(records[:50]):
            header.append(f"#{i + 1}:")
            if isinstance(rec, dict):
                for k, v in rec.items():
                    sv = str(v)
                    if len(sv) > 300:
                        sv = sv[:300] + "..."
                    header.append(f"  {k}: {sv}")
            else:
                header.append(f"  {rec}")
            header.append("")
        if len(records) > 50:
            header.append(f"... and {len(records) - 50} more records")
        return format_text_response(
            "\n".join(header),
            tool_name=tool_name,
            raw=True,
            structured_data={"records": records, **(meta_extra or {})},
            metadata={"filter": filter_, "limit": limit},
        )

    def _format_single(
        self,
        result: dict,
        *,
        tool_name: str,
        label: str,
        identifier: str,
    ) -> str:
        """Shared formatter for the get_* single-record tools."""
        if not result.get("success"):
            return format_text_response(
                f"{tool_name} failed:\n{result.get('error', 'Unknown error')}",
                tool_name=tool_name,
                raw=True,
            )
        resources = result["resources"]
        record = resources[0] if isinstance(resources, list) and resources else resources
        lines = [f"{label} ({identifier}):", ""]
        if isinstance(record, dict):
            for k, v in record.items():
                sv = str(v)
                if len(sv) > 2000:
                    sv = sv[:2000] + "..."
                lines.append(f"{k}: {sv}")
        else:
            lines.append(str(record))
        return format_text_response(
            "\n".join(lines),
            tool_name=tool_name,
            raw=True,
            structured_data={"record": record},
            metadata={"id": identifier},
        )
```

- [ ] **Step 4: Implement the two tools**

In `NGSIEMModule`, below `_format_single`, add:

```python
    async def ngsiem_list_saved_queries(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate saved NGSIEM searches (enrichment functions, etc.)."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_saved_queries, "list_saved_queries", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_saved_queries",
            label="Saved Queries",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_get_saved_query_template(
        self,
        id: Annotated[str, "Saved query ID"],
    ) -> str:
        """Fetch the live body + metadata of one saved NGSIEM search."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(
            falcon.get_saved_query_template, "get_saved_query_template", ids=id
        )
        return self._format_single(
            result,
            tool_name="ngsiem_get_saved_query_template",
            label="Saved Query Template",
            identifier=id,
        )
```

- [ ] **Step 5: Register both tools**

In the existing `register_tools` method (currently only registers `ngsiem_query`), append:

```python
        self._add_tool(
            server,
            self.ngsiem_list_saved_queries,
            name="ngsiem_list_saved_queries",
            description="Enumerate saved NGSIEM queries (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_get_saved_query_template,
            name="ngsiem_get_saved_query_template",
            description="Fetch the live body + metadata of one saved NGSIEM query.",
        )
```

- [ ] **Step 6: Run the tests to verify pass**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py -v
```
Expected: all saved-query tests + earlier `TestCallAndUnwrap` tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem.py tests/test_ngsiem_reads.py
git commit -m "feat(fr07): add ngsiem_list_saved_queries + ngsiem_get_saved_query_template"
```

---

## Task 4: Lookup-file tools (`ngsiem_list_lookup_files`, `ngsiem_get_lookup_file`)

**Files:**
- Modify: `src/crowdstrike_mcp/modules/ngsiem.py`
- Test: `tests/test_ngsiem_reads.py`

`get_lookup_file` has the extra `include_content` flag — metadata-only by default.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_ngsiem_reads.py`:

```python
class TestListLookupFiles:
    def test_returns_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_lookup_files.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "l1", "name": "blocked_domains.csv", "last_modified": "t1",
                 "row_count": 400, "schema": "..." * 20},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_lookup_files())
        assert "l1" in result and "blocked_domains.csv" in result
        assert "row_count" not in result  # not in compact field set

    def test_detail_true_returns_full(self, ngsiem_module):
        ngsiem_module.falcon.list_lookup_files.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "l1", "name": "x", "row_count": 42},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_lookup_files(detail=True))
        assert "row_count" in result
        assert "42" in result

    def test_caps_limit(self, ngsiem_module):
        ngsiem_module.falcon.list_lookup_files.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_lookup_files(limit=9999))
        assert ngsiem_module.falcon.list_lookup_files.call_args.kwargs["limit"] == 1000


class TestGetLookupFile:
    FULL_RECORD = {
        "id": "l1",
        "name": "blocked_domains.csv",
        "row_count": 385,
        "schema": [{"name": "domain", "type": "string"}],
        "content": "domain\\nfoo.example\\nbar.example\\n",
        "last_modified": "2026-04-10T00:00:00Z",
    }

    def test_metadata_only_by_default(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = {
            "status_code": 200, "body": {"resources": [self.FULL_RECORD]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_lookup_file(id="l1"))
        assert "blocked_domains.csv" in result
        assert "385" in result
        assert "foo.example" not in result  # content stripped
        assert "bar.example" not in result

    def test_include_content_true_returns_content(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = {
            "status_code": 200, "body": {"resources": [self.FULL_RECORD]},
        }
        result = asyncio.run(
            ngsiem_module.ngsiem_get_lookup_file(id="l1", include_content=True)
        )
        assert "foo.example" in result
        assert "bar.example" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_lookup_file(id="abc"))
        kwargs = ngsiem_module.falcon.get_lookup_file.call_args.kwargs
        assert kwargs["ids"] == "abc" or kwargs["ids"] == ["abc"]

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = {
            "status_code": 404, "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_lookup_file(id="missing"))
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run the tests to verify failure**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py::TestListLookupFiles tests/test_ngsiem_reads.py::TestGetLookupFile -v
```
Expected: FAIL with missing attribute errors.

- [ ] **Step 3: Implement the two tools**

In `NGSIEMModule`, below `ngsiem_get_saved_query_template`, add:

```python
    async def ngsiem_list_lookup_files(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate NGSIEM lookup files."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_lookup_files, "list_lookup_files", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_lookup_files",
            label="Lookup Files",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_get_lookup_file(
        self,
        id: Annotated[str, "Lookup file ID"],
        include_content: Annotated[bool, "Return file content, not just metadata"] = False,
    ) -> str:
        """Fetch a lookup file — metadata only unless include_content=True."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(falcon.get_lookup_file, "get_lookup_file", ids=id)
        if result.get("success") and not include_content:
            # Strip content from each record client-side; metadata fields retained.
            stripped: list = []
            for rec in result["resources"] or []:
                if isinstance(rec, dict):
                    stripped.append({k: v for k, v in rec.items() if k != "content"})
                else:
                    stripped.append(rec)
            result["resources"] = stripped
        return self._format_single(
            result,
            tool_name="ngsiem_get_lookup_file",
            label="Lookup File",
            identifier=id,
        )
```

- [ ] **Step 4: Register both tools**

Append to `register_tools`:

```python
        self._add_tool(
            server,
            self.ngsiem_list_lookup_files,
            name="ngsiem_list_lookup_files",
            description="Enumerate NGSIEM lookup files (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_get_lookup_file,
            name="ngsiem_get_lookup_file",
            description="Fetch a lookup file; metadata only unless include_content=True.",
        )
```

- [ ] **Step 5: Run the tests to verify pass**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py -v
```
Expected: all prior tests + new lookup-file tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem.py tests/test_ngsiem_reads.py
git commit -m "feat(fr07): add ngsiem_list_lookup_files + ngsiem_get_lookup_file"
```

---

## Task 5: Dashboard & parser tools (3 tools)

**Files:**
- Modify: `src/crowdstrike_mcp/modules/ngsiem.py`
- Test: `tests/test_ngsiem_reads.py`

Three tools: `ngsiem_list_dashboards`, `ngsiem_list_parsers`, `ngsiem_get_parser`. Same pattern as saved queries — compact list + single get.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_ngsiem_reads.py`:

```python
class TestListDashboards:
    def test_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_dashboards.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "d1", "name": "Ingestion Overview", "last_modified": "t1",
                 "widgets": ["..." * 50]},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_dashboards())
        assert "Ingestion Overview" in result
        assert "widgets" not in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_dashboards.return_value = {
            "status_code": 500, "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_dashboards())
        assert "failed" in result.lower()


class TestListParsers:
    def test_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_parsers.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "p1", "name": "box-parser", "last_modified": "t",
                 "script": "#" * 1000},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_parsers())
        assert "box-parser" in result
        assert "script" not in result

    def test_detail_true_returns_script(self, ngsiem_module):
        ngsiem_module.falcon.list_parsers.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "p1", "name": "box-parser", "script": "MARKER_STRING"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_parsers(detail=True))
        assert "MARKER_STRING" in result


class TestGetParser:
    def test_returns_parser_detail(self, ngsiem_module):
        ngsiem_module.falcon.get_parser.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "p1", "name": "box-parser", "script": "MARKER_STRING"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_parser(id="p1"))
        assert "p1" in result
        assert "MARKER_STRING" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_parser.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_parser(id="p1"))
        kwargs = ngsiem_module.falcon.get_parser.call_args.kwargs
        assert kwargs["ids"] == "p1" or kwargs["ids"] == ["p1"]

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_parser.return_value = {
            "status_code": 404, "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_parser(id="missing"))
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run the tests to verify failure**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py::TestListDashboards tests/test_ngsiem_reads.py::TestListParsers tests/test_ngsiem_reads.py::TestGetParser -v
```
Expected: FAIL on missing methods.

- [ ] **Step 3: Implement the three tools**

In `NGSIEMModule`, below `ngsiem_get_lookup_file`, add:

```python
    async def ngsiem_list_dashboards(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate NGSIEM dashboards."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_dashboards, "list_dashboards", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_dashboards",
            label="Dashboards",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_list_parsers(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate NGSIEM parsers."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_parsers, "list_parsers", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_parsers",
            label="Parsers",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_get_parser(
        self,
        id: Annotated[str, "Parser ID"],
    ) -> str:
        """Fetch a parser's live configuration + script."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(falcon.get_parser, "get_parser", ids=id)
        return self._format_single(
            result,
            tool_name="ngsiem_get_parser",
            label="Parser",
            identifier=id,
        )
```

- [ ] **Step 4: Register the three tools**

Append to `register_tools`:

```python
        self._add_tool(
            server,
            self.ngsiem_list_dashboards,
            name="ngsiem_list_dashboards",
            description="Enumerate NGSIEM dashboards (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_list_parsers,
            name="ngsiem_list_parsers",
            description="Enumerate NGSIEM parsers (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_get_parser,
            name="ngsiem_get_parser",
            description="Fetch a parser's live configuration + script.",
        )
```

- [ ] **Step 5: Run the tests to verify pass**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py -v
```
Expected: all prior + new tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem.py tests/test_ngsiem_reads.py
git commit -m "feat(fr07): add ngsiem dashboard + parser read tools (3 tools)"
```

---

## Task 6: Ingestion / connector tools (5 tools)

**Files:**
- Modify: `src/crowdstrike_mcp/modules/ngsiem.py`
- Test: `tests/test_ngsiem_reads.py`

Five tools: `ngsiem_list_data_connections`, `ngsiem_get_data_connection` (→ `get_connection_by_id`), `ngsiem_get_provisioning_status`, `ngsiem_list_data_connectors`, `ngsiem_list_connector_configs`.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_ngsiem_reads.py`:

```python
class TestListDataConnections:
    def test_compact_projection_with_state(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connections.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "c1", "name": "box-prod", "state": "active",
                 "last_modified": "t1", "config_blob": "..." * 100},
                {"id": "c2", "name": "cato-prod", "state": "failed"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_data_connections())
        assert "box-prod" in result and "active" in result
        assert "cato-prod" in result and "failed" in result
        assert "config_blob" not in result

    def test_passes_filter(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connections.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_data_connections(filter="state:'failed'"))
        kwargs = ngsiem_module.falcon.list_data_connections.call_args.kwargs
        assert kwargs["filter"] == "state:'failed'"

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connections.return_value = {
            "status_code": 403, "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_data_connections())
        assert "failed" in result.lower()


class TestGetDataConnection:
    def test_returns_connection_detail(self, ngsiem_module):
        ngsiem_module.falcon.get_connection_by_id.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "c1", "name": "box-prod", "state": "active", "config": {"endpoint": "https://x"}},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_data_connection(id="c1"))
        assert "box-prod" in result
        assert "endpoint" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_connection_by_id.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_data_connection(id="c1"))
        kwargs = ngsiem_module.falcon.get_connection_by_id.call_args.kwargs
        assert kwargs["ids"] == "c1" or kwargs["ids"] == ["c1"]


class TestGetProvisioningStatus:
    def test_returns_status(self, ngsiem_module):
        ngsiem_module.falcon.get_provisioning_status.return_value = {
            "status_code": 200,
            "body": {"resources": [{"provisioned": True, "region": "us-1"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_provisioning_status())
        assert "provisioned" in result
        assert "us-1" in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_provisioning_status.return_value = {
            "status_code": 500, "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_provisioning_status())
        assert "failed" in result.lower()


class TestListDataConnectors:
    def test_returns_connector_types(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connectors.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "box", "name": "Box"},
                {"id": "cato", "name": "Cato"},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_data_connectors())
        assert "Box" in result and "Cato" in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connectors.return_value = {
            "status_code": 403, "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_data_connectors())
        assert "failed" in result.lower()


class TestListConnectorConfigs:
    def test_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_connector_configs.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {"id": "cfg1", "name": "box-cfg", "last_modified": "t",
                 "big_blob": "..." * 100},
            ]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_connector_configs())
        assert "box-cfg" in result
        assert "big_blob" not in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_connector_configs.return_value = {
            "status_code": 403, "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_connector_configs())
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run the tests to verify failure**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py::TestListDataConnections tests/test_ngsiem_reads.py::TestGetDataConnection tests/test_ngsiem_reads.py::TestGetProvisioningStatus tests/test_ngsiem_reads.py::TestListDataConnectors tests/test_ngsiem_reads.py::TestListConnectorConfigs -v
```
Expected: FAIL on missing methods.

- [ ] **Step 3: Implement the five tools**

In `NGSIEMModule`, below `ngsiem_get_parser`, add:

```python
    async def ngsiem_list_data_connections(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate NGSIEM data connections (ingestion pipelines)."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(
            falcon.list_data_connections, "list_data_connections", **kwargs
        )
        return self._format_list(
            result,
            tool_name="ngsiem_list_data_connections",
            label="Data Connections",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_get_data_connection(
        self,
        id: Annotated[str, "Data connection ID"],
    ) -> str:
        """Fetch a single data connection's state + configuration."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(
            falcon.get_connection_by_id, "get_connection_by_id", ids=id
        )
        return self._format_single(
            result,
            tool_name="ngsiem_get_data_connection",
            label="Data Connection",
            identifier=id,
        )

    async def ngsiem_get_provisioning_status(self) -> str:
        """Fetch overall NGSIEM ingestion provisioning / health status."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(
            falcon.get_provisioning_status, "get_provisioning_status"
        )
        return self._format_single(
            result,
            tool_name="ngsiem_get_provisioning_status",
            label="Provisioning Status",
            identifier="(tenant)",
        )

    async def ngsiem_list_data_connectors(self) -> str:
        """Enumerate available NGSIEM data connector types."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(
            falcon.list_data_connectors, "list_data_connectors"
        )
        return self._format_list(
            result,
            tool_name="ngsiem_list_data_connectors",
            label="Data Connectors",
            filter_=None,
            limit=1000,
            detail=True,  # connector-type records are small; return full
        )

    async def ngsiem_list_connector_configs(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate connector configuration instances."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(
            falcon.list_connector_configs, "list_connector_configs", **kwargs
        )
        return self._format_list(
            result,
            tool_name="ngsiem_list_connector_configs",
            label="Connector Configs",
            filter_=filter,
            limit=limit,
            detail=detail,
        )
```

- [ ] **Step 4: Register the five tools**

Append to `register_tools`:

```python
        self._add_tool(
            server,
            self.ngsiem_list_data_connections,
            name="ngsiem_list_data_connections",
            description="Enumerate NGSIEM data connections (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_get_data_connection,
            name="ngsiem_get_data_connection",
            description="Fetch a single data connection's state + configuration.",
        )
        self._add_tool(
            server,
            self.ngsiem_get_provisioning_status,
            name="ngsiem_get_provisioning_status",
            description="Fetch overall NGSIEM ingestion provisioning / health status.",
        )
        self._add_tool(
            server,
            self.ngsiem_list_data_connectors,
            name="ngsiem_list_data_connectors",
            description="Enumerate available NGSIEM data connector types.",
        )
        self._add_tool(
            server,
            self.ngsiem_list_connector_configs,
            name="ngsiem_list_connector_configs",
            description="Enumerate connector configuration instances (compact projection by default).",
        )
```

- [ ] **Step 5: Run the tests to verify pass**

Run:
```bash
python -m pytest tests/test_ngsiem_reads.py -v
```
Expected: full file passes.

- [ ] **Step 6: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem.py tests/test_ngsiem_reads.py
git commit -m "feat(fr07): add ngsiem ingestion + connector read tools (5 tools)"
```

---

## Task 7: Tool-registration + smoke-list coverage

**Files:**
- Modify: `tests/test_ngsiem_reads.py` (new registration test)
- Modify: `tests/test_smoke_tools_list.py` IF it pins an expected tool count for NGSIEM

- [ ] **Step 1: Add a registration test**

Append to `tests/test_ngsiem_reads.py`:

```python
class TestNgsiemReadToolRegistration:
    EXPECTED_NEW_TOOLS = [
        "ngsiem_list_saved_queries",
        "ngsiem_get_saved_query_template",
        "ngsiem_list_lookup_files",
        "ngsiem_get_lookup_file",
        "ngsiem_list_dashboards",
        "ngsiem_list_parsers",
        "ngsiem_get_parser",
        "ngsiem_list_data_connections",
        "ngsiem_get_data_connection",
        "ngsiem_get_provisioning_status",
        "ngsiem_list_data_connectors",
        "ngsiem_list_connector_configs",
    ]

    def test_all_tools_register_as_read(self, ngsiem_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        ngsiem_module.register_tools(server)
        for name in self.EXPECTED_NEW_TOOLS:
            assert name in ngsiem_module.tools, f"{name} not registered"
        # And the pre-existing tool stays registered
        assert "ngsiem_query" in ngsiem_module.tools
```

- [ ] **Step 2: Check whether `test_smoke_tools_list.py` enumerates NGSIEM tools**

Run:
```bash
python -m pytest tests/test_smoke_tools_list.py -v
```

Then inspect:
```bash
grep -n "ngsiem" tests/test_smoke_tools_list.py || echo "no ngsiem references"
```

- [ ] **Step 3: If the smoke test pins a count/list, extend it**

If the smoke test uses a fixed list or count of expected tools for NGSIEM, update the expected list to include all 12 new names. Do NOT change the test's structural assertions — only the expected data. If no ngsiem-specific pin exists, skip this step.

- [ ] **Step 4: Run the full test suite to verify pass**

Run:
```bash
python -m pytest tests/ -q
```
Expected: full suite green.

- [ ] **Step 5: Commit**

```bash
git add tests/test_ngsiem_reads.py tests/test_smoke_tools_list.py
git commit -m "test(fr07): registration coverage for 12 ngsiem read tools"
```

(If `test_smoke_tools_list.py` was not modified in Step 3, omit it from the `git add` line.)

---

## Task 8: Documentation updates

**Files:**
- Modify: `README.md`
- Modify: `docs/FRs/README.md`
- Modify: `docs/FRs/07-ngsiem-read-expansion.md`

- [ ] **Step 1: Update `README.md`**

Find the section that enumerates tools per module (search for `ngsiem_query` to locate it). Add the 12 new tool names under the NGSIEM heading, in the same format the existing entries use. If the section groups tools by table rows, keep the grouping from the FR (saved searches, lookup files, dashboards/parsers, ingestion). If there's no NGSIEM tool table, add one short bulleted list of the 12 new tools next to the existing `ngsiem_query` entry. Do not restructure unrelated sections.

- [ ] **Step 2: Update `docs/FRs/README.md`**

Flip the status column for FR 07 to Implemented (use the same wording/format other implemented FRs use — check FR 01 and FR 02 rows for the convention). Add the completion date `2026-04-21`.

- [ ] **Step 3: Append implementation note to `docs/FRs/07-ngsiem-read-expansion.md`**

At the end of the file, add:

```markdown

---

## Implementation

**Implemented:** 2026-04-21
**Branch:** `feature/fr07-ngsiem-read-expansion`
**Plan:** `docs/superpowers/plans/2026-04-21-fr07-ngsiem-read-expansion.md`
**Spec:** `docs/superpowers/specs/2026-04-21-fr07-ngsiem-read-expansion-design.md`

All 12 tools in the Proposed MCP Tools table shipped as read-only. The
`ngsiem_ingestion_health` composite tool floated in Open Question 1 was
deferred — agents compose from `get_provisioning_status` +
`list_data_connections` when needed.
```

- [ ] **Step 4: Commit**

```bash
git add README.md docs/FRs/README.md docs/FRs/07-ngsiem-read-expansion.md
git commit -m "docs(fr07): update tool inventory and FR status for ngsiem reads"
```

---

## Task 9: Lint, format, full suite, and final verification

**Files:** none new

- [ ] **Step 1: Run ruff lint**

Run:
```bash
python -m ruff check src/ tests/
```
Expected: no errors. If errors are flagged in the new code, fix them inline. Do not touch unrelated files.

- [ ] **Step 2: Run ruff format check**

Run:
```bash
python -m ruff format --check src/crowdstrike_mcp/modules/ngsiem.py tests/test_ngsiem_reads.py src/crowdstrike_mcp/common/api_scopes.py
```

If reformatting is needed, run without `--check`:
```bash
python -m ruff format src/crowdstrike_mcp/modules/ngsiem.py tests/test_ngsiem_reads.py src/crowdstrike_mcp/common/api_scopes.py
```

- [ ] **Step 3: Run the full test suite**

Run:
```bash
python -m pytest tests/ -q
```
Expected: full suite green, including pre-existing tests.

- [ ] **Step 4: Verify the module line count is within expectations**

Run:
```bash
wc -l src/crowdstrike_mcp/modules/ngsiem.py
```
Expected: between 700 and 950 lines. If larger, inspect for duplication that could be factored — but do not over-refactor.

- [ ] **Step 5: Verify tool inventory from a smoke import**

Run:
```bash
python -c "
from unittest.mock import MagicMock
from crowdstrike_mcp.modules.ngsiem import NGSIEMModule
m = NGSIEMModule(MagicMock())
server = MagicMock()
server.tool.return_value = lambda fn: fn
m.register_tools(server)
print('\n'.join(sorted(m.tools)))
print(f'Total: {len(m.tools)}')
"
```
Expected output: 13 tool names (`ngsiem_query` plus the 12 new ones), printed alphabetically.

- [ ] **Step 6: Commit any format fixups (if Step 2 reformatted anything)**

```bash
git add -u
git diff --cached --stat
git commit -m "style(fr07): apply ruff format to ngsiem read tools"
```

If nothing is staged, skip the commit.

- [ ] **Step 7: Final review — show branch log**

Run:
```bash
git log --oneline master..HEAD
```
Expected: roughly 8–10 commits, each small and focused. Confirm commit messages read cleanly; no `wip` / `fixup` / `debug` messages.

---

## Completion criteria

- [ ] All 12 new tools registered under `tier="read"` (verified via Task 9 Step 5)
- [ ] All new tests pass (Task 9 Step 3)
- [ ] Full test suite green, no regressions in pre-existing tests
- [ ] `ruff check` + `ruff format` both clean
- [ ] Scope mappings added for 11 new operations
- [ ] README + FR docs updated
- [ ] Branch `feature/fr07-ngsiem-read-expansion` has a clean linear commit history on top of `master`

After completion, use `superpowers:finishing-a-development-branch` to decide merge vs PR.
