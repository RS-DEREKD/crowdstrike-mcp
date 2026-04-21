# FR 02: Spotlight Vulnerabilities Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 5 read-only MCP tools wrapping falconpy's `SpotlightVulnerabilities` collection so the agent can answer "is this host vulnerable to the CVE implicated in this detection?" without a console pivot.

**Architecture:** Extend the existing `SpotlightModule` in `src/crowdstrike_mcp/modules/spotlight.py` (do not create a new module). The existing module already wraps `SpotlightEvaluationLogic`; `SpotlightVulnerabilities` is the same logical domain. This mirrors the `CloudSecurityModule` pattern of grouping multiple falconpy classes by domain, not by class. All tools are read-only (tier="read"); no write paths exist in falconpy for this collection.

**Tech Stack:** Python 3.11+, `crowdstrike-falconpy>=1.6.1`, `mcp>=1.12.1`, FastMCP, pytest.

**Spec:** `\\wsl.localhost\Ubuntu-24.04\home\wwebster\projects\command-center\sectors\CrowdStrike\crowdstrike-detections\docs\features\mcp-feature-requests\02-spotlight-vulnerabilities.md`

---

## Tools to Ship

| Tool | Falconpy method | Purpose |
|---|---|---|
| `spotlight_query_vulnerabilities` | `query_vulnerabilities()` | Find vuln IDs by FQL filter |
| `spotlight_get_vulnerabilities` | `get_vulnerabilities()` | Fetch full records for IDs |
| `spotlight_vulnerabilities_combined` | `query_vulnerabilities_combined()` | One-shot query+get (ergonomic default) |
| `spotlight_get_remediations` | `get_remediations_v2()` | Remediation details |
| `spotlight_host_vulns` | composed (`query_vulnerabilities_combined` with a host filter) | Triage-shortcut: host → open CVEs |

Defaults: `limit=50`, max `limit=500`; `spotlight_host_vulns` pre-filters `status:'open'`; other tools leave status filtering to the caller.

---

## File Structure

**Modify:**
- `src/crowdstrike_mcp/modules/spotlight.py` — add `SpotlightVulnerabilities` import + 5 tool methods + internal helpers.
- `src/crowdstrike_mcp/common/api_scopes.py` — add scope mappings for the new operations.
- `src/crowdstrike_mcp/resources/fql_guides.py` — add `SPOTLIGHT_VULN_FQL` constant.
- `tests/test_spotlight.py` — add test classes for the 5 new tools + registration assertions.
- `README.md` — bump tool count and add Spotlight vulnerabilities row to the tools table.

**Create:** none (the module file exists).

---

## Conventions to Match (non-obvious)

Observed from `hosts.py`, `cloud_security.py`, and the existing `spotlight.py`:

1. **Service-class availability guard.** Wrap the `from falconpy import SpotlightVulnerabilities` in `try/except ImportError` with a module-level `SPOTLIGHT_VULNS_AVAILABLE` flag, and check inside each internal `_method` (return an error dict on unavailable). Same pattern as `Hosts` / `CloudSecurity`.
2. **Public async tool → internal sync `_method` split.** Public tool methods only shape output; all falconpy I/O and error handling lives in `_method` returning `{"success": bool, ...}`.
3. **Use `format_api_error(response, context, operation="<falconpy_operation_name>")`** on non-2xx; the scope-aware 403 handling requires the operation name to appear in `api_scopes.py`.
4. **`format_text_response(..., raw=True)`** is the return envelope.
5. **Test fixture trick:** tests patch the falconpy class and set `module.falcon = mock_instance` plus `module._service = lambda cls: mock_instance`. Follow the existing `spotlight_module` fixture pattern; extend it to also patch `SpotlightVulnerabilities`.
6. **Tool description strings** should lead with the analyst question they answer, not the API they wrap. See `host_lookup` and `cloud_get_risks` descriptions.
7. **FQL filter construction.** When the tool accepts multiple scalar filters (e.g. `cve_id`, `severity`), build the list and `"+".join(filter_parts)` — same as `cloud_security._get_cloud_risks`.
8. **Result bounding.** Default `limit=50`, cap at `500` (spec). Use `min(max_results, 500)` when passing to falconpy.

---

## Task 1: Add FQL guide + scope mappings + falconpy availability flag

**Files:**
- Modify: `src/crowdstrike_mcp/resources/fql_guides.py` (append new constant)
- Modify: `src/crowdstrike_mcp/common/api_scopes.py` (add 4 new entries)
- Modify: `src/crowdstrike_mcp/modules/spotlight.py:1-30` (add import + availability flag; keep SpotlightEvaluationLogic working)

- [ ] **Step 1: Write failing test for scope mappings**

Add to `tests/test_spotlight.py`:

```python
class TestSpotlightVulnScopes:
    """Scope mappings for new operations exist in api_scopes."""

    def test_query_vulnerabilities_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("query_vulnerabilities") == ["spotlight-vulnerabilities:read"]

    def test_get_vulnerabilities_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("get_vulnerabilities") == ["spotlight-vulnerabilities:read"]

    def test_combined_vulnerabilities_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("query_vulnerabilities_combined") == ["spotlight-vulnerabilities:read"]

    def test_remediations_v2_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        assert get_required_scopes("get_remediations_v2") == ["spotlight-vulnerabilities:read"]
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_spotlight.py::TestSpotlightVulnScopes -v`
Expected: 4 FAIL with the scopes returning `[]`.

- [ ] **Step 3: Add scope mappings**

Edit `src/crowdstrike_mcp/common/api_scopes.py` — locate the `# Spotlight Evaluation Logic` section (around the `combinedSupportedEvaluationExt` entry) and insert immediately after it:

```python
    # Spotlight Vulnerabilities
    "query_vulnerabilities": ["spotlight-vulnerabilities:read"],
    "get_vulnerabilities": ["spotlight-vulnerabilities:read"],
    "query_vulnerabilities_combined": ["spotlight-vulnerabilities:read"],
    "get_remediations_v2": ["spotlight-vulnerabilities:read"],
```

- [ ] **Step 4: Run scope tests — confirm they pass**

Run: `pytest tests/test_spotlight.py::TestSpotlightVulnScopes -v`
Expected: 4 PASS.

- [ ] **Step 5: Add FQL guide**

Edit `src/crowdstrike_mcp/resources/fql_guides.py` — append this constant at the end of the `# -- Resource content definitions --` block:

```python
SPOTLIGHT_VULN_FQL = """\
# Spotlight Vulnerabilities FQL Syntax (query_vulnerabilities / query_vulnerabilities_combined)

## Common Fields
- `aid` — Agent/device ID (UUID). Example: `aid:'abc123...'`
- `cve.id` — CVE identifier. Example: `cve.id:'CVE-2024-1234'`
- `cve.severity` — Severity string: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'
- `cve.exploit_status` — Integer 0–90 (higher = more evidence of exploitation in the wild)
- `status` — Vulnerability state: 'open', 'closed', 'reopen', 'expired'
- `created_timestamp` — ISO 8601 timestamp. Example: `created_timestamp:>='now-30d'`
- `closed_timestamp` — ISO 8601 timestamp.
- `host_info.hostname` — Hostname (case-sensitive).
- `host_info.platform_name` — 'Windows', 'Mac', 'Linux'.
- `apps.product_name_version` — Product name + version string.
- `suppression_info.is_suppressed` — Boolean.

## Triage Recipes
- Open criticals on a host: `aid:'<device_id>'+status:'open'+cve.severity:'CRITICAL'`
- Fleet affected by a CVE: `cve.id:'CVE-2024-1234'+status:'open'`
- Exploit-in-the-wild only: `status:'open'+cve.exploit_status:>=60`

## Combining
AND with `+`. OR within a single field uses `,`. Example:
`status:'open'+cve.severity:['CRITICAL','HIGH']`

## Facet Parameter
`query_vulnerabilities_combined` accepts `facet` to include joined data:
- `cve` — CVE metadata (severity, score, exprt_rating)
- `host_info` — Hostname, platform, OS
- `remediation` — Remediation IDs
- `evaluation_logic` — Why Spotlight considers the host vulnerable
"""
```

- [ ] **Step 6: Add availability flag + import to spotlight module**

Edit `src/crowdstrike_mcp/modules/spotlight.py` — replace the existing `from falconpy import SpotlightEvaluationLogic` line with:

```python
try:
    from falconpy import SpotlightEvaluationLogic

    SPOTLIGHT_EVAL_AVAILABLE = True
except ImportError:
    SPOTLIGHT_EVAL_AVAILABLE = False

try:
    from falconpy import SpotlightVulnerabilities

    SPOTLIGHT_VULNS_AVAILABLE = True
except ImportError:
    SPOTLIGHT_VULNS_AVAILABLE = False
```

Also update the `__init__`:

```python
def __init__(self, client):
    super().__init__(client)
    if not SPOTLIGHT_EVAL_AVAILABLE and not SPOTLIGHT_VULNS_AVAILABLE:
        raise ImportError(
            "Neither SpotlightEvaluationLogic nor SpotlightVulnerabilities available. "
            "Ensure crowdstrike-falconpy >= 1.6.1 is installed."
        )
    self._log("Initialized")
```

- [ ] **Step 7: Run full test suite — existing tests must still pass**

Run: `pytest tests/test_spotlight.py -v`
Expected: All existing tests still pass (evaluation logic tests unchanged), new scope tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/crowdstrike_mcp/common/api_scopes.py src/crowdstrike_mcp/resources/fql_guides.py src/crowdstrike_mcp/modules/spotlight.py tests/test_spotlight.py
git commit -m "feat(spotlight): scaffold SpotlightVulnerabilities support

Add falconpy import guard, scope mappings for 4 new operations, and FQL
guide resource content for upcoming vulnerability query tools."
```

---

## Task 2: `spotlight_query_vulnerabilities` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/spotlight.py` (add tool method + internal helper + register)
- Modify: `tests/test_spotlight.py` (add test class)

- [ ] **Step 1: Write failing test**

Append to `tests/test_spotlight.py`:

```python
@pytest.fixture
def spotlight_vuln_module(mock_client):
    """Create SpotlightModule with both Spotlight APIs mocked."""
    with patch("crowdstrike_mcp.modules.spotlight.SpotlightEvaluationLogic") as MockEval, \
         patch("crowdstrike_mcp.modules.spotlight.SpotlightVulnerabilities") as MockVulns:
        mock_eval = MagicMock()
        mock_vulns = MagicMock()
        MockEval.return_value = mock_eval
        MockVulns.return_value = mock_vulns
        from crowdstrike_mcp.modules.spotlight import SpotlightModule

        module = SpotlightModule(mock_client)
        # route _service(cls) to the right mock based on class name
        def _fake_service(cls):
            return mock_vulns if cls.__name__ == "SpotlightVulnerabilities" else mock_eval
        module._service = _fake_service
        module.falcon_eval = mock_eval
        module.falcon_vulns = mock_vulns
        return module


class TestSpotlightQueryVulnerabilities:
    def test_returns_vuln_ids(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": ["vuln-1", "vuln-2", "vuln-3"]},
        }
        result = asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(filter="status:'open'")
        )
        assert "vuln-1" in result
        assert "3" in result  # count

    def test_passes_filter_and_limit(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(
                filter="cve.id:'CVE-2024-1234'", limit=25
            )
        )
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.assert_called_once()
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities.call_args.kwargs
        assert kwargs["filter"] == "cve.id:'CVE-2024-1234'"
        assert kwargs["limit"] == 25

    def test_caps_limit_at_500(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(
                filter="status:'open'", limit=9999
            )
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities.call_args.kwargs
        assert kwargs["limit"] == 500

    def test_requires_filter(self, spotlight_vuln_module):
        result = asyncio.run(spotlight_vuln_module.spotlight_query_vulnerabilities(filter=""))
        assert "filter" in result.lower()

    def test_passes_after_token(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(
                filter="status:'open'", after="token-xyz"
            )
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities.call_args.kwargs
        assert kwargs["after"] == "token-xyz"

    def test_handles_api_error(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(
            spotlight_vuln_module.spotlight_query_vulnerabilities(filter="status:'open'")
        )
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_spotlight.py::TestSpotlightQueryVulnerabilities -v`
Expected: 6 FAIL — method does not exist.

- [ ] **Step 3: Implement tool + internal helper**

Edit `src/crowdstrike_mcp/modules/spotlight.py`. After the existing `spotlight_supported_evaluations` method (before closing class), add:

```python
    async def spotlight_query_vulnerabilities(
        self,
        filter: Annotated[str, "FQL filter expression (required). See falcon://fql/spotlight-vulnerabilities."],
        limit: Annotated[int, "Max IDs to return (default 50, max 500)"] = 50,
        after: Annotated[Optional[str], "Pagination token from a prior call"] = None,
        sort: Annotated[Optional[str], "Sort expression (e.g. 'created_timestamp|desc')"] = None,
    ) -> str:
        """Find vulnerability IDs matching an FQL filter."""
        result = self._query_vulnerabilities(filter=filter, limit=limit, after=after, sort=sort)

        if not result.get("success"):
            return format_text_response(f"Failed to query vulnerabilities: {result.get('error')}", raw=True)

        ids = result["ids"]
        lines = [
            f"Spotlight Vulnerability IDs: {len(ids)} returned (total={result.get('total', 'unknown')})",
            "",
        ]
        if result.get("after"):
            lines.append(f"Next page token: `{result['after']}`")
            lines.append("")
        if not ids:
            lines.append("No vulnerabilities matched the filter.")
        else:
            for i, vid in enumerate(ids, 1):
                lines.append(f"{i}. {vid}")
        return format_text_response("\n".join(lines), raw=True)
```

Then add the internal helper at the bottom of the class:

```python
    def _query_vulnerabilities(self, filter, limit=50, after=None, sort=None):
        if not SPOTLIGHT_VULNS_AVAILABLE:
            return {"success": False, "error": "SpotlightVulnerabilities client not available"}
        if not filter:
            return {"success": False, "error": "filter is required (e.g. status:'open')"}
        try:
            svc = self._service(SpotlightVulnerabilities)
            kwargs = {"filter": filter, "limit": min(limit, 500)}
            if after:
                kwargs["after"] = after
            if sort:
                kwargs["sort"] = sort
            r = svc.query_vulnerabilities(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to query vulnerabilities", operation="query_vulnerabilities")}
            body = r.get("body", {})
            ids = body.get("resources", [])
            meta = body.get("meta", {}).get("pagination", {})
            return {
                "success": True,
                "ids": ids,
                "total": meta.get("total", len(ids)),
                "after": meta.get("after"),
            }
        except Exception as e:
            return {"success": False, "error": f"Error querying vulnerabilities: {e}"}
```

Register the tool in `register_tools`:

```python
        self._add_tool(
            server,
            self.spotlight_query_vulnerabilities,
            name="spotlight_query_vulnerabilities",
            description=(
                "Find vulnerability IDs matching an FQL filter. Use to locate open "
                "CVEs by host (`aid`), CVE ID, severity, or age. Returns IDs only — "
                "use spotlight_get_vulnerabilities or spotlight_vulnerabilities_combined "
                "for full records."
            ),
        )
```

- [ ] **Step 4: Run tool tests — confirm they pass**

Run: `pytest tests/test_spotlight.py::TestSpotlightQueryVulnerabilities -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/spotlight.py tests/test_spotlight.py
git commit -m "feat(spotlight): add spotlight_query_vulnerabilities tool

Thin wrapper over SpotlightVulnerabilities.query_vulnerabilities().
Returns vulnerability IDs for a given FQL filter with limit/after
pagination support."
```

---

## Task 3: `spotlight_get_vulnerabilities` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/spotlight.py`
- Modify: `tests/test_spotlight.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_spotlight.py`:

```python
class TestSpotlightGetVulnerabilities:
    def test_returns_vuln_details(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.get_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {
                    "id": "vuln-1",
                    "cve": {"id": "CVE-2024-1234", "severity": "CRITICAL", "base_score": 9.8},
                    "host_info": {"hostname": "web-01", "platform_name": "Linux"},
                    "status": "open",
                    "created_timestamp": "2026-04-01T00:00:00Z",
                }
            ]},
        }
        result = asyncio.run(
            spotlight_vuln_module.spotlight_get_vulnerabilities(ids=["vuln-1"])
        )
        assert "CVE-2024-1234" in result
        assert "CRITICAL" in result
        assert "web-01" in result

    def test_requires_ids(self, spotlight_vuln_module):
        result = asyncio.run(spotlight_vuln_module.spotlight_get_vulnerabilities(ids=[]))
        assert "ids" in result.lower() or "required" in result.lower()

    def test_passes_ids_to_falconpy(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.get_vulnerabilities.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(spotlight_vuln_module.spotlight_get_vulnerabilities(ids=["a", "b"]))
        spotlight_vuln_module.falcon_vulns.get_vulnerabilities.assert_called_once_with(ids=["a", "b"])

    def test_handles_api_error(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.get_vulnerabilities.return_value = {
            "status_code": 500, "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(spotlight_vuln_module.spotlight_get_vulnerabilities(ids=["x"]))
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_spotlight.py::TestSpotlightGetVulnerabilities -v`
Expected: 4 FAIL.

- [ ] **Step 3: Implement tool + helper**

In `src/crowdstrike_mcp/modules/spotlight.py`, add tool method after `spotlight_query_vulnerabilities`:

```python
    async def spotlight_get_vulnerabilities(
        self,
        ids: Annotated[list[str], "Vulnerability IDs (from spotlight_query_vulnerabilities)"],
    ) -> str:
        """Fetch full vulnerability records by ID."""
        result = self._get_vulnerabilities(ids)
        if not result.get("success"):
            return format_text_response(f"Failed to get vulnerabilities: {result.get('error')}", raw=True)

        resources = result["resources"]
        lines = [f"Spotlight Vulnerabilities: {len(resources)} records", ""]
        if not resources:
            lines.append("No records returned.")
        else:
            for i, v in enumerate(resources, 1):
                cve = v.get("cve", {}) or {}
                host = v.get("host_info", {}) or {}
                lines.append(f"{i}. **{cve.get('id', 'UNKNOWN CVE')}** [{cve.get('severity', '?')}] score={cve.get('base_score', '?')}")
                lines.append(f"   Host: {host.get('hostname', '?')} ({host.get('platform_name', '?')})")
                lines.append(f"   Status: {v.get('status', '?')} | Created: {v.get('created_timestamp', '?')}")
                if cve.get("exploit_status") is not None:
                    lines.append(f"   Exploit status: {cve['exploit_status']}")
                if v.get("apps"):
                    app_names = [a.get("product_name_version", "") for a in v["apps"][:3]]
                    lines.append(f"   Apps: {'; '.join(a for a in app_names if a)}")
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)
```

Internal helper (at bottom):

```python
    def _get_vulnerabilities(self, ids):
        if not SPOTLIGHT_VULNS_AVAILABLE:
            return {"success": False, "error": "SpotlightVulnerabilities client not available"}
        if not ids:
            return {"success": False, "error": "ids list is required"}
        try:
            svc = self._service(SpotlightVulnerabilities)
            r = svc.get_vulnerabilities(ids=ids)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to get vulnerabilities", operation="get_vulnerabilities")}
            return {"success": True, "resources": r.get("body", {}).get("resources", [])}
        except Exception as e:
            return {"success": False, "error": f"Error getting vulnerabilities: {e}"}
```

Register in `register_tools`:

```python
        self._add_tool(
            server,
            self.spotlight_get_vulnerabilities,
            name="spotlight_get_vulnerabilities",
            description=(
                "Fetch full vulnerability records by ID: CVE metadata, severity, host "
                "info, exploit status, affected apps. Pair with spotlight_query_vulnerabilities."
            ),
        )
```

- [ ] **Step 4: Run tool tests — confirm they pass**

Run: `pytest tests/test_spotlight.py::TestSpotlightGetVulnerabilities -v`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/spotlight.py tests/test_spotlight.py
git commit -m "feat(spotlight): add spotlight_get_vulnerabilities tool

Fetch full vulnerability records (CVE, host, status, apps) for IDs
returned by spotlight_query_vulnerabilities."
```

---

## Task 4: `spotlight_vulnerabilities_combined` (ergonomic default)

**Files:**
- Modify: `src/crowdstrike_mcp/modules/spotlight.py`
- Modify: `tests/test_spotlight.py`

This is the spec-recommended default — analysts almost always want query+get in one call.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_spotlight.py`:

```python
class TestSpotlightVulnerabilitiesCombined:
    def test_returns_projected_records(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {
                    "id": "vuln-1",
                    "cve": {"id": "CVE-2024-1234", "severity": "CRITICAL", "base_score": 9.8, "exploit_status": 90},
                    "host_info": {"hostname": "web-01", "platform_name": "Linux"},
                    "status": "open",
                    "created_timestamp": "2026-04-01T00:00:00Z",
                    "apps": [{"product_name_version": "openssh 8.0"}],
                }
            ]},
        }
        result = asyncio.run(
            spotlight_vuln_module.spotlight_vulnerabilities_combined(filter="status:'open'")
        )
        assert "CVE-2024-1234" in result
        assert "CRITICAL" in result
        assert "web-01" in result

    def test_default_facets_include_cve_and_host(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_vulnerabilities_combined(filter="status:'open'")
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.call_args.kwargs
        assert kwargs["facet"] == ["cve", "host_info"]

    def test_custom_facets_override_default(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_vulnerabilities_combined(
                filter="status:'open'", facet=["cve", "remediation"]
            )
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.call_args.kwargs
        assert kwargs["facet"] == ["cve", "remediation"]

    def test_requires_filter(self, spotlight_vuln_module):
        result = asyncio.run(spotlight_vuln_module.spotlight_vulnerabilities_combined(filter=""))
        assert "filter" in result.lower()

    def test_caps_limit(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_vulnerabilities_combined(filter="status:'open'", limit=9999)
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.call_args.kwargs
        assert kwargs["limit"] == 500

    def test_handles_api_error(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 403, "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(
            spotlight_vuln_module.spotlight_vulnerabilities_combined(filter="status:'open'")
        )
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_spotlight.py::TestSpotlightVulnerabilitiesCombined -v`
Expected: 6 FAIL.

- [ ] **Step 3: Implement tool + shared projection helper**

At the top of the `SpotlightModule` class (after `register_tools`), add a shared projection helper (used by tasks 4, 5, 6):

```python
    @staticmethod
    def _project_vuln(v: dict) -> dict:
        cve = v.get("cve", {}) or {}
        host = v.get("host_info", {}) or {}
        return {
            "id": v.get("id", ""),
            "cve_id": cve.get("id", ""),
            "severity": cve.get("severity", ""),
            "base_score": cve.get("base_score"),
            "exploit_status": cve.get("exploit_status"),
            "status": v.get("status", ""),
            "hostname": host.get("hostname", ""),
            "platform": host.get("platform_name", ""),
            "created_timestamp": v.get("created_timestamp", ""),
            "apps": [a.get("product_name_version", "") for a in (v.get("apps") or [])[:5]],
            "remediation_ids": (v.get("remediation") or {}).get("ids", []),
        }
```

Add the tool method:

```python
    async def spotlight_vulnerabilities_combined(
        self,
        filter: Annotated[str, "FQL filter expression (required)"],
        limit: Annotated[int, "Max results (default 50, max 500)"] = 50,
        facet: Annotated[Optional[list[str]], "Facets to include (default: cve, host_info)"] = None,
        after: Annotated[Optional[str], "Pagination token"] = None,
        sort: Annotated[Optional[str], "Sort expression"] = None,
    ) -> str:
        """Query + get in one call; the recommended default for vuln lookups."""
        result = self._vulnerabilities_combined(filter=filter, limit=limit, facet=facet, after=after, sort=sort)
        if not result.get("success"):
            return format_text_response(f"Failed to query vulnerabilities: {result.get('error')}", raw=True)
        return self._format_vuln_list(result, header="Spotlight Vulnerabilities (combined)")
```

And shared list formatter (place alongside `_project_vuln`):

```python
    def _format_vuln_list(self, result: dict, header: str) -> str:
        items = result["vulns"]
        lines = [f"{header}: {len(items)} returned (total={result.get('total', 'unknown')})", ""]
        if result.get("after"):
            lines.append(f"Next page token: `{result['after']}`")
            lines.append("")
        if not items:
            lines.append("No vulnerabilities matched the filter.")
        else:
            for i, v in enumerate(items, 1):
                lines.append(
                    f"{i}. **{v['cve_id'] or '(no CVE)'}** [{v['severity']}] score={v['base_score']} "
                    f"exploit={v['exploit_status']}"
                )
                lines.append(f"   Host: {v['hostname']} ({v['platform']}) | Status: {v['status']} | Created: {v['created_timestamp']}")
                if v["apps"]:
                    lines.append(f"   Apps: {'; '.join(a for a in v['apps'] if a)}")
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)
```

Internal helper:

```python
    def _vulnerabilities_combined(self, filter, limit=50, facet=None, after=None, sort=None):
        if not SPOTLIGHT_VULNS_AVAILABLE:
            return {"success": False, "error": "SpotlightVulnerabilities client not available"}
        if not filter:
            return {"success": False, "error": "filter is required"}
        try:
            svc = self._service(SpotlightVulnerabilities)
            kwargs = {
                "filter": filter,
                "limit": min(limit, 500),
                "facet": facet if facet else ["cve", "host_info"],
            }
            if after:
                kwargs["after"] = after
            if sort:
                kwargs["sort"] = sort
            r = svc.query_vulnerabilities_combined(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to query vulnerabilities combined", operation="query_vulnerabilities_combined")}
            body = r.get("body", {})
            resources = body.get("resources", [])
            meta = body.get("meta", {}).get("pagination", {})
            return {
                "success": True,
                "vulns": [self._project_vuln(v) for v in resources],
                "total": meta.get("total", len(resources)),
                "after": meta.get("after"),
            }
        except Exception as e:
            return {"success": False, "error": f"Error in combined query: {e}"}
```

Register tool:

```python
        self._add_tool(
            server,
            self.spotlight_vulnerabilities_combined,
            name="spotlight_vulnerabilities_combined",
            description=(
                "Query vulnerabilities with full record projection in one call. "
                "Default tool for 'show me open CVEs matching X' — returns CVE, "
                "severity, host, status, and affected apps. Prefer this over the "
                "query/get split unless paginating very large result sets."
            ),
        )
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_spotlight.py::TestSpotlightVulnerabilitiesCombined -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/spotlight.py tests/test_spotlight.py
git commit -m "feat(spotlight): add spotlight_vulnerabilities_combined (ergonomic default)

Combined query+get with triage-friendly projection: CVE, severity,
host, status, apps. Default facets: cve + host_info."
```

---

## Task 5: `spotlight_get_remediations` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/spotlight.py`
- Modify: `tests/test_spotlight.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_spotlight.py`:

```python
class TestSpotlightGetRemediations:
    def test_returns_remediation_details(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.get_remediations_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {
                    "id": "rem-1",
                    "title": "Apply patch KB-001",
                    "action": "Install vendor update",
                    "reference": "https://example.com/patch",
                }
            ]},
        }
        result = asyncio.run(
            spotlight_vuln_module.spotlight_get_remediations(ids=["rem-1"])
        )
        assert "Apply patch KB-001" in result
        assert "rem-1" in result

    def test_requires_ids(self, spotlight_vuln_module):
        result = asyncio.run(spotlight_vuln_module.spotlight_get_remediations(ids=[]))
        assert "ids" in result.lower() or "required" in result.lower()

    def test_passes_ids(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.get_remediations_v2.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(spotlight_vuln_module.spotlight_get_remediations(ids=["a", "b"]))
        spotlight_vuln_module.falcon_vulns.get_remediations_v2.assert_called_once_with(ids=["a", "b"])

    def test_handles_api_error(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.get_remediations_v2.return_value = {
            "status_code": 404, "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(spotlight_vuln_module.spotlight_get_remediations(ids=["x"]))
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_spotlight.py::TestSpotlightGetRemediations -v`
Expected: 4 FAIL.

- [ ] **Step 3: Implement tool**

Add to `src/crowdstrike_mcp/modules/spotlight.py`:

```python
    async def spotlight_get_remediations(
        self,
        ids: Annotated[list[str], "Remediation IDs (from a vulnerability record's remediation.ids list)"],
    ) -> str:
        """Fetch remediation instructions by ID."""
        result = self._get_remediations(ids)
        if not result.get("success"):
            return format_text_response(f"Failed to get remediations: {result.get('error')}", raw=True)
        resources = result["resources"]
        lines = [f"Spotlight Remediations: {len(resources)} records", ""]
        if not resources:
            lines.append("No remediations returned.")
        else:
            for i, rem in enumerate(resources, 1):
                lines.append(f"{i}. **{rem.get('title', 'Untitled')}** ({rem.get('id', 'N/A')})")
                if rem.get("action"):
                    lines.append(f"   Action: {rem['action']}")
                if rem.get("reference"):
                    lines.append(f"   Reference: {rem['reference']}")
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)
```

Internal helper:

```python
    def _get_remediations(self, ids):
        if not SPOTLIGHT_VULNS_AVAILABLE:
            return {"success": False, "error": "SpotlightVulnerabilities client not available"}
        if not ids:
            return {"success": False, "error": "ids list is required"}
        try:
            svc = self._service(SpotlightVulnerabilities)
            r = svc.get_remediations_v2(ids=ids)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to get remediations", operation="get_remediations_v2")}
            return {"success": True, "resources": r.get("body", {}).get("resources", [])}
        except Exception as e:
            return {"success": False, "error": f"Error getting remediations: {e}"}
```

Register:

```python
        self._add_tool(
            server,
            self.spotlight_get_remediations,
            name="spotlight_get_remediations",
            description=(
                "Get remediation instructions (vendor patches, config changes) "
                "by remediation ID. Pair with vulnerability records returned by "
                "spotlight_vulnerabilities_combined."
            ),
        )
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_spotlight.py::TestSpotlightGetRemediations -v`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/spotlight.py tests/test_spotlight.py
git commit -m "feat(spotlight): add spotlight_get_remediations tool

Wraps get_remediations_v2 for patch/config guidance keyed by
remediation IDs from vulnerability records."
```

---

## Task 6: `spotlight_host_vulns` composite helper

**Files:**
- Modify: `src/crowdstrike_mcp/modules/spotlight.py`
- Modify: `tests/test_spotlight.py`

Per the spec's open question #1, this caller wants the composite helper: given a device_id (and optionally a hostname, which gets resolved through `Hosts` → `aid`), return all open vulnerabilities. Keep it simple: **device_id only in v1** (hostname resolution is a Hosts-module concern; the agent can chain `host_lookup` first).

- [ ] **Step 1: Write failing tests**

Append to `tests/test_spotlight.py`:

```python
class TestSpotlightHostVulns:
    def test_builds_aid_filter_with_open_status(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(spotlight_vuln_module.spotlight_host_vulns(device_id="abc123"))
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.call_args.kwargs
        assert "aid:'abc123'" in kwargs["filter"]
        assert "status:'open'" in kwargs["filter"]

    def test_allows_override_status(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_host_vulns(
                device_id="abc123", include_closed=True
            )
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.call_args.kwargs
        assert "status:'open'" not in kwargs["filter"]
        assert "aid:'abc123'" in kwargs["filter"]

    def test_requires_device_id(self, spotlight_vuln_module):
        result = asyncio.run(spotlight_vuln_module.spotlight_host_vulns(device_id=""))
        assert "device_id" in result.lower() or "required" in result.lower()

    def test_applies_severity_floor(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_host_vulns(
                device_id="abc123", min_severity="HIGH"
            )
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.call_args.kwargs
        assert "cve.severity" in kwargs["filter"]
        # severity floor must include HIGH *and* everything above it
        assert "HIGH" in kwargs["filter"]
        assert "CRITICAL" in kwargs["filter"]

    def test_cve_id_param_adds_filter(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(
            spotlight_vuln_module.spotlight_host_vulns(
                device_id="abc123", cve_id="CVE-2024-1234"
            )
        )
        kwargs = spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.call_args.kwargs
        assert "aid:'abc123'" in kwargs["filter"]
        assert "cve.id:'CVE-2024-1234'" in kwargs["filter"]

    def test_returns_formatted_list(self, spotlight_vuln_module):
        spotlight_vuln_module.falcon_vulns.query_vulnerabilities_combined.return_value = {
            "status_code": 200,
            "body": {"resources": [
                {
                    "id": "v-1",
                    "cve": {"id": "CVE-2024-1", "severity": "CRITICAL", "base_score": 9.8},
                    "host_info": {"hostname": "web-01", "platform_name": "Linux"},
                    "status": "open",
                }
            ]},
        }
        result = asyncio.run(spotlight_vuln_module.spotlight_host_vulns(device_id="abc123"))
        assert "CVE-2024-1" in result
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_spotlight.py::TestSpotlightHostVulns -v`
Expected: 6 FAIL.

- [ ] **Step 3: Implement composite**

Add to `src/crowdstrike_mcp/modules/spotlight.py`:

```python
    async def spotlight_host_vulns(
        self,
        device_id: Annotated[str, "Falcon device/agent ID (aid) to list vulns for"],
        cve_id: Annotated[Optional[str], "Filter to a single CVE (e.g. 'CVE-2024-1234'). Use for 'is this host affected by X?' triage."] = None,
        include_closed: Annotated[bool, "If True, include closed/remediated vulns (default False)"] = False,
        min_severity: Annotated[Optional[str], "Minimum severity: CRITICAL | HIGH | MEDIUM | LOW"] = None,
        limit: Annotated[int, "Max results (default 50, max 500)"] = 50,
    ) -> str:
        """Triage shortcut: all (open) vulnerabilities for a single host."""
        if not device_id:
            return format_text_response("Failed: device_id is required", raw=True)

        filter_parts = [f"aid:'{device_id}'"]
        if cve_id:
            filter_parts.append(f"cve.id:'{cve_id}'")
        if not include_closed:
            filter_parts.append("status:'open'")
        if min_severity:
            severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if min_severity.upper() in severity_order:
                idx = severity_order.index(min_severity.upper())
                allowed = severity_order[idx:]
                filter_parts.append(f"cve.severity:[{','.join(repr(s) for s in allowed)}]")

        filter_str = "+".join(filter_parts)
        result = self._vulnerabilities_combined(filter=filter_str, limit=limit)
        if not result.get("success"):
            return format_text_response(f"Failed to get host vulnerabilities: {result.get('error')}", raw=True)
        return self._format_vuln_list(result, header=f"Vulnerabilities on host {device_id}")
```

Register:

```python
        self._add_tool(
            server,
            self.spotlight_host_vulns,
            name="spotlight_host_vulns",
            description=(
                "Triage shortcut: list open vulnerabilities on a specific host by "
                "device_id (aid). Pre-filters status:'open' unless include_closed=True. "
                "Optional min_severity floor. Use this for 'is this host vulnerable?' "
                "during live alert triage."
            ),
        )
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_spotlight.py::TestSpotlightHostVulns -v`
Expected: 6 PASS.

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass — no regressions.

- [ ] **Step 6: Commit**

```bash
git add src/crowdstrike_mcp/modules/spotlight.py tests/test_spotlight.py
git commit -m "feat(spotlight): add spotlight_host_vulns triage shortcut

Given a device_id, returns open vulns with optional severity floor.
Answers 'is this host vulnerable?' in one call during live triage."
```

---

## Task 7: Register FQL guide resource + README update

**Files:**
- Modify: `src/crowdstrike_mcp/modules/spotlight.py` (add `register_resources`)
- Modify: `README.md`

- [ ] **Step 1: Write failing test for resource registration**

Append to `tests/test_spotlight.py`:

```python
class TestSpotlightResources:
    def test_registers_vuln_fql_resource(self, spotlight_vuln_module):
        server = MagicMock()
        server.resource.return_value = lambda fn: fn
        spotlight_vuln_module.register_resources(server)
        assert "falcon://fql/spotlight-vulnerabilities" in spotlight_vuln_module.resources
```

- [ ] **Step 2: Run test**

Run: `pytest tests/test_spotlight.py::TestSpotlightResources -v`
Expected: 1 FAIL (no `register_resources` override).

- [ ] **Step 3: Implement `register_resources`**

Add to `SpotlightModule` (after `__init__`, before `register_tools`):

```python
    def register_resources(self, server: FastMCP) -> None:
        from crowdstrike_mcp.resources.fql_guides import SPOTLIGHT_VULN_FQL

        def _spotlight_vuln_fql():
            return SPOTLIGHT_VULN_FQL

        server.resource(
            "falcon://fql/spotlight-vulnerabilities",
            name="Spotlight Vulnerabilities FQL Syntax",
            description="Documentation: FQL filter syntax for Spotlight vulnerability queries",
        )(_spotlight_vuln_fql)
        self.resources.append("falcon://fql/spotlight-vulnerabilities")
```

- [ ] **Step 4: Run test**

Run: `pytest tests/test_spotlight.py::TestSpotlightResources -v`
Expected: 1 PASS.

- [ ] **Step 5: Update README tool count + table**

First, determine the current tool count:

```bash
grep -n "tools across" README.md
```

Bump that number by 5 (four new `spotlight_*` tools + `spotlight_host_vulns`). Then locate the tools table in `README.md` and add rows for the 5 new tools under the Spotlight section (or create one). Match the existing table's column layout exactly — do not invent new columns.

- [ ] **Step 6: Run full test suite one last time**

Run: `pytest tests/ -v`
Expected: All tests pass.

- [ ] **Step 7: Smoke-test the server boots**

Run: `python -m crowdstrike_mcp --help`
Expected: help text prints, no import errors.

- [ ] **Step 8: Final commit**

```bash
git add src/crowdstrike_mcp/modules/spotlight.py tests/test_spotlight.py README.md
git commit -m "feat(spotlight): register FQL guide resource + docs

Expose falcon://fql/spotlight-vulnerabilities resource for self-service
filter syntax. Update README tool count and tools table."
```

---

## Verification Checklist

Before declaring done:

- [ ] `pytest tests/ -v` — all pass
- [ ] `ruff check src/ tests/` — no violations
- [ ] `python -m crowdstrike_mcp --help` — boots clean
- [ ] All 5 new tools appear in `SpotlightModule.tools` after `register_tools()`
- [ ] Scope lookup works for all 4 new operation names (`get_required_scopes` returns the right scope)
- [ ] `falcon://fql/spotlight-vulnerabilities` resource is registered
- [ ] No changes to the existing `spotlight_supported_evaluations` tool — it must still work identically

## Out of Scope (Deferred)

- **Unlicensed-tenant UX.** Unlicensed Spotlight returns 403; `format_api_error` already appends the required scope (`spotlight-vulnerabilities:read`) via `get_required_scopes`. That is the intended behavior — no separate license-detection path in v1.
- **Hostname → device_id resolution in `spotlight_host_vulns`.** Agent chains `host_lookup` first; keeps this module's falconpy surface limited to `SpotlightVulnerabilities`.
- **Auto-expanding remediation details in `spotlight_vulnerabilities_combined`.** Add the `remediation` facet by default only if usage patterns show it's always wanted; today it's opt-in via `facet=["cve", "host_info", "remediation"]`.
- **CLI-level pagination helper.** `after` token surfaces to the caller; no auto-loop across pages in v1.
