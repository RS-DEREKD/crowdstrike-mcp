# FR 01: Identity Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a single read-only MCP tool, `identity_investigate_entity`, that answers "does Falcon already consider this user identity-compromised, and why?" in one call. The tool wraps CrowdStrike Identity Protection's GraphQL endpoint to resolve entities by name / email / IP / domain / entityId, then runs any combination of 4 investigations: entity_details, risk_assessment, timeline_analysis, relationship_analysis.

**Architecture:** New module `src/crowdstrike_mcp/modules/idp.py` — ported from CrowdStrike's official `falcon-mcp` reference implementation (`falcon_mcp_idp.py`, MIT-licensed, already vendored in the repo root). Unlike our other modules, this one wraps **one** falconpy class (`IdentityProtection`) and **one** falconpy method (`graphql()`); all tool surface is composed inside the module. REST-based sensor / policy-rule paths in the original FR spec are explicitly replaced — the REST `query_sensors` / `get_sensor_details` endpoints operate on *endpoint-sensor devices*, not identity entities with risk scores. Identity risk lives only behind GraphQL.

**Tech Stack:** Python 3.11+, `crowdstrike-falconpy>=1.6.1`, `mcp>=1.12.1`, FastMCP, pytest.

**Spec:** `docs/FRs/01-identity-protection.md` (expanded by this plan — see note on REST vs GraphQL above).

**Supersedes:** any prior FR 01 plan targeting `query_sensors` / `get_sensor_details`. Those endpoints do not answer the triage question.

---

## Attribution

This module is a port of the `IdpModule` from CrowdStrike's official `falcon-mcp`
(https://github.com/CrowdStrike/falcon-mcp, MIT-licensed). The vendored reference file
`falcon_mcp_idp.py` sits at the repo root and must **remain untracked** (do not commit it;
add to `.gitignore` if not already ignored — check with `git status` during Task 1).

**Deliverables for attribution:**

1. **New file** `THIRD_PARTY_NOTICES.md` at repo root — created in Task 1. Content:

   ```markdown
   # Third-Party Notices

   This project incorporates components from the following third-party software.

   ## falcon-mcp (CrowdStrike)

   - Source: https://github.com/CrowdStrike/falcon-mcp
   - License: MIT
   - Copyright (c) 2024 CrowdStrike Holdings, Inc.

   The module `src/crowdstrike_mcp/modules/idp.py` is a port and
   adaptation of `falcon_mcp/modules/idp.py` from that project, translated to this
   repository's tool-registration, typing, and error-handling conventions. Notable
   differences from the upstream version: pydantic `Field` annotations replaced with
   `Annotated[Type, "description"]`; `_base_query_api_call` helper replaced with direct
   falconpy `graphql()` calls + our `format_api_error`; `_add_tool` signature adapted
   to our `tier="read"` pattern; output formatting via `format_text_response(..., raw=True)`.

   Full upstream license text:

   MIT License

   Copyright (c) 2024 CrowdStrike Holdings, Inc.

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to do so, subject to the
   following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND...
   ```

2. **Module docstring header** in `idp.py`:

   ```python
   """
   Identity Protection Module — CrowdStrike Falcon Identity Protection (IDP) via GraphQL.

   Tool:
     identity_investigate_entity — One-call entity investigation:
        resolve identifier(s) → run entity_details, risk_assessment, timeline_analysis,
        and/or relationship_analysis → synthesize single response.

   Ported from CrowdStrike's falcon-mcp (https://github.com/CrowdStrike/falcon-mcp,
   MIT-licensed). See THIRD_PARTY_NOTICES.md at the repo root. Adapted to this
   project's tool/typing/error conventions: Annotated[Type, "desc"] instead of
   pydantic.Field, format_api_error for 403 scope guidance, single-tool registration.
   """
   ```

3. **README** already contains a "License" / "Acknowledgements" footer (or gets one in Task 8) — add a line referencing the notices file.

---

## Tool Surface

One tool: **`identity_investigate_entity`** (registered with `tier="read"`).

**Rationale for single composed tool** (FR 01 open question #1): our FR explicitly prefers composed-for-triage over query/get split. The upstream `falcon-mcp` made the same call for the same reason.

### Parameter schema

All parameters use `Annotated[Type, "description"]` (our repo's convention). Defaults match upstream.

| Param | Type | Default | Notes |
|---|---|---|---|
| `username` | `str \| None` | `None` | **Our addition** — ergonomic shortcut for the 80% case ("does Falcon consider this user compromised?"). Merged into `entity_names` before resolution. De-duplicated if already present. |
| `quick_triage` | `bool` | `False` | **Our addition** — one-shot triage mode. Forces `investigation_types=["entity_details", "risk_assessment"]`, `include_associations=False`, `include_accounts=False`, `include_incidents=False`, `limit=5`. Overrides any explicit values for those params. |
| `entity_ids` | `list[str] \| None` | `None` | Direct entity IDs; bypass resolution step. |
| `entity_names` | `list[str] \| None` | `None` | Display names. AND-combined with other identifiers. |
| `email_addresses` | `list[str] \| None` | `None` | Forces `types: [USER]`. |
| `ip_addresses` | `list[str] \| None` | `None` | Forces `types: [ENDPOINT]`. USER criteria take precedence on conflict — see Task 2. |
| `domain_names` | `list[str] \| None` | `None` | Adds `domains:` GraphQL filter. |
| `investigation_types` | `list[str]` | `["entity_details"]` | Any subset of: `entity_details`, `risk_assessment`, `timeline_analysis`, `relationship_analysis`. |
| `timeline_start_time` | `str \| None` | `None` | ISO-8601. Only used when `timeline_analysis` included. |
| `timeline_end_time` | `str \| None` | `None` | ISO-8601. Only used when `timeline_analysis` included. |
| `timeline_event_types` | `list[str] \| None` | `None` | Any of: `ACTIVITY`, `NOTIFICATION`, `THREAT`, `ENTITY`, `AUDIT`, `POLICY`, `SYSTEM`. |
| `relationship_depth` | `int` | `2` | 1–3 (validated). Only used when `relationship_analysis` included. |
| `limit` | `int` | `10` | 1–200 (validated). Caps all entity/timeline/relationship page sizes. |
| `include_associations` | `bool` | `True` | Include entity associations in details. |
| `include_accounts` | `bool` | `True` | Include AD/SSO/Azure account descriptors in details. |
| `include_incidents` | `bool` | `True` | Include open security incidents in details. |
| `include_raw` | `bool` | `False` | **Our addition** — when True, append the full raw GraphQL JSON to the response for deep inspection; default off because `relationship_analysis` at depth=3 can be large. |

### Output envelope (our flavor, via `format_text_response(raw=True)`)

A human-readable header with:

- Investigation summary block (entity count, resolved IDs, investigation types run, timestamp, status).
- One formatted section per requested investigation, showing a compact projection (top-N per entity).
- Cross-investigation insights (multi-entity risk-factor overlap, timeline↔relationship correlation) when applicable.
- Optional `<details>`-wrapped JSON fenced block with the full raw structure when `include_raw=True`.

Internal plumbing (the `_investigate_entity` helper) returns the structured `{"success", ...}` dict exactly like upstream, and the public async tool formats from that.

---

## Scope Mappings

The FR's listed scopes for the Identity Protection workflow are 5:

| Scope | Why required |
|---|---|
| `identity-protection-assessment:read` | Risk score / risk factor fields on `entities()`. |
| `identity-protection-detections:read` | Reading detections, entity incidents. |
| `identity-protection-entities:read` | The `entities()` query itself. |
| `identity-protection-timeline:read` | The `timeline()` query. |
| `identity-protection-graphql:write` | **API quirk** — the GraphQL endpoint is a POST; CrowdStrike's scoping model requires a `:write` scope on the transport even though this tool only executes read queries. |

Because the endpoint is exactly one operation (`post_graphql`), we register **one** operation-ID entry that lists all 5. The tool is still registered `tier="read"` (semantically read-only from analyst POV) — the `:write` scope is a platform requirement, not a write intent.

**In `src/crowdstrike_mcp/common/api_scopes.py`, insert after the Spotlight block:**

```python
# Identity Protection
# NOTE: post_graphql is a read-only query in this module, but CrowdStrike's API
# surface requires identity-protection-graphql:write for ALL GraphQL calls even
# when the query is strictly read-only. The tool is still tier="read".
"post_graphql": [
    "identity-protection-assessment:read",
    "identity-protection-detections:read",
    "identity-protection-entities:read",
    "identity-protection-timeline:read",
    "identity-protection-graphql:write",
],
```

The `format_api_error` helper automatically prints all 5 scopes on a 403.

---

## File Structure

**Modify:**
- `src/crowdstrike_mcp/common/api_scopes.py` — add `post_graphql` entry.
- `tests/test_smoke_tools_list.py` — add `identity_investigate_entity` to `EXPECTED_READ_TOOLS`; add `IdentityProtection` patch.
- `README.md` — bump tool count from 51 → 52, add Identity Protection section.

**Create:**
- `src/crowdstrike_mcp/modules/idp.py` — the module.
- `tests/test_idp.py` — test file.
- `THIRD_PARTY_NOTICES.md` (repo root).

**Do not modify:** nothing else. No new FQL guide (this tool doesn't use FQL). No new common/ helper (everything stays in the module — matches upstream containment).

---

## Conventions to Match (non-obvious)

Observed from `spotlight.py`, `cloud_security.py`, and `hosts.py`:

1. **Falconpy import guard** — mirror `SPOTLIGHT_VULNS_AVAILABLE`:
   ```python
   try:
       from falconpy import IdentityProtection
       IDENTITY_PROTECTION_AVAILABLE = True
   except ImportError:
       IDENTITY_PROTECTION_AVAILABLE = False
   ```
2. **Public async tool → internal sync helper** returning `{"success": bool, ...}`.
3. **`format_text_response(..., raw=True)`** envelope.
4. **`format_api_error(response, context, operation="post_graphql")`** on non-2xx.
5. **`_service(cls)` pattern** — never instantiate falconpy directly; always `self._service(IdentityProtection)`.
6. **Test fixture** — patch `crowdstrike_mcp.modules.idp.IdentityProtection`, set `module._service = lambda cls: mock`, expose as `module.falcon`.
7. **GraphQL call shape** — upstream uses `self.falcon.graphql(body={"query": "..."})`. Our direct equivalent (falconpy signature, confirmed from `inspect.getsource(IdentityProtection.graphql)`):

   ```python
   response = self._service(IdentityProtection).graphql(body={"query": query_str})
   # returns: {"status_code": 200, "body": {"data": {...}, "errors": [...]}}
   ```

   Operation ID for scope lookup: `"post_graphql"` (confirmed via `falconpy._endpoint._identity_protection._identity_protection_endpoints`).

8. **GraphQL error shape** — GraphQL returns HTTP 200 even when the query has a semantic error; those errors live in `body["errors"]` as a non-empty list. We must treat non-empty `body["errors"]` as failure regardless of `status_code`. Pure transport errors (auth failure, 403, 5xx) still come back via `status_code`. Helper `_graphql_call()` — defined in Task 2 — handles both paths in one place.

---

## Task 1: Module skeleton, scope mapping, third-party notices

**Files:**
- Create: `THIRD_PARTY_NOTICES.md`
- Modify: `src/crowdstrike_mcp/common/api_scopes.py`
- Create: `src/crowdstrike_mcp/modules/idp.py` (skeleton only — class, import guard, empty `register_tools`)
- Create: `tests/test_idp.py` (fixture + scope test)

- [ ] **Step 1: Write failing test for scope mapping and module import**

`tests/test_idp.py`:

```python
"""Tests for Identity Protection module."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def idp_module(mock_client):
    """Create IDPModule with mocked IdentityProtection falconpy class."""
    with patch("crowdstrike_mcp.modules.idp.IdentityProtection") as MockIDP:
        mock_idp = MagicMock()
        MockIDP.return_value = mock_idp
        from crowdstrike_mcp.modules.idp import IDPModule

        module = IDPModule(mock_client)
        module._service = lambda cls: mock_idp
        module.falcon = mock_idp  # tests configure via module.falcon.graphql.return_value
        return module


class TestIdentityProtectionScopes:
    """Scope mapping for post_graphql operation exists in api_scopes."""

    def test_post_graphql_requires_all_five_scopes(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        scopes = get_required_scopes("post_graphql")
        assert "identity-protection-assessment:read" in scopes
        assert "identity-protection-detections:read" in scopes
        assert "identity-protection-entities:read" in scopes
        assert "identity-protection-timeline:read" in scopes
        assert "identity-protection-graphql:write" in scopes
        assert len(scopes) == 5


class TestIDPModuleScaffolding:
    """Module imports cleanly, registers zero tools until the public tool is added."""

    def test_module_instantiates(self, idp_module):
        assert idp_module is not None

    def test_module_has_falcon_client(self, idp_module):
        assert idp_module.falcon is not None
```

- [ ] **Step 2: Run tests — confirm they fail**

`pytest tests/test_idp.py -v`
Expected: `TestIdentityProtectionScopes` fails (scopes return `[]`); module-import tests fail (module doesn't exist).

- [ ] **Step 3: Add scope mapping**

Edit `src/crowdstrike_mcp/common/api_scopes.py`. After the Spotlight Vulnerabilities block, before the CAO Hunting block, insert:

```python
    # Identity Protection
    # NOTE: post_graphql is a read-only query in this module, but CrowdStrike's
    # API surface requires identity-protection-graphql:write for ALL GraphQL
    # calls even when the query is strictly read-only. Tool stays tier="read".
    "post_graphql": [
        "identity-protection-assessment:read",
        "identity-protection-detections:read",
        "identity-protection-entities:read",
        "identity-protection-timeline:read",
        "identity-protection-graphql:write",
    ],
```

- [ ] **Step 4: Create `THIRD_PARTY_NOTICES.md`** at repo root (content from Attribution section above).

- [ ] **Step 5: Create module skeleton `src/crowdstrike_mcp/modules/idp.py`:**

```python
"""
Identity Protection Module — CrowdStrike Falcon Identity Protection (IDP) via GraphQL.

Tool:
  identity_investigate_entity — One-call entity investigation:
     resolve identifier(s) → run entity_details, risk_assessment, timeline_analysis,
     and/or relationship_analysis → synthesize single response.

Ported from CrowdStrike's falcon-mcp (https://github.com/CrowdStrike/falcon-mcp,
MIT-licensed). See THIRD_PARTY_NOTICES.md at the repo root.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Any, Optional

try:
    from falconpy import IdentityProtection

    IDENTITY_PROTECTION_AVAILABLE = True
except ImportError:
    IDENTITY_PROTECTION_AVAILABLE = False

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


# Allowed enum values (mirrored from upstream + CrowdStrike GraphQL schema)
VALID_INVESTIGATION_TYPES = {
    "entity_details",
    "risk_assessment",
    "timeline_analysis",
    "relationship_analysis",
}
VALID_TIMELINE_EVENT_TYPES = {
    "ACTIVITY", "NOTIFICATION", "THREAT",
    "ENTITY", "AUDIT", "POLICY", "SYSTEM",
}


class IDPModule(BaseModule):
    """Falcon Identity Protection tools (GraphQL-backed)."""

    def __init__(self, client):
        super().__init__(client)
        if not IDENTITY_PROTECTION_AVAILABLE:
            raise ImportError(
                "IdentityProtection service class not available. "
                "Ensure crowdstrike-falconpy >= 1.6.1 is installed."
            )
        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        # Tool registered in Task 7.
        pass
```

- [ ] **Step 6: Run tests — confirm scope + scaffolding tests pass**

`pytest tests/test_idp.py -v`
Expected: 3 PASS.

- [ ] **Step 7: Sanity — all existing tests still pass**

`pytest tests/ -v`
Expected: no regressions. Note: the smoke-test `test_no_unexpected_tools` still passes because no tool has been registered yet.

- [ ] **Step 8: Commit**

```bash
git add src/crowdstrike_mcp/modules/idp.py \
        src/crowdstrike_mcp/common/api_scopes.py \
        tests/test_idp.py \
        THIRD_PARTY_NOTICES.md
git commit -m "feat(idp): scaffold Identity Protection module

Add scope mapping for post_graphql (5 scopes incl. graphql:write quirk),
module skeleton with IdentityProtection import guard, and third-party
notices for the upstream falcon-mcp port."
```

---

## Task 2: Entity resolution (`_resolve_entities` + GraphQL call helper)

Foundation for every investigation type. Also defines the central `_graphql_call()` helper.

**Files:**
- Modify: `src/crowdstrike_mcp/modules/idp.py`
- Modify: `tests/test_idp.py`

- [ ] **Step 1: Write failing tests**

```python
class TestGraphqlCallHelper:
    """_graphql_call handles both transport errors and GraphQL-level errors."""

    def test_200_with_data_returns_data(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [{"entityId": "e1"}]}}},
        }
        result = idp_module._graphql_call("query { x }", context="test")
        assert result["success"] is True
        assert result["data"]["entities"]["nodes"][0]["entityId"] == "e1"

    def test_non_200_returns_error_with_operation(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._graphql_call("query { x }", context="resolve")
        assert result["success"] is False
        # exact-match substrings that would break if someone dropped the operation name
        assert "HTTP 403" in result["error"]
        assert "resolve" in result["error"]

    def test_200_but_graphql_errors_returns_error(self, idp_module):
        """GraphQL returns 200 with a non-empty errors array on semantic failure."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {
                "data": None,
                "errors": [{"message": "Field entityId does not exist on type Foo"}],
            },
        }
        result = idp_module._graphql_call("query { x }", context="bad-field")
        assert result["success"] is False
        assert "Field entityId" in result["error"]

    def test_exception_in_falconpy_returns_error(self, idp_module):
        idp_module.falcon.graphql.side_effect = RuntimeError("connection dropped")
        result = idp_module._graphql_call("query { x }", context="boom")
        assert result["success"] is False
        assert "connection dropped" in result["error"]


class TestResolveEntities:
    """_resolve_entities builds correct GraphQL and returns entity ids."""

    def test_entity_ids_passthrough(self, idp_module):
        result = idp_module._resolve_entities(
            {"entity_ids": ["e1", "e2"], "limit": 10}
        )
        assert isinstance(result, list)
        assert set(result) == {"e1", "e2"}
        # No GraphQL call needed when only entity_ids are given
        idp_module.falcon.graphql.assert_not_called()

    def test_entity_names_triggers_graphql(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [{"entityId": "e-resolved"}]}}},
        }
        result = idp_module._resolve_entities(
            {"entity_names": ["Administrator"], "limit": 10}
        )
        assert result == ["e-resolved"]
        call = idp_module.falcon.graphql.call_args
        query = call.kwargs["body"]["query"]
        # AND of primaryDisplayNames filter present
        assert 'primaryDisplayNames:' in query
        assert '"Administrator"' in query

    def test_email_addresses_forces_user_type(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._resolve_entities(
            {"email_addresses": ["alice@corp.local"], "limit": 10}
        )
        query = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'secondaryDisplayNames:' in query
        assert 'types: [USER]' in query

    def test_ip_addresses_forces_endpoint_type(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._resolve_entities(
            {"ip_addresses": ["10.0.0.5"], "limit": 10}
        )
        query = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'types: [ENDPOINT]' in query
        assert '"10.0.0.5"' in query

    def test_user_criteria_wins_on_user_endpoint_conflict(self, idp_module):
        """When both email and IP are supplied, IPs are dropped (USER prioritised)."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._resolve_entities(
            {
                "email_addresses": ["alice@corp.local"],
                "ip_addresses": ["10.0.0.5"],
                "limit": 10,
            }
        )
        query = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'types: [USER]' in query
        assert 'types: [ENDPOINT]' not in query
        assert '"10.0.0.5"' not in query

    def test_domain_filter_adds_accounts_field(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._resolve_entities(
            {"domain_names": ["CORP.LOCAL"], "limit": 10}
        )
        query = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'domains:' in query
        assert '"CORP.LOCAL"' in query
        assert 'ActiveDirectoryAccountDescriptor' in query

    def test_returns_unique_ids(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {"entityId": "dup"}, {"entityId": "dup"}, {"entityId": "uniq"}
            ]}}},
        }
        result = idp_module._resolve_entities(
            {"entity_ids": ["dup"], "entity_names": ["X"], "limit": 10}
        )
        assert sorted(result) == ["dup", "uniq"]

    def test_graphql_error_bubbles_up_as_dict(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._resolve_entities(
            {"entity_names": ["Admin"], "limit": 10}
        )
        assert isinstance(result, dict)
        assert "error" in result
        assert "HTTP 403" in result["error"]
```

- [ ] **Step 2: Run tests — expect 12 FAIL**

- [ ] **Step 3: Implement `_graphql_call` + `_resolve_entities` + filter helpers**

Append to `idp.py` (inside class):

```python
    # --------------------------------------------------
    # Core GraphQL helper — single place that talks to falconpy
    # --------------------------------------------------
    def _graphql_call(self, query: str, context: str) -> dict[str, Any]:
        """Run a GraphQL query. Handles transport + GraphQL-level errors.

        Returns:
            On success: {"success": True, "data": <top-level data dict>}
            On failure: {"success": False, "error": "<message>"}
        """
        try:
            svc = self._service(IdentityProtection)
            response = svc.graphql(body={"query": query})
        except Exception as exc:
            return {"success": False, "error": f"{context}: {exc}"}

        status = response.get("status_code", 0)
        body = response.get("body", {}) or {}

        # Transport-level failure (non-2xx) — defer to format_api_error for scope msg
        if not (200 <= status < 300):
            return {
                "success": False,
                "error": format_api_error(response, context=context, operation="post_graphql"),
            }

        # GraphQL-level errors can arrive on HTTP 200. Treat non-empty errors[] as failure.
        gql_errors = body.get("errors")
        if isinstance(gql_errors, list) and gql_errors:
            msgs = [
                e.get("message", str(e)) if isinstance(e, dict) else str(e)
                for e in gql_errors
            ]
            return {"success": False, "error": f"{context}: GraphQL error: {'; '.join(msgs)}"}

        return {"success": True, "data": body.get("data", {}) or {}}

    # NOTE: do NOT add a "sanitize" helper that strips backslashes/quotes.
    # `json.dumps()` already escapes GraphQL-unsafe characters correctly, and
    # stripping them silently corrupts legitimate AD values (e.g. `DOMAIN\\user`).

    # --------------------------------------------------
    # Entity resolution
    # --------------------------------------------------
    def _resolve_entities(self, identifiers: dict[str, Any]) -> list[str] | dict[str, Any]:
        """Resolve various identifier kinds to entity IDs via a single AND-combined
        GraphQL query. entity_ids pass through unchanged.

        Returns:
            list[str]: resolved entity ids (de-duplicated) on success
            dict: {"error": "..."} on GraphQL/transport failure
        """
        resolved_ids: list[str] = []

        # Direct entity IDs — no resolution needed
        direct_ids = identifiers.get("entity_ids")
        if direct_ids and isinstance(direct_ids, list):
            resolved_ids.extend(direct_ids)

        emails = identifiers.get("email_addresses")
        ips = identifiers.get("ip_addresses")
        has_user = bool(emails)
        has_endpoint = bool(ips)

        # USER and ENDPOINT types are mutually exclusive in a single `entities()` query;
        # prioritise USER because the triage workflow centres on user identity risk.
        if has_user and has_endpoint:
            self._log("WARN: email + IP supplied; dropping IP filter (USER wins)")
            ips = None
            has_endpoint = False

        query_filters: list[str] = []
        query_fields: set[str] = set()

        self._add_name_filter(identifiers.get("entity_names"), query_fields, query_filters)
        self._add_email_filter(emails, query_fields, query_filters)
        self._add_ip_filter(ips, has_user, query_fields, query_filters)
        domain_names = self._add_domain_filter(identifiers.get("domain_names"), query_fields, query_filters)

        if query_filters:
            limit = identifiers.get("limit") or 50
            fields_string = "\n                ".join(sorted(query_fields))
            if domain_names:
                fields_string += """
                accounts {
                    ... on ActiveDirectoryAccountDescriptor {
                        domain
                        samAccountName
                    }
                }"""
            query = f"""
            query {{
                entities({", ".join(query_filters)}, first: {limit}) {{
                    nodes {{
                        entityId
                        {fields_string}
                    }}
                }}
            }}
            """
            result = self._graphql_call(query, context="Failed to resolve entities")
            if not result.get("success"):
                return {"error": result["error"]}
            nodes = result["data"].get("entities", {}).get("nodes", [])
            if isinstance(nodes, list):
                resolved_ids.extend(n.get("entityId") for n in nodes if isinstance(n, dict) and n.get("entityId"))

        return sorted({i for i in resolved_ids if i})

    def _add_name_filter(self, names, fields, filters):
        if names and isinstance(names, list):
            vals = json.dumps(list(names))
            filters.append(f"primaryDisplayNames: {vals}")
            fields.add("primaryDisplayName")

    def _add_email_filter(self, emails, fields, filters):
        if emails and isinstance(emails, list):
            vals = json.dumps(list(emails))
            filters.append(f"secondaryDisplayNames: {vals}")
            filters.append("types: [USER]")
            fields.add("primaryDisplayName")
            fields.add("secondaryDisplayName")

    def _add_ip_filter(self, ips, has_user, fields, filters):
        if ips and isinstance(ips, list) and not has_user:
            vals = json.dumps(list(ips))
            filters.append(f"primaryDisplayNames: {vals}")
            filters.append("types: [ENDPOINT]")
            fields.add("primaryDisplayName")

    def _add_domain_filter(self, domains, fields, filters):
        if domains and isinstance(domains, list):
            vals = json.dumps(list(domains))
            filters.append(f"domains: {vals}")
            fields.add("primaryDisplayName")
            fields.add("secondaryDisplayName")
            return domains
        return None
```

- [ ] **Step 4: Run tests — expect 12 PASS**

`pytest tests/test_idp.py -v`

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/idp.py tests/test_idp.py
git commit -m "feat(idp): add GraphQL call helper and entity resolution

Centralises all falconpy.graphql() traffic through _graphql_call, which
handles both transport and GraphQL-level errors (non-empty errors[] on
HTTP 200). _resolve_entities composes identifier kinds via AND, with
USER-precedence over ENDPOINT on conflicts."
```

---

## Task 3: `entity_details` investigation

**Files:**
- Modify: `src/crowdstrike_mcp/modules/idp.py`
- Modify: `tests/test_idp.py`

- [ ] **Step 1: Write failing tests**

```python
class TestEntityDetailsInvestigation:
    def test_builds_query_with_all_includes_on(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {
                    "entityId": "e1",
                    "primaryDisplayName": "Administrator",
                    "type": "USER",
                    "riskScore": 75,
                    "riskScoreSeverity": "HIGH",
                    "riskFactors": [{"type": "STALE_ACCOUNT", "severity": "HIGH"}],
                    "accounts": [{"domain": "CORP", "samAccountName": "admin"}],
                }
            ]}}},
        }
        result = idp_module._get_entity_details_batch(
            ["e1"],
            {"include_associations": True, "include_accounts": True, "include_incidents": True},
        )
        assert result["entity_count"] == 1
        assert result["entities"][0]["entityId"] == "e1"
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        # All include-blocks present
        assert "riskFactors" in q
        assert "associations" in q
        assert "openIncidents" in q
        assert "accounts" in q
        assert "ActiveDirectoryAccountDescriptor" in q

    def test_include_flags_drop_optional_sections(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._get_entity_details_batch(
            ["e1"],
            {"include_associations": False, "include_accounts": False, "include_incidents": False},
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert "associations" not in q
        assert "openIncidents" not in q
        assert "ActiveDirectoryAccountDescriptor" not in q
        # Core fields still present
        assert "riskScore" in q

    def test_handles_api_error(self, idp_module):
        """403 carries through as an error response — operation name preserved so
        scope-aware error message fires."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._get_entity_details_batch(
            ["e1"], {"include_associations": True, "include_accounts": True, "include_incidents": True}
        )
        assert "error" in result
        assert "HTTP 403" in result["error"]

    def test_entity_ids_are_json_escaped(self, idp_module):
        """Entity IDs must be json.dumps-escaped to avoid GraphQL syntax breakage."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._get_entity_details_batch(
            ['e"1', "e-2"],
            {"include_associations": True, "include_accounts": True, "include_incidents": True},
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        # Both IDs appear; embedded quote is escaped
        assert '"e-2"' in q
        assert 'e\\"1' in q or '"e\\"1"' in q or '"e1"' in q  # json.dumps escapes as \"
```

- [ ] **Step 2: Run tests — expect 4 FAIL**

- [ ] **Step 3: Implement**

```python
    # --------------------------------------------------
    # entity_details
    # --------------------------------------------------
    def _build_entity_details_query(
        self,
        entity_ids: list[str],
        include_risk_factors: bool,
        include_associations: bool,
        include_incidents: bool,
        include_accounts: bool,
    ) -> str:
        ids_json = json.dumps(entity_ids)
        fields = [
            "entityId", "primaryDisplayName", "secondaryDisplayName",
            "type", "riskScore", "riskScoreSeverity",
        ]
        if include_risk_factors:
            fields.append("riskFactors { type severity }")
        if include_associations:
            fields.append("""
                associations {
                    bindingType
                    ... on EntityAssociation {
                        entity { entityId primaryDisplayName secondaryDisplayName type }
                    }
                    ... on LocalAdminLocalUserAssociation { accountName }
                    ... on LocalAdminDomainEntityAssociation {
                        entityType
                        entity { entityId primaryDisplayName secondaryDisplayName }
                    }
                    ... on GeoLocationAssociation {
                        geoLocation { country countryCode city cityCode latitude longitude }
                    }
                }""")
        if include_incidents:
            fields.append("""
                openIncidents(first: 10) {
                    nodes {
                        type startTime endTime
                        compromisedEntities { entityId primaryDisplayName }
                    }
                }""")
        if include_accounts:
            fields.append("""
                accounts {
                    ... on ActiveDirectoryAccountDescriptor {
                        domain samAccountName ou servicePrincipalNames
                        passwordAttributes { lastChange strength }
                        expirationTime
                    }
                    ... on SsoUserAccountDescriptor {
                        dataSource mostRecentActivity title creationTime
                        passwordAttributes { lastChange }
                    }
                    ... on AzureCloudServiceAdapterDescriptor {
                        registeredTenantType appOwnerOrganizationId
                        publisherDomain signInAudience
                    }
                    ... on CloudServiceAdapterDescriptor { dataSourceParticipantIdentifier }
                }""")
        fields_str = "\n                ".join(fields)
        return f"""
        query {{
            entities(entityIds: {ids_json}, first: 50) {{
                nodes {{
                    {fields_str}
                }}
            }}
        }}
        """

    def _get_entity_details_batch(
        self, entity_ids: list[str], options: dict[str, Any]
    ) -> dict[str, Any]:
        query = self._build_entity_details_query(
            entity_ids=entity_ids,
            include_risk_factors=True,
            include_associations=options.get("include_associations", True),
            include_incidents=options.get("include_incidents", True),
            include_accounts=options.get("include_accounts", True),
        )
        result = self._graphql_call(query, context="Failed to get entity details")
        if not result.get("success"):
            return {"error": result["error"]}
        nodes = result["data"].get("entities", {}).get("nodes", []) or []
        nodes = [n for n in nodes if isinstance(n, dict)]
        return {"entities": nodes, "entity_count": len(nodes)}
```

- [ ] **Step 4: Run tests — 4 PASS**

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/idp.py tests/test_idp.py
git commit -m "feat(idp): entity_details investigation path

Build and execute the entities() detail GraphQL with opt-in
associations/incidents/accounts sub-selections."
```

---

## Task 4: `risk_assessment` investigation

**Files:**
- Modify: `src/crowdstrike_mcp/modules/idp.py`
- Modify: `tests/test_idp.py`

- [ ] **Step 1: Write failing tests**

```python
class TestRiskAssessmentInvestigation:
    def test_returns_risk_scores_with_factors(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {
                    "entityId": "e1",
                    "primaryDisplayName": "Admin",
                    "riskScore": 90,
                    "riskScoreSeverity": "CRITICAL",
                    "riskFactors": [
                        {"type": "ADMIN_ACCOUNT", "severity": "HIGH"},
                        {"type": "STALE_ACCOUNT", "severity": "MEDIUM"},
                    ],
                }
            ]}}},
        }
        result = idp_module._assess_risks_batch(["e1"], {"include_risk_factors": True})
        assert result["entity_count"] == 1
        ra = result["risk_assessments"][0]
        assert ra["riskScore"] == 90
        assert ra["riskScoreSeverity"] == "CRITICAL"
        assert len(ra["riskFactors"]) == 2

    def test_without_risk_factors(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._assess_risks_batch(["e1"], {"include_risk_factors": False})
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert "riskScore" in q
        assert "riskFactors" not in q

    def test_handles_api_error(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Boom"}]},
        }
        result = idp_module._assess_risks_batch(["e1"], {"include_risk_factors": True})
        assert "error" in result
        assert "HTTP 500" in result["error"]

    def test_defensive_projection_on_missing_fields(self, idp_module):
        """Missing riskScore / riskFactors → safe defaults, not KeyError."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {"entityId": "e1", "primaryDisplayName": "X"}
            ]}}},
        }
        result = idp_module._assess_risks_batch(["e1"], {"include_risk_factors": True})
        ra = result["risk_assessments"][0]
        assert ra["riskScore"] == 0
        assert ra["riskScoreSeverity"] == "LOW"
        assert ra["riskFactors"] == []
```

- [ ] **Step 2: Run tests — 4 FAIL**

- [ ] **Step 3: Implement**

```python
    # --------------------------------------------------
    # risk_assessment
    # --------------------------------------------------
    def _build_risk_assessment_query(self, entity_ids: list[str], include_factors: bool) -> str:
        ids_json = json.dumps(entity_ids)
        risk = "riskScore\n                riskScoreSeverity"
        if include_factors:
            risk += "\n                riskFactors { type severity }"
        return f"""
        query {{
            entities(entityIds: {ids_json}, first: 50) {{
                nodes {{
                    entityId
                    primaryDisplayName
                    {risk}
                }}
            }}
        }}
        """

    def _assess_risks_batch(self, entity_ids: list[str], options: dict[str, Any]) -> dict[str, Any]:
        query = self._build_risk_assessment_query(entity_ids, options.get("include_risk_factors", True))
        result = self._graphql_call(query, context="Failed to assess risks")
        if not result.get("success"):
            return {"error": result["error"]}
        nodes = result["data"].get("entities", {}).get("nodes", []) or []
        assessments = [
            {
                "entityId": n.get("entityId"),
                "primaryDisplayName": n.get("primaryDisplayName"),
                "riskScore": n.get("riskScore", 0),
                "riskScoreSeverity": n.get("riskScoreSeverity", "LOW"),
                "riskFactors": n.get("riskFactors", []) if isinstance(n.get("riskFactors"), list) else [],
            }
            for n in nodes if isinstance(n, dict)
        ]
        return {"risk_assessments": assessments, "entity_count": len(assessments)}
```

- [ ] **Step 4: Run tests — 4 PASS**

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/idp.py tests/test_idp.py
git commit -m "feat(idp): risk_assessment investigation path

Query riskScore/severity/factors for a batch of entities; defensive
projection for missing optional fields."
```

---

## Task 5: `timeline_analysis` investigation

**Files:**
- Modify: `src/crowdstrike_mcp/modules/idp.py`
- Modify: `tests/test_idp.py`

One GraphQL query **per entity ID** (upstream shape — timeline filter accepts a single sourceEntityQuery).

- [ ] **Step 1: Write failing tests**

```python
class TestTimelineInvestigation:
    def test_loops_per_entity(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"timeline": {"nodes": [], "pageInfo": {"hasNextPage": False}}}},
        }
        idp_module._get_entity_timelines_batch(["e1", "e2"], {"limit": 50})
        assert idp_module.falcon.graphql.call_count == 2

    def test_query_embeds_entity_id_and_time_range(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"timeline": {"nodes": []}}},
        }
        idp_module._get_entity_timelines_batch(
            ["e1"],
            {
                "start_time": "2026-04-01T00:00:00Z",
                "end_time": "2026-04-20T00:00:00Z",
                "event_types": ["AUDIT", "ACTIVITY"],
                "limit": 25,
            },
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'entityIds: ["e1"]' in q
        assert 'startTime: "2026-04-01T00:00:00Z"' in q
        assert 'endTime: "2026-04-20T00:00:00Z"' in q
        # Event types rendered as unquoted enums
        assert "categories: [AUDIT, ACTIVITY]" in q
        assert "first: 25" in q

    def test_returns_timelines_keyed_by_entity(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"timeline": {
                "nodes": [{"eventId": "ev1", "eventType": "AUDIT"}],
                "pageInfo": {"hasNextPage": False},
            }}},
        }
        result = idp_module._get_entity_timelines_batch(["e1"], {"limit": 50})
        assert result["entity_count"] == 1
        assert result["timelines"][0]["entity_id"] == "e1"
        assert result["timelines"][0]["timeline"][0]["eventId"] == "ev1"

    def test_early_exit_on_first_error(self, idp_module):
        """If entity #1 fails with 403, we don't silently keep iterating."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._get_entity_timelines_batch(["e1", "e2"], {"limit": 50})
        assert "error" in result
        # We bailed after the first call
        assert idp_module.falcon.graphql.call_count == 1
```

- [ ] **Step 2: Run tests — 4 FAIL**

- [ ] **Step 3: Implement**

Port the timeline fragments from `falcon_mcp_idp.py` lines 441-690 verbatim. Compact re-shape:

```python
    # --------------------------------------------------
    # timeline_analysis
    # --------------------------------------------------
    _TIMELINE_FRAGMENTS = """
        ... on TimelineUserOnEndpointActivityEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineAuthenticationEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineAlertEvent {
            sourceEntity { entityId primaryDisplayName }
        }
        ... on TimelineDceRpcEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineFailedAuthenticationEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineSuccessfulAuthenticationEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineServiceAccessEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineFileOperationEvent {
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineLdapSearchEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineRemoteCodeExecutionEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineConnectorConfigurationEvent { category }
        ... on TimelineConnectorConfigurationAddedEvent { category }
        ... on TimelineConnectorConfigurationDeletedEvent { category }
        ... on TimelineConnectorConfigurationModifiedEvent { category }
    """

    def _build_timeline_query(
        self, entity_id: str,
        start_time: str | None, end_time: str | None,
        event_types: list[str] | None, limit: int,
    ) -> str:
        filters = [f'sourceEntityQuery: {{entityIds: ["{entity_id}"]}}']
        if isinstance(start_time, str) and start_time:
            filters.append(f'startTime: "{start_time}"')
        if isinstance(end_time, str) and end_time:
            filters.append(f'endTime: "{end_time}"')
        if isinstance(event_types, list) and event_types:
            filters.append(f"categories: [{', '.join(event_types)}]")
        return f"""
        query {{
            timeline({", ".join(filters)}, first: {limit}) {{
                nodes {{
                    eventId eventType eventSeverity timestamp
                    {self._TIMELINE_FRAGMENTS}
                }}
                pageInfo {{ hasNextPage endCursor }}
            }}
        }}
        """

    def _get_entity_timelines_batch(
        self, entity_ids: list[str], options: dict[str, Any]
    ) -> dict[str, Any]:
        timelines = []
        for eid in entity_ids:
            query = self._build_timeline_query(
                entity_id=eid,
                start_time=options.get("start_time"),
                end_time=options.get("end_time"),
                event_types=options.get("event_types"),
                limit=options.get("limit", 50),
            )
            result = self._graphql_call(query, context=f"Failed to get timeline for '{eid}'")
            if not result.get("success"):
                return {"error": result["error"]}
            tl = result["data"].get("timeline", {}) or {}
            timelines.append({
                "entity_id": eid,
                "timeline": tl.get("nodes", []) if isinstance(tl.get("nodes"), list) else [],
                "page_info": tl.get("pageInfo", {}) if isinstance(tl.get("pageInfo"), dict) else {},
            })
        return {"timelines": timelines, "entity_count": len(entity_ids)}
```

- [ ] **Step 4: Run tests — 4 PASS**

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/idp.py tests/test_idp.py
git commit -m "feat(idp): timeline_analysis investigation path

Per-entity timeline() queries with authentication, service-access,
LDAP, RCE, file-op, and connector-configuration event fragments."
```

---

## Task 6: `relationship_analysis` investigation

**Files:**
- Modify: `src/crowdstrike_mcp/modules/idp.py`
- Modify: `tests/test_idp.py`

- [ ] **Step 1: Write failing tests**

```python
class TestRelationshipInvestigation:
    def test_depth_one_query_has_no_nesting(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 1, "include_risk_context": True, "limit": 50}
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        # depth=1 still contains at least one associations block
        assert q.count("associations {") >= 1

    def test_depth_three_nests_three_levels(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 3, "include_risk_context": True, "limit": 50}
        )
        q3 = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]

        # Reset and build depth=2 query for comparison
        idp_module.falcon.graphql.reset_mock()
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": True, "limit": 50}
        )
        q2 = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]

        # Reset and build depth=1 query for comparison
        idp_module.falcon.graphql.reset_mock()
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 1, "include_risk_context": True, "limit": 50}
        )
        q1 = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]

        # `{nested}` is interpolated into both EntityAssociation and
        # LocalAdminDomainEntityAssociation fragments at every level (matches
        # upstream falcon-mcp), so block counts follow 1, 3, 7 — i.e. each
        # additional level of depth doubles the previous level's new blocks.
        c1 = q1.count("associations {")
        c2 = q2.count("associations {")
        c3 = q3.count("associations {")
        assert c1 == 1, f"depth=1 expected 1 block, got {c1}"
        assert c2 == 3, f"depth=2 expected 3 blocks, got {c2}"
        assert c3 == 7, f"depth=3 expected 7 blocks, got {c3}"
        # And each depth strictly exceeds the previous — regression guard
        assert c1 < c2 < c3

    def test_without_risk_context_omits_risk_fields(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": False, "limit": 50}
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert "riskScore" not in q
        assert "riskFactors" not in q

    def test_empty_nodes_yields_zero_associations(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        result = idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": True, "limit": 50}
        )
        assert result["relationships"][0]["associations"] == []
        assert result["relationships"][0]["relationship_count"] == 0

    def test_handles_api_error(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": True, "limit": 50}
        )
        assert "error" in result

    def test_counts_associations_defensively_when_field_missing(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {"entityId": "e1"}  # no associations field
            ]}}},
        }
        result = idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": True, "limit": 50}
        )
        assert result["relationships"][0]["associations"] == []
        assert result["relationships"][0]["relationship_count"] == 0
```

- [ ] **Step 2: Run tests — 6 FAIL**

- [ ] **Step 3: Implement**

```python
    # --------------------------------------------------
    # relationship_analysis
    # --------------------------------------------------
    def _build_relationship_query(
        self, entity_id: str, depth: int, include_risk_context: bool, limit: int
    ) -> str:
        risk_fields = ""
        if include_risk_context:
            risk_fields = """
                riskScore
                riskScoreSeverity
                riskFactors { type severity }
            """

        def associations_block(remaining: int) -> str:
            if remaining <= 0:
                return ""
            nested = associations_block(remaining - 1) if remaining > 1 else ""
            return f"""
                associations {{
                    bindingType
                    ... on EntityAssociation {{
                        entity {{
                            entityId primaryDisplayName secondaryDisplayName type
                            {risk_fields}
                            {nested}
                        }}
                    }}
                    ... on LocalAdminLocalUserAssociation {{ accountName }}
                    ... on LocalAdminDomainEntityAssociation {{
                        entityType
                        entity {{
                            entityId primaryDisplayName secondaryDisplayName type
                            {risk_fields}
                            {nested}
                        }}
                    }}
                    ... on GeoLocationAssociation {{
                        geoLocation {{ country countryCode city cityCode latitude longitude }}
                    }}
                }}
            """

        return f"""
        query {{
            entities(entityIds: ["{entity_id}"], first: {limit}) {{
                nodes {{
                    entityId primaryDisplayName secondaryDisplayName type
                    {risk_fields}
                    {associations_block(depth)}
                }}
            }}
        }}
        """

    def _analyze_relationships_batch(
        self, entity_ids: list[str], options: dict[str, Any]
    ) -> dict[str, Any]:
        relationships = []
        depth = options.get("relationship_depth", 2)
        for eid in entity_ids:
            query = self._build_relationship_query(
                entity_id=eid,
                depth=depth,
                include_risk_context=options.get("include_risk_context", True),
                limit=options.get("limit", 50),
            )
            result = self._graphql_call(query, context=f"Failed to analyze relationships for '{eid}'")
            if not result.get("success"):
                return {"error": result["error"]}
            nodes = result["data"].get("entities", {}).get("nodes", []) or []
            if nodes and isinstance(nodes[0], dict):
                associations = nodes[0].get("associations", [])
                if not isinstance(associations, list):
                    associations = []
            else:
                associations = []
            relationships.append({
                "entity_id": eid,
                "associations": associations,
                "relationship_count": len(associations),
            })
        return {"relationships": relationships, "entity_count": len(entity_ids)}
```

- [ ] **Step 4: Run tests — 6 PASS**

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/idp.py tests/test_idp.py
git commit -m "feat(idp): relationship_analysis investigation path

Nested associations GraphQL 1-3 levels deep, with optional riskScore
context at each level. Defensive list-type checks on the response."
```

---

## Task 7: Public `identity_investigate_entity` tool + validation + synthesis

**Files:**
- Modify: `src/crowdstrike_mcp/modules/idp.py`
- Modify: `tests/test_idp.py`

- [ ] **Step 1: Write failing tests**

```python
class TestIdentityInvestigateEntityValidation:
    def test_no_identifiers_errors(self, idp_module):
        result = asyncio.run(
            idp_module.identity_investigate_entity(investigation_types=["entity_details"])
        )
        assert "at least one" in result.lower() or "identifier" in result.lower()
        idp_module.falcon.graphql.assert_not_called()

    def test_invalid_investigation_type_errors(self, idp_module):
        result = asyncio.run(
            idp_module.identity_investigate_entity(
                entity_ids=["e1"],
                investigation_types=["not_a_real_type"],
            )
        )
        assert "not_a_real_type" in result

    def test_invalid_timeline_event_type_errors(self, idp_module):
        result = asyncio.run(
            idp_module.identity_investigate_entity(
                entity_ids=["e1"],
                investigation_types=["timeline_analysis"],
                timeline_event_types=["NOT_A_CATEGORY"],
            )
        )
        assert "NOT_A_CATEGORY" in result

    def test_depth_out_of_range_errors(self, idp_module):
        result = asyncio.run(
            idp_module.identity_investigate_entity(
                entity_ids=["e1"],
                investigation_types=["relationship_analysis"],
                relationship_depth=7,
            )
        )
        assert "depth" in result.lower()

    def test_limit_out_of_range_errors(self, idp_module):
        result = asyncio.run(
            idp_module.identity_investigate_entity(entity_ids=["e1"], limit=5000)
        )
        assert "limit" in result.lower()

    def test_empty_investigation_types_errors(self, idp_module):
        result = asyncio.run(
            idp_module.identity_investigate_entity(
                entity_ids=["e1"], investigation_types=[]
            )
        )
        assert "investigation_types" in result
        assert "empty" in result.lower() or "cannot" in result.lower()
        idp_module.falcon.graphql.assert_not_called()


class TestIdentityInvestigateEntityConvenienceParams:
    def test_username_merges_into_entity_names(self, idp_module):
        """`username="jdoe"` → resolution query contains primaryDisplayNames: ["jdoe"]."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [{"entityId": "e1"}]}}},
        }
        # Only entity_details; set nodes response for the details query
        def router(**kw):
            q = kw["body"]["query"]
            if "primaryDisplayNames: [\"jdoe\"]" in q:
                return {
                    "status_code": 200,
                    "body": {"data": {"entities": {"nodes": [{"entityId": "e1"}]}}},
                }
            # details query for resolved id
            return {
                "status_code": 200,
                "body": {"data": {"entities": {"nodes": [
                    {"entityId": "e1", "primaryDisplayName": "jdoe", "type": "USER", "riskScore": 80}
                ]}}},
            }
        idp_module.falcon.graphql.side_effect = router
        result = asyncio.run(
            idp_module.identity_investigate_entity(username="jdoe")
        )
        assert "jdoe" in result
        # Verify the resolution call happened with the username in primaryDisplayNames
        assert any(
            'primaryDisplayNames: ["jdoe"]' in c.kwargs["body"]["query"]
            for c in idp_module.falcon.graphql.call_args_list
        )

    def test_username_and_entity_names_combined(self, idp_module):
        """`username=` is appended to `entity_names=`, not replacing it."""
        calls_seen = []
        def router(**kw):
            calls_seen.append(kw["body"]["query"])
            return {
                "status_code": 200,
                "body": {"data": {"entities": {"nodes": [{"entityId": "e1"}]}}},
            }
        idp_module.falcon.graphql.side_effect = router
        asyncio.run(
            idp_module.identity_investigate_entity(
                username="jdoe",
                entity_names=["Administrator"],
                investigation_types=["entity_details"],
            )
        )
        resolution_q = calls_seen[0]
        assert '"Administrator"' in resolution_q
        assert '"jdoe"' in resolution_q

    def test_username_duplicate_not_doubled(self, idp_module):
        """If `username` is already in `entity_names`, don't duplicate it."""
        captured = []
        def router(**kw):
            captured.append(kw["body"]["query"])
            return {
                "status_code": 200,
                "body": {"data": {"entities": {"nodes": [{"entityId": "e1"}]}}},
            }
        idp_module.falcon.graphql.side_effect = router
        asyncio.run(
            idp_module.identity_investigate_entity(
                username="jdoe",
                entity_names=["jdoe"],
                investigation_types=["entity_details"],
            )
        )
        # Should appear exactly once in the resolution query
        assert captured[0].count('"jdoe"') == 1

    def test_quick_triage_forces_lean_investigation(self, idp_module):
        """`quick_triage=True` → investigation_types locked to [entity_details, risk_assessment],
        and the includes are all False."""
        queries = []
        def router(**kw):
            queries.append(kw["body"]["query"])
            return {
                "status_code": 200,
                "body": {"data": {"entities": {"nodes": [
                    {"entityId": "e1", "primaryDisplayName": "jdoe", "type": "USER",
                     "riskScore": 90, "riskScoreSeverity": "HIGH"}
                ]}}},
            }
        idp_module.falcon.graphql.side_effect = router
        result = asyncio.run(
            idp_module.identity_investigate_entity(
                username="jdoe",
                quick_triage=True,
                # Explicit opposite settings — quick_triage should override all of them
                investigation_types=["timeline_analysis", "relationship_analysis"],
                include_associations=True,
                include_accounts=True,
                include_incidents=True,
                limit=100,
            )
        )
        # Sections present
        assert "## entity_details" in result
        assert "## risk_assessment" in result
        # Sections NOT present — quick_triage forces a 2-element list
        assert "## timeline_analysis" not in result
        assert "## relationship_analysis" not in result
        # Includes forced off: no association/account/incident fragments in details query
        details_q = next((q for q in queries if "entities(entityIds:" in q), "")
        assert "associations {" not in details_q
        assert "accounts {" not in details_q
        assert "openIncidents" not in details_q

    def test_resolves_then_runs_details(self, idp_module):
        def graphql_router(body):
            q = body["query"]
            if "primaryDisplayNames" in q and "entities" in q:
                return {
                    "status_code": 200,
                    "body": {"data": {"entities": {"nodes": [{"entityId": "e-resolved"}]}}},
                }
            if "entityIds" in q:
                return {
                    "status_code": 200,
                    "body": {"data": {"entities": {"nodes": [
                        {"entityId": "e-resolved", "primaryDisplayName": "Admin", "type": "USER",
                         "riskScore": 80, "riskScoreSeverity": "HIGH"}
                    ]}}},
                }
            return {"status_code": 500, "body": {"errors": [{"message": "unexpected query"}]}}

        idp_module.falcon.graphql.side_effect = lambda **kw: graphql_router(kw["body"])
        result = asyncio.run(
            idp_module.identity_investigate_entity(
                entity_names=["Admin"],
                investigation_types=["entity_details"],
            )
        )
        assert "e-resolved" in result
        assert "Admin" in result
        # At least two calls — one resolve, one details
        assert idp_module.falcon.graphql.call_count >= 2

    def test_zero_resolved_entities_returns_clear_error(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        result = asyncio.run(
            idp_module.identity_investigate_entity(
                entity_names=["NoSuchUser"],
                investigation_types=["entity_details"],
            )
        )
        assert "no entit" in result.lower()

    def test_multiple_investigation_types_produce_sections(self, idp_module):
        def router(body):
            q = body["query"]
            if "riskFactors" in q and "entities(entityIds" in q and "openIncidents" in q:
                return {"status_code": 200, "body": {"data": {"entities": {"nodes": [
                    {"entityId": "e1", "primaryDisplayName": "A", "type": "USER",
                     "riskScore": 42, "riskScoreSeverity": "MEDIUM"}
                ]}}}}
            if "riskFactors" in q:  # risk assessment (no openIncidents)
                return {"status_code": 200, "body": {"data": {"entities": {"nodes": [
                    {"entityId": "e1", "primaryDisplayName": "A",
                     "riskScore": 42, "riskScoreSeverity": "MEDIUM", "riskFactors": []}
                ]}}}}
            return {"status_code": 200, "body": {"data": {"entities": {"nodes": []}}}}

        idp_module.falcon.graphql.side_effect = lambda **kw: router(kw["body"])
        result = asyncio.run(
            idp_module.identity_investigate_entity(
                entity_ids=["e1"],
                investigation_types=["entity_details", "risk_assessment"],
            )
        )
        # Both investigation types surface in the output
        assert "entity_details" in result.lower() or "Entity Details" in result
        assert "risk_assessment" in result.lower() or "Risk Assessment" in result

    def test_tool_registers_as_read(self, idp_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        idp_module.register_tools(server)
        assert "identity_investigate_entity" in idp_module.tools
```

- [ ] **Step 2: Run tests — 9 FAIL**

- [ ] **Step 3: Implement public tool + validation + synthesis**

```python
    # --------------------------------------------------
    # Public tool + validation + synthesis
    # --------------------------------------------------
    def _validate_params(
        self,
        identifier_lists: list[list[str] | None],
        investigation_types: list[str],
        timeline_event_types: list[str] | None,
        relationship_depth: int,
        limit: int,
    ) -> str | None:
        if not any(identifier_lists):
            return (
                "At least one entity identifier must be provided "
                "(username, entity_ids, entity_names, email_addresses, ip_addresses, or domain_names)."
            )
        if not investigation_types:
            return (
                "investigation_types cannot be empty. Provide any subset of: "
                f"{sorted(VALID_INVESTIGATION_TYPES)}."
            )
        bad_inv = [t for t in investigation_types if t not in VALID_INVESTIGATION_TYPES]
        if bad_inv:
            return (
                f"Invalid investigation_types: {bad_inv}. "
                f"Valid values: {sorted(VALID_INVESTIGATION_TYPES)}."
            )
        if timeline_event_types:
            bad_ev = [t for t in timeline_event_types if t not in VALID_TIMELINE_EVENT_TYPES]
            if bad_ev:
                return (
                    f"Invalid timeline_event_types: {bad_ev}. "
                    f"Valid values: {sorted(VALID_TIMELINE_EVENT_TYPES)}."
                )
        if not 1 <= relationship_depth <= 3:
            return f"relationship_depth must be between 1 and 3 (got {relationship_depth})."
        if not 1 <= limit <= 200:
            return f"limit must be between 1 and 200 (got {limit})."
        return None

    def _execute_investigation(
        self, inv_type: str, entity_ids: list[str], params: dict[str, Any]
    ) -> dict[str, Any]:
        if inv_type == "entity_details":
            return self._get_entity_details_batch(entity_ids, {
                "include_associations": params["include_associations"],
                "include_accounts": params["include_accounts"],
                "include_incidents": params["include_incidents"],
            })
        if inv_type == "risk_assessment":
            return self._assess_risks_batch(entity_ids, {"include_risk_factors": True})
        if inv_type == "timeline_analysis":
            return self._get_entity_timelines_batch(entity_ids, {
                "start_time": params.get("timeline_start_time"),
                "end_time": params.get("timeline_end_time"),
                "event_types": params.get("timeline_event_types"),
                "limit": params["limit"],
            })
        if inv_type == "relationship_analysis":
            return self._analyze_relationships_batch(entity_ids, {
                "relationship_depth": params["relationship_depth"],
                "include_risk_context": True,
                "limit": params["limit"],
            })
        return {"error": f"Unknown investigation type: {inv_type}"}

    def _format_investigation_response(
        self,
        entity_ids: list[str],
        investigation_results: dict[str, dict[str, Any]],
        investigation_types: list[str],
        include_raw: bool,
    ) -> str:
        lines: list[str] = []
        lines.append(f"# Identity Investigation — {len(entity_ids)} entit{'y' if len(entity_ids) == 1 else 'ies'}")
        lines.append("")
        lines.append(f"Investigations run: {', '.join(investigation_types)}")
        lines.append(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"Resolved entity IDs: {', '.join(entity_ids)}")
        lines.append("")

        for inv_type in investigation_types:
            r = investigation_results.get(inv_type, {})
            lines.append(f"## {inv_type}")
            lines.append("")
            if inv_type == "entity_details":
                for e in r.get("entities", []):
                    if not isinstance(e, dict):
                        continue
                    lines.append(
                        f"- **{e.get('primaryDisplayName', '?')}** "
                        f"({e.get('type', '?')}) "
                        f"risk={e.get('riskScore', '?')} [{e.get('riskScoreSeverity', '?')}] "
                        f"id=`{e.get('entityId', '?')}`"
                    )
                    factors = e.get("riskFactors") or []
                    if isinstance(factors, list) and factors:
                        top = ", ".join(f"{f.get('type')}({f.get('severity')})" for f in factors[:5] if isinstance(f, dict))
                        lines.append(f"  - Top risk factors: {top}")
                    incidents = ((e.get("openIncidents") or {}).get("nodes") or []) if isinstance(e.get("openIncidents"), dict) else []
                    if incidents:
                        lines.append(f"  - Open incidents: {len(incidents)}")
            elif inv_type == "risk_assessment":
                for ra in r.get("risk_assessments", []):
                    lines.append(
                        f"- **{ra.get('primaryDisplayName', '?')}** "
                        f"risk={ra.get('riskScore', 0)} [{ra.get('riskScoreSeverity', 'LOW')}] "
                        f"id=`{ra.get('entityId', '?')}`"
                    )
                    factors = ra.get("riskFactors") or []
                    if isinstance(factors, list) and factors:
                        for f in factors[:10]:
                            if isinstance(f, dict):
                                lines.append(f"  - {f.get('type', '?')} ({f.get('severity', '?')})")
            elif inv_type == "timeline_analysis":
                for tl in r.get("timelines", []):
                    events = tl.get("timeline", []) or []
                    lines.append(f"- Entity `{tl.get('entity_id', '?')}`: {len(events)} events")
                    for ev in events[:10]:
                        if isinstance(ev, dict):
                            lines.append(f"  - {ev.get('timestamp', '?')} {ev.get('eventType', '?')} [{ev.get('eventSeverity', '?')}] id=`{ev.get('eventId', '?')}`")
            elif inv_type == "relationship_analysis":
                for rel in r.get("relationships", []):
                    assocs = rel.get("associations") or []
                    lines.append(f"- Entity `{rel.get('entity_id', '?')}`: {rel.get('relationship_count', 0)} associations")
                    for a in assocs[:10] if isinstance(assocs, list) else []:
                        if isinstance(a, dict):
                            ent = a.get("entity") or {}
                            if isinstance(ent, dict) and ent:
                                lines.append(f"  - [{a.get('bindingType', '?')}] → {ent.get('primaryDisplayName', '?')} ({ent.get('type', '?')})")
                            else:
                                lines.append(f"  - [{a.get('bindingType', '?')}]")
            lines.append("")

        if include_raw:
            lines.append("## Raw GraphQL results")
            lines.append("```json")
            lines.append(json.dumps({
                "entity_ids": entity_ids,
                "investigations": investigation_results,
            }, indent=2, default=str))
            lines.append("```")

        return "\n".join(lines)

    async def identity_investigate_entity(
        self,
        username: Annotated[Optional[str],
            "Ergonomic shortcut: single username/display name. Merged into entity_names."] = None,
        quick_triage: Annotated[bool,
            "One-shot triage mode: forces investigation_types=[entity_details, risk_assessment] "
            "with lean includes (no associations/accounts/incidents, limit=5). Good default for "
            "'does Falcon consider this user compromised?'."] = False,
        entity_ids: Annotated[Optional[list[str]],
            "Direct entity IDs to investigate (skip identifier resolution)."] = None,
        entity_names: Annotated[Optional[list[str]],
            "Entity display names (e.g. ['Administrator']). AND-combined with other identifier kinds."] = None,
        email_addresses: Annotated[Optional[list[str]],
            "Email addresses (restricts search to USER entities)."] = None,
        ip_addresses: Annotated[Optional[list[str]],
            "IP addresses (restricts search to ENDPOINT entities). Ignored if email_addresses given."] = None,
        domain_names: Annotated[Optional[list[str]],
            "Domain names (e.g. ['CORP.LOCAL'])."] = None,
        investigation_types: Annotated[list[str],
            "Any subset of: entity_details, risk_assessment, timeline_analysis, relationship_analysis."
        ] = None,
        timeline_start_time: Annotated[Optional[str], "ISO-8601 timestamp (timeline_analysis only)."] = None,
        timeline_end_time: Annotated[Optional[str], "ISO-8601 timestamp (timeline_analysis only)."] = None,
        timeline_event_types: Annotated[Optional[list[str]],
            "Filter timeline categories: ACTIVITY, NOTIFICATION, THREAT, ENTITY, AUDIT, POLICY, SYSTEM."] = None,
        relationship_depth: Annotated[int, "Relationship nesting depth 1-3 (relationship_analysis only)."] = 2,
        limit: Annotated[int, "Max results per query (1-200)."] = 10,
        include_associations: Annotated[bool, "Include entity associations in details."] = True,
        include_accounts: Annotated[bool, "Include AD/SSO/Azure account descriptors in details."] = True,
        include_incidents: Annotated[bool, "Include open security incidents in details."] = True,
        include_raw: Annotated[bool, "Append raw GraphQL JSON to the response (default False)."] = False,
    ) -> str:
        """Investigate an identity entity in Falcon IDP.

        Resolves identifier(s) to entity IDs, then runs any combination of
        entity_details / risk_assessment / timeline_analysis / relationship_analysis.
        """
        # Ergonomic shortcuts applied BEFORE validation so the usual
        # identifier/investigation_types rules still run on the merged values.
        if username:
            merged_names = list(entity_names or [])
            if username not in merged_names:
                merged_names.append(username)
            entity_names = merged_names

        if quick_triage:
            investigation_types = ["entity_details", "risk_assessment"]
            include_associations = False
            include_accounts = False
            include_incidents = False
            limit = 5
        elif investigation_types is None:
            investigation_types = ["entity_details"]

        validation_err = self._validate_params(
            [entity_ids, entity_names, email_addresses, ip_addresses, domain_names],
            investigation_types,
            timeline_event_types,
            relationship_depth,
            limit,
        )
        if validation_err:
            return format_text_response(f"Failed: {validation_err}", raw=True)

        resolved = self._resolve_entities({
            "entity_ids": entity_ids,
            "entity_names": entity_names,
            "email_addresses": email_addresses,
            "ip_addresses": ip_addresses,
            "domain_names": domain_names,
            "limit": limit,
        })
        if isinstance(resolved, dict) and "error" in resolved:
            return format_text_response(f"Failed to resolve entities: {resolved['error']}", raw=True)
        if not resolved:
            return format_text_response(
                "No entities found matching the provided criteria.",
                raw=True,
            )

        params = {
            "include_associations": include_associations,
            "include_accounts": include_accounts,
            "include_incidents": include_incidents,
            "timeline_start_time": timeline_start_time,
            "timeline_end_time": timeline_end_time,
            "timeline_event_types": timeline_event_types,
            "relationship_depth": relationship_depth,
            "limit": limit,
        }

        investigation_results: dict[str, dict[str, Any]] = {}
        for inv_type in investigation_types:
            res = self._execute_investigation(inv_type, resolved, params)
            if "error" in res:
                return format_text_response(
                    f"Failed during '{inv_type}' investigation: {res['error']}",
                    raw=True,
                )
            investigation_results[inv_type] = res

        return format_text_response(
            self._format_investigation_response(
                resolved, investigation_results, investigation_types, include_raw
            ),
            raw=True,
        )
```

Replace the `pass` in `register_tools` with:

```python
    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.identity_investigate_entity,
            name="identity_investigate_entity",
            description=(
                "Falcon Identity Protection: investigate a user/device entity by name, "
                "email, IP, domain, or entity ID. Returns identity risk score + risk "
                "factors, AD/SSO/Azure account descriptors, open incidents, activity "
                "timeline, and/or nested relationship graph — any combination in one "
                "call. Primary triage tool for 'does Falcon consider this user "
                "identity-compromised?'."
            ),
            tier="read",
        )
```

- [ ] **Step 4: Run tests — 14 PASS**

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/idp.py tests/test_idp.py
git commit -m "feat(idp): public identity_investigate_entity tool

Composes resolution + investigation types into a single tool with
validation. Synthesised output projection shows top-N risk factors,
incidents, timeline events, and associations per entity; optional
include_raw for full GraphQL JSON."
```

---

## Task 8: Smoke test update + README refresh

**Files:**
- Modify: `tests/test_smoke_tools_list.py`
- Modify: `README.md`

- [ ] **Step 1: Update smoke-test expectations**

In `tests/test_smoke_tools_list.py`:

1. Add `"crowdstrike_mcp.modules.idp.IdentityProtection"` to `_FALCONPY_PATCHES`.
2. Add `"identity_investigate_entity"` to `EXPECTED_READ_TOOLS`.
3. Add a new `patch.multiple` call inside `_patch_falconpy`:
   ```python
   patch.multiple("crowdstrike_mcp.modules.idp", IdentityProtection=MagicMock()),
   ```

- [ ] **Step 2: Run smoke tests — confirm they pass**

`pytest tests/test_smoke_tools_list.py -v`

- [ ] **Step 3: Run full test suite**

`pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 4: Run ruff**

`ruff check src/ tests/`
Expected: no violations.

- [ ] **Step 5: README update**

In `README.md`:

1. Bump line 5 count: `51 tools across 11 modules` → `52 tools across 12 modules`.
2. Bump line 528: `all 51 tools` → `all 52 tools`.
3. Add an Identity Protection section to the tool table (mirror the Spotlight section's column layout). Tool: `identity_investigate_entity`, description: "One-call identity triage — resolve user/device by name/email/IP/domain, return risk + timeline + relationships.", scopes: the 5 listed above.
4. In the acknowledgements / license footer add: "Contains a port of the IdentityProtection module from CrowdStrike's falcon-mcp (MIT). See THIRD_PARTY_NOTICES.md."

- [ ] **Step 6: Smoke-test the server boots**

`python -m crowdstrike_mcp --help`
Expected: help text prints, no import errors.

- [ ] **Step 7: Final commit**

```bash
git add tests/test_smoke_tools_list.py README.md
git commit -m "feat(idp): register identity_investigate_entity and update docs

Smoke-test expects the new tool and patches IdentityProtection. README
tool count 51 → 52, adds Identity Protection section and third-party
notices link."
```

---

## Verification Checklist

- [ ] `pytest tests/ -v` — all pass
- [ ] `ruff check src/ tests/` — clean
- [ ] `python -m crowdstrike_mcp --help` — boots
- [ ] `identity_investigate_entity` shown in `_collect_tools(..., allow_writes=False)`
- [ ] `get_required_scopes("post_graphql")` returns all 5 scopes
- [ ] 403 from falconpy surfaces "Required API scopes for 'post_graphql':" line with all 5
- [ ] 200 with non-empty `body["errors"]` surfaces a `GraphQL error:` message (tested in Task 2)
- [ ] Validation rejects: no identifiers, bogus investigation_type, bogus timeline event, depth>3, limit>200
- [ ] `THIRD_PARTY_NOTICES.md` exists at repo root
- [ ] `falcon_mcp_idp.py` remains untracked

---

## Self-Review — Bug Classes to Catch

### From FR 02's postmortem

1. **Dict-vs-list confusion in projections.** Every projection helper wraps the upstream field access in `isinstance(x, dict)` / `isinstance(x, list)` guards before iterating. Specifically: `nodes` can be `None`, `associations` can be `None`, `riskFactors` can be missing, `openIncidents` can be a dict with a missing `nodes`. Each of these cases is exercised in tests — see `test_defensive_projection_on_missing_fields`, `test_counts_associations_defensively_when_field_missing`.

2. **Weak test assertions.** All error-path tests assert on **substrings that would change if the operation name or HTTP code were dropped** (`"HTTP 403"`, the exact `operation` context string, `"GraphQL error:"`). Filter-construction tests assert on specific GraphQL substrings (`'types: [USER]'`, `'primaryDisplayNames:'`, `'categories: [AUDIT, ACTIVITY]'`) not just "did the method get called". This means an operation-ID regression (e.g. someone changing `"post_graphql"` to `"preempt_graphql"`) will fail concretely.

3. **Missed smoke-test update.** Task 8 is an explicit gate: tool name goes into `EXPECTED_READ_TOOLS`, falconpy class goes into `_FALCONPY_PATCHES` + `_patch_falconpy`. The `test_no_unexpected_tools` smoke test will fail if either is forgotten.

### New for this FR

4. **GraphQL error shape (HTTP 200 + errors).** GraphQL returns 200 for semantic errors; transport-level `format_api_error` wouldn't see those. `_graphql_call` checks `body["errors"]` explicitly and returns a distinct error message prefixed with `"GraphQL error:"`. Tested in `test_200_but_graphql_errors_returns_error`.

5. **Operation ID correctness.** Confirmed by reading `falconpy/_endpoint/_idp.py` and `inspect.getsource(IdentityProtection.graphql)`: the operation ID is **`post_graphql`** (not `api.preempt.proxy.post.graphql` which is the Swagger path, nor `preempt_graphql`). This is the exact string used in `api_scopes.py` and in every `_graphql_call(context, operation="post_graphql")` call inside `format_api_error`.

6. **GraphQL query validity.** Brace-balance check (visually) done for each `_build_*_query`:
   - `_build_entity_details_query`: outer `query { entities(...) { nodes { ... } } }` — 3 pairs; each included fragment block ends with `}` matching its opener.
   - `_build_timeline_query`: `query { timeline(...) { nodes { ... } pageInfo { ... } } }` — all balanced; the `_TIMELINE_FRAGMENTS` constant has 13 `...on Xxx {}` blocks, each independently balanced.
   - `_build_risk_assessment_query`: trivial — three levels, balanced.
   - `_build_relationship_query`: recursive associations block interpolates `{nested}` into BOTH `EntityAssociation` and `LocalAdminDomainEntityAssociation` fragments at each level (matches upstream falcon-mcp), so block counts grow 1, 3, 7 by depth. `test_depth_three_nests_three_levels` asserts exact counts at all three depths to lock in this behavior.

7. **Field-name parity with upstream.** Every GraphQL identifier used (`entities`, `entityIds`, `primaryDisplayName`, `secondaryDisplayName`, `riskScore`, `riskScoreSeverity`, `riskFactors`, `associations`, `bindingType`, `openIncidents`, `compromisedEntities`, `timeline`, `sourceEntityQuery`, `categories`, `accounts`, `ActiveDirectoryAccountDescriptor`, `SsoUserAccountDescriptor`, `AzureCloudServiceAdapterDescriptor`, `CloudServiceAdapterDescriptor`, `EntityAssociation`, `LocalAdminLocalUserAssociation`, `LocalAdminDomainEntityAssociation`, `GeoLocationAssociation`, etc.) is copied verbatim from `falcon_mcp_idp.py`. Do not retype these from memory — copy-paste.

8. **USER vs ENDPOINT conflict.** Upstream prioritises USER on conflict; we preserve that behaviour and explicitly test it (`test_user_criteria_wins_on_user_endpoint_conflict`). The `_log` warning fires so callers have trail when their IP filter was silently dropped.

9. **Output size.** `relationship_analysis` at `depth=3` with 10 entities can easily be 10s of KB. The compact projection shows max 10 associations per entity; full payload is opt-in via `include_raw=True`. Limit param caps to 200 (same as upstream's bound).

10. **Testing via side_effect routing.** `test_resolves_then_runs_details` and `test_multiple_investigation_types_produce_sections` use `side_effect` lambdas that route different queries to different mock responses. This catches wiring bugs (e.g. tool calling the wrong internal helper) that a single `return_value` would miss.

---

## Out of Scope (Deferred to v2)

- **Write operations.** `create_policy_rule`, `delete_policy_rules`, `post_policy_rules`, entity state mutations. Policy management is an admin workflow and belongs in a gated `identity_admin` module, not here.
- **Policy-rule CRUD read path.** FR originally listed `identity_list_policy_rules` / `identity_get_policy_rule`; those are REST endpoints on the same falconpy class (`query_policy_rules`, `get_policy_rules`). Omitted from v1 because the primary triage workflow is entity-risk, not "which policy rule fires here". Add when analyst demand surfaces.
- **Raw GraphQL passthrough tool.** FR open question #2. No — `identity_investigate_entity` + `include_raw=True` covers 95% of needs; a raw-GraphQL power-user tool can come later if needed.
- **Rate limiting / per-module throttling.** FR open question #3. Not solved by this module; if IDP endpoints throttle us, surface the `429` via normal `format_api_error` and let the caller back off. A module-level semaphore is a cross-cutting concern for a separate plan.
- **Bulk / paginated sweeps across many entities.** `limit` cap of 200 deliberately keeps this a triage tool, not a data-export tool.
- **Hostname → entity resolution via Hosts module chain.** Agent is expected to chain `host_lookup` first if it has a hostname but no IP.
- **Caching.** Risk scores can be volatile; no client-side cache.