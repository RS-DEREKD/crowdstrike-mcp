# FR 08: Cloud Risk Enriched Timeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship one read-only MCP tool, `cloud_get_risk_timeline`, that returns the enriched Falcon Cloud Security timeline (risk-instance history + configuration changes + actors) for a single cloud asset keyed by its GCRN.

**Architecture:** Extend the existing `CloudSecurityModule` in `src/crowdstrike_mcp/modules/cloud_security.py`. Call the endpoint `GET /cloud-security-timeline/entities/cloud-risks-enriched-timeline/v1` via `falconpy.APIHarnessV2` (no native wrapper yet; mirrors the fallback pattern in `correlation.py`). Register the tool only when `APIHarnessV2` is importable. All filtering (`risk_id`, `since`, `max_results`) happens client-side — the endpoint's only parameter is `id` (the GCRN).

**Tech Stack:** Python 3.11+, `crowdstrike-falconpy>=1.6.1` (for `APIHarnessV2`), `mcp>=1.12.1`, FastMCP, pytest.

**Spec:** `docs/superpowers/specs/2026-04-21-fr08-cloud-risk-timeline-design.md`
**FR doc:** `docs/FRs/08-cloud-risk-timeline.md`

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `src/crowdstrike_mcp/modules/cloud_security.py` | Modify | Add `APIHarnessV2` import flag, tool method, internal `_get_risk_timeline`, registration guard |
| `src/crowdstrike_mcp/common/api_scopes.py` | Modify | Add scope mapping for the pinned operation id |
| `tests/test_cloud_timeline.py` | Create | Unit tests with fixtures derived from the swagger example |
| `tests/test_smoke_tools_list.py` | Modify | Add `cloud_get_risk_timeline` to `EXPECTED_READ_TOOLS` |
| `README.md` | Modify | Add tool row to Cloud Security table (~line 294) and API-scope table (~line 552) |
| `docs/FRs/08-cloud-risk-timeline.md` | Modify | Mark open questions resolved, link to design doc |

---

## Task 1: Scaffold imports, fixtures, and test file

**Files:**
- Modify: `src/crowdstrike_mcp/modules/cloud_security.py` (add `APIHarnessV2` import flag near the top, alongside the three existing `try:` blocks)
- Create: `tests/test_cloud_timeline.py`

### Step 1.1: Add `APIHarnessV2` import block to `cloud_security.py`

Open `src/crowdstrike_mcp/modules/cloud_security.py`. After the existing `CloudSecurityAssets` try/except (around lines 37–42), append:

```python
try:
    from falconpy import APIHarnessV2

    HARNESS_AVAILABLE = True
except ImportError:
    HARNESS_AVAILABLE = False
```

- [ ] Make the edit above.

- [ ] **Step 1.2: Verify import still works**

Run: `python -c "from crowdstrike_mcp.modules.cloud_security import HARNESS_AVAILABLE; print(HARNESS_AVAILABLE)"`
Expected: `True`

- [ ] **Step 1.3: Create fixture file `tests/test_cloud_timeline.py`**

Create the file with fixtures matching the swagger example. The fixture represents one AWS S3 bucket with two risk instances (one open, one resolved-then-reopened) and two configuration changes.

```python
"""Tests for cloud_get_risk_timeline tool."""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest


SAMPLE_TIMELINE_BODY = {
    "resources": [
        {
            "asset": {
                "id": "crn:aws:s3:us-east-1:123456789012:bucket/example-bucket",
                "account_id": "123456789012",
                "account_name": "prod-account",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "resource_id": "example-bucket",
                "type": "AWS::S3::Bucket",
            },
            "timeline": {
                "configuration_changes": [
                    {
                        "id": "cc-001",
                        "asset_id": "crn:aws:s3:us-east-1:123456789012:bucket/example-bucket",
                        "asset_revision": 41,
                        "external_asset_type": "AWS::S3::Bucket",
                        "updated_at": "2026-04-10T11:59:00Z",
                        "changes": [
                            {
                                "action": "set",
                                "attribute": "public_access_block.block_public_acls",
                                "details": {"value": True},
                            }
                        ],
                        "resource_events": [
                            {
                                "event_name": "PutPublicAccessBlock",
                                "timestamp": "2026-04-10T11:59:00Z",
                                "user_id": "arn:aws:iam::123456789012:user/alice",
                                "user_name": "alice",
                            }
                        ],
                    },
                    {
                        "id": "cc-002",
                        "asset_id": "crn:aws:s3:us-east-1:123456789012:bucket/example-bucket",
                        "asset_revision": 42,
                        "external_asset_type": "AWS::S3::Bucket",
                        "updated_at": "2026-04-18T09:12:00Z",
                        "changes": [
                            {
                                "action": "set",
                                "attribute": "public_access_block.block_public_acls",
                                "details": {"value": False},
                            }
                        ],
                        "resource_events": [
                            {
                                "event_name": "PutPublicAccessBlock",
                                "timestamp": "2026-04-18T09:12:00Z",
                                "user_id": "arn:aws:iam::123456789012:user/bob",
                                "user_name": "bob",
                            }
                        ],
                    },
                ],
                "risks": {
                    "risk_instances": [
                        {
                            "id": "ri-100",
                            "rule_name": "S3 bucket publicly accessible",
                            "severity": "high",
                            "current_status": "open",
                            "reason": "block_public_acls disabled",
                            "first_seen": "2026-04-18T09:12:00Z",
                            "last_seen": "2026-04-21T15:00:00Z",
                            "resolved_at": None,
                            "risk_factors_categories": ["data_exposure"],
                            "events": [
                                {
                                    "event_type": "risk_reopened",
                                    "occurred_at": "2026-04-18T09:12:00Z",
                                    "details": {},
                                },
                                {
                                    "event_type": "risk_opened",
                                    "occurred_at": "2026-04-05T08:00:00Z",
                                    "details": {},
                                },
                            ],
                        },
                        {
                            "id": "ri-200",
                            "rule_name": "S3 bucket missing encryption",
                            "severity": "medium",
                            "current_status": "resolved",
                            "reason": "sse-s3 not configured",
                            "first_seen": "2026-03-01T00:00:00Z",
                            "last_seen": "2026-03-15T00:00:00Z",
                            "resolved_at": "2026-03-15T00:00:00Z",
                            "risk_factors_categories": ["encryption"],
                            "events": [
                                {
                                    "event_type": "risk_resolved",
                                    "occurred_at": "2026-03-15T00:00:00Z",
                                    "details": {},
                                },
                                {
                                    "event_type": "risk_opened",
                                    "occurred_at": "2026-03-01T00:00:00Z",
                                    "details": {},
                                },
                            ],
                        },
                    ]
                },
            },
        }
    ]
}


@pytest.fixture
def cloud_module(mock_client):
    """Create CloudSecurityModule with all falconpy classes (and APIHarnessV2) mocked."""
    with patch("crowdstrike_mcp.modules.cloud_security.CloudSecurity") as MockCS, \
         patch("crowdstrike_mcp.modules.cloud_security.CloudSecurityDetections") as MockCSD, \
         patch("crowdstrike_mcp.modules.cloud_security.CloudSecurityAssets") as MockCSA, \
         patch("crowdstrike_mcp.modules.cloud_security.APIHarnessV2") as MockHarness:
        mock_cs = MagicMock()
        mock_csd = MagicMock()
        mock_csa = MagicMock()
        mock_harness = MagicMock()
        MockCS.return_value = mock_cs
        MockCSD.return_value = mock_csd
        MockCSA.return_value = mock_csa
        MockHarness.return_value = mock_harness

        from crowdstrike_mcp.modules.cloud_security import CloudSecurityModule

        module = CloudSecurityModule(mock_client)

        def _fake_service(cls):
            name = cls.__name__
            return {
                "CloudSecurity": mock_cs,
                "CloudSecurityDetections": mock_csd,
                "CloudSecurityAssets": mock_csa,
                "APIHarnessV2": mock_harness,
            }[name]

        module._service = _fake_service
        module.harness = mock_harness
        return module
```

- [ ] Create the file above.

- [ ] **Step 1.4: Run pytest to confirm the file is discovered with no collection errors**

Run: `pytest tests/test_cloud_timeline.py -q`
Expected: `no tests ran` (0 tests, 0 errors).

- [ ] **Step 1.5: Commit**

```bash
git add src/crowdstrike_mcp/modules/cloud_security.py tests/test_cloud_timeline.py
git commit -m "chore(cloud): scaffold APIHarnessV2 flag and timeline test fixtures

Adds optional APIHarnessV2 import (HARNESS_AVAILABLE flag) to cloud_security
module and creates tests/test_cloud_timeline.py with swagger-derived
fixtures. Mirrors the harness fallback pattern in correlation.py."
```

---

## Task 2: Pin the falconpy operation id and scope mapping

**Purpose:** The endpoint is not wrapped as a native method, so we call it through `APIHarnessV2.command(<operation_id>, **kwargs)`. The operation id comes from the swagger's `operationId` and is stable across falconpy releases. We pin it here and add the scope to `api_scopes.py` so 403 messages include actionable guidance.

**Files:**
- Modify: `src/crowdstrike_mcp/common/api_scopes.py` (add entry in the cloud section near line 54–59)

### Step 2.1: Discover the operation id

- [ ] Run a one-shot Python command to list `APIHarnessV2` operations whose name contains "timeline":

```bash
python -c "from falconpy import APIHarnessV2; a = APIHarnessV2(client_id='x', client_secret='y', base_url='https://api.crowdstrike.com'); print([c for c in a.commands if 'timeline' in c[0].lower() or 'enriched' in c[0].lower()])"
```

Expected: a list like `[('GetCloudRisksEnrichedTimeline', '/cloud-security-timeline/entities/cloud-risks-enriched-timeline/v1', 'GET', ...)]`. Capture the exact operation id string (first element of the tuple).

If the list is empty, the installed falconpy version is older than the endpoint. In that case, call the endpoint by path instead via `APIHarnessV2.override(method="GET", route="/cloud-security-timeline/entities/cloud-risks-enriched-timeline/v1", parameters={"id": asset_id})` — pin a sentinel like `"__override__"` as the operation id for the scope map and note this in an inline comment.

- [ ] **Step 2.2: Record the pinned operation id**

Define a module-level constant at the top of `cloud_security.py` (just below the `HARNESS_AVAILABLE` block):

```python
# Falconpy operation id for GET /cloud-security-timeline/entities/cloud-risks-enriched-timeline/v1.
# Pinned via APIHarnessV2 introspection on 2026-04-21; verified with the installed falconpy version.
TIMELINE_OPERATION_ID = "GetCloudRisksEnrichedTimeline"  # replace with the string discovered in Step 2.1
```

Replace the default value with the exact string from Step 2.1 before continuing.

- [ ] **Step 2.3: Add API scope mapping**

Edit `src/crowdstrike_mcp/common/api_scopes.py`. In the cloud block (near lines 54–59), add:

```python
    "GetCloudRisksEnrichedTimeline": ["cloud-security:read"],
```

Replace the key with whatever `TIMELINE_OPERATION_ID` was pinned to in Step 2.2. The scope `cloud-security:read` matches `combined_cloud_risks` (the same service family).

- [ ] **Step 2.4: Verify the scope lookup works**

Run: `python -c "from crowdstrike_mcp.common.api_scopes import get_required_scopes; print(get_required_scopes('GetCloudRisksEnrichedTimeline'))"`
Expected: `['cloud-security:read']` (or whatever key you pinned).

- [ ] **Step 2.5: Commit**

```bash
git add src/crowdstrike_mcp/modules/cloud_security.py src/crowdstrike_mcp/common/api_scopes.py
git commit -m "feat(cloud): pin timeline operation id and api scope

Pins TIMELINE_OPERATION_ID for the enriched timeline endpoint discovered
via APIHarnessV2 introspection, and registers the cloud-security:read
scope so 403 responses include actionable guidance."
```

---

## Task 3: Happy-path projection — `_get_risk_timeline` returns shaped dict

**Files:**
- Modify: `src/crowdstrike_mcp/modules/cloud_security.py` (add `_get_risk_timeline` method at the end of the class, alongside the other `_get_*` / `_query_*` internal methods)
- Modify: `tests/test_cloud_timeline.py`

### Step 3.1: Write the failing projection test

Append to `tests/test_cloud_timeline.py`:

```python
class TestGetRiskTimelineProjection:
    """Unit tests for _get_risk_timeline — projection only (no filters, no merge)."""

    def test_returns_shaped_asset_block(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(
            asset_id="crn:aws:s3:us-east-1:123456789012:bucket/example-bucket"
        )
        assert result["success"] is True
        asset = result["asset"]
        assert asset["id"] == "crn:aws:s3:us-east-1:123456789012:bucket/example-bucket"
        assert asset["cloud_provider"] == "aws"
        assert asset["account_id"] == "123456789012"
        assert asset["region"] == "us-east-1"
        assert asset["resource_id"] == "example-bucket"
        assert asset["type"] == "AWS::S3::Bucket"

    def test_projects_risk_instances(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:...")
        assert result["total_risks"] == 2
        risk = next(r for r in result["risks"] if r["id"] == "ri-100")
        assert risk["rule_name"] == "S3 bucket publicly accessible"
        assert risk["severity"] == "high"
        assert risk["current_status"] == "open"
        assert risk["first_seen"] == "2026-04-18T09:12:00Z"
        assert risk["resolved_at"] is None
        assert risk["risk_factors_categories"] == ["data_exposure"]
        assert len(risk["events"]) == 2

    def test_projects_configuration_changes(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:...")
        assert result["total_changes"] == 2
        change = next(c for c in result["changes"] if c["id"] == "cc-002")
        assert change["asset_revision"] == 42
        assert change["external_asset_type"] == "AWS::S3::Bucket"
        assert change["updated_at"] == "2026-04-18T09:12:00Z"
        assert change["changes"] == [
            {"action": "set", "attribute": "public_access_block.block_public_acls"}
        ]
        assert change["resource_events"][0]["event_name"] == "PutPublicAccessBlock"
        assert change["resource_events"][0]["user_name"] == "bob"

    def test_passes_asset_id_as_query_parameter(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        cloud_module._get_risk_timeline(asset_id="crn:example")
        # command() called exactly once with override="GET,<path>" and parameters={"id": <gcrn>}
        assert cloud_module.harness.command.call_count == 1
        _, kwargs = cloud_module.harness.command.call_args
        assert kwargs.get("override", "").startswith("GET,/cloud-security-timeline")
        assert kwargs.get("parameters", {}).get("id") == "crn:example"
```

- [ ] Add the test class above.

- [ ] **Step 3.2: Run the tests and confirm they fail with AttributeError**

Run: `pytest tests/test_cloud_timeline.py::TestGetRiskTimelineProjection -q`
Expected: FAIL (`AttributeError: 'CloudSecurityModule' object has no attribute '_get_risk_timeline'`).

- [ ] **Step 3.3: Implement `_get_risk_timeline` projection**

Append this method to the `CloudSecurityModule` class in `src/crowdstrike_mcp/modules/cloud_security.py`, after `_get_compliance_by_account`:

```python
    def _get_risk_timeline(self, asset_id, risk_id=None, since=None, full=False, max_results=50):
        if not HARNESS_AVAILABLE:
            return {"success": False, "error": "APIHarnessV2 client not available"}
        try:
            harness = self._service(APIHarnessV2)
            r = harness.command(
                override=TIMELINE_OVERRIDE,
                parameters={"id": asset_id},
            )

            if r["status_code"] != 200:
                err = format_api_error(
                    r,
                    "Failed to get cloud risk timeline",
                    operation=TIMELINE_OPERATION_ID,
                )
                if r["status_code"] == 429:
                    err += "\n\nRate limit: this endpoint allows 500 requests/min per CID."
                return {"success": False, "error": err}

            resources = r.get("body", {}).get("resources", [])
            if not resources:
                return {
                    "success": False,
                    "error": (
                        f"No timeline found for GCRN '{asset_id}' "
                        "(feature may not be enabled on this tenant or GCRN is unknown)."
                    ),
                }

            entry = resources[0]
            a = entry.get("asset", {}) or {}
            tl = entry.get("timeline", {}) or {}

            asset = {
                "id": a.get("id", ""),
                "cloud_provider": a.get("cloud_provider", ""),
                "account_id": a.get("account_id", ""),
                "account_name": a.get("account_name", ""),
                "region": a.get("region", ""),
                "resource_id": a.get("resource_id", ""),
                "type": a.get("type", ""),
            }

            risks = []
            for ri in (tl.get("risks", {}) or {}).get("risk_instances", []) or []:
                risks.append(
                    {
                        "id": ri.get("id", ""),
                        "rule_name": ri.get("rule_name", ""),
                        "severity": ri.get("severity", ""),
                        "current_status": ri.get("current_status", ""),
                        "reason": ri.get("reason", ""),
                        "first_seen": ri.get("first_seen", ""),
                        "last_seen": ri.get("last_seen", ""),
                        "resolved_at": ri.get("resolved_at"),
                        "risk_factors_categories": ri.get("risk_factors_categories", []),
                        "events": [
                            {
                                "event_type": e.get("event_type", ""),
                                "occurred_at": e.get("occurred_at", ""),
                            }
                            for e in (ri.get("events") or [])
                        ],
                    }
                )

            changes = []
            for cc in tl.get("configuration_changes", []) or []:
                changes.append(
                    {
                        "id": cc.get("id", ""),
                        "asset_revision": cc.get("asset_revision", 0),
                        "external_asset_type": cc.get("external_asset_type", ""),
                        "updated_at": cc.get("updated_at", ""),
                        "changes": [
                            {
                                "action": ch.get("action", ""),
                                "attribute": ch.get("attribute", ""),
                            }
                            for ch in (cc.get("changes") or [])
                        ],
                        "resource_events": [
                            {
                                "event_name": ev.get("event_name", ""),
                                "timestamp": ev.get("timestamp", ""),
                                "user_id": ev.get("user_id", ""),
                                "user_name": ev.get("user_name", ""),
                            }
                            for ev in (cc.get("resource_events") or [])
                        ],
                    }
                )

            return {
                "success": True,
                "asset": asset,
                "risks": risks,
                "changes": changes,
                "timeline": [],  # populated in Task 5
                "total_risks": len(risks),
                "total_changes": len(changes),
            }
        except Exception as e:
            return {"success": False, "error": f"Error getting cloud risk timeline: {e}"}
```

- [ ] **Step 3.4: Run the tests and confirm they pass**

Run: `pytest tests/test_cloud_timeline.py::TestGetRiskTimelineProjection -q`
Expected: 4 passed.

- [ ] **Step 3.5: Run the full suite**

Run: `pytest -q --no-header`
Expected: all green (185 + 4 new = 189 passed).

- [ ] **Step 3.6: Commit**

```bash
git add src/crowdstrike_mcp/modules/cloud_security.py tests/test_cloud_timeline.py
git commit -m "feat(cloud): project enriched timeline response

Adds _get_risk_timeline that calls the endpoint via APIHarnessV2 and
projects the response into flat asset/risks/changes dicts. Unit tests
cover asset projection, risk_instance projection, configuration_changes
projection, and verify the endpoint is called with id=<GCRN>."
```

---

## Task 4: Client-side filters — `risk_id` and `since`

**Files:**
- Modify: `src/crowdstrike_mcp/modules/cloud_security.py` (extend `_get_risk_timeline`)
- Modify: `tests/test_cloud_timeline.py`

### Step 4.1: Write the failing filter tests

Append to `tests/test_cloud_timeline.py`:

```python
class TestRiskTimelineFilters:
    """Client-side filter behaviour."""

    def test_risk_id_filter_keeps_only_matching_instance(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", risk_id="ri-100")
        assert result["total_risks"] == 1
        assert result["risks"][0]["id"] == "ri-100"
        # Changes untouched by risk_id filter
        assert result["total_changes"] == 2

    def test_risk_id_filter_no_match_yields_empty_risks(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", risk_id="ri-nope")
        assert result["success"] is True
        assert result["total_risks"] == 0
        assert result["risks"] == []

    def test_since_drops_older_risk_events(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        # Drop everything before 2026-04-01 → ri-200 has no remaining events (all before)
        # and ri-100 keeps one event (2026-04-18). ri-200 should be removed entirely.
        result = cloud_module._get_risk_timeline(asset_id="crn:x", since="2026-04-01T00:00:00Z")
        ri_ids = {r["id"] for r in result["risks"]}
        assert ri_ids == {"ri-100"}
        ri100 = result["risks"][0]
        assert len(ri100["events"]) == 1
        assert ri100["events"][0]["occurred_at"] == "2026-04-18T09:12:00Z"

    def test_since_drops_older_configuration_changes(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", since="2026-04-15T00:00:00Z")
        assert {c["id"] for c in result["changes"]} == {"cc-002"}
```

- [ ] Add the test class above.

- [ ] **Step 4.2: Run the tests and confirm they fail**

Run: `pytest tests/test_cloud_timeline.py::TestRiskTimelineFilters -q`
Expected: FAIL (filters not yet applied — `risk_id` ignored, `since` ignored).

- [ ] **Step 4.3: Add filter logic to `_get_risk_timeline`**

In `_get_risk_timeline`, after the `risks` and `changes` lists are built but before the return dict is assembled, insert:

```python
            # --- Client-side filters ---
            if risk_id is not None:
                risks = [r for r in risks if r["id"] == risk_id]

            if since is not None:
                risks = _apply_since_to_risks(risks, since)
                changes = _apply_since_to_changes(changes, since)
```

Then add these two module-level helpers just above the `CloudSecurityModule` class definition (near the top of the file, after the `TIMELINE_OPERATION_ID` constant):

```python
def _apply_since_to_risks(risks: list[dict], since: str) -> list[dict]:
    """Drop risk events older than ``since``; drop risk instances that become empty."""
    out: list[dict] = []
    for r in risks:
        kept = [e for e in r["events"] if e["occurred_at"] >= since]
        if kept:
            out.append({**r, "events": kept})
    return out


def _apply_since_to_changes(changes: list[dict], since: str) -> list[dict]:
    """Drop configuration_change resource_events older than ``since``; drop changes that become empty."""
    out: list[dict] = []
    for c in changes:
        kept = [ev for ev in c["resource_events"] if ev["timestamp"] >= since]
        if kept:
            out.append({**c, "resource_events": kept})
    return out
```

Also update the return dict's `total_risks` / `total_changes` to reflect the filtered lists:

```python
            return {
                "success": True,
                "asset": asset,
                "risks": risks,
                "changes": changes,
                "timeline": [],  # populated in Task 5
                "total_risks": len(risks),
                "total_changes": len(changes),
            }
```

(The block already uses `len(risks)` / `len(changes)`; confirm no change needed. If Task 3's version hard-coded the pre-filter length, update.)

- [ ] **Step 4.4: Run the tests and confirm they pass**

Run: `pytest tests/test_cloud_timeline.py::TestRiskTimelineFilters -q`
Expected: 4 passed.

- [ ] **Step 4.5: Run full suite**

Run: `pytest -q --no-header`
Expected: all green (193 passed).

- [ ] **Step 4.6: Commit**

```bash
git add src/crowdstrike_mcp/modules/cloud_security.py tests/test_cloud_timeline.py
git commit -m "feat(cloud): client-side risk_id and since filters for timeline

Adds _apply_since_to_risks and _apply_since_to_changes helpers. risk_id
keeps only the matching risk_instance; since drops events (and empty
risks/changes) older than the ISO-8601 timestamp."
```

---

## Task 5: Build merged event-level timeline

**Files:**
- Modify: `src/crowdstrike_mcp/modules/cloud_security.py` (extend `_get_risk_timeline` and add a helper)
- Modify: `tests/test_cloud_timeline.py`

### Step 5.1: Write the failing merge tests

Append to `tests/test_cloud_timeline.py`:

```python
class TestMergedTimeline:
    """Event-level merge: risk events + change resource_events, sorted desc by timestamp."""

    def test_timeline_contains_one_row_per_risk_event_and_resource_event(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x")
        # 2 risks × 2 events + 2 changes × 1 resource_event = 6 rows
        assert len(result["timeline"]) == 6

    def test_timeline_sorted_descending_by_timestamp(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x")
        timestamps = [row["timestamp"] for row in result["timeline"]]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_timeline_rows_carry_kind_and_source_id(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x")
        kinds = {row["kind"] for row in result["timeline"]}
        assert kinds == {"risk", "change"}
        risk_row = next(r for r in result["timeline"] if r["kind"] == "risk")
        assert "source_id" in risk_row and risk_row["source_id"].startswith("ri-")
        change_row = next(r for r in result["timeline"] if r["kind"] == "change")
        assert change_row["source_id"].startswith("cc-")

    def test_timeline_respects_max_results(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", max_results=3)
        assert len(result["timeline"]) == 3
        # Still sorted descending
        ts = [row["timestamp"] for row in result["timeline"]]
        assert ts == sorted(ts, reverse=True)

    def test_timeline_emits_synthetic_row_for_risk_with_no_events(self, cloud_module):
        body = {
            "resources": [
                {
                    "asset": SAMPLE_TIMELINE_BODY["resources"][0]["asset"],
                    "timeline": {
                        "configuration_changes": [],
                        "risks": {
                            "risk_instances": [
                                {
                                    "id": "ri-synth",
                                    "rule_name": "silent risk",
                                    "severity": "low",
                                    "current_status": "open",
                                    "reason": "",
                                    "first_seen": "2026-04-01T00:00:00Z",
                                    "last_seen": "2026-04-20T00:00:00Z",
                                    "resolved_at": None,
                                    "risk_factors_categories": [],
                                    "events": [],
                                }
                            ]
                        },
                    },
                }
            ]
        }
        cloud_module.harness.command.return_value = {"status_code": 200, "body": body}
        result = cloud_module._get_risk_timeline(asset_id="crn:x")
        assert len(result["timeline"]) == 1
        row = result["timeline"][0]
        assert row["kind"] == "risk"
        assert row["event_type"] == "risk_current_state"
        assert row["timestamp"] == "2026-04-20T00:00:00Z"
        assert row["source_id"] == "ri-synth"
```

- [ ] Add the test class above.

- [ ] **Step 5.2: Run the tests and confirm they fail**

Run: `pytest tests/test_cloud_timeline.py::TestMergedTimeline -q`
Expected: FAIL (`timeline` is empty per Task 3's placeholder).

- [ ] **Step 5.3: Implement the merge helper and wire into `_get_risk_timeline`**

Add this helper to the module-level helpers near the top of the file (next to `_apply_since_to_risks`):

```python
def _build_merged_timeline(risks: list[dict], changes: list[dict], max_results: int) -> list[dict]:
    """Event-level merge: one row per risk event and per configuration_change resource_event.

    Each row: {kind: 'risk'|'change', event_type|event_name: str, timestamp: str,
               source_id: str, extras: dict}. Rows sorted descending by timestamp,
               trimmed to ``max_results``.
    """
    rows: list[dict] = []

    for r in risks:
        if r["events"]:
            for e in r["events"]:
                rows.append(
                    {
                        "kind": "risk",
                        "event_type": e["event_type"],
                        "timestamp": e["occurred_at"],
                        "source_id": r["id"],
                        "rule_name": r["rule_name"],
                        "severity": r["severity"],
                    }
                )
        else:
            rows.append(
                {
                    "kind": "risk",
                    "event_type": "risk_current_state",
                    "timestamp": r["last_seen"],
                    "source_id": r["id"],
                    "rule_name": r["rule_name"],
                    "severity": r["severity"],
                }
            )

    for c in changes:
        for ev in c["resource_events"]:
            rows.append(
                {
                    "kind": "change",
                    "event_name": ev["event_name"],
                    "timestamp": ev["timestamp"],
                    "source_id": c["id"],
                    "asset_revision": c["asset_revision"],
                    "user_id": ev["user_id"],
                    "user_name": ev["user_name"],
                }
            )

    rows.sort(key=lambda row: row["timestamp"], reverse=True)
    return rows[:max_results]
```

In `_get_risk_timeline`, replace the placeholder `"timeline": []` with:

```python
                "timeline": _build_merged_timeline(risks, changes, max_results),
```

- [ ] **Step 5.4: Run the tests and confirm they pass**

Run: `pytest tests/test_cloud_timeline.py::TestMergedTimeline -q`
Expected: 5 passed.

- [ ] **Step 5.5: Run full suite**

Run: `pytest -q --no-header`
Expected: all green (198 passed).

- [ ] **Step 5.6: Commit**

```bash
git add src/crowdstrike_mcp/modules/cloud_security.py tests/test_cloud_timeline.py
git commit -m "feat(cloud): build merged event-level timeline

Adds _build_merged_timeline: one row per risk event and configuration
change resource_event, sorted descending by timestamp and capped at
max_results. Emits a synthetic risk_current_state row for risk
instances with no events."
```

---

## Task 6: Text formatting — default projection + `full=True` raw JSON

**Files:**
- Modify: `src/crowdstrike_mcp/modules/cloud_security.py` (add public `cloud_get_risk_timeline` method)
- Modify: `tests/test_cloud_timeline.py`

### Step 6.1: Write the failing formatting tests

Append to `tests/test_cloud_timeline.py`:

```python
class TestCloudGetRiskTimelineFormatting:
    """Public tool method: text rendering and full=True raw JSON."""

    def test_default_renders_asset_header(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        out = asyncio.run(
            cloud_module.cloud_get_risk_timeline(asset_id="crn:x")
        )
        assert "Cloud Risk Timeline for" in out
        assert "AWS::S3::Bucket" in out
        assert "123456789012" in out

    def test_default_lists_risks_and_changes(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        out = asyncio.run(
            cloud_module.cloud_get_risk_timeline(asset_id="crn:x")
        )
        assert "S3 bucket publicly accessible" in out
        assert "S3 bucket missing encryption" in out
        assert "PutPublicAccessBlock" in out

    def test_default_renders_merged_timeline_section(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        out = asyncio.run(
            cloud_module.cloud_get_risk_timeline(asset_id="crn:x")
        )
        assert "Merged timeline" in out
        assert "2026-04-18T09:12:00Z" in out

    def test_full_returns_json_payload(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        out = asyncio.run(
            cloud_module.cloud_get_risk_timeline(asset_id="crn:x", full=True)
        )
        parsed = json.loads(out)
        assert parsed["success"] is True
        assert parsed["asset"]["cloud_provider"] == "aws"
        assert parsed["total_risks"] == 2

    def test_empty_timeline_message(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        out = asyncio.run(
            cloud_module.cloud_get_risk_timeline(asset_id="crn:missing")
        )
        assert "No timeline found" in out
        assert "crn:missing" in out

    def test_api_error_surfaces_cleanly(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        out = asyncio.run(
            cloud_module.cloud_get_risk_timeline(asset_id="crn:x")
        )
        assert "Failed to get cloud risk timeline" in out
        assert "403" in out

    def test_429_surfaces_rate_limit_note(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 429,
            "body": {"errors": [{"message": "Too Many Requests"}]},
        }
        out = asyncio.run(
            cloud_module.cloud_get_risk_timeline(asset_id="crn:x")
        )
        assert "429" in out
        assert "500 requests/min" in out
```

- [ ] Add the test class above.

- [ ] **Step 6.2: Run tests to confirm they fail**

Run: `pytest tests/test_cloud_timeline.py::TestCloudGetRiskTimelineFormatting -q`
Expected: FAIL (`AttributeError: ... 'cloud_get_risk_timeline'`).

- [ ] **Step 6.3: Implement the public tool method**

Append this method to `CloudSecurityModule` just after `cloud_compliance_by_account` (before the internal `_get_*` block):

```python
    async def cloud_get_risk_timeline(
        self,
        asset_id: Annotated[str, "GCRN (Global Cloud Resource Name) of the cloud asset"],
        risk_id: Annotated[Optional[str], "Filter to a single risk instance by its id"] = None,
        since: Annotated[Optional[str], "ISO-8601 timestamp; drop events/changes older than this"] = None,
        full: Annotated[bool, "Return the raw JSON payload instead of the projected summary"] = False,
        max_results: Annotated[int, "Cap on total merged timeline rows rendered (default: 50)"] = 50,
    ) -> str:
        """Retrieve the enriched cloud-risk timeline for a single asset (GCRN)."""
        result = self._get_risk_timeline(
            asset_id=asset_id,
            risk_id=risk_id,
            since=since,
            full=full,
            max_results=max_results,
        )

        if not result.get("success"):
            return format_text_response(result.get("error", "Unknown error"), raw=True)

        if full:
            return format_text_response(json.dumps(result, default=str, indent=2), raw=True)

        asset = result["asset"]
        lines: list[str] = [
            f"Cloud Risk Timeline for {asset.get('id', asset_id)}",
            f"Asset: {asset.get('type', '')} in "
            f"{asset.get('cloud_provider', '')}/{asset.get('account_id', '')}/{asset.get('region', '')}"
            f" (resource_id={asset.get('resource_id', '')})",
            "",
        ]

        risks = result["risks"]
        lines.append(f"Risks: {result['total_risks']} total")
        for i, r in enumerate(risks, 1):
            lines.append(
                f"  {i}. [{r['severity'].upper()}] {r['rule_name']}  "
                f"status={r['current_status']}  first_seen={r['first_seen']}  last_seen={r['last_seen']}"
            )
            if r.get("reason"):
                lines.append(f"     reason: {r['reason'][:200]}")
            if r["events"]:
                ev_str = "; ".join(f"{e['event_type']} @ {e['occurred_at']}" for e in r["events"][:5])
                lines.append(f"     events: {ev_str}")
        lines.append("")

        changes = result["changes"]
        lines.append(f"Configuration changes: {result['total_changes']} total")
        for i, c in enumerate(changes, 1):
            lines.append(
                f"  {i}. {c['updated_at']}  rev {c['asset_revision']}  {c['external_asset_type']}"
            )
            if c.get("changes"):
                chg_str = "; ".join(f"{ch['action']} {ch['attribute']}" for ch in c["changes"][:5])
                lines.append(f"     changes: {chg_str}")
            for ev in c.get("resource_events", [])[:3]:
                lines.append(
                    f"     triggered by: {ev.get('event_name', '')} "
                    f"user={ev.get('user_name', ev.get('user_id', ''))}"
                )
        lines.append("")

        tl = result["timeline"]
        lines.append(f"Merged timeline (most recent first, up to {max_results}):")
        for row in tl:
            if row["kind"] == "risk":
                lines.append(
                    f"  {row['timestamp']}  risk     {row['event_type']}  {row.get('rule_name', '')}"
                )
            else:
                lines.append(
                    f"  {row['timestamp']}  change   rev{row.get('asset_revision', '?')}  "
                    f"{row.get('event_name', '')} by {row.get('user_name', row.get('user_id', ''))}"
                )

        return format_text_response("\n".join(lines), raw=True)
```

- [ ] **Step 6.4: Run the tests and confirm they pass**

Run: `pytest tests/test_cloud_timeline.py::TestCloudGetRiskTimelineFormatting -q`
Expected: 7 passed.

- [ ] **Step 6.5: Run full suite**

Run: `pytest -q --no-header`
Expected: all green (205 passed).

- [ ] **Step 6.6: Commit**

```bash
git add src/crowdstrike_mcp/modules/cloud_security.py tests/test_cloud_timeline.py
git commit -m "feat(cloud): cloud_get_risk_timeline public tool method

Adds the async tool that calls _get_risk_timeline, renders a
triage-friendly summary (asset header, risks, changes, merged
timeline), and returns raw JSON when full=True. Empty timelines and
API errors surface as human-readable strings."
```

---

## Task 7: Register tool with HARNESS_AVAILABLE guard

**Files:**
- Modify: `src/crowdstrike_mcp/modules/cloud_security.py` (extend `register_tools`)
- Modify: `src/crowdstrike_mcp/modules/cloud_security.py` (update module docstring)
- Modify: `tests/test_cloud_timeline.py`
- Modify: `tests/test_smoke_tools_list.py` (add tool to `EXPECTED_READ_TOOLS`)

### Step 7.1: Write the failing registration tests

Append to `tests/test_cloud_timeline.py`:

```python
class TestCloudTimelineRegistration:
    def test_tool_registers_as_read_when_harness_available(self, cloud_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        cloud_module.register_tools(server)
        assert "cloud_get_risk_timeline" in cloud_module.tools

    def test_tool_not_registered_when_harness_unavailable(self, mock_client):
        # Patch HARNESS_AVAILABLE to False and verify the tool is skipped
        with patch("crowdstrike_mcp.modules.cloud_security.CloudSecurity") as MockCS, \
             patch("crowdstrike_mcp.modules.cloud_security.CloudSecurityDetections") as MockCSD, \
             patch("crowdstrike_mcp.modules.cloud_security.CloudSecurityAssets") as MockCSA, \
             patch("crowdstrike_mcp.modules.cloud_security.HARNESS_AVAILABLE", False):
            MockCS.return_value = MagicMock()
            MockCSD.return_value = MagicMock()
            MockCSA.return_value = MagicMock()
            from crowdstrike_mcp.modules.cloud_security import CloudSecurityModule
            module = CloudSecurityModule(mock_client)
            server = MagicMock()
            server.tool.return_value = lambda fn: fn
            module.register_tools(server)
            assert "cloud_get_risk_timeline" not in module.tools
            # Other tools still registered
            assert "cloud_get_risks" in module.tools
```

- [ ] Add the test class above.

- [ ] **Step 7.2: Run tests to confirm they fail**

Run: `pytest tests/test_cloud_timeline.py::TestCloudTimelineRegistration -q`
Expected: FAIL (tool not registered).

- [ ] **Step 7.3: Wire registration into `register_tools`**

At the end of `CloudSecurityModule.register_tools`, add:

```python
        if HARNESS_AVAILABLE:
            self._add_tool(
                server,
                self.cloud_get_risk_timeline,
                name="cloud_get_risk_timeline",
                description=(
                    "Retrieve the Falcon Cloud Security enriched timeline for a cloud "
                    "asset by GCRN: risk-instance history (open/close/reopen events), "
                    "configuration changes, and the actors behind them. Answers "
                    "'how did this risk get here?' for a single asset."
                ),
            )
```

- [ ] **Step 7.4: Update the module docstring tool list**

In `cloud_security.py`, replace the `Tools:` list at the top of the module with:

```python
"""
Cloud Security Module — cloud risks, IOM detections, assets, compliance, and timelines.

Tools:
  cloud_get_risks             — Cloud security risks ranked by score
  cloud_get_iom_detections    — IOM detections with MITRE and remediation
  cloud_query_assets          — Cloud asset inventory across providers
  cloud_compliance_by_account — Compliance posture by account/region
  cloud_get_risk_timeline     — Enriched risk/change timeline for one asset (GCRN)
"""
```

- [ ] **Step 7.5: Add the tool to `EXPECTED_READ_TOOLS` in the smoke test**

Edit `tests/test_smoke_tools_list.py`. Inside the `EXPECTED_READ_TOOLS` set, after `"cloud_compliance_by_account"` (line 49), add:

```python
    "cloud_get_risk_timeline",
```

Also add `"APIHarnessV2"` to the `_patch_falconpy` function's `cloud_security` patch dict:

```python
        patch.multiple(
            "crowdstrike_mcp.modules.cloud_security",
            CloudSecurity=MagicMock(),
            CloudSecurityDetections=MagicMock(),
            CloudSecurityAssets=MagicMock(),
            APIHarnessV2=MagicMock(),
        ),
```

Leave `HARNESS_AVAILABLE` as its real value (True in a normal install) so the smoke test sees the tool.

- [ ] **Step 7.6: Run registration tests and smoke test**

Run: `pytest tests/test_cloud_timeline.py::TestCloudTimelineRegistration tests/test_smoke_tools_list.py -q`
Expected: all passed.

- [ ] **Step 7.7: Run full suite**

Run: `pytest -q --no-header`
Expected: all green (207 passed).

- [ ] **Step 7.8: Commit**

```bash
git add src/crowdstrike_mcp/modules/cloud_security.py tests/test_cloud_timeline.py tests/test_smoke_tools_list.py
git commit -m "feat(cloud): register cloud_get_risk_timeline tool

Registers the tool at read tier when APIHarnessV2 is importable.
Module gracefully degrades to its existing 4 tools when the harness
is unavailable. Smoke test allowlist and falconpy patch updated."
```

---

## Task 8: Docs — README and FR doc

**Files:**
- Modify: `README.md`
- Modify: `docs/FRs/08-cloud-risk-timeline.md`

### Step 8.1: Add the tool to the README Cloud Security table

In `README.md`, locate the Cloud Security tool table (near line 294). After the `cloud_compliance_by_account` row, add:

```markdown
| `cloud_get_risk_timeline` | Enriched per-asset timeline (GCRN): risk open/close/reopen events + config changes + actors |
```

- [ ] **Step 8.2: Add the tool to the README API-scope table**

In `README.md`, locate the scope table (near line 552). After the `cloud_compliance_by_account` row, add:

```markdown
| `cloud_get_risk_timeline` | Cloud Security | `cloud-security:read` | |
```

- [ ] **Step 8.3: Update module and tool counts in the README header**

Line 5 currently reads: `**v3.0** — Modular auto-discovery architecture with 51 tools across 11 modules.`

Increment the tool count to 52. (Module count unchanged — we extended an existing module.)

- [ ] **Step 8.4: Update `docs/FRs/08-cloud-risk-timeline.md`**

At the end of the `## Open Questions` section, replace the three numbered questions with a resolution block:

```markdown
## Open Questions — Resolved (2026-04-21)

1. **Asset ID format.** Confirmed via swagger: the endpoint accepts a single
   `id` query parameter, a GCRN (Global Cloud Resource Name) string.
2. **Risk scoping.** The endpoint has no server-side `risk_id` filter; it
   returns all risks on the asset. `risk_id` is exposed on the MCP tool as a
   client-side filter.
3. **Wait for falconpy coverage?** No — shipping via `APIHarnessV2` now,
   mirroring the pattern in `correlation.py`. Tracked as a follow-up to swap
   to a native falconpy method once released.

## Design

See `docs/superpowers/specs/2026-04-21-fr08-cloud-risk-timeline-design.md`.
```

- [ ] **Step 8.5: Commit**

```bash
git add README.md docs/FRs/08-cloud-risk-timeline.md
git commit -m "docs(fr08): document cloud_get_risk_timeline tool

Adds the tool to the README Cloud Security and API-scope tables,
bumps the tool count to 52, and resolves the open questions in the
FR doc with a link to the design spec."
```

---

## Task 9: Final sweep — lint, full suite, summary

**Files:** none modified.

- [ ] **Step 9.1: Run ruff format and lint**

Run: `ruff format src/crowdstrike_mcp/modules/cloud_security.py tests/test_cloud_timeline.py`
Run: `ruff check src/crowdstrike_mcp/modules/cloud_security.py tests/test_cloud_timeline.py`
Expected: no errors; either zero files reformatted, or a reformat commit.

If ruff reformats anything:

```bash
git add src/crowdstrike_mcp/modules/cloud_security.py tests/test_cloud_timeline.py
git commit -m "style(cloud): ruff format fr08 additions"
```

- [ ] **Step 9.2: Run the full test suite with verbose failure output**

Run: `pytest -q --no-header`
Expected: all green.

- [ ] **Step 9.3: Confirm tool count via the smoke test**

Run: `pytest tests/test_smoke_tools_list.py -v`
Expected: all four tests pass. `test_no_unexpected_tools` confirms the full registered set matches the allowlist (52 tools total: 40 read + 12 write, including the new `cloud_get_risk_timeline`).

- [ ] **Step 9.4: Print final summary for review**

Run:

```bash
git log --oneline master..HEAD
```

Expected: the commits from Tasks 1–8 (plus the design doc commit from brainstorming, and possibly a ruff commit from Step 9.1). Review the list; each commit should be atomic and self-describing.

---

## Follow-ups (not part of this plan)

1. **Swap `APIHarnessV2` to native falconpy method** once the endpoint is wrapped. Changes: replace `harness.command(TIMELINE_OPERATION_ID, id=asset_id)` with the native call, keep the tool signature unchanged. Drop `HARNESS_AVAILABLE` guard if all code paths move to the native class.
2. **Validate non-AWS payloads.** Swagger is provider-agnostic but real Azure/GCP change-event shapes may differ. Revisit projection keys if payloads in the wild diverge.
