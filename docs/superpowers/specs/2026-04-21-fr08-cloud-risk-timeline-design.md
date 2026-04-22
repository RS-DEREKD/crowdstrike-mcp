# FR 08: Cloud Risk Enriched Timeline — Design

**Date:** 2026-04-21
**Feature Request:** `docs/FRs/08-cloud-risk-timeline.md`
**Posture:** Read-only
**Size:** Small (single endpoint, single tool)

## Goal

Ship one read-only MCP tool, `cloud_get_risk_timeline`, that answers
*"how did this cloud risk get here?"* in one call. The tool wraps the Falcon
Cloud Security *Timeline Explorer* endpoint, returning a merged history of
risk-instance events and configuration changes for a single cloud asset,
keyed by its GCRN (Global Cloud Resource Name).

This is the triage pivot from `cloud_get_risks` / `cloud_get_iom_detections`
(current state of a risk) to "who changed what, when, and how did the risk
open/close/reopen over time?".

## Endpoint

| Field | Value |
|---|---|
| Method | `GET` |
| Path | `/cloud-security-timeline/entities/cloud-risks-enriched-timeline/v1` |
| Required query param | `id` — GCRN string |
| Rate limit | 500 req/min per CID (HTTP 429 on overrun) |
| Response shape | `resources[0]` → `{ asset, timeline: { configuration_changes, risks.risk_instances } }` |

Swagger was reviewed 2026-04-21; the endpoint is **not yet wrapped in the
installed falconpy**. Use `APIHarnessV2` for the raw call now; swap to a
native falconpy method when one lands (tracked as follow-up).

## Architecture

### Module placement

Extend the existing `CloudSecurityModule` in
`src/crowdstrike_mcp/modules/cloud_security.py`. One new tool does not warrant
a new module, and the tool is the natural triage pivot from the other cloud
tools already there.

### Raw-harness fallback pattern

Mirror the precedent set in `src/crowdstrike_mcp/modules/correlation.py`:

```python
try:
    from falconpy import APIHarnessV2
    HARNESS_AVAILABLE = True
except ImportError:
    HARNESS_AVAILABLE = False
```

At tool-registration time, register `cloud_get_risk_timeline` only when
`HARNESS_AVAILABLE` is true. The rest of `CloudSecurityModule` continues to
register regardless, so a missing harness degrades gracefully.

When a future falconpy release wraps the endpoint (e.g. as
`CloudSecurity.get_cloud_risks_enriched_timeline()`), swap the call site and
keep the tool signature unchanged.

### Tool signature

```python
async def cloud_get_risk_timeline(
    asset_id: Annotated[str, "GCRN (Global Cloud Resource Name) of the cloud asset"],
    risk_id: Annotated[Optional[str], "Filter to a single risk instance by its id"] = None,
    since: Annotated[Optional[str], "ISO-8601 timestamp; drop events/changes older than this"] = None,
    full: Annotated[bool, "Return the raw JSON payload instead of the projected summary"] = False,
    max_results: Annotated[int, "Cap on total merged timeline rows rendered (default: 50)"] = 50,
) -> str
```

Only `asset_id` is a server parameter. `risk_id`, `since`, and `max_results`
are all applied client-side in the tool.

### Internal method

`_get_risk_timeline(asset_id, risk_id, since, full, max_results) -> dict`

Returns `{"success": True, "asset": {...}, "risks": [...], "changes": [...],
"timeline": [...], "total_risks": int, "total_changes": int}` on success, or
`{"success": False, "error": str}` on failure.

Flow:

1. Build harness service: `harness = self._service(APIHarnessV2)`.
2. Call: `r = harness.command(<operation_id>, parameters={"id": asset_id})`.
   The operation id will be pinned during implementation after confirming
   against the installed falconpy's swagger dict. Expected: a name of the
   form `GetCloudRisksEnrichedTimelineMixin0` (falconpy convention — verify
   via `falconpy.APIHarnessV2().commands` or the vendored swagger when
   implementing).
3. On non-200, return a shaped error via `format_api_error`.
4. Extract `resources[0]` (endpoint returns one asset block per call).
5. Project:
   - **asset**: `id` (GCRN), `cloud_provider`, `account_id`, `account_name`,
     `region`, `resource_id`, `type`.
   - **risks**: for each `risk_instances[i]` → `id`, `rule_name`, `severity`,
     `current_status`, `first_seen`, `last_seen`, `resolved_at`, `reason`,
     compact `events` (event_type + occurred_at), and
     `risk_factors_categories`.
   - **changes**: for each `configuration_changes[i]` → `id`, `asset_revision`,
     `external_asset_type`, `updated_at`, flattened `changes`
     (action + attribute), and `resource_events`
     (event_name, timestamp, user_id, user_name).
6. Apply client-side filters:
   - if `risk_id` → keep only the matching risk instance.
   - if `since` → drop risk events and config-change resource_events whose
     timestamp is older than `since`; drop risks/changes that become empty
     as a result.
7. Build an event-level merged timeline: one row per risk event (from
   `risk_instance.events[]`, keyed on `occurred_at`) and one row per config
   change's `resource_events[]` entry (keyed on `timestamp`). If a risk
   instance has no events, emit a single synthetic row at `last_seen`
   tagged `risk_current_state`. Sort the merged list descending by
   timestamp; trim to `max_results`.
8. Return the shaped dict.

### Output formatting

Default (`full=False`) — plain text via `format_text_response(..., raw=True)`:

```
Cloud Risk Timeline for <GCRN>
Asset: <type> in <provider>/<account_id>/<region> (resource_id=<...>)

Risks: <N> total
  1. [HIGH] <rule_name>  status=open  first_seen=<ts>  last_seen=<ts>
     reason: <reason[:200]>
     events: risk_opened @ 2026-04-10T12:00Z; risk_reopened @ 2026-04-18T09:12Z

Configuration changes: <M> total
  1. 2026-04-18T09:12Z  rev 42  AWS::S3::Bucket
     changes: set public_access_block.block_public_acls=false
     triggered by: user=arn:aws:iam::... action=PutPublicAccessBlock

Merged timeline (most recent first, up to <max_results>):
  2026-04-18T09:12Z  change   rev42  PutPublicAccessBlock by <user>
  2026-04-18T09:12Z  risk     risk_reopened  <rule_name>
  2026-04-10T12:00Z  risk     risk_opened    <rule_name>
  ...
```

`full=True` → `json.dumps(shaped_dict, default=str, indent=2)` wrapped in
`format_text_response(..., raw=True)`.

### Error handling

| Status | Handling |
|---|---|
| 200, empty `resources` | "No timeline found for GCRN `<id>` (feature may not be enabled on this tenant or GCRN is unknown)." |
| 403 | `format_api_error` surfaces a message noting Falcon Cloud Security subscription / scope is required. |
| 404 | Same as empty-resources message. |
| 429 | Surface rate-limit error with note: endpoint allows 500 req/min per CID. |
| Other | Generic `format_api_error` path. |

## Testing

Add `tests/test_cloud_timeline.py` (new file — keeps existing
`test_cloud_security.py` focused on the previously-shipped tools).

Mock `APIHarnessV2.command()` with fixtures derived from the swagger example
payload. Cases:

1. Happy path — asset + 2 risks + 3 config changes; verify projection and
   merged timeline ordering.
2. `risk_id` filter — keeps only the matching instance; changes unaffected.
3. `since` filter — drops older events; verify risks/changes emptied by
   the filter are removed.
4. `full=True` — raw JSON returned verbatim.
5. `max_results` truncation — timeline list capped.
6. Empty `resources` — clean "no timeline" message.
7. 403 — scope-guidance message.
8. 429 — rate-limit surfaced.
9. `HARNESS_AVAILABLE=False` at import — tool not registered; other
   `cloud_*` tools still present. Covered by patching the flag and
   re-running `register_tools`.

## Registration and docs

- Register in `CloudSecurityModule.register_tools` via `_add_tool(...)`, tier
  `"read"`.
- Tool description (draft): "Retrieve the enriched Falcon Cloud Security
  timeline for a cloud asset by GCRN: risk-instance history (open / close /
  reopen events), configuration changes, and the actors behind them.
  Answers *how did this risk get here?* for a single asset."
- Update the `CloudSecurityModule` module docstring's tool list.
- Add the tool to the tool table in `README.md`.
- Update `docs/FRs/08-cloud-risk-timeline.md`:
  - Mark "Open Questions" resolved (GCRN confirmed; no server-side
    `risk_id` / `time_range`; shipping via `APIHarnessV2`).
  - Link to this design doc.

## Out of scope

- **Bulk / multi-asset timelines.** The endpoint is per-GCRN; no pagination
  over multiple assets. Agents wanting multi-asset views call the tool
  per asset.
- **Write operations.** Timeline is read-only by nature.
- **Response-store integration for oversized payloads.** Default projection +
  `max_results` cap is sufficient for v1; revisit only if real timelines
  blow past sensible text sizes.
- **Native falconpy method.** Swap when falconpy wraps the endpoint;
  tracked as a follow-up, not part of this deliverable.

## Follow-ups

1. Swap `APIHarnessV2` → native falconpy method once released.
2. Extend to non-AWS cloud providers' change-event schemas if payload shapes
   differ in practice (the swagger is provider-agnostic but real payloads
   may vary).
