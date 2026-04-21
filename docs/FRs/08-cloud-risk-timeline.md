# FR 08: Cloud Risk Enriched Timeline

**Requested**: 2026-04-20
**Lens**: Triage + investigation
**Falconpy**: `cloud_security` (endpoint not yet wrapped — may require raw `APIHarnessV2` call)
**Posture**: Read-only
**Size**: Small (single endpoint)

## Problem

Existing MCP cloud tools (`cloud_get_risks`, `cloud_get_iom_detections`,
`cloud_compliance_by_account`) return the current state of a cloud risk but not
*how it got there*. When triaging a risk on a specific asset, the agent cannot
answer:

- When was this misconfiguration introduced?
- Which revision / change introduced it?
- Who made the change?
- Has this risk re-opened before, and what triggered each occurrence?

Today this requires pivoting into the Falcon Cloud Security console's new
Timeline Explorer view (released 2026-04 — see CrowdStrike release notes
"Uncover the Root Cause of Cloud Risks with Timeline Explorer").

## Impact

Unlocks root-cause analysis for cloud posture alerts inside the MCP workflow:

1. **Cloud IOM/CSPM triage**: given an asset + risk, return the change event
   that introduced it (actor, timestamp, config diff). Converts "this bucket
   is public" into "this bucket was made public by <principal> at <timestamp>
   via <change>" in a single tool call.
2. **Recurrence analysis**: detect risks that have opened/closed/reopened,
   useful for spotting broken remediation or drift loops.
3. **Cross-reference with CloudTrail detections**: pair timeline actor/time
   data with existing AWS detections to confirm whether the change was
   authorized.

## Proposed MCP Tools

| Tool | Purpose | Key args |
|---|---|---|
| `cloud_get_risk_timeline` | Retrieve enriched timeline for a single cloud asset: risk history, config changes, audit events | `asset_id: str`, `risk_id: str` (optional — scope to one risk), `time_range: str` |

## Falconpy / API Methods Used

| MCP tool | API endpoint | Falconpy method |
|---|---|---|
| `cloud_get_risk_timeline` | `GET /entities/cloud-risks-enriched-timeline/v1` | Not yet wrapped in installed falconpy (`cloud_security` has `combined_cloud_risks` but no timeline method). Implement via `APIHarnessV2` raw call until falconpy adds it, then switch. |

## Safety & Scope

- **Read-only.** Single GET endpoint, no writes.
- **Tenant availability.** Released for US-1, US-2, EU-1 (we're US-2 → in
  scope). US-GOV-1 rolling out; tool should surface a clean error if the
  endpoint 404s on tenants without the feature rather than a generic
  stack trace.
- **Subscription gated.** Requires Falcon Cloud Security (any CNAPP tier).
  Handle 403 gracefully.
- **Output shaping.** Timeline responses can be large for long-lived assets;
  project a triage-friendly subset by default (event timestamp, event type,
  actor, risk_id, change_summary) and expose a `full=true` flag for the raw
  payload.

## Open Questions

1. **Asset ID format.** What identifier does the endpoint accept — internal
   CrowdStrike asset UUID, cloud-native ARN/resource ID, or both? Confirm
   against the swagger when falconpy wraps it.
2. **Risk scoping.** If `risk_id` is omitted, does the endpoint return all
   risks on the asset, or does it require a risk filter? Impacts whether
   the tool is primarily asset-centric or risk-centric.
3. **Should this wait for falconpy coverage?** The raw `APIHarnessV2` path
   works today but adds a maintenance edge case. If falconpy's release
   cadence adds the method within a few weeks, deferring avoids churn.
