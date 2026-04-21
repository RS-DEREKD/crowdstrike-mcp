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

## Open Questions — Resolved (2026-04-21)

1. **Asset ID format.** Confirmed via swagger: the endpoint accepts a single
   `id` query parameter, a GCRN (Global Cloud Resource Name) string.
2. **Risk scoping.** The endpoint has no server-side `risk_id` filter; it
   returns all risks on the asset. `risk_id` is exposed on the MCP tool as a
   client-side filter.
3. **Wait for falconpy coverage?** No — shipping via `APIHarnessV2.command(override=...)`
   now, since falconpy 1.6.1 does not wrap this endpoint. Mirrors the
   pattern in `correlation.py`. Tracked as a follow-up to swap to a native
   falconpy method once released.

## Design

See `docs/superpowers/specs/2026-04-21-fr08-cloud-risk-timeline-design.md`.
