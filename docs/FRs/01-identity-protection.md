# FR 01: Identity Protection

**Requested**: 2026-04-17
**Lens**: Triage
**Falconpy**: `identity_protection`
**Posture**: Read-only (write/policy-mgmt out of scope)

## Problem

Every EntraID-triggered alert in this environment is triaged without CrowdStrike
Identity Protection context. The detections repo currently ships 151 Microsoft/
EntraID detections and 18 EntraID enrichment saved-searches, but the Claude
agent has no way to ask Falcon Identity Protection whether the target user is
already flagged risky — or why. Analysts pivot to the console for that context.

Recent examples where this gap was felt:

- `microsoft___entra_id___distributed_password_spray` (PR #168) — when this
  fires, the obvious triage question is "does Falcon already consider this
  user identity-compromised?" — not answerable from MCP today.
- 2026-04-16 credential-attack triage week — multi-day investigation of password-
  spray patterns across 70+ user accounts; every account lookup was a manual
  console hop.

## Impact

Unlocks one-call triage context for any EntraID-driven alert:

1. Given a username or UPN, return Falcon's identity-risk posture and the
   underlying signals that drove the score.
2. Given an AD host/device, return the sensor aggregate view Identity
   Protection uses for policy evaluation.
3. Read the live policy-rule set so triage can reason about "would this be
   blocked if the attacker attempted the next step?"

Secondary benefit: community value — many consumers of `crowdstrike-mcp` have
Identity Protection licensed even if this caller's tenant does not currently.

## Proposed MCP Tools

| Tool | Purpose | Key args |
|---|---|---|
| `identity_risk_lookup` | Query sensors/entities by username, UPN, hostname, or IP; return risk score + triggering signals | `username` OR `upn` OR `hostname` OR `ip`; optional `limit` |
| `identity_get_sensor_details` | Retrieve full details for one or more sensor/entity IDs returned by the lookup | `ids: list[str]` |
| `identity_get_sensor_aggregates` | Get aggregate statistics for sensors (risk distribution, trend, etc.) | `body` (falconpy passthrough) |
| `identity_list_policy_rules` | List Identity Protection policy rules with filters | optional `filter`, `limit` |
| `identity_get_policy_rule` | Retrieve a single policy rule by ID for the "would this be blocked?" question | `ids: list[str]` |

Optional advanced (consider punting):
- `identity_graphql` — raw GraphQL passthrough for advanced queries. Falconpy
  exposes `graphql()`; could be a power-user escape hatch. Only include if the
  maintainer sees analyst demand.

## Falconpy Methods Used

From `src/falconpy/identity_protection.py`:

| MCP tool | Falconpy method |
|---|---|
| `identity_risk_lookup` | `query_sensors()` → `get_sensor_details()` chained (MCP composes both) |
| `identity_get_sensor_details` | `get_sensor_details()` |
| `identity_get_sensor_aggregates` | `get_sensor_aggregates()` |
| `identity_list_policy_rules` | `query_policy_rules()` → `get_policy_rules()` chained |
| `identity_get_policy_rule` | `get_policy_rules()` |
| `identity_graphql` (optional) | `graphql()` |

## Safety & Scope

- **Read-only.** Excludes `create_policy_rule` and `delete_policy_rules` — policy
  management is an admin workflow that belongs elsewhere (likely a dedicated
  `identity_admin` module with higher permission gating).
- **Output shaping.** `identity_risk_lookup` should return a compact triage
  projection by default (user, risk_score, top_factors, last_seen). Full
  entity detail available via `identity_get_sensor_details`.
- **Consistent parameter naming.** Align with the existing MCP convention —
  prefer `time_range` over `start_time` (see the existing `ngsiem_query`
  parameter-mismatch bug).

## Open Questions

1. Does the MCP maintainer want a single composed tool (`identity_risk_lookup`
   returns full detail) or the explicit query→get split (matching falconpy
   shape)? Preference from this caller: composed for triage ergonomics.
2. Should the `graphql` passthrough ship in v1 or wait for demand?
3. Rate-limit considerations — Identity Protection endpoints have historically
   been stricter than other Falcon APIs; does MCP need per-module throttling?
