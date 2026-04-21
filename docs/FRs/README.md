# CrowdStrike MCP — Feature Requests

A batch of feature-request docs for `crowdstrike-mcp`, originally authored 2026-04-17 from
the perspective of a daily consumer (this detections repo). Each doc proposes a
set of MCP tools backed by an existing `falconpy` service collection.

Intended as a handoff to the MCP maintainer. Each FR is self-contained and
independently implementable — they do not depend on each other.

## Index

| # | Title | Primary lens | Falconpy collection | Proposed tools | Status |
|---|---|---|---|---|---|
| 01 | [Identity Protection](01-identity-protection.md) | Triage | `identity_protection` | 4-5 read-only | Implemented |
| 02 | [Spotlight Vulnerabilities](02-spotlight-vulnerabilities.md) | Triage | `spotlight_vulnerabilities` | 3-4 read-only | Implemented |
| 03 | [RTR read-only session + commands](03-rtr-read-only.md) | Triage | `real_time_response` | ~7 (restricted subset) | Implemented |
| 04 | [Falcon X Sandbox](04-falconx-sandbox.md) | Triage + hunting | `falconx_sandbox` | 6-8 (submit + reads) | Proposed |
| 05 | [Intel + Indicator Graph](05-intel-and-indicator-graph.md) | Hunting | `intel` + `intelligence_indicator_graph` | 7-8 | Proposed |
| 06 | [Threat Graph](06-threat-graph.md) | Triage + hunting | `threatgraph` | 4-5 | Proposed |
| 07 | [NGSIEM read expansion](07-ngsiem-read-expansion.md) | IaC + triage | `ngsiem` (read subset) | 12 read-only | Implemented 2026-04-21 |
| 08 | [Cloud Risk Enriched Timeline](08-cloud-risk-timeline.md) | Triage + investigation | `cloud_security` (raw API — new endpoint) | 1 (small) | Proposed |

## Lens definitions

- **Triage (A)**: tools the Claude agent reaches for during live alert investigation — reduces console pivots and enables evidence collection in a single conversation
- **Hunting (C)**: tools that expand what hypothesis-driven or indicator-driven hunts can ask without leaving the MCP

## Format

Each FR follows this structure (mirroring `crowdstrike-mcp/docs/bugs/` conventions):

1. **Problem** — what capability is missing and why it matters
2. **Impact** — concrete workflows this unblocks, ideally with a specific example from the detections repo
3. **Proposed MCP Tools** — tool name, one-line purpose, key arguments
4. **Falconpy Methods Used** — direct mapping to the `falconpy` service class
5. **Safety & Scope** — read/write posture, rate-limit concerns, what is explicitly NOT in scope
6. **Open Questions** — decisions the maintainer needs to make

## Out of scope for this batch

- **Incidents API** — CrowdStrike is deprecating this endpoint soon; skipped on that basis
- **Custom IOA rules** — overlaps with correlation_rules already in MCP; revisit if use case emerges
- **Sensor/IOA/ML exclusions audit** — valuable but narrower than the seven here; candidate for a follow-up batch
- **Admin RTR** (`real_time_response_admin`) — write-heavy; out of scope for FR #03's read-only framing
- **All NGSIEM write/delete/install** — talonctl IaC owns those; FR #07 is read-only
