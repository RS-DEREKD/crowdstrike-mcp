# FR 05: Intel + Indicator Graph

**Requested**: 2026-04-17
**Lens**: Hunting (hypothesis- and indicator-driven)
**Falconpy**: `intel` + `intelligence_indicator_graph`
**Posture**: Read-only

## Problem

The MCP has no Falcon Intelligence integration. Today, hypothesis-driven hunts
start from a manual console pivot:

- Analyst reads Falcon Intel's latest Actor/Report/MITRE page
- Manually extracts indicators and TTPs
- Writes a hunt query in the detections repo
- Comes back to MCP to execute against NG-SIEM

The MCP has no way to ask "who is Wicked Panda, what indicators do they use,
what MITRE techniques, and do any of those indicators appear in our telemetry?"
as a single agent-driven flow.

Likewise, indicator pivot (IP → related domains → related hashes → sharing
actors) lives entirely in the console today. The agent can list an IP in an
alert but cannot expand it.

## Impact

Two connected hunting workflows:

1. **Actor-driven hunt prep**: given an actor name or ID, pull associated
   indicators, MITRE techniques, and malware family. Generate an NG-SIEM
   query targeting the indicator set automatically. "Is Wicked Panda's
   latest TTP visible in our fleet?"
2. **IOC pivot during active triage**: given a single indicator from a
   detection (IP, domain, hash), expand to related indicators via the
   Indicator Graph. Feed the expanded set back into a follow-up hunt.

Concrete example: the PR #168 `microsoft___entra_id___distributed_password_spray`
detection identifies user targets but doesn't surface which actor's TTP the
spray matches. With this FR the agent can check whether the source IPs
correlate to any known Intel indicator set, flipping an unattributed incident
into an attributed one.

## Proposed MCP Tools

Two service collections wrapped as one coherent FR — they're frequently used
together.

### Intel (`intel.py`)

| Tool | Purpose | Key args |
|---|---|---|
| `intel_query_actors` | Find actor entity IDs by name, origin, target country, industry | `filter: str` (FQL), `limit: int` |
| `intel_get_actors` | Get full actor entity detail (TTPs, malware families, targets) | `ids: list[str]` |
| `intel_query_indicators` | Find indicator entity IDs by type, value, malicious-confidence | `filter: str`, `limit: int` |
| `intel_get_indicators` | Get full indicator entity detail | `ids: list[str]` |
| `intel_get_mitre_report` | Get a MITRE ATT&CK attribution report for an actor | `actor_id: str`, optional `format: "json"|"csv"` |
| `intel_query_reports` | Find intel reports by topic, actor, date | `filter: str`, `limit: int` |
| `intel_get_reports` | Get intel report metadata | `ids: list[str]` |

Out of v1 scope (include if demand): `get_report_pdf` (binary download),
`get_malware_report`, `get_rule_entities` (YARA rule feeds).

### Indicator Graph (`intelligence_indicator_graph.py`)

Only 2 methods in falconpy — both in scope:

| Tool | Purpose | Key args |
|---|---|---|
| `indicator_graph_search` | Full-text search the indicator graph | `query: str`, `limit: int` |
| `indicator_graph_lookup` | Lookup a specific indicator and its neighbors (related domains, hashes, IPs) | `value: str`, optional `type: str`, optional `depth: int` |

## Falconpy Methods Used

From `src/falconpy/intel.py`:

| MCP tool | Falconpy method |
|---|---|
| `intel_query_actors` | `query_actor_ids()` |
| `intel_get_actors` | `get_actor_entities()` |
| `intel_query_indicators` | `query_indicator_ids()` |
| `intel_get_indicators` | `get_indicator_entities()` |
| `intel_get_mitre_report` | `get_mitre_report()` |
| `intel_query_reports` | `query_report_ids()` |
| `intel_get_reports` | `get_report_entities()` |

From `src/falconpy/intelligence_indicator_graph.py`:

| MCP tool | Falconpy method |
|---|---|
| `indicator_graph_search` | `search()` |
| `indicator_graph_lookup` | `lookup()` |

## Safety & Scope

- **Read-only.** Both collections are pure read surfaces in falconpy.
- **License gating.** Falcon Intel is a paid add-on tier. MCP should detect
  403/401 and return a clean "Intel not licensed on this tenant" error rather
  than a cryptic HTTP failure.
- **Output shaping.** Actor/Report entities include long-form narrative fields
  (thousands of tokens). Provide a `summary_only` mode that returns name,
  origin, target_countries, target_industries, known_as, and aka — full
  narrative available via explicit `get_*` with a `detail=true` flag.
- **Rate limits.** Intel endpoints are stricter than operational endpoints —
  surface retry-after on 429 rather than silent backoff.

## Open Questions

1. **Auto-pivot helper?** A compound tool
   `intel_pivot_indicator(value)` that runs
   `indicator_graph_lookup` → `intel_query_indicators` →
   `intel_get_indicators` in sequence would save the agent two calls per
   pivot. Risk: opinionated shape. Start with primitives, add the compound
   if usage patterns converge.
2. **Does the Intel module need a local cache?** Indicator entities are
   relatively stable (hash-keyed); caching for the agent session avoids
   re-fetching the same record across tools. MCP-wide concern though.
3. **PDF report download.** Useful for human handoff but heavy for agent
   consumption. Defer to v2 of this FR.
