# FR 02: Spotlight Vulnerabilities

**Requested**: 2026-04-17
**Lens**: Triage
**Falconpy**: `spotlight_vulnerabilities`
**Posture**: Read-only

## Problem

During alert triage, the Claude agent can look up a host (`host_lookup` returns
OS, policies, containment status) but cannot answer "is this host vulnerable to
the CVE implicated in the detection?" Today this is a console pivot — opening
Spotlight, searching the host, eyeballing the exposure list.

Specific friction points:

- Malware-download or exploit-attempt alerts on endpoints — knowing the host's
  patch status dictates whether this was a likely compromise or a failed
  exploit against a patched system.
- Advisory-driven hunts (new CVE published by vendor) — starting position
  should be "list affected hosts in our fleet," which today requires console work.

## Impact

Unlocks two workflow patterns:

1. **Host-first triage**: given a host ID or hostname, return all open
   vulnerabilities ranked by exploit probability / severity. "This alert fires
   on a host with 3 critical open exposures vs 0" changes response urgency.
2. **CVE-first hunt**: given a CVE ID, return the set of affected hosts.
   Directly supports threat-intel-driven hunts when a new exploit-in-the-wild
   CVE drops.

## Proposed MCP Tools

| Tool | Purpose | Key args |
|---|---|---|
| `spotlight_query_vulnerabilities` | Find vulnerability IDs matching FQL filter (host, CVE, severity, status) | `filter: str` (FQL), `limit: int`, `after: str` |
| `spotlight_get_vulnerabilities` | Fetch full vulnerability records for a set of IDs | `ids: list[str]` |
| `spotlight_vulnerabilities_combined` | One-shot combined query+get (ergonomic default) | `filter: str`, `limit: int` |
| `spotlight_get_remediations` | Get remediation instructions for vulnerability IDs | `ids: list[str]` |

## Falconpy Methods Used

From `src/falconpy/spotlight_vulnerabilities.py`:

| MCP tool | Falconpy method |
|---|---|
| `spotlight_query_vulnerabilities` | `query_vulnerabilities()` |
| `spotlight_get_vulnerabilities` | `get_vulnerabilities()` |
| `spotlight_vulnerabilities_combined` | `query_vulnerabilities_combined()` |
| `spotlight_get_remediations` | `get_remediations_v2()` (prefer v2 over legacy) |

Falconpy exposes 5 methods total; this FR covers all of them except the
legacy `get_remediations()` in favor of v2.

## Safety & Scope

- **Read-only.** Spotlight is a pure read surface in falconpy — no writes exist.
- **Output shaping.** `spotlight_vulnerabilities_combined` should project a
  triage-friendly subset: CVE, severity, exploit_status, age, affected hosts.
  Raw `products_per_day` / `host_info` arrays belong in the detail call.
- **Result bounding.** Default `limit=50`, max `limit=500`. Large-fleet CVE
  queries will otherwise balloon response size.

## Open Questions

1. **Composite host→CVE helper?** The common triage question is "give me the
   vulnerabilities for host X." This is a natural composition:
   `spotlight_host_vulns(aid_or_hostname)`. Worth adding on top of the raw
   query/get pair. Preference from this caller: yes, include it.
2. Should the MCP pre-filter to "status:open" by default (analysts almost never
   care about remediated vulns during triage)?
3. Does the tenant need to license Spotlight for this module to be registered?
   If so, how does MCP handle the unlicensed-but-registered case gracefully?
