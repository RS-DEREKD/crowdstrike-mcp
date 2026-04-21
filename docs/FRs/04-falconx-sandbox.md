# FR 04: Falcon X Sandbox

**Requested**: 2026-04-17
**Lens**: Triage + hunting
**Falconpy**: `falconx_sandbox`
**Posture**: Mixed — read-heavy with two explicit writes (`submit`, `upload_sample`)

## Problem

When a detection carries a file hash or the agent retrieves a binary via RTR
(FR #03), there's no way for the MCP to send that sample to Falcon X Sandbox
for dynamic analysis — or to retrieve an existing sandbox report for a hash
the environment has already analyzed.

Today the only dynamic-analysis path in the broader Command Center stack is
VirusTotal via the PhishER pipeline. That's appropriate for email-delivered
samples but not for endpoint-delivered binaries where Falcon X is already
licensed and has richer behavioral data.

## Impact

Two workflow patterns:

1. **Triage on-demand detonation**: a suspicious-executable detection fires,
   agent retrieves the binary via RTR `getfile`, submits to Falcon X, polls
   for the report, and includes behavioral-summary context in its triage
   write-up.
2. **Hash-first lookup during hunts**: given a hash observed in a hunt,
   check if Falcon X already has a report. Avoid re-detonating, pull the
   existing summary directly into the hunt narrative.

Concrete example: the `box___suspicious_file_upload` detection (PR #168) tables
`file.hash.sha1` — but the agent can't actually do anything with that hash
beyond citing it. With this FR, the agent can look up any existing Falcon X
report keyed by the hash and include behavioral details in the triage package.

## Proposed MCP Tools

| Tool | Purpose | Key args |
|---|---|---|
| `sandbox_query_reports` | Find report IDs by filter (sha256, submission time, verdict) | `filter: str` (FQL), `limit: int` |
| `sandbox_get_summary_reports` | Get compact summary for report IDs — verdict + top behaviors | `ids: list[str]` |
| `sandbox_get_reports` | Get full reports (network, process tree, dropped files) | `ids: list[str]` |
| `sandbox_query_samples` | Find sample IDs the environment has ingested | `filter: str`, `limit: int` |
| `sandbox_get_sample_metadata` | Look up sample metadata by sha256 (does the environment already have a report?) | `ids: list[str]` |
| `sandbox_upload_sample` | Upload a sample file for future sandbox submission | `filename: str`, `file_data: bytes`, optional `is_confidential: bool` |
| `sandbox_submit` | Submit a sample (previously uploaded or by URL) for sandbox detonation | `sha256: str` OR `url: str`, `environment_id: int`, optional `action_script`, `system_date` |
| `sandbox_get_artifacts` | Retrieve sandbox artifacts (memdump, extracted strings) referenced in a report | `id: str`, `name: str` |

Optional:
- `sandbox_get_memory_dump` — only if the analyst often pulls memdumps
- `sandbox_get_hex_dump` / `sandbox_get_dump_extracted_strings` — niche

## Falconpy Methods Used

From `src/falconpy/falconx_sandbox.py`:

| MCP tool | Falconpy method |
|---|---|
| `sandbox_query_reports` | `query_reports()` |
| `sandbox_get_summary_reports` | `get_summary_reports()` |
| `sandbox_get_reports` | `get_reports()` |
| `sandbox_query_samples` | `query_sample()` |
| `sandbox_get_sample_metadata` | `get_sample()` |
| `sandbox_upload_sample` | `upload_sample()` |
| `sandbox_submit` | `submit()` |
| `sandbox_get_artifacts` | `get_artifacts()` |
| `sandbox_get_memory_dump` (optional) | `get_memory_dump()` |
| `sandbox_get_hex_dump` (optional) | `get_hex_dump()` |

## Safety & Scope

- **Write operations are intentional.** `upload_sample` and `submit` are the
  only non-read operations; they're scoped to sandbox detonation with no host
  impact. Still, MCP should require explicit opt-in (e.g., caller passes
  `confirm_submit=True`) to prevent accidental uploads from an exploratory
  agent run.
- **Sample handling.** `upload_sample` payloads are binaries — MCP should not
  log the payload bytes. Log only the sha256, filename, and submitter context.
- **Confidentiality flag.** Respect Falcon X's `is_confidential` flag when
  uploading from Claude-driven flows; default to `True` unless the caller
  explicitly marks otherwise. Uploaded samples should not enter CrowdStrike's
  public intelligence graph by accident.
- **Output shaping.** `get_reports` responses are huge (process trees, network
  flows, YARA matches). `get_summary_reports` should be the default agent path;
  `get_reports` is available when the agent needs depth.
- **Quota awareness.** Falcon X has per-tenant detonation quotas. MCP should
  surface quota-related API errors clearly rather than retrying.

## Open Questions

1. **Automatic chain with RTR `getfile`?** When FR #03's
   `rtr_get_extracted_file_contents` retrieves a binary, is there value in a
   one-call helper `sandbox_analyze_rtr_file(session_id, sha256)` that wraps
   upload+submit+poll? Convenient, but adds magic. Lean toward composable
   primitives and document the chain in skills.
2. **Should `sandbox_submit` default to a specific `environment_id`** (Windows
   10 x64 is the most common) or require the caller to specify? Require
   explicit, to prevent silently detonating a macOS binary in Windows.
3. **Response-store integration.** Full `get_reports` output is large —
   should MCP automatically store the report in the response store and
   return only summary + storage ID?
