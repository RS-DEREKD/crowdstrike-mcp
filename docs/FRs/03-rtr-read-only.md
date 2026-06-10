# FR 03: Real-Time Response (read-only session + commands)

**Requested**: 2026-04-17
**Lens**: Triage
**Falconpy**: `real_time_response`
**Posture**: Read-only subset — no admin commands, no file writes, no scripts

## Problem

The MCP today exposes `host_contain` and `host_lift_containment` from the
response module — containment only. There is no live evidence-collection
surface. For triage that needs "what's on this host right now?" (running
processes, open network connections, filesystem artifacts, a specific registry
value), the analyst must open Falcon Console → RTR → session manually.

This cuts the Claude agent out of the evidence phase entirely. The agent can
classify an alert as TP, pull historical telemetry via `ngsiem_query`, and
recommend containment — but cannot gather current-state evidence to confirm.

## Impact

Enables live triage workflows the agent can run end-to-end:

1. **Alert-backed evidence collection**: on a suspicious process alert, `ls`
   the parent directory, `ps` the process tree, `reg query` relevant
   persistence keys, `getfile` a binary for sandbox submission (via FR #04).
2. **Post-containment triage**: after containing a host, the session is still
   usable — collect artifacts while the host is isolated, ship them to the
   response store for offline analysis.
3. **"Is X installed?" checks**: during shadow-IT detections (Grammarly,
   unauthorized cloud sync), `ls "%APPDATA%\..."` confirms installation
   vs runtime process match.

## Proposed MCP Tools

Scoped deliberately tight. **Active-responder tier only** — excludes admin
commands like `put`, `runscript`, `cp`.

| Tool | Purpose | Key args |
|---|---|---|
| `rtr_init_session` | Establish an RTR session against a host | `device_id: str`, optional `queue_offline: bool` |
| `rtr_list_sessions` | List active RTR sessions (the agent's own) | optional `filter`, `limit` |
| `rtr_pulse_session` | Keep-alive ping on an existing session | `session_id: str` |
| `rtr_execute_command` | Run a **read-only** active-responder command (`ls`, `ps`, `reg query`, `getfile`, `env`, `ipconfig`, `netstat`, etc.) with strict allowlist enforcement | `session_id: str`, `base_command: str`, `command_string: str` |
| `rtr_check_command_status` | Poll for command completion + stdout/stderr | `cloud_request_id: str`, `session_id: str` |
| `rtr_get_extracted_file_contents` | Retrieve contents of a file pulled via `get` | `session_id: str`, `sha256: str`, optional `filename: str` |
| `rtr_list_files` | List files the session has pulled so far | `session_id: str` |

Explicitly NOT proposed in this FR:
- `delete_file` — not read-only
- `batch_active_responder_command` — multi-host containment-adjacent; separate FR
- Admin tier commands (`put`, `runscript`, `cp`, `mv`, `mkdir`, `rm`) — out of scope
- `real_time_response_admin` module — entirely out of scope

## Falconpy Methods Used

From `src/falconpy/real_time_response.py`:

| MCP tool | Falconpy method |
|---|---|
| `rtr_init_session` | `init_session()` |
| `rtr_list_sessions` | `list_sessions()` |
| `rtr_pulse_session` | `pulse_session()` |
| `rtr_execute_command` | `execute_active_responder_command()` |
| `rtr_check_command_status` | `check_active_responder_command_status()` |
| `rtr_get_extracted_file_contents` | `get_extracted_file_contents()` |
| `rtr_list_files` | `list_files_v2()` (prefer v2) |

## Safety & Scope

- **Strict command allowlist in the MCP layer.** `rtr_execute_command` must
  validate `base_command` against an allowlist before submission:
  `ls, ps, reg query, getfile, cat, env, ipconfig, netstat, cd, pwd,
   filehash, eventlog view, zip, mount, users, history, memdump`.
  Any write/exec verb (`cp`, `mv`, `rm`, `put`, `runscript`, `kill`) rejected
  at the MCP layer — do not rely solely on CrowdStrike API scoping.
- **Session lifecycle.** MCP should auto-timeout sessions it created if the
  agent abandons them. Falcon sessions otherwise auto-expire at 10 minutes
  idle, but explicit close is cleaner.
- **Audit trail.** Every `rtr_execute_command` invocation should log
  `session_id`, `device_id`, `base_command`, `command_string` at MCP's
  audit level so the organization has a record of what the agent did.
- **Rate-limit awareness.** RTR has aggressive rate limits at the Falcon API
  layer; the MCP should surface retry-after semantics to callers rather than
  silently retrying.

## Open Questions

1. **Allowlist source of truth.** Hardcoded in the MCP vs environment config?
   Preference from this caller: hardcoded with a documented `extra_allowed`
   env var escape hatch for operators who want to expand carefully.
2. **Session reuse vs per-call init.** Init is expensive; should the MCP
   maintain a session pool keyed by `device_id`? Simpler v1: every call
   inits its own session, caller uses `rtr_list_sessions` + `rtr_pulse_session`
   if they want persistence.
3. **Should `getfile` results auto-upload to the response store?** When the
   agent pulls a file for analysis, it's almost always going to hand it to a
   downstream tool. An automatic response-store upload on `get_extracted_file_contents`
   would make chaining cleaner.
