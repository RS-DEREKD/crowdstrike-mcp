# FR 03: Real-Time Response (read-only) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 7 MCP tools wrapping falconpy's `RealTimeResponse` collection so the agent can open an RTR session against a host, run a strict-allowlisted set of read-only active-responder commands (`ls`, `ps`, `reg query`, `getfile`, etc.), poll for results, and retrieve extracted files — all without a console pivot.

**Architecture:** Create a new `RTRModule` at `src/crowdstrike_mcp/modules/rtr.py`. Auto-discovery strips the `Module` suffix and lowercases, so `RTRModule` in `modules/rtr.py` becomes module name `rtr`. All tools register at `tier="read"` per the FR's "Read-only subset" posture — safety is enforced by a hardcoded MCP-layer **command allowlist** in `rtr_execute_command`, not by the read/write tier gate. Every execute invocation also writes an audit entry (same pattern as `response.py` containment logs). Only `RealTimeResponse` (active-responder tier) is wired up; `real_time_response_admin` is entirely out of scope.

**Tech Stack:** Python 3.11+, `crowdstrike-falconpy>=1.6.1`, `mcp>=1.12.1`, FastMCP, pytest.

**Spec:** `docs/FRs/03-rtr-read-only.md`

---

## Tools to Ship

| Tool | Falconpy method | Operation ID | Purpose |
|---|---|---|---|
| `rtr_init_session` | `init_session` | `RTR_InitSession` | Open an RTR session against a host (`device_id` → `session_id`) |
| `rtr_list_sessions` | `list_sessions` | `RTR_ListSessions` | List metadata for the calling user's sessions by ID |
| `rtr_pulse_session` | `pulse_session` | `RTR_PulseSession` | Keep-alive ping (resets the 10-min idle timeout) |
| `rtr_execute_command` | `execute_active_responder_command` | `RTR_ExecuteActiveResponderCommand` | Run an allowlisted active-responder command |
| `rtr_check_command_status` | `check_active_responder_command_status` | `RTR_CheckActiveResponderCommandStatus` | Poll a submitted command; return stdout/stderr |
| `rtr_list_files` | `list_files_v2` | `RTR_ListFilesV2` | List files the session has pulled via `get` |
| `rtr_get_extracted_file_contents` | `get_extracted_file_contents` | `RTR_GetExtractedFileContents` | Download a pulled file to a local path (7z, password `infected`) |

Defaults and limits:
- No default limits on `rtr_list_sessions.ids` (it's a POST with a body of IDs — caller provides them).
- `rtr_execute_command` base-command allowlist is hardcoded: `ls, ps, reg query, getfile, cat, env, ipconfig, netstat, cd, pwd, filehash, eventlog view, zip, mount, users, history, memdump`. Env var `CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED` (comma-separated) adds to the list at module init. Hard-deny verbs (`cp, mv, rm, put, runscript, kill, mkdir`) are rejected even if added via the env var.
- `rtr_get_extracted_file_contents` writes the 7z to `~/.config/falcon/rtr_downloads/<sha256>.7z` (creates dir if missing) and returns the path.
- Tier: all 7 tools `tier="read"` (FR stance: the whole subset is read-only). The allowlist is the safety control, not the tier gate.

Explicitly deferred (not built in v1):
- `rtr_close_session` (Falcon sessions auto-expire at 10 min idle).
- Session pooling / auto-reuse keyed by `device_id`.
- Auto-upload of extracted file contents to the response store.
- Hostname → `device_id` resolution (caller chains `host_lookup` first).

---

## File Structure

**Create:**
- `src/crowdstrike_mcp/modules/rtr.py` — new `RTRModule` with 7 tool methods, `_method` helpers, command-allowlist validator, audit logger.
- `tests/test_rtr.py` — test classes per tool + scopes + registration + allowlist enforcement.

**Modify:**
- `src/crowdstrike_mcp/common/api_scopes.py` — add scope mappings for 7 operation IDs.
- `src/crowdstrike_mcp/resources/fql_guides.py` — add `RTR_COMMANDS_GUIDE` constant (not FQL, but the file is the canonical "docs constants" registry).
- `tests/test_smoke_tools_list.py` — add `crowdstrike_mcp.modules.rtr.RealTimeResponse` to `_FALCONPY_PATCHES` + `_patch_falconpy()` + the 7 tool names to `EXPECTED_READ_TOOLS`.
- `README.md` — bump tool count and add an RTR section to the tools table.

---

## Conventions to Match (non-obvious)

Observed from `spotlight.py`, `response.py`, `hosts.py`, `cao_hunting.py`, `base.py`, `registry.py`:

1. **Module discovery.** `RTRModule` in `rtr.py` → auto-registered as `rtr`. Don't touch `registry.py`; just match the class-name / filename convention.
2. **Service-class availability guard.** Wrap `from falconpy import RealTimeResponse` in `try/except ImportError` with module-level `RTR_AVAILABLE`; raise `ImportError` in `__init__` when unavailable (matches `ResponseModule`).
3. **Public async tool → internal sync `_method` split.** Public tool methods shape text output only; falconpy I/O + error handling lives in `_method` returning `{"success": bool, ...}`. Same pattern as `spotlight._query_vulnerabilities` etc.
4. **Scope-aware 403 handling.** Use `format_api_error(response, context, operation="<RTR_OperationId>")` — the operation string must match the `operation_id=` value falconpy uses (`RTR_InitSession` etc., not the python method name). Add each to `api_scopes.py`.
5. **`format_text_response(..., raw=True)`** is the return envelope.
6. **Test fixture pattern.** `rtr_module` fixture mirrors the `spotlight_module` fixture — patch `RealTimeResponse`, set `module._service = lambda cls: mock` and `module.falcon = mock`. Single mock is sufficient (one falconpy class).
7. **Tool description strings** lead with the analyst question, not the API. E.g. "Open an RTR session on a host so you can run evidence-collection commands against it" — not "Wraps RTR_InitSession".
8. **Audit log path + format** match `response.py._write_audit_log`: newline-delimited JSON under `~/.config/falcon/rtr_audit.log`. Fields: `timestamp`, `tool`, `session_id`, `device_id`, `base_command`, `command_string`, `cloud_request_id`, `result`, `api_response_code`.
9. **`_service(cls)` always creates a fresh falconpy client** keyed to the current auth context — don't cache the service instance on `self`. Follow `response.py._get_device` and `spotlight._query_vulnerabilities` patterns.
10. **Allowlist enforcement happens BEFORE the falconpy call.** Every `rtr_execute_command` invocation runs through the allowlist check even if the CrowdStrike API would also reject it — the FR is explicit: "do not rely solely on CrowdStrike API scoping."

---

## Task 1: Scaffolding — module file, scope mappings, RTR command guide

**Files:**
- Create: `src/crowdstrike_mcp/modules/rtr.py`
- Modify: `src/crowdstrike_mcp/common/api_scopes.py`
- Modify: `src/crowdstrike_mcp/resources/fql_guides.py`
- Create: `tests/test_rtr.py`

- [ ] **Step 1: Write failing tests for scope mappings**

Create `tests/test_rtr.py` with:

```python
"""Tests for Real-Time Response (read-only) module."""

import asyncio
import json
import os
from unittest.mock import MagicMock, patch

import pytest


class TestRTRScopes:
    """Scope mappings for the 7 RTR operations exist in api_scopes."""

    @pytest.mark.parametrize(
        "op, scope",
        [
            ("RTR_InitSession", "real-time-response:write"),
            ("RTR_ListSessions", "real-time-response:read"),
            ("RTR_PulseSession", "real-time-response:write"),
            ("RTR_ExecuteActiveResponderCommand", "real-time-response:write"),
            ("RTR_CheckActiveResponderCommandStatus", "real-time-response:read"),
            ("RTR_GetExtractedFileContents", "real-time-response:read"),
            ("RTR_ListFilesV2", "real-time-response:read"),
        ],
    )
    def test_operation_has_expected_scope(self, op, scope):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes

        assert get_required_scopes(op) == [scope]
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_rtr.py::TestRTRScopes -v`
Expected: 7 FAIL (scopes return `[]`).

- [ ] **Step 3: Add scope mappings**

Edit `src/crowdstrike_mcp/common/api_scopes.py`. Locate the final entry in `OPERATION_SCOPES` (the `create_export_archive` line under `# CAO Hunting`). Append a new section immediately after it, before the closing `}`:

```python
    # Real-Time Response (read-only subset — FR03)
    "RTR_InitSession": ["real-time-response:write"],
    "RTR_ListSessions": ["real-time-response:read"],
    "RTR_PulseSession": ["real-time-response:write"],
    "RTR_ExecuteActiveResponderCommand": ["real-time-response:write"],
    "RTR_CheckActiveResponderCommandStatus": ["real-time-response:read"],
    "RTR_GetExtractedFileContents": ["real-time-response:read"],
    "RTR_ListFilesV2": ["real-time-response:read"],
```

- [ ] **Step 4: Run scope tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRScopes -v`
Expected: 7 PASS.

- [ ] **Step 5: Add RTR command guide constant**

Edit `src/crowdstrike_mcp/resources/fql_guides.py`. Immediately **before** the `def register_fql_resources(server: FastMCP)` function, append:

```python
RTR_COMMANDS_GUIDE = """\
# Real-Time Response — Allowlisted Commands (read-only subset)

## Base commands allowed by this MCP
- `ls` — list directory contents. Example: `ls "C:\\\\Windows\\\\Temp"`
- `ps` — list running processes. Example: `ps`
- `reg query` — query a Windows registry key/value. Example: `reg query HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run`
- `getfile` — queue a file retrieval (pull to the Falcon cloud; then use rtr_list_files + rtr_get_extracted_file_contents to download)
- `cat` — print a file's contents to session output. Example: `cat /etc/hosts`
- `env` — dump environment variables on the host
- `ipconfig` — Windows: network adapter info
- `netstat` — active network connections
- `cd` — change the session's working directory. Example: `cd "C:\\\\Users"`
- `pwd` — print current session directory
- `filehash` — SHA256 hash of a file. Example: `filehash "C:\\\\Windows\\\\System32\\\\cmd.exe"`
- `eventlog view` — Windows event log read. Example: `eventlog view Security -Count 50`
- `zip` — archive files (no extraction on the host)
- `mount` — list mounted volumes
- `users` — list logged-in users
- `history` — session command history
- `memdump` — process memory dump (writes to session working dir, pull via getfile)

## Always denied — rejected at the MCP layer
`cp`, `mv`, `rm`, `put`, `runscript`, `kill`, `mkdir`. These are denied even if added
via the `CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED` env var — the deny list wins.

## `base_command` vs `command_string`
- `base_command`: the first token only (what's allowlisted). E.g. `ls` or `reg query`.
- `command_string`: the full command as typed. E.g. `ls "C:\\\\Users\\\\Administrator"`.
  The `command_string` MUST start with the `base_command`.

## Typical flow
1. `rtr_init_session(device_id=...)` → returns `session_id`.
2. `rtr_execute_command(session_id, base_command='ps', command_string='ps')` → returns `cloud_request_id`.
3. `rtr_check_command_status(cloud_request_id, session_id)` — poll until `complete:true`; returns stdout/stderr.
4. If a file was pulled via `getfile`: `rtr_list_files(session_id)` → `rtr_get_extracted_file_contents(session_id, sha256)`.

## Retrieved files
7z archives password-protected with `infected` (standard CrowdStrike convention).
Saved by this MCP to `~/.config/falcon/rtr_downloads/<sha256>.7z`.

## Sessions auto-expire after 10 minutes idle
Use `rtr_pulse_session(session_id)` to keep long-running triage sessions alive.
"""
```

(Double-backslashes render as single backslashes inside the triple-quoted string — that's what ends up in the resource text.)

- [ ] **Step 6: Write failing test for module file existence + import**

Append to `tests/test_rtr.py`:

```python
class TestRTRModuleImport:
    def test_module_imports(self):
        from crowdstrike_mcp.modules.rtr import RTRModule
        assert RTRModule is not None

    def test_module_uses_real_time_response(self, mock_client):
        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse") as MockRTR:
            MockRTR.return_value = MagicMock()
            from crowdstrike_mcp.modules.rtr import RTRModule

            module = RTRModule(mock_client)
            assert module is not None
            assert module.tools == []  # nothing registered yet


@pytest.fixture
def rtr_module(mock_client, tmp_path):
    """Create RTRModule with RealTimeResponse mocked. Audit log + download dir redirected to tmp."""
    with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse") as MockRTR:
        mock_rtr = MagicMock()
        MockRTR.return_value = mock_rtr
        from crowdstrike_mcp.modules.rtr import RTRModule

        module = RTRModule(mock_client)
        module._service = lambda cls: mock_rtr
        module.falcon = mock_rtr
        # redirect side-effect paths into tmp so tests don't touch the real user config
        module._audit_log_path = str(tmp_path / "rtr_audit.log")
        module._download_dir = str(tmp_path / "rtr_downloads")
        return module
```

- [ ] **Step 7: Create the module file (scaffolding only)**

Create `src/crowdstrike_mcp/modules/rtr.py`:

```python
"""
Real-Time Response Module — read-only active-responder subset.

Tools:
  rtr_init_session                 — Open a session against a host
  rtr_list_sessions                — List session metadata for given session IDs
  rtr_pulse_session                — Keep-alive ping (resets 10-min idle timeout)
  rtr_execute_command              — Run an allowlisted active-responder command
  rtr_check_command_status         — Poll a submitted command; return stdout/stderr
  rtr_list_files                   — List files pulled via `getfile`
  rtr_get_extracted_file_contents  — Download a pulled file (7z, password: infected)

Safety model:
  1. Hardcoded base-command allowlist enforced at the MCP layer before every
     execute call. Env var `CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED` adds to the list;
     hard-deny verbs (cp, mv, rm, put, runscript, kill, mkdir) always reject.
  2. Every execute invocation writes a JSON line to
     ~/.config/falcon/rtr_audit.log with session_id, device_id, base_command,
     command_string, cloud_request_id, result, status_code.
  3. Admin tier (real_time_response_admin) is entirely out of scope.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Optional

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

try:
    from falconpy import RealTimeResponse

    RTR_AVAILABLE = True
except ImportError:
    RTR_AVAILABLE = False


# Hardcoded base-command allowlist (FR03 §Safety & Scope).
DEFAULT_ALLOWED_BASE_COMMANDS = {
    "ls",
    "ps",
    "reg query",
    "getfile",
    "cat",
    "env",
    "ipconfig",
    "netstat",
    "cd",
    "pwd",
    "filehash",
    "eventlog view",
    "zip",
    "mount",
    "users",
    "history",
    "memdump",
}

# Always-denied verbs (override anything added via the env var).
HARD_DENIED_BASE_COMMANDS = {
    "cp",
    "mv",
    "rm",
    "put",
    "runscript",
    "kill",
    "mkdir",
}


class RTRModule(BaseModule):
    """Real-Time Response — read-only session + command subset."""

    def __init__(self, client):
        super().__init__(client)
        if not RTR_AVAILABLE:
            raise ImportError(
                "falconpy.RealTimeResponse not available. "
                "Ensure crowdstrike-falconpy >= 1.6.1 is installed."
            )

        # Load allowlist (hardcoded default + optional env-var extras, minus deny list).
        self._allowlist = self._load_allowlist()

        # Audit + download paths — tests override these on the fixture instance.
        self._audit_log_path = os.path.expanduser("~/.config/falcon/rtr_audit.log")
        self._download_dir = os.path.expanduser("~/.config/falcon/rtr_downloads")

        self._log(f"Initialized. Allowlist size: {len(self._allowlist)}")

    def register_resources(self, server: FastMCP) -> None:
        from crowdstrike_mcp.resources.fql_guides import RTR_COMMANDS_GUIDE

        def _rtr_commands_guide():
            return RTR_COMMANDS_GUIDE

        server.resource(
            "falcon://rtr/commands",
            name="RTR Command Allowlist & Usage",
            description="Documentation: allowlisted base commands and RTR triage flow",
        )(_rtr_commands_guide)
        self.resources.append("falcon://rtr/commands")

    def register_tools(self, server: FastMCP) -> None:
        # Tool registrations added in subsequent tasks.
        pass

    # ------------------------------------------------------------------
    # Allowlist + audit helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_allowlist() -> set[str]:
        allowed = set(DEFAULT_ALLOWED_BASE_COMMANDS)
        extras_env = os.environ.get("CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED", "")
        for raw in extras_env.split(","):
            cmd = raw.strip().lower()
            if cmd:
                allowed.add(cmd)
        # Deny list always wins.
        return allowed - HARD_DENIED_BASE_COMMANDS

    def _validate_command(self, base_command: str, command_string: str) -> Optional[str]:
        """Return None if valid, else an error message."""
        bc = (base_command or "").strip().lower()
        cs = (command_string or "").strip()
        if not bc:
            return "base_command is required"
        if not cs:
            return "command_string is required"
        if bc in HARD_DENIED_BASE_COMMANDS:
            return f"base_command '{bc}' is hard-denied by this MCP"
        if bc not in self._allowlist:
            return (
                f"base_command '{bc}' is not in the allowlist. "
                f"Allowed: {sorted(self._allowlist)}"
            )
        # command_string must start with the base_command (case-insensitive).
        if not cs.lower().startswith(bc):
            return (
                f"command_string must start with base_command. "
                f"Got base_command='{bc}', command_string='{cs}'"
            )
        return None

    def _write_audit_log(
        self,
        tool: str,
        session_id: str,
        device_id: str,
        base_command: str,
        command_string: str,
        cloud_request_id: Optional[str],
        success: bool,
        status_code: int,
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "session_id": session_id,
            "device_id": device_id,
            "base_command": base_command,
            "command_string": command_string,
            "cloud_request_id": cloud_request_id,
            "result": "success" if success else "failure",
            "api_response_code": status_code,
        }
        try:
            os.makedirs(os.path.dirname(self._audit_log_path), exist_ok=True)
            with open(self._audit_log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            self._log(f"Failed to write audit log: {e}")
```

- [ ] **Step 8: Run the import + allowlist tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRModuleImport -v`
Expected: 2 PASS.

- [ ] **Step 9: Add allowlist unit tests**

Append to `tests/test_rtr.py`:

```python
class TestRTRAllowlist:
    def test_default_allowlist_contains_read_only_verbs(self, rtr_module):
        for verb in ["ls", "ps", "reg query", "getfile", "cat", "pwd"]:
            assert verb in rtr_module._allowlist

    def test_default_allowlist_excludes_hard_denied(self, rtr_module):
        for verb in ["cp", "mv", "rm", "put", "runscript", "kill", "mkdir"]:
            assert verb not in rtr_module._allowlist

    def test_extras_env_var_adds_commands(self, mock_client, monkeypatch, tmp_path):
        monkeypatch.setenv("CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED", "tasklist, whoami")
        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse"):
            from crowdstrike_mcp.modules.rtr import RTRModule
            m = RTRModule(mock_client)
            assert "tasklist" in m._allowlist
            assert "whoami" in m._allowlist

    def test_extras_cannot_bypass_hard_deny(self, mock_client, monkeypatch):
        monkeypatch.setenv("CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED", "rm, put, runscript")
        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse"):
            from crowdstrike_mcp.modules.rtr import RTRModule
            m = RTRModule(mock_client)
            assert "rm" not in m._allowlist
            assert "put" not in m._allowlist
            assert "runscript" not in m._allowlist

    def test_validate_command_accepts_allowed(self, rtr_module):
        assert rtr_module._validate_command("ls", "ls C:\\Users") is None

    def test_validate_command_rejects_unlisted(self, rtr_module):
        err = rtr_module._validate_command("tasklist", "tasklist")
        assert err is not None
        assert "allowlist" in err.lower()

    def test_validate_command_rejects_hard_denied(self, rtr_module):
        err = rtr_module._validate_command("rm", "rm -rf /")
        assert err is not None
        assert "hard-denied" in err.lower()

    def test_validate_command_requires_matching_prefix(self, rtr_module):
        err = rtr_module._validate_command("ls", "ps aux")
        assert err is not None
        assert "start with" in err.lower()
```

- [ ] **Step 10: Run allowlist tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRAllowlist -v`
Expected: 8 PASS.

- [ ] **Step 11: Commit**

```bash
git add src/crowdstrike_mcp/common/api_scopes.py src/crowdstrike_mcp/resources/fql_guides.py src/crowdstrike_mcp/modules/rtr.py tests/test_rtr.py
git commit -m "feat(rtr): scaffold RealTimeResponse module + command allowlist

Add falconpy import guard, scope mappings for 7 RTR operations,
RTR command guide resource content, and the hardcoded base-command
allowlist with env-var extension + hard-deny override."
```

---

## Task 2: `rtr_init_session` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/rtr.py`
- Modify: `tests/test_rtr.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_rtr.py`:

```python
class TestRTRInitSession:
    def test_returns_session_id(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 201,
            "body": {
                "resources": [
                    {"session_id": "sess-abc", "device_id": "dev-123", "pwd": "/"}
                ]
            },
        }
        result = asyncio.run(rtr_module.rtr_init_session(device_id="dev-123"))
        assert "sess-abc" in result
        assert "dev-123" in result

    def test_passes_device_id_and_queue_offline(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "s", "device_id": "dev-123"}]},
        }
        asyncio.run(
            rtr_module.rtr_init_session(device_id="dev-123", queue_offline=True)
        )
        rtr_module.falcon.init_session.assert_called_once_with(
            device_id="dev-123", queue_offline=True
        )

    def test_default_queue_offline_false(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "s", "device_id": "dev-123"}]},
        }
        asyncio.run(rtr_module.rtr_init_session(device_id="dev-123"))
        kwargs = rtr_module.falcon.init_session.call_args.kwargs
        assert kwargs["queue_offline"] is False

    def test_requires_device_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_init_session(device_id=""))
        assert "device_id" in result.lower()

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(rtr_module.rtr_init_session(device_id="dev-123"))
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_rtr.py::TestRTRInitSession -v`
Expected: 5 FAIL — method not defined.

- [ ] **Step 3: Implement tool + helper**

In `src/crowdstrike_mcp/modules/rtr.py`, inside the `RTRModule` class, replace the placeholder `register_tools` body with the first tool registration and add the method. After `_write_audit_log`, append:

```python
    async def rtr_init_session(
        self,
        device_id: Annotated[str, "Falcon device/agent ID to open a session on (from host_lookup)"],
        queue_offline: Annotated[
            bool, "If the host is offline, queue the session and run on next check-in"
        ] = False,
    ) -> str:
        """Open an RTR session against a host so commands can be run on it."""
        result = self._init_session(device_id=device_id, queue_offline=queue_offline)
        if not result.get("success"):
            return format_text_response(
                f"Failed to init RTR session: {result.get('error')}", raw=True
            )
        s = result["session"]
        lines = [
            f"RTR session opened on {s.get('device_id', device_id)}",
            f"  session_id: {s.get('session_id', '?')}",
        ]
        if s.get("pwd"):
            lines.append(f"  pwd: {s['pwd']}")
        if s.get("created_at"):
            lines.append(f"  created_at: {s['created_at']}")
        lines.append("")
        lines.append(
            "Session auto-expires after 10 minutes idle. Use rtr_pulse_session "
            "to keep it alive; use rtr_execute_command to run allowlisted commands."
        )
        return format_text_response("\n".join(lines), raw=True)

    def _init_session(self, device_id: str, queue_offline: bool):
        if not device_id:
            return {"success": False, "error": "device_id is required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.init_session(device_id=device_id, queue_offline=queue_offline)
            status = r.get("status_code", 0)
            if not (200 <= status < 300):
                return {
                    "success": False,
                    "error": format_api_error(
                        r, "Failed to init RTR session", operation="RTR_InitSession"
                    ),
                }
            resources = r.get("body", {}).get("resources", [])
            session = resources[0] if resources else {}
            return {"success": True, "session": session}
        except Exception as e:
            return {"success": False, "error": f"Error initializing RTR session: {e}"}
```

Then update `register_tools` to register this tool:

```python
    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.rtr_init_session,
            name="rtr_init_session",
            description=(
                "Open an RTR session on a host so you can run allowlisted "
                "evidence-collection commands against it. Returns a session_id "
                "needed by rtr_execute_command and friends. Sessions auto-expire "
                "after 10 minutes idle."
            ),
        )
```

- [ ] **Step 4: Run tool tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRInitSession -v`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/rtr.py tests/test_rtr.py
git commit -m "feat(rtr): add rtr_init_session tool

Thin wrapper over RealTimeResponse.init_session() — returns session_id
plus pwd/created_at metadata. Supports queue_offline for offline hosts."
```

---

## Task 3: `rtr_list_sessions` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/rtr.py`
- Modify: `tests/test_rtr.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_rtr.py`:

```python
class TestRTRListSessions:
    def test_returns_session_metadata(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "sess-1",
                        "device_id": "dev-1",
                        "created_at": "2026-04-20T00:00:00Z",
                        "updated_at": "2026-04-20T00:01:00Z",
                        "pwd": "C:\\Users",
                    }
                ]
            },
        }
        result = asyncio.run(rtr_module.rtr_list_sessions(ids=["sess-1"]))
        assert "sess-1" in result
        assert "dev-1" in result

    def test_passes_ids_to_falconpy(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(rtr_module.rtr_list_sessions(ids=["a", "b", "c"]))
        rtr_module.falcon.list_sessions.assert_called_once_with(ids=["a", "b", "c"])

    def test_requires_ids(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_list_sessions(ids=[]))
        assert "ids" in result.lower()

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(rtr_module.rtr_list_sessions(ids=["sess-1"]))
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_rtr.py::TestRTRListSessions -v`
Expected: 4 FAIL.

- [ ] **Step 3: Implement tool + helper**

In `src/crowdstrike_mcp/modules/rtr.py`, after `rtr_init_session` / `_init_session`, append:

```python
    async def rtr_list_sessions(
        self,
        ids: Annotated[list[str], "RTR session IDs to look up (returns only sessions owned by the calling user)"],
    ) -> str:
        """List metadata for one or more RTR session IDs."""
        result = self._list_sessions(ids)
        if not result.get("success"):
            return format_text_response(
                f"Failed to list RTR sessions: {result.get('error')}", raw=True
            )
        sessions = result["sessions"]
        lines = [f"RTR Sessions: {len(sessions)} records", ""]
        if not sessions:
            lines.append("No sessions returned (ids may be unknown or owned by another user).")
        else:
            for i, s in enumerate(sessions, 1):
                lines.append(
                    f"{i}. {s.get('id', '?')} on {s.get('device_id', '?')}"
                )
                if s.get("pwd"):
                    lines.append(f"   pwd: {s['pwd']}")
                if s.get("created_at") or s.get("updated_at"):
                    lines.append(
                        f"   created: {s.get('created_at', '?')} | updated: {s.get('updated_at', '?')}"
                    )
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)

    def _list_sessions(self, ids):
        if not ids:
            return {"success": False, "error": "ids list is required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.list_sessions(ids=ids)
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        r, "Failed to list RTR sessions", operation="RTR_ListSessions"
                    ),
                }
            return {"success": True, "sessions": r.get("body", {}).get("resources", [])}
        except Exception as e:
            return {"success": False, "error": f"Error listing RTR sessions: {e}"}
```

Update `register_tools` — add right after the `rtr_init_session` registration:

```python
        self._add_tool(
            server,
            self.rtr_list_sessions,
            name="rtr_list_sessions",
            description=(
                "Look up metadata for RTR session IDs you've opened "
                "(device_id, pwd, created/updated timestamps). Only returns "
                "sessions owned by the calling user."
            ),
        )
```

- [ ] **Step 4: Run tool tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRListSessions -v`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/rtr.py tests/test_rtr.py
git commit -m "feat(rtr): add rtr_list_sessions tool

Return metadata for RTR session IDs owned by the calling user."
```

---

## Task 4: `rtr_pulse_session` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/rtr.py`
- Modify: `tests/test_rtr.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_rtr.py`:

```python
class TestRTRPulseSession:
    def test_pulses_session(self, rtr_module):
        rtr_module.falcon.pulse_session.return_value = {
            "status_code": 201,
            "body": {
                "resources": [
                    {"session_id": "sess-abc", "device_id": "dev-123"}
                ]
            },
        }
        result = asyncio.run(rtr_module.rtr_pulse_session(session_id="sess-abc"))
        assert "sess-abc" in result
        assert "refreshed" in result.lower() or "pulsed" in result.lower()

    def test_falconpy_called_with_device_id_from_session(self, rtr_module):
        # pulse_session needs device_id — we must resolve it first from the session
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "sess-abc", "device_id": "dev-xyz"}]},
        }
        rtr_module.falcon.pulse_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "sess-abc", "device_id": "dev-xyz"}]},
        }
        asyncio.run(rtr_module.rtr_pulse_session(session_id="sess-abc"))
        rtr_module.falcon.pulse_session.assert_called_once_with(device_id="dev-xyz")

    def test_requires_session_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_pulse_session(session_id=""))
        assert "session_id" in result.lower()

    def test_reports_when_session_not_found(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        result = asyncio.run(rtr_module.rtr_pulse_session(session_id="sess-missing"))
        assert "not found" in result.lower() or "unknown" in result.lower()

    def test_handles_pulse_api_error(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "sess-abc", "device_id": "dev-1"}]},
        }
        rtr_module.falcon.pulse_session.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(rtr_module.rtr_pulse_session(session_id="sess-abc"))
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_rtr.py::TestRTRPulseSession -v`
Expected: 5 FAIL.

- [ ] **Step 3: Implement tool + helper**

Per falconpy: `pulse_session` takes `device_id`, not `session_id`. Resolve the `device_id` from the session via `list_sessions` first. Append to `rtr.py` after `rtr_list_sessions` / `_list_sessions`:

```python
    async def rtr_pulse_session(
        self,
        session_id: Annotated[str, "RTR session ID to keep alive"],
    ) -> str:
        """Refresh a session's idle timeout (otherwise expires after 10 min)."""
        result = self._pulse_session(session_id)
        if not result.get("success"):
            return format_text_response(
                f"Failed to pulse RTR session: {result.get('error')}", raw=True
            )
        s = result["session"]
        return format_text_response(
            f"Session {s.get('session_id', session_id)} refreshed on {s.get('device_id', '?')}",
            raw=True,
        )

    def _pulse_session(self, session_id: str):
        if not session_id:
            return {"success": False, "error": "session_id is required"}
        # Resolve device_id via list_sessions (pulse_session requires device_id).
        try:
            svc = self._service(RealTimeResponse)
            lookup = svc.list_sessions(ids=[session_id])
            if lookup["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        lookup, "Failed to look up session", operation="RTR_ListSessions"
                    ),
                }
            resources = lookup.get("body", {}).get("resources", [])
            if not resources:
                return {
                    "success": False,
                    "error": f"Session {session_id} not found (may have expired or is owned by another user)",
                }
            device_id = resources[0].get("device_id")
            if not device_id:
                return {"success": False, "error": f"Session {session_id} has no device_id"}

            r = svc.pulse_session(device_id=device_id)
            if not (200 <= r.get("status_code", 0) < 300):
                return {
                    "success": False,
                    "error": format_api_error(
                        r, "Failed to pulse RTR session", operation="RTR_PulseSession"
                    ),
                }
            pulsed = r.get("body", {}).get("resources", [])
            return {"success": True, "session": pulsed[0] if pulsed else {"session_id": session_id, "device_id": device_id}}
        except Exception as e:
            return {"success": False, "error": f"Error pulsing RTR session: {e}"}
```

Register in `register_tools` after `rtr_list_sessions`:

```python
        self._add_tool(
            server,
            self.rtr_pulse_session,
            name="rtr_pulse_session",
            description=(
                "Keep an RTR session alive (resets the 10-minute idle timeout). "
                "Use during long-running triage where you're waiting on analyst "
                "review between commands."
            ),
        )
```

- [ ] **Step 4: Run tool tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRPulseSession -v`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/rtr.py tests/test_rtr.py
git commit -m "feat(rtr): add rtr_pulse_session tool

Resolve device_id via list_sessions, then pulse to refresh the
10-minute idle timeout. Handles missing/expired sessions explicitly."
```

---

## Task 5: `rtr_execute_command` tool (with allowlist + audit log)

**Files:**
- Modify: `src/crowdstrike_mcp/modules/rtr.py`
- Modify: `tests/test_rtr.py`

This is the core safety-critical tool. Allowlist check runs **before** the falconpy call; audit log writes on every invocation (success or failure).

- [ ] **Step 1: Write failing tests**

Append to `tests/test_rtr.py`:

```python
class TestRTRExecuteCommand:
    def test_executes_allowed_command(self, rtr_module):
        rtr_module.falcon.execute_active_responder_command.return_value = {
            "status_code": 201,
            "body": {
                "resources": [
                    {
                        "cloud_request_id": "req-42",
                        "session_id": "sess-abc",
                        "queued_command_offline": False,
                    }
                ]
            },
        }
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="sess-abc",
                device_id="dev-1",
                base_command="ls",
                command_string="ls C:\\Users",
            )
        )
        assert "req-42" in result
        rtr_module.falcon.execute_active_responder_command.assert_called_once()

    def test_rejects_unlisted_command_before_api_call(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s",
                device_id="d",
                base_command="tasklist",
                command_string="tasklist",
            )
        )
        assert "allowlist" in result.lower()
        rtr_module.falcon.execute_active_responder_command.assert_not_called()

    def test_rejects_hard_denied_command(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s",
                device_id="d",
                base_command="rm",
                command_string="rm -rf /",
            )
        )
        assert "hard-denied" in result.lower()
        rtr_module.falcon.execute_active_responder_command.assert_not_called()

    def test_rejects_when_command_string_does_not_start_with_base(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s",
                device_id="d",
                base_command="ls",
                command_string="ps aux",
            )
        )
        assert "start with" in result.lower()
        rtr_module.falcon.execute_active_responder_command.assert_not_called()

    def test_writes_audit_log_on_success(self, rtr_module):
        rtr_module.falcon.execute_active_responder_command.return_value = {
            "status_code": 201,
            "body": {
                "resources": [
                    {"cloud_request_id": "req-42", "session_id": "sess-abc"}
                ]
            },
        }
        asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="sess-abc",
                device_id="dev-1",
                base_command="ps",
                command_string="ps",
            )
        )
        assert os.path.exists(rtr_module._audit_log_path)
        with open(rtr_module._audit_log_path) as f:
            lines = f.readlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["tool"] == "rtr_execute_command"
        assert entry["session_id"] == "sess-abc"
        assert entry["device_id"] == "dev-1"
        assert entry["base_command"] == "ps"
        assert entry["command_string"] == "ps"
        assert entry["cloud_request_id"] == "req-42"
        assert entry["result"] == "success"
        assert entry["api_response_code"] == 201

    def test_writes_audit_log_on_allowlist_rejection(self, rtr_module):
        asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s",
                device_id="d",
                base_command="rm",
                command_string="rm file",
            )
        )
        assert os.path.exists(rtr_module._audit_log_path)
        with open(rtr_module._audit_log_path) as f:
            entry = json.loads(f.readlines()[0])
        assert entry["result"] == "failure"
        # 0 indicates the call never reached the API
        assert entry["api_response_code"] == 0

    def test_passes_all_args_to_falconpy(self, rtr_module):
        rtr_module.falcon.execute_active_responder_command.return_value = {
            "status_code": 201, "body": {"resources": [{"cloud_request_id": "r"}]},
        }
        asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="sess-abc",
                device_id="dev-1",
                base_command="reg query",
                command_string="reg query HKLM\\Software",
            )
        )
        kwargs = rtr_module.falcon.execute_active_responder_command.call_args.kwargs
        assert kwargs["session_id"] == "sess-abc"
        assert kwargs["device_id"] == "dev-1"
        assert kwargs["base_command"] == "reg query"
        assert kwargs["command_string"] == "reg query HKLM\\Software"

    def test_api_error_is_reported_and_audited(self, rtr_module):
        rtr_module.falcon.execute_active_responder_command.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s", device_id="d",
                base_command="ps", command_string="ps",
            )
        )
        assert "failed" in result.lower()
        with open(rtr_module._audit_log_path) as f:
            entry = json.loads(f.readlines()[0])
        assert entry["result"] == "failure"
        assert entry["api_response_code"] == 500
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_rtr.py::TestRTRExecuteCommand -v`
Expected: 8 FAIL.

- [ ] **Step 3: Implement tool + helper**

Append to `rtr.py` after `rtr_pulse_session` / `_pulse_session`:

```python
    async def rtr_execute_command(
        self,
        session_id: Annotated[str, "RTR session ID (from rtr_init_session)"],
        device_id: Annotated[str, "Device ID the session is bound to"],
        base_command: Annotated[
            str,
            "Base command (first token only). Must be in the allowlist — see falcon://rtr/commands.",
        ],
        command_string: Annotated[
            str,
            "Full command as typed. Must start with base_command. Example: 'ls C:\\\\Users'",
        ],
    ) -> str:
        """Run an allowlisted read-only active-responder command on a host."""
        # Allowlist check happens before any falconpy call; failures are still audited.
        validation_error = self._validate_command(base_command, command_string)
        if validation_error:
            self._write_audit_log(
                tool="rtr_execute_command",
                session_id=session_id,
                device_id=device_id,
                base_command=base_command,
                command_string=command_string,
                cloud_request_id=None,
                success=False,
                status_code=0,
            )
            return format_text_response(
                f"Failed: {validation_error}", raw=True
            )

        result = self._execute_command(
            session_id=session_id,
            device_id=device_id,
            base_command=base_command,
            command_string=command_string,
        )
        if not result.get("success"):
            return format_text_response(
                f"Failed to execute RTR command: {result.get('error')}", raw=True
            )
        r = result["resource"]
        lines = [
            "RTR command submitted.",
            f"  cloud_request_id: {r.get('cloud_request_id', '?')}",
            f"  session_id: {r.get('session_id', session_id)}",
        ]
        if r.get("queued_command_offline"):
            lines.append("  queued_command_offline: True (will run on next check-in)")
        lines.append("")
        lines.append("Poll rtr_check_command_status(cloud_request_id, session_id) for output.")
        return format_text_response("\n".join(lines), raw=True)

    def _execute_command(
        self,
        session_id: str,
        device_id: str,
        base_command: str,
        command_string: str,
    ):
        if not session_id or not device_id:
            return {"success": False, "error": "session_id and device_id are required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.execute_active_responder_command(
                session_id=session_id,
                device_id=device_id,
                base_command=base_command,
                command_string=command_string,
            )
            status = r.get("status_code", 0)
            resources = r.get("body", {}).get("resources", [])
            resource = resources[0] if resources else {}
            cloud_request_id = resource.get("cloud_request_id")
            success = 200 <= status < 300
            self._write_audit_log(
                tool="rtr_execute_command",
                session_id=session_id,
                device_id=device_id,
                base_command=base_command,
                command_string=command_string,
                cloud_request_id=cloud_request_id,
                success=success,
                status_code=status,
            )
            if not success:
                return {
                    "success": False,
                    "error": format_api_error(
                        r,
                        "Failed to execute RTR command",
                        operation="RTR_ExecuteActiveResponderCommand",
                    ),
                }
            return {"success": True, "resource": resource}
        except Exception as e:
            self._write_audit_log(
                tool="rtr_execute_command",
                session_id=session_id,
                device_id=device_id,
                base_command=base_command,
                command_string=command_string,
                cloud_request_id=None,
                success=False,
                status_code=0,
            )
            return {"success": False, "error": f"Error executing RTR command: {e}"}
```

Register in `register_tools` after `rtr_pulse_session`:

```python
        self._add_tool(
            server,
            self.rtr_execute_command,
            name="rtr_execute_command",
            description=(
                "Run a read-only active-responder command on a host (ls, ps, "
                "reg query, getfile, cat, netstat, ...). Base command must be "
                "in the allowlist. See falcon://rtr/commands. Returns a "
                "cloud_request_id — poll rtr_check_command_status for output. "
                "Every invocation (including rejections) is written to "
                "~/.config/falcon/rtr_audit.log."
            ),
        )
```

- [ ] **Step 4: Run tool tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRExecuteCommand -v`
Expected: 8 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/rtr.py tests/test_rtr.py
git commit -m "feat(rtr): add rtr_execute_command with allowlist + audit log

Enforces the hardcoded base-command allowlist before the falconpy
call. Every invocation (success, API failure, and allowlist rejection)
writes a JSON line to ~/.config/falcon/rtr_audit.log."
```

---

## Task 6: `rtr_check_command_status` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/rtr.py`
- Modify: `tests/test_rtr.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_rtr.py`:

```python
class TestRTRCheckCommandStatus:
    def test_returns_stdout_when_complete(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "complete": True,
                        "stdout": "PID   CMD\n1234  notepad.exe\n",
                        "stderr": "",
                        "task_id": "req-42",
                    }
                ]
            },
        }
        result = asyncio.run(
            rtr_module.rtr_check_command_status(
                cloud_request_id="req-42", session_id="sess-abc"
            )
        )
        assert "notepad.exe" in result
        assert "complete" in result.lower()

    def test_reports_pending_when_not_complete(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 200,
            "body": {"resources": [{"complete": False, "stdout": "", "stderr": ""}]},
        }
        result = asyncio.run(
            rtr_module.rtr_check_command_status(
                cloud_request_id="req-42", session_id="sess-abc"
            )
        )
        assert "pending" in result.lower() or "not complete" in result.lower()

    def test_surfaces_stderr_when_present(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"complete": True, "stdout": "", "stderr": "Access denied"}
                ]
            },
        }
        result = asyncio.run(
            rtr_module.rtr_check_command_status(
                cloud_request_id="req-42", session_id="sess-abc"
            )
        )
        assert "Access denied" in result

    def test_requires_cloud_request_id(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_check_command_status(
                cloud_request_id="", session_id="sess-abc"
            )
        )
        assert "cloud_request_id" in result.lower()

    def test_requires_session_id(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_check_command_status(
                cloud_request_id="req-42", session_id=""
            )
        )
        assert "session_id" in result.lower()

    def test_passes_both_args(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 200,
            "body": {"resources": [{"complete": True, "stdout": "ok"}]},
        }
        asyncio.run(
            rtr_module.rtr_check_command_status(
                cloud_request_id="req-42", session_id="sess-abc"
            )
        )
        kwargs = rtr_module.falcon.check_active_responder_command_status.call_args.kwargs
        assert kwargs["cloud_request_id"] == "req-42"
        assert kwargs["session_id"] == "sess-abc"

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(
            rtr_module.rtr_check_command_status(
                cloud_request_id="req-42", session_id="sess-abc"
            )
        )
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_rtr.py::TestRTRCheckCommandStatus -v`
Expected: 7 FAIL.

- [ ] **Step 3: Implement tool + helper**

Append to `rtr.py` after `rtr_execute_command` / `_execute_command`:

```python
    async def rtr_check_command_status(
        self,
        cloud_request_id: Annotated[str, "Cloud request ID returned by rtr_execute_command"],
        session_id: Annotated[str, "RTR session ID the command ran in"],
    ) -> str:
        """Poll a submitted RTR command for completion + stdout/stderr."""
        result = self._check_command_status(
            cloud_request_id=cloud_request_id, session_id=session_id
        )
        if not result.get("success"):
            return format_text_response(
                f"Failed to check RTR command status: {result.get('error')}", raw=True
            )
        r = result["resource"]
        complete = bool(r.get("complete", False))
        stdout = r.get("stdout", "") or ""
        stderr = r.get("stderr", "") or ""
        header = "RTR command complete" if complete else "RTR command pending (not complete)"
        lines = [header, f"  cloud_request_id: {cloud_request_id}", ""]
        if stdout:
            lines.append("--- stdout ---")
            lines.append(stdout)
        if stderr:
            lines.append("--- stderr ---")
            lines.append(stderr)
        if not stdout and not stderr:
            lines.append("(no output yet)")
        return format_text_response("\n".join(lines), raw=True)

    def _check_command_status(self, cloud_request_id: str, session_id: str):
        if not cloud_request_id:
            return {"success": False, "error": "cloud_request_id is required"}
        if not session_id:
            return {"success": False, "error": "session_id is required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.check_active_responder_command_status(
                cloud_request_id=cloud_request_id, session_id=session_id
            )
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        r,
                        "Failed to check RTR command status",
                        operation="RTR_CheckActiveResponderCommandStatus",
                    ),
                }
            resources = r.get("body", {}).get("resources", [])
            return {"success": True, "resource": resources[0] if resources else {}}
        except Exception as e:
            return {"success": False, "error": f"Error checking RTR command status: {e}"}
```

Register in `register_tools` after `rtr_execute_command`:

```python
        self._add_tool(
            server,
            self.rtr_check_command_status,
            name="rtr_check_command_status",
            description=(
                "Poll a cloud_request_id returned by rtr_execute_command until "
                "complete:true, then return stdout/stderr. RTR commands are "
                "async; first check usually returns complete:false — poll again."
            ),
        )
```

- [ ] **Step 4: Run tool tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRCheckCommandStatus -v`
Expected: 7 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/rtr.py tests/test_rtr.py
git commit -m "feat(rtr): add rtr_check_command_status tool

Poll an RTR cloud_request_id; surface complete:true|false + stdout
+ stderr. Callers loop until complete."
```

---

## Task 7: `rtr_list_files` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/rtr.py`
- Modify: `tests/test_rtr.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_rtr.py`:

```python
class TestRTRListFiles:
    def test_returns_file_list(self, rtr_module):
        rtr_module.falcon.list_files_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "file-1",
                        "sha256": "abc123",
                        "name": "suspicious.exe",
                        "size": 12345,
                        "created_at": "2026-04-20T00:00:00Z",
                    }
                ]
            },
        }
        result = asyncio.run(rtr_module.rtr_list_files(session_id="sess-abc"))
        assert "suspicious.exe" in result
        assert "abc123" in result

    def test_passes_session_id(self, rtr_module):
        rtr_module.falcon.list_files_v2.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        asyncio.run(rtr_module.rtr_list_files(session_id="sess-abc"))
        rtr_module.falcon.list_files_v2.assert_called_once_with(session_id="sess-abc")

    def test_requires_session_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_list_files(session_id=""))
        assert "session_id" in result.lower()

    def test_handles_empty_results(self, rtr_module):
        rtr_module.falcon.list_files_v2.return_value = {
            "status_code": 200, "body": {"resources": []},
        }
        result = asyncio.run(rtr_module.rtr_list_files(session_id="sess-abc"))
        assert "no files" in result.lower() or "0" in result

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.list_files_v2.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(rtr_module.rtr_list_files(session_id="sess-abc"))
        assert "failed" in result.lower()
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_rtr.py::TestRTRListFiles -v`
Expected: 5 FAIL.

- [ ] **Step 3: Implement tool + helper**

Append to `rtr.py` after `rtr_check_command_status` / `_check_command_status`:

```python
    async def rtr_list_files(
        self,
        session_id: Annotated[str, "RTR session ID"],
    ) -> str:
        """List files pulled via `getfile` in this session."""
        result = self._list_files(session_id)
        if not result.get("success"):
            return format_text_response(
                f"Failed to list RTR session files: {result.get('error')}", raw=True
            )
        files = result["files"]
        lines = [f"RTR Session Files: {len(files)} records", ""]
        if not files:
            lines.append("No files have been pulled in this session. Use `getfile` first.")
        else:
            for i, f in enumerate(files, 1):
                lines.append(
                    f"{i}. **{f.get('name', '?')}** — sha256: {f.get('sha256', '?')}"
                )
                lines.append(
                    f"   size: {f.get('size', '?')} | created: {f.get('created_at', '?')}"
                )
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)

    def _list_files(self, session_id: str):
        if not session_id:
            return {"success": False, "error": "session_id is required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.list_files_v2(session_id=session_id)
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        r, "Failed to list RTR files", operation="RTR_ListFilesV2"
                    ),
                }
            return {"success": True, "files": r.get("body", {}).get("resources", [])}
        except Exception as e:
            return {"success": False, "error": f"Error listing RTR files: {e}"}
```

Register in `register_tools` after `rtr_check_command_status`:

```python
        self._add_tool(
            server,
            self.rtr_list_files,
            name="rtr_list_files",
            description=(
                "List files pulled into an RTR session via `getfile`. Returns "
                "name, sha256, and size. Pair with rtr_get_extracted_file_contents "
                "to download the 7z archive."
            ),
        )
```

- [ ] **Step 4: Run tool tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRListFiles -v`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/rtr.py tests/test_rtr.py
git commit -m "feat(rtr): add rtr_list_files tool

Wrap list_files_v2 to enumerate files pulled into the session via
getfile, keyed by sha256."
```

---

## Task 8: `rtr_get_extracted_file_contents` tool

**Files:**
- Modify: `src/crowdstrike_mcp/modules/rtr.py`
- Modify: `tests/test_rtr.py`

Falconpy returns raw bytes on SUCCESS and a dict on FAILURE. We save the bytes to `~/.config/falcon/rtr_downloads/<sha256>.7z` and return the path.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_rtr.py`:

```python
class TestRTRGetExtractedFileContents:
    def test_saves_bytes_and_returns_path(self, rtr_module):
        # On success, falconpy returns raw bytes (7z archive), not a dict
        rtr_module.falcon.get_extracted_file_contents.return_value = b"\x37\x7a\xbc\xafFAKE_7Z"
        result = asyncio.run(
            rtr_module.rtr_get_extracted_file_contents(
                session_id="sess-abc", sha256="abc123"
            )
        )
        expected_path = os.path.join(rtr_module._download_dir, "abc123.7z")
        assert expected_path in result
        assert os.path.exists(expected_path)
        with open(expected_path, "rb") as f:
            assert f.read().startswith(b"\x37\x7a\xbc\xaf")

    def test_passes_session_id_sha256_and_filename(self, rtr_module):
        rtr_module.falcon.get_extracted_file_contents.return_value = b"BYTES"
        asyncio.run(
            rtr_module.rtr_get_extracted_file_contents(
                session_id="sess-abc", sha256="abc", filename="evidence.exe"
            )
        )
        kwargs = rtr_module.falcon.get_extracted_file_contents.call_args.kwargs
        assert kwargs["session_id"] == "sess-abc"
        assert kwargs["sha256"] == "abc"
        assert kwargs["filename"] == "evidence.exe"

    def test_requires_session_id(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_get_extracted_file_contents(session_id="", sha256="abc")
        )
        assert "session_id" in result.lower()

    def test_requires_sha256(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_get_extracted_file_contents(session_id="s", sha256="")
        )
        assert "sha256" in result.lower()

    def test_handles_failure_dict(self, rtr_module):
        rtr_module.falcon.get_extracted_file_contents.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(
            rtr_module.rtr_get_extracted_file_contents(
                session_id="sess-abc", sha256="abc"
            )
        )
        assert "failed" in result.lower()

    def test_mentions_password_reminder(self, rtr_module):
        rtr_module.falcon.get_extracted_file_contents.return_value = b"7z-bytes"
        result = asyncio.run(
            rtr_module.rtr_get_extracted_file_contents(
                session_id="sess-abc", sha256="abc"
            )
        )
        # Users must know the archive password to extract
        assert "infected" in result.lower()
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_rtr.py::TestRTRGetExtractedFileContents -v`
Expected: 6 FAIL.

- [ ] **Step 3: Implement tool + helper**

Append to `rtr.py` after `rtr_list_files` / `_list_files`:

```python
    async def rtr_get_extracted_file_contents(
        self,
        session_id: Annotated[str, "RTR session ID the file was pulled in"],
        sha256: Annotated[str, "SHA256 of the pulled file (from rtr_list_files)"],
        filename: Annotated[
            Optional[str],
            "Optional filename hint passed to the API (archive-internal name)",
        ] = None,
    ) -> str:
        """Download a pulled file to a local 7z (password `infected`)."""
        result = self._get_extracted_file_contents(
            session_id=session_id, sha256=sha256, filename=filename
        )
        if not result.get("success"):
            return format_text_response(
                f"Failed to get extracted file contents: {result.get('error')}", raw=True
            )
        path = result["path"]
        size = result["size"]
        lines = [
            f"Downloaded {size} bytes to {path}",
            "",
            "The archive is a 7zip file password-protected with the password `infected` "
            "(standard CrowdStrike RTR convention). Extract with `7z x -pinfected <path>`.",
        ]
        return format_text_response("\n".join(lines), raw=True)

    def _get_extracted_file_contents(
        self,
        session_id: str,
        sha256: str,
        filename: Optional[str],
    ):
        if not session_id:
            return {"success": False, "error": "session_id is required"}
        if not sha256:
            return {"success": False, "error": "sha256 is required"}
        try:
            svc = self._service(RealTimeResponse)
            kwargs = {"session_id": session_id, "sha256": sha256}
            if filename:
                kwargs["filename"] = filename
            r = svc.get_extracted_file_contents(**kwargs)
            # Falconpy returns raw bytes on SUCCESS, dict on FAILURE.
            if isinstance(r, dict):
                return {
                    "success": False,
                    "error": format_api_error(
                        r,
                        "Failed to download RTR file",
                        operation="RTR_GetExtractedFileContents",
                    ),
                }
            data = bytes(r) if not isinstance(r, (bytes, bytearray)) else r
            os.makedirs(self._download_dir, exist_ok=True)
            path = os.path.join(self._download_dir, f"{sha256}.7z")
            with open(path, "wb") as f:
                f.write(data)
            return {"success": True, "path": path, "size": len(data)}
        except Exception as e:
            return {"success": False, "error": f"Error downloading RTR file: {e}"}
```

Register in `register_tools` after `rtr_list_files`:

```python
        self._add_tool(
            server,
            self.rtr_get_extracted_file_contents,
            name="rtr_get_extracted_file_contents",
            description=(
                "Download a file pulled via `getfile` to a local 7z archive "
                "(saved under ~/.config/falcon/rtr_downloads/<sha256>.7z). "
                "Password: `infected`. Use rtr_list_files to find the sha256 first."
            ),
        )
```

- [ ] **Step 4: Run tool tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRGetExtractedFileContents -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/rtr.py tests/test_rtr.py
git commit -m "feat(rtr): add rtr_get_extracted_file_contents tool

Download a file pulled via \`getfile\` to
~/.config/falcon/rtr_downloads/<sha256>.7z. Archive is password
'infected' per CrowdStrike convention."
```

---

## Task 9: Smoke-test registration + resource test + README

**Files:**
- Modify: `tests/test_smoke_tools_list.py`
- Modify: `tests/test_rtr.py` (add module registration tests)
- Modify: `README.md`

- [ ] **Step 1: Write failing test for registration / resource**

Append to `tests/test_rtr.py`:

```python
class TestRTRToolRegistration:
    def test_all_seven_tools_register_as_read(self, rtr_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        rtr_module.register_tools(server)
        expected = {
            "rtr_init_session",
            "rtr_list_sessions",
            "rtr_pulse_session",
            "rtr_execute_command",
            "rtr_check_command_status",
            "rtr_list_files",
            "rtr_get_extracted_file_contents",
        }
        assert expected.issubset(set(rtr_module.tools))


class TestRTRResources:
    def test_registers_commands_guide(self, rtr_module):
        server = MagicMock()
        server.resource.return_value = lambda fn: fn
        rtr_module.register_resources(server)
        assert "falcon://rtr/commands" in rtr_module.resources
```

- [ ] **Step 2: Run tests — confirm they pass**

Run: `pytest tests/test_rtr.py::TestRTRToolRegistration tests/test_rtr.py::TestRTRResources -v`
Expected: 2 PASS (the module file already registers all seven tools and the resource).

- [ ] **Step 3: Update the smoke-list test**

Edit `tests/test_smoke_tools_list.py`:

1. Add `"crowdstrike_mcp.modules.rtr.RealTimeResponse"` to `_FALCONPY_PATCHES` (alphabetical order — between `modules.response.Hosts` and `modules.spotlight.SpotlightEvaluationLogic`):

```python
    "crowdstrike_mcp.modules.response.Hosts",
    "crowdstrike_mcp.modules.rtr.RealTimeResponse",
    "crowdstrike_mcp.modules.spotlight.SpotlightEvaluationLogic",
```

2. Add a patch entry inside `_patch_falconpy()`:

```python
        patch.multiple("crowdstrike_mcp.modules.response", Hosts=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.rtr", RealTimeResponse=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.spotlight", SpotlightEvaluationLogic=MagicMock()),
```

3. Add the 7 RTR tool names to `EXPECTED_READ_TOOLS` (group them together with a comment):

```python
    # RTR (FR03)
    "rtr_init_session",
    "rtr_list_sessions",
    "rtr_pulse_session",
    "rtr_execute_command",
    "rtr_check_command_status",
    "rtr_list_files",
    "rtr_get_extracted_file_contents",
```

- [ ] **Step 4: Run smoke test — confirm it passes**

Run: `pytest tests/test_smoke_tools_list.py -v`
Expected: all PASS (read tools include RTR; no unexpected tools).

- [ ] **Step 5: Run the full test suite — no regressions**

Run: `pytest tests/ -v`
Expected: All tests pass.

- [ ] **Step 6: Update README tool count + add RTR section**

First, find the current tool count phrase in `README.md`:

```bash
grep -n "tools across" README.md
```

Bump the count by 7. Then locate the tools table — find the existing "Response" / containment section (search for `host_contain`) and add a new section immediately after it:

```markdown
### Real-Time Response (read-only subset)
| Tool | Purpose |
|---|---|
| `rtr_init_session` | Open an RTR session on a host |
| `rtr_list_sessions` | List metadata for owned session IDs |
| `rtr_pulse_session` | Keep-alive ping (resets 10-min idle timeout) |
| `rtr_execute_command` | Run an allowlisted read-only active-responder command |
| `rtr_check_command_status` | Poll submitted command for stdout/stderr |
| `rtr_list_files` | List files pulled via `getfile` |
| `rtr_get_extracted_file_contents` | Download a pulled file (7z, password `infected`) |

All RTR tools register as read-tier. Safety is enforced by a hardcoded MCP-layer
command allowlist (`ls, ps, reg query, getfile, cat, env, ipconfig, netstat, cd,
pwd, filehash, eventlog view, zip, mount, users, history, memdump`) plus a
never-allowed deny list (`cp, mv, rm, put, runscript, kill, mkdir`). Extend via
env var `CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED` (comma-separated) — deny list always
wins. Every `rtr_execute_command` invocation is audited to
`~/.config/falcon/rtr_audit.log`.
```

Match the existing table style — don't invent new columns.

- [ ] **Step 7: Smoke-test the server boots**

Run: `PYTHONPATH=src python -m crowdstrike_mcp --help`
Expected: help text prints, no import errors, `rtr` appears as a discoverable module.

- [ ] **Step 8: Run ruff**

Run: `ruff check src/ tests/`
Expected: no violations. If there are any, fix them before committing.

- [ ] **Step 9: Final commit**

```bash
git add src/crowdstrike_mcp/modules/rtr.py tests/test_rtr.py tests/test_smoke_tools_list.py README.md
git commit -m "feat(rtr): register RTR module in smoke test + README

Add rtr_* tools to EXPECTED_READ_TOOLS, patch RealTimeResponse in the
smoke harness, and document the RTR tools + allowlist/audit model in
the README."
```

---

## Verification Checklist

Before declaring done:

- [ ] `pytest tests/ -v` — all pass
- [ ] `ruff check src/ tests/` — no violations
- [ ] `PYTHONPATH=src python -m crowdstrike_mcp --help` — boots clean
- [ ] All 7 RTR tools appear in `RTRModule.tools` after `register_tools()`
- [ ] `rtr` shows up in `registry.get_module_names()` output
- [ ] Scope lookup works for all 7 RTR operation IDs (`get_required_scopes` returns the right scope)
- [ ] `falcon://rtr/commands` resource is registered
- [ ] Allowlist tests prove `rm`/`put`/`runscript`/`kill` never reach the API
- [ ] Audit log gets written on both success and allowlist-rejection paths

## Out of Scope (Deferred)

- **`rtr_close_session` / explicit session teardown.** Falcon auto-expires at 10 min idle; explicit close is a nice-to-have not required for v1.
- **Session pooling keyed by `device_id`.** v1 policy: every caller opens its own session; agent decides whether to reuse via `rtr_list_sessions`.
- **Auto-upload of extracted file contents to the response store.** FR open question #3 — defer until usage patterns confirm it's worth the coupling between modules.
- **Hostname → `device_id` resolution.** Agent chains `host_lookup` first. Keeping this module's falconpy surface limited to `RealTimeResponse`.
- **Rate-limit-aware retries.** `format_api_error` already surfaces the HTTP status; callers handle backoff. No auto-retry loop in v1.
- **`real_time_response_admin` tier tools** (`put`, `runscript`, admin scripts). Entirely out of scope — separate FR if/when needed.
- **Streaming download from `get_extracted_file_contents`.** Current implementation buffers the entire archive in memory. Fine for triage-sized files (tens of MB); revisit if memdumps exceed that.
