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
from typing import TYPE_CHECKING, Optional

from crowdstrike_mcp.modules.base import BaseModule

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
