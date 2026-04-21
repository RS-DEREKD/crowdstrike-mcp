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

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Internal helpers (one per tool)
    # ------------------------------------------------------------------

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
