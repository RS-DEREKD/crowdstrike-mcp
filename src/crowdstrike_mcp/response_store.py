"""
ResponseStore — in-memory structured data store for large MCP tool responses.

Stores raw Python dicts from tool output (before text formatting) so the
get_stored_response MCP tool can do field-level extraction without Bash/grep.

This file lives at the root level (peer to utils.py) to keep the dependency
direction clean: utils.py imports from here, modules import from utils.py.

Isolation: the store is partitioned per session. In HTTP transports a single
process serves many authenticated tenants, so a process-global store would let
one tenant read another's stored Falcon data via predictable ref_ids. The
session id is set per request by session_auth_middleware; stdio (single client)
uses the default session. All access is guarded by a lock since FastMCP runs
sync tool bodies in a worker threadpool.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import datetime, timezone

# Per-session partition key. Set by session_auth_middleware for HTTP transports;
# stdio and tests use the default single-session value.
_DEFAULT_SESSION = "local"
_session_id: ContextVar[str] = ContextVar("response_store_session", default=_DEFAULT_SESSION)


def set_response_session(session_id: str) -> Token:
    """Bind the response-store session for the current context. Returns a reset token."""
    return _session_id.set(session_id)


def reset_response_session(token: Token) -> None:
    """Restore the previous response-store session using a token from set_response_session."""
    _session_id.reset(token)


@dataclass
class StoredResponse:
    """A stored structured response from an MCP tool."""

    ref_id: str
    tool_name: str
    timestamp: datetime
    data: dict
    metadata: dict
    record_count: int


class ResponseStore:
    """Session-partitioned in-memory store for structured MCP tool responses.

    All methods are classmethods — no instantiation needed. Each session gets an
    LRU buffer capped at ``_max_entries``; the number of retained sessions is
    capped at ``_max_sessions`` (oldest session evicted whole). Thread-safe.
    """

    _lock: threading.RLock = threading.RLock()
    # session_id -> (ref_id -> StoredResponse), ordered by recency (LRU).
    _sessions: "OrderedDict[str, OrderedDict[str, StoredResponse]]" = OrderedDict()
    # session_id -> monotonic ref counter (never reused, so ref_ids stay unique).
    _counters: dict[str, int] = {}
    _max_entries: int = 50
    _max_sessions: int = 100

    @classmethod
    def store(
        cls,
        data: dict,
        tool_name: str = "",
        metadata: dict | None = None,
    ) -> str:
        """Store structured data for the current session and return a ref_id."""
        with cls._lock:
            sk = _session_id.get()
            entries = cls._sessions.get(sk)
            if entries is None:
                # New session — bound total sessions before adding.
                while len(cls._sessions) >= cls._max_sessions:
                    old_sk, _ = cls._sessions.popitem(last=False)
                    cls._counters.pop(old_sk, None)
                entries = OrderedDict()
                cls._sessions[sk] = entries
                cls._counters[sk] = 0
            cls._sessions.move_to_end(sk)  # session recency

            cls._counters[sk] += 1
            ref_id = f"resp_{cls._counters[sk]:03d}"

            if len(entries) >= cls._max_entries:
                entries.popitem(last=False)  # evict least-recently-used in this session

            entries[ref_id] = StoredResponse(
                ref_id=ref_id,
                tool_name=tool_name,
                timestamp=datetime.now(timezone.utc),
                data=data,
                metadata=metadata or {},
                record_count=cls._count_records(data),
            )
            return ref_id

    @classmethod
    def get(cls, ref_id: str) -> StoredResponse | None:
        """Retrieve a stored response by ref_id within the current session."""
        with cls._lock:
            entries = cls._sessions.get(_session_id.get())
            if not entries:
                return None
            sr = entries.get(ref_id)
            if sr is not None:
                entries.move_to_end(ref_id)  # reading refreshes LRU recency
            return sr

    @classmethod
    def list_refs(cls) -> list[dict]:
        """Return summary of all stored responses for the current session."""
        with cls._lock:
            entries = cls._sessions.get(_session_id.get())
            if not entries:
                return []
            return [
                {
                    "ref_id": sr.ref_id,
                    "tool_name": sr.tool_name,
                    "timestamp": sr.timestamp.isoformat(),
                    "record_count": sr.record_count,
                    "metadata": sr.metadata,
                }
                for sr in entries.values()
            ]

    @classmethod
    def _count_records(cls, data: dict) -> int:
        """Count records generically: sum lengths of all top-level list values."""
        return sum(len(v) for v in data.values() if isinstance(v, list))

    @classmethod
    def _reset(cls) -> None:
        """Clear all stored responses and counters. For testing only."""
        with cls._lock:
            cls._sessions.clear()
            cls._counters.clear()
