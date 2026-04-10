"""
ResponseStore — in-memory structured data store for large MCP tool responses.

Stores raw Python dicts from tool output (before text formatting) so the
get_stored_response MCP tool can do field-level extraction without Bash/grep.

This file lives at the root level (peer to utils.py) to keep the dependency
direction clean: utils.py imports from here, modules import from utils.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


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
    """Singleton in-memory store for structured MCP tool responses.

    All methods are classmethods — no instantiation needed.
    Ring buffer with FIFO eviction at _max_entries.
    """

    _store: dict[str, StoredResponse] = {}
    _counter: int = 0
    _max_entries: int = 50

    @classmethod
    def store(
        cls,
        data: dict,
        tool_name: str = "",
        metadata: dict | None = None,
    ) -> str:
        """Store structured data and return a ref_id (e.g., 'resp_001')."""
        cls._counter += 1
        ref_id = f"resp_{cls._counter:03d}"

        if len(cls._store) >= cls._max_entries:
            cls._evict_oldest()

        record_count = cls._count_records(data)

        cls._store[ref_id] = StoredResponse(
            ref_id=ref_id,
            tool_name=tool_name,
            timestamp=datetime.now(),
            data=data,
            metadata=metadata or {},
            record_count=record_count,
        )

        return ref_id

    @classmethod
    def get(cls, ref_id: str) -> StoredResponse | None:
        """Retrieve a stored response by ref_id."""
        return cls._store.get(ref_id)

    @classmethod
    def list_refs(cls) -> list[dict]:
        """Return summary of all stored responses."""
        return [
            {
                "ref_id": sr.ref_id,
                "tool_name": sr.tool_name,
                "timestamp": sr.timestamp.isoformat(),
                "record_count": sr.record_count,
                "metadata": sr.metadata,
            }
            for sr in cls._store.values()
        ]

    @classmethod
    def _count_records(cls, data: dict) -> int:
        """Count records generically: sum lengths of all top-level list values."""
        return sum(len(v) for v in data.values() if isinstance(v, list))

    @classmethod
    def _evict_oldest(cls) -> None:
        """Remove the oldest entry (FIFO)."""
        if cls._store:
            oldest_key = next(iter(cls._store))
            del cls._store[oldest_key]

    @classmethod
    def _reset(cls) -> None:
        """Clear all stored responses and reset counter. For testing only."""
        cls._store.clear()
        cls._counter = 0
