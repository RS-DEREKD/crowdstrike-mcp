"""Security/robustness tests for ResponseStore hardening.

Covers the criticals and highs from the architecture review:

* C1 — per-session isolation: one session cannot read another's stored
  responses (no cross-tenant leak / IDOR in HTTP mode).
* C2 — thread safety: concurrent stores issue unique ref_ids (atomic counter).
* H1 — LRU eviction: a recently-read ref survives eviction; a cold one doesn't.
* H2 — storage gating: trivially small responses don't consume buffer slots.
"""

import threading

import pytest

from crowdstrike_mcp.response_store import (
    ResponseStore,
    reset_response_session,
    set_response_session,
)
from crowdstrike_mcp.utils import LARGE_RESPONSE_THRESHOLD, format_text_response


@pytest.fixture(autouse=True)
def clean_store():
    ResponseStore._reset()
    yield
    ResponseStore._reset()


def _large_data():
    """Structured payload whose JSON serialization exceeds the threshold."""
    return {"events": [{"idx": i, "blob": "x" * 64} for i in range(1000)]}


def _small_data():
    return {"events": [{"idx": 0}]}


class TestSessionIsolation:
    def test_other_session_cannot_read_ref(self):
        tok_a = set_response_session("tenant-a")
        ref = ResponseStore.store(_small_data(), tool_name="ngsiem_query")
        reset_response_session(tok_a)

        tok_b = set_response_session("tenant-b")
        try:
            assert ResponseStore.get(ref) is None
        finally:
            reset_response_session(tok_b)

    def test_owning_session_can_read_ref(self):
        tok = set_response_session("tenant-a")
        try:
            ref = ResponseStore.store(_small_data(), tool_name="ngsiem_query")
            assert ResponseStore.get(ref) is not None
        finally:
            reset_response_session(tok)

    def test_list_refs_scoped_to_session(self):
        tok_a = set_response_session("tenant-a")
        ResponseStore.store(_small_data(), tool_name="a_tool")
        reset_response_session(tok_a)

        tok_b = set_response_session("tenant-b")
        try:
            assert ResponseStore.list_refs() == []
        finally:
            reset_response_session(tok_b)

    def test_ref_ids_independent_per_session(self):
        tok_a = set_response_session("tenant-a")
        ref_a = ResponseStore.store(_small_data(), tool_name="a")
        reset_response_session(tok_a)

        tok_b = set_response_session("tenant-b")
        try:
            ref_b = ResponseStore.store(_small_data(), tool_name="b")
            # Each session counts from 1 — same surface id, isolated stores.
            assert ref_a == "resp_001"
            assert ref_b == "resp_001"
            assert ResponseStore.get(ref_b) is not None
        finally:
            reset_response_session(tok_b)


class TestThreadSafety:
    def test_concurrent_stores_issue_unique_ref_ids(self):
        results: list[str] = []
        lock = threading.Lock()

        def worker(i):
            rid = ResponseStore.store({"events": [{"i": i}]}, tool_name="t")
            with lock:
                results.append(rid)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 100
        assert len(set(results)) == 100  # no duplicate / lost ref_ids under contention


class TestLruEviction:
    def test_recently_read_ref_survives_eviction(self):
        tok = set_response_session("tenant-a")
        try:
            max_n = ResponseStore._max_entries
            for _ in range(max_n):
                ResponseStore.store(_small_data(), tool_name="t")

            # Touch resp_001 so it becomes most-recently-used.
            assert ResponseStore.get("resp_001") is not None

            # One more store forces eviction of the cold oldest (resp_002),
            # not the freshly-read resp_001.
            ResponseStore.store(_small_data(), tool_name="t")

            assert ResponseStore.get("resp_001") is not None  # survived (hot)
            assert ResponseStore.get("resp_002") is None  # evicted (cold)
        finally:
            reset_response_session(tok)


class TestStorageGating:
    def test_small_text_and_small_data_not_stored(self):
        tok = set_response_session("tenant-a")
        try:
            out = format_text_response("ok", tool_name="t", raw=True, structured_data=_small_data())
            assert "[Structured data available" not in out
            assert ResponseStore.list_refs() == []
        finally:
            reset_response_session(tok)

    def test_small_text_large_data_is_stored(self):
        tok = set_response_session("tenant-a")
        try:
            out = format_text_response("short summary", tool_name="t", raw=True, structured_data=_large_data())
            assert "[Structured data available" in out
            assert len(ResponseStore.list_refs()) == 1
        finally:
            reset_response_session(tok)

    def test_large_text_small_data_is_stored(self):
        tok = set_response_session("tenant-a")
        try:
            big_text = "x" * (LARGE_RESPONSE_THRESHOLD + 1)
            out = format_text_response(big_text, tool_name="t", raw=True, structured_data=_small_data())
            assert "RESPONSE TRUNCATED" in out
            assert "resp_" in out  # ref offered for recovery
            assert len(ResponseStore.list_refs()) == 1
        finally:
            reset_response_session(tok)
