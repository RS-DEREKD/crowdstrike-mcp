# MCP Tool Improvements Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pagination, summary mode, and field projection to CrowdStrike MCP tools to reduce SOC agent friction.

**Architecture:** Per-tool parameter additions — no new abstractions. Each feature is implemented directly in its module (`alerts.py`, `ngsiem.py`) with supporting FQL guide updates. All new parameters have backward-compatible defaults.

**Tech Stack:** Python 3.11, FalconPy SDK, FastMCP, pytest

**Spec:** `docs/superpowers/specs/2026-04-07-mcp-improvements-design.md`

---

## Chunk 1: `get_alerts` Pagination + Server-Side Search

### Task 1: Add pagination unit tests

**Files:**
- Create: `tests/test_alerts_pagination.py`

- [ ] **Step 1: Write failing tests for offset, q, and server-side pattern_name**

```python
"""Tests for get_alerts pagination, q search, and server-side pattern_name."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def alerts_module(mock_client):
    """Create an AlertsModule with mocked FalconPy services."""
    with patch("modules.alerts.Alerts") as MockAlerts, \
         patch("modules.alerts.NGSIEM", create=True):
        mock_alerts_api = MagicMock()
        MockAlerts.return_value = mock_alerts_api
        from modules.alerts import AlertsModule
        module = AlertsModule(mock_client)
        module.alerts = mock_alerts_api
        yield module, mock_alerts_api


class TestGetAlertsPagination:
    """Tests for offset parameter in get_alerts."""

    def test_offset_passed_to_api(self, alerts_module):
        """offset parameter is forwarded to query_alerts_v2."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        module._get_alerts(offset=100)

        mock_api.query_alerts_v2.assert_called_once()
        assert mock_api.query_alerts_v2.call_args.kwargs["offset"] == 100

    def test_offset_negative_clamped_to_zero(self, alerts_module):
        """Negative offset is clamped to 0."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        module._get_alerts(offset=-5)

        assert mock_api.query_alerts_v2.call_args.kwargs["offset"] == 0

    def test_next_offset_mid_page(self, alerts_module):
        """next_offset is offset + count when more results exist."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["id1", "id2"],
                "meta": {"pagination": {"total": 100}},
            },
        }
        mock_api.get_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"composite_id": "cid:ngsiem:cid:id1", "name": "Test1", "severity_name": "Low", "severity": 20, "status": "new", "created_timestamp": "2026-04-07T00:00:00Z", "updated_timestamp": "", "product": "ngsiem", "tags": [], "description": ""},
                    {"composite_id": "cid:ngsiem:cid:id2", "name": "Test2", "severity_name": "Low", "severity": 20, "status": "new", "created_timestamp": "2026-04-07T00:00:00Z", "updated_timestamp": "", "product": "ngsiem", "tags": [], "description": ""},
                ],
            },
        }

        result = module._get_alerts(offset=0, max_results=2)

        assert result["success"] is True
        assert result["next_offset"] == 2
        assert result["offset"] == 0

    def test_next_offset_last_page(self, alerts_module):
        """next_offset is None on the last page."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["id1"],
                "meta": {"pagination": {"total": 1}},
            },
        }
        mock_api.get_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"composite_id": "cid:ngsiem:cid:id1", "name": "Test1", "severity_name": "Low", "severity": 20, "status": "new", "created_timestamp": "2026-04-07T00:00:00Z", "updated_timestamp": "", "product": "ngsiem", "tags": [], "description": ""},
                ],
            },
        }

        result = module._get_alerts(offset=0, max_results=50)

        assert result["success"] is True
        assert result["next_offset"] is None

    def test_next_offset_empty_results(self, alerts_module):
        """next_offset is None when no results returned."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        result = module._get_alerts(offset=0)

        assert result["success"] is True
        assert result["next_offset"] is None


class TestGetAlertsQParam:
    """Tests for q (free-text search) parameter."""

    def test_q_passed_to_api(self, alerts_module):
        """q parameter is forwarded to query_alerts_v2."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        module._get_alerts(q="MCP Server")

        assert mock_api.query_alerts_v2.call_args.kwargs["q"] == "MCP Server"

    def test_q_empty_string_treated_as_none(self, alerts_module):
        """Empty string q is not passed to the API."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        module._get_alerts(q="")

        call_kwargs = mock_api.query_alerts_v2.call_args
        # q should not be in kwargs, or should be None
        q_val = call_kwargs.kwargs.get("q") if call_kwargs.kwargs else None
        assert q_val is None

    def test_q_echoed_in_response(self, alerts_module):
        """q value is echoed in the response dict."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        result = module._get_alerts(q="test search")

        assert result.get("q") == "test search"


class TestGetAlertsPatternNameFQL:
    """Tests for server-side pattern_name via FQL wildcard."""

    def test_pattern_name_in_fql_filter(self, alerts_module):
        """pattern_name is added to FQL filter as case-insensitive wildcard."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        module._get_alerts(pattern_name="MCP Server")

        call_kwargs = mock_api.query_alerts_v2.call_args
        filter_str = call_kwargs.kwargs.get("filter", "") or call_kwargs[1].get("filter", "")
        assert "name:~*'*MCP Server*'" in filter_str

    def test_pattern_name_sanitized(self, alerts_module):
        """Single quotes in pattern_name are stripped to produce valid FQL."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        module._get_alerts(pattern_name="it's a test")

        call_kwargs = mock_api.query_alerts_v2.call_args
        filter_str = call_kwargs.kwargs.get("filter", "")
        # Internal single quotes stripped — result is valid FQL
        assert "name:~*'*its a test*'" in filter_str

    def test_no_client_side_filtering(self, alerts_module):
        """With pattern_name, all API results are returned without client-side filtering."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["id1", "id2"],
                "meta": {"pagination": {"total": 2}},
            },
        }
        mock_api.get_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"composite_id": "cid:ngsiem:cid:id1", "name": "Alpha", "severity_name": "Low", "severity": 20, "status": "new", "created_timestamp": "", "updated_timestamp": "", "product": "ngsiem", "tags": [], "description": ""},
                    {"composite_id": "cid:ngsiem:cid:id2", "name": "Beta", "severity_name": "Low", "severity": 20, "status": "new", "created_timestamp": "", "updated_timestamp": "", "product": "ngsiem", "tags": [], "description": ""},
                ],
            },
        }

        result = module._get_alerts(pattern_name="Alpha", max_results=50)

        # Both alerts returned — no client-side filtering
        assert result["count"] == 2


class TestGetAlertsMaxResults:
    """Tests for raised max_results cap."""

    def test_max_results_clamped_to_1000(self, alerts_module):
        """max_results above 1000 is clamped."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        module._get_alerts(max_results=5000)

        assert mock_api.query_alerts_v2.call_args.kwargs["limit"] == 1000

    def test_max_results_minimum_is_1(self, alerts_module):
        """max_results below 1 is clamped to 1."""
        module, mock_api = alerts_module
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [], "meta": {"pagination": {"total": 0}}},
        }

        module._get_alerts(max_results=0)

        assert mock_api.query_alerts_v2.call_args.kwargs["limit"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python3 -m pytest tests/test_alerts_pagination.py -v`
Expected: FAIL — `_get_alerts` doesn't accept `offset`, `q` params yet

- [ ] **Step 3: Commit test file**

```bash
git add tests/test_alerts_pagination.py
git commit -m "test: add failing tests for get_alerts pagination, q search, and pattern_name FQL"
```

---

### Task 2: Implement get_alerts pagination + server-side search

**Files:**
- Modify: `modules/alerts.py:113-121` (get_alerts signature)
- Modify: `modules/alerts.py:234-344` (_get_alerts implementation)

- [ ] **Step 4: Update `get_alerts` tool signature**

In `modules/alerts.py`, replace the `get_alerts` method signature (lines 113-121) with:

```python
    async def get_alerts(
        self,
        severity: Annotated[str, "Minimum severity level"] = "ALL",
        time_range: Annotated[str, "Time range (e.g. '1h', '6h', '12h', '1d', '7d', '30d')"] = "1d",
        status: Annotated[str, "Filter by alert status"] = "all",
        pattern_name: Annotated[Optional[str], "Wildcard match on detection/alert name (server-side FQL)"] = None,
        product: Annotated[str, "Filter by detection source/product type"] = "all",
        max_results: Annotated[int, "Maximum alerts to return (default: 50, max: 1000)"] = 50,
        offset: Annotated[int, "Number of alerts to skip for pagination (default: 0)"] = 0,
        q: Annotated[Optional[str], "Free-text search across all alert metadata"] = None,
        summary_mode: Annotated[bool, "Return compact key-fields only (default: false)"] = False,
    ) -> str:
```

Update the call to `_get_alerts` (lines 123-130) to pass the new params:

```python
        result = self._get_alerts(
            severity=severity,
            time_range=time_range,
            status=status,
            pattern_name=pattern_name,
            product=product,
            max_results=max_results,
            offset=offset,
            q=q,
        )
```

Update the response formatting (lines 138-161) to include pagination info:

```python
        alerts_list = result["alerts"]
        lines = [
            f"Alerts Retrieved: {result['count']} (of {result['total_available']} total)",
            f"Filter: severity={severity}, time_range={time_range}, status={status}, product={product}",
        ]
        if pattern_name:
            lines.append(f"Pattern: {pattern_name}")
        if q:
            lines.append(f"Search: {q}")
        if result.get("offset", 0) > 0 or result.get("next_offset") is not None:
            lines.append(f"Offset: {result.get('offset', 0)} | Next: {result.get('next_offset', 'None')}")
        lines.append("")
```

- [ ] **Step 5: Update `_get_alerts` implementation**

In `modules/alerts.py`, replace the `_get_alerts` method signature (line 234) with:

```python
    def _get_alerts(self, severity="ALL", time_range="1d", status="all", pattern_name=None, product="all", max_results=50, offset=0, q=None):
```

Add input validation and max_results clamping after the time parsing (after line 243):

```python
            # Input validation
            max_results = min(max(max_results, 1), 1000)
            offset = max(offset, 0)
            if q is not None and not q.strip():
                q = None
```

Replace the `pattern_name` comment and product filter section (lines 255-267) with:

```python
            # Server-side name filtering via FQL wildcard (case-insensitive)
            if pattern_name:
                sanitized = sanitize_input(pattern_name)
                # Strip internal single quotes to prevent FQL syntax breakage
                sanitized = sanitized.replace("'", "")
                filter_parts.append(f"name:~*'*{sanitized}*'")

            if product.lower() != "all":
                fql_values = PRODUCT_FQL_MAP.get(product.lower())
                if fql_values:
                    product_list = ",".join(f"'{v}'" for v in fql_values)
                    filter_parts.append(f"product:[{product_list}]")

            filter_query = "+".join(filter_parts)

            fetch_limit = min(max_results, 1000)
```

Add `sanitize_input` to the imports at the top of the file (line 26-31):

```python
from utils import (
    PRODUCT_FQL_MAP,
    extract_detection_id,
    format_text_response,
    parse_composite_id,
    sanitize_input,
)
```

Update the empty-results return dict (lines 282-289) to include new fields:

```python
            if not alert_ids:
                return {
                    "success": True,
                    "alerts": [],
                    "count": 0,
                    "total_available": 0,
                    "offset": offset,
                    "next_offset": None,
                    "filter": filter_query,
                    "q": q,
                    "time_range": time_range,
                }
```

Update the `query_alerts_v2` call (lines 269-273) to pass offset and q:

```python
            api_kwargs = {
                "filter": filter_query,
                "limit": fetch_limit,
                "sort": "created_timestamp.desc",
                "offset": offset,
            }
            if q:
                api_kwargs["q"] = q

            response = self.alerts.query_alerts_v2(**api_kwargs)
```

Remove the client-side filtering block (lines 327-333) and replace with:

```python
            # No client-side filtering needed — pattern_name is now FQL server-side

            return {
                "success": True,
                "alerts": alert_summaries,
                "count": len(alert_summaries),
                "total_available": total_available,
                "offset": offset,
                "next_offset": (offset + len(alert_summaries)) if (offset + len(alert_summaries)) < total_available else None,
                "filter": filter_query,
                "q": q,
                "time_range": time_range,
            }
```

- [ ] **Step 6: Run pagination tests to verify they pass**

Run: `.venv/bin/python3 -m pytest tests/test_alerts_pagination.py -v`
Expected: All PASS

- [ ] **Step 7: Run full test suite to check for regressions**

Run: `.venv/bin/python3 -m pytest tests/ -v`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add modules/alerts.py tests/test_alerts_pagination.py
git commit -m "feat(alerts): add pagination (offset), q search, and server-side pattern_name FQL"
```

---

## Chunk 2: `get_alerts` Summary Mode

### Task 3: Add summary mode unit tests

**Files:**
- Modify: `tests/test_alerts_pagination.py` (add new test class)

- [ ] **Step 9: Write failing tests for summary_mode**

Append to `tests/test_alerts_pagination.py`:

```python
class TestGetAlertsSummaryMode:
    """Tests for summary_mode on get_alerts."""

    def _make_ngsiem_alert(self, name="Test Alert"):
        """Helper: create a mock NGSIEM alert with all fields."""
        return {
            "composite_id": "cid:ngsiem:cid:id1",
            "name": name,
            "severity_name": "High",
            "severity": 40,
            "status": "new",
            "created_timestamp": "2026-04-07T00:00:00Z",
            "updated_timestamp": "2026-04-07T01:00:00Z",
            "assigned_to_name": "analyst",
            "type": "detection",
            "product": "ngsiem",
            "tags": ["soc-triage"],
            "description": "A " * 200,  # long description
            "tactic": "Discovery",
            "technique": "T1518.001",
            "host_names": ["RR-J2XJG94"],
            "user_names": ["admin"],
        }

    def _make_cwpp_alert(self):
        """Helper: create a mock CWPP alert (sparse fields)."""
        return {
            "composite_id": "cid:cwpp:cid:id2",
            "name": "RunningAsRootContainer",
            "severity_name": "Informational",
            "severity": 4,
            "status": "new",
            "created_timestamp": "2026-04-07T00:00:00Z",
            "updated_timestamp": "",
            "product": "cwpp",
            "description": "Container running as root",
        }

    def test_summary_mode_trims_fields(self, alerts_module):
        """summary_mode=True returns only the compact field set."""
        module, mock_api = alerts_module
        ngsiem_alert = self._make_ngsiem_alert()
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["id1"],
                "meta": {"pagination": {"total": 1}},
            },
        }
        mock_api.get_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [ngsiem_alert]},
        }

        result = module._get_alerts(summary_mode=True)

        assert result["success"] is True
        alert = result["alerts"][0]
        # Summary fields present
        assert "composite_id" in alert
        assert "name" in alert
        assert "severity" in alert
        assert "status" in alert
        assert "product" in alert
        assert "created_timestamp" in alert
        assert "tactic" in alert
        assert "host_names" in alert
        # Full-mode fields absent
        assert "description" not in alert
        assert "updated_timestamp" not in alert
        assert "severity_value" not in alert
        assert "assigned_to" not in alert
        assert "type" not in alert

    def test_summary_mode_handles_missing_fields(self, alerts_module):
        """summary_mode works on CWPP alerts that lack tactic/technique/host_names."""
        module, mock_api = alerts_module
        cwpp_alert = self._make_cwpp_alert()
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["id2"],
                "meta": {"pagination": {"total": 1}},
            },
        }
        mock_api.get_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [cwpp_alert]},
        }

        result = module._get_alerts(summary_mode=True)

        assert result["success"] is True
        alert = result["alerts"][0]
        assert alert["composite_id"] == "cid:cwpp:cid:id2"
        # Missing fields should be None, not KeyError
        assert alert.get("tactic") is None
        assert alert.get("host_names") is None

    def test_summary_mode_false_returns_full_fields(self, alerts_module):
        """summary_mode=False (default) returns all fields including description."""
        module, mock_api = alerts_module
        ngsiem_alert = self._make_ngsiem_alert()
        mock_api.query_alerts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["id1"],
                "meta": {"pagination": {"total": 1}},
            },
        }
        mock_api.get_alerts_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [ngsiem_alert]},
        }

        result = module._get_alerts(summary_mode=False)

        assert result["success"] is True
        alert = result["alerts"][0]
        assert "description" in alert
        assert "severity_value" in alert
```

- [ ] **Step 10: Run tests to verify they fail**

Run: `.venv/bin/python3 -m pytest tests/test_alerts_pagination.py::TestGetAlertsSummaryMode -v`
Expected: FAIL — `_get_alerts` doesn't accept `summary_mode` yet

- [ ] **Step 11: Commit test additions**

```bash
git add tests/test_alerts_pagination.py
git commit -m "test: add failing tests for get_alerts summary_mode"
```

---

### Task 4: Implement get_alerts summary mode

**Files:**
- Modify: `modules/alerts.py:234` (_get_alerts — add summary_mode param and field trimming)

- [ ] **Step 12: Add summary_mode to _get_alerts**

Update `_get_alerts` signature to include `summary_mode=False`:

```python
    def _get_alerts(self, severity="ALL", time_range="1d", status="all", pattern_name=None, product="all", max_results=50, offset=0, q=None, summary_mode=False):
```

After the alert_summaries construction loop (after the `for a in alerts_data:` block), add summary mode trimming before the return:

```python
            if summary_mode:
                summary_alerts = []
                for a_raw, a_summary in zip(alerts_data, alert_summaries):
                    summary_alerts.append({
                        "composite_id": a_summary["composite_id"],
                        "name": a_summary["name"],
                        "severity": a_summary["severity"],
                        "status": a_summary["status"],
                        "product": a_summary["product_name"],
                        "created_timestamp": a_summary["created_timestamp"],
                        "tactic": a_raw.get("tactic"),
                        "technique": a_raw.get("technique"),
                        "host_names": a_raw.get("host_names"),
                        "user_names": a_raw.get("user_names"),
                        "tags": a_raw.get("tags"),
                    })
                alert_summaries = summary_alerts
```

Also pass `summary_mode` through from `get_alerts()` to `_get_alerts()`:

```python
        result = self._get_alerts(
            ...,
            summary_mode=summary_mode,
        )
```

- [ ] **Step 13: Run summary mode tests**

Run: `.venv/bin/python3 -m pytest tests/test_alerts_pagination.py::TestGetAlertsSummaryMode -v`
Expected: All PASS

- [ ] **Step 14: Run full test suite**

Run: `.venv/bin/python3 -m pytest tests/ -v`
Expected: All PASS

- [ ] **Step 15: Commit**

```bash
git add modules/alerts.py
git commit -m "feat(alerts): add summary_mode for compact key-fields responses"
```

---

## Chunk 2b: `alert_analysis` Summary Mode

### Task 5: Add alert_analysis summary mode tests

**Files:**
- Create: `tests/test_alert_analysis_summary.py`

- [ ] **Step 16: Write failing tests for alert_analysis summary_mode**

```python
"""Tests for alert_analysis summary_mode."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def alerts_module_with_ngsiem(mock_client):
    """Create AlertsModule with mocked NGSIEM for enrichment."""
    with patch("modules.alerts.Alerts") as MockAlerts, \
         patch("modules.alerts.NGSIEM") as MockNGSIEM:
        mock_alerts_api = MagicMock()
        mock_ngsiem_api = MagicMock()
        MockAlerts.return_value = mock_alerts_api
        MockNGSIEM.return_value = mock_ngsiem_api
        from modules.alerts import AlertsModule
        module = AlertsModule(mock_client)
        module.alerts = mock_alerts_api
        module._ngsiem = mock_ngsiem_api
        yield module, mock_alerts_api


class TestAlertAnalysisSummaryMode:
    """Tests for summary_mode on alert_analysis."""

    def test_summary_caps_events_at_5(self, alerts_module_with_ngsiem):
        """summary_mode=True caps related events at 5."""
        module, mock_api = alerts_module_with_ngsiem

        analysis_result = {
            "success": True,
            "alert": {
                "name": "Test Detection",
                "composite_id": "cid:ngsiem:cid:id1",
                "severity_name": "High",
                "severity": 40,
                "status": "new",
                "type": "detection",
                "product": "ngsiem",
                "tags": ["soc-triage"],
                "tactic": "Discovery",
                "technique": "T1518.001",
                "created_timestamp": "2026-04-07T00:00:00Z",
                "updated_timestamp": "",
            },
            "product_type": "ngsiem",
            "product_name": "NG-SIEM",
            "enrichment_type": "ngsiem_events",
            "events": [
                {"@timestamp": f"2026-04-07T0{i}:00:00Z", "event.action": "ConsoleLogin", "ComputerName": f"host{i}", "UserName": "admin", "source.ip": "10.0.0.1"}
                for i in range(10)
            ],
            "events_matched": 47,
            "behaviors": None,
            "enrichment_note": None,
        }

        response_text = module._format_alert_analysis_response(analysis_result, summary_mode=True)

        # Should mention "5 of 47"
        assert "5 of 47" in response_text or "Showing 5" in response_text
        # Should NOT contain all 10 events
        assert "host9" not in response_text

    def test_summary_ngsiem_event_fields(self, alerts_module_with_ngsiem):
        """summary_mode projects correct fields for NGSIEM events."""
        module, _ = alerts_module_with_ngsiem

        analysis_result = {
            "success": True,
            "alert": {
                "name": "Test", "composite_id": "cid:ngsiem:cid:id1",
                "severity_name": "High", "severity": 40, "status": "new",
                "product": "ngsiem", "tactic": "Discovery", "technique": "T1518",
                "created_timestamp": "", "updated_timestamp": "",
            },
            "product_type": "ngsiem",
            "product_name": "NG-SIEM",
            "enrichment_type": "ngsiem_events",
            "events": [
                {"@timestamp": "2026-04-07T00:00:00Z", "event.action": "ConsoleLogin", "ComputerName": "host1", "UserName": "admin", "source.ip": "10.0.0.1", "extra_field": "should_not_appear_in_summary"}
            ],
            "events_matched": 1,
            "behaviors": None,
            "enrichment_note": None,
        }

        response_text = module._format_alert_analysis_response(analysis_result, summary_mode=True)

        # Key fields should be present
        assert "ComputerName" in response_text or "host1" in response_text
        # Full JSON dump should NOT be present (no extra_field in summary)
        assert "extra_field" not in response_text

    def test_summary_mode_false_includes_full_json(self, alerts_module_with_ngsiem):
        """summary_mode=False (default) includes full JSON event dumps."""
        module, _ = alerts_module_with_ngsiem

        analysis_result = {
            "success": True,
            "alert": {
                "name": "Test", "composite_id": "cid:ngsiem:cid:id1",
                "severity_name": "High", "severity": 40, "status": "new",
                "product": "ngsiem", "created_timestamp": "", "updated_timestamp": "",
            },
            "product_type": "ngsiem",
            "product_name": "NG-SIEM",
            "enrichment_type": "ngsiem_events",
            "events": [
                {"@timestamp": "2026-04-07T00:00:00Z", "extra_field": "visible_in_full"}
            ],
            "events_matched": 1,
            "behaviors": None,
            "enrichment_note": None,
        }

        response_text = module._format_alert_analysis_response(analysis_result, summary_mode=False)

        assert "extra_field" in response_text
```

- [ ] **Step 17: Run tests to verify they fail**

Run: `.venv/bin/python3 -m pytest tests/test_alert_analysis_summary.py -v`
Expected: FAIL — `_format_alert_analysis_response` doesn't accept `summary_mode`

- [ ] **Step 18: Commit test file**

```bash
git add tests/test_alert_analysis_summary.py
git commit -m "test: add failing tests for alert_analysis summary_mode"
```

---

### Task 6: Implement alert_analysis summary mode

**Files:**
- Modify: `modules/alerts.py:163-179` (alert_analysis tool signature)
- Modify: `modules/alerts.py:606-731` (_format_alert_analysis_response)

- [ ] **Step 19: Update alert_analysis signature**

Update `alert_analysis` (line 163-167) to accept `summary_mode`:

```python
    async def alert_analysis(
        self,
        detection_id: Annotated[str, "The composite detection ID to analyze"],
        max_events: Annotated[int, "Maximum related events to retrieve (for NGSIEM)"] = 10,
        summary_mode: Annotated[bool, "Return compact summary only (default: false)"] = False,
    ) -> str:
```

Update the call to `_format_alert_analysis_response` (line 178):

```python
        response_text = self._format_alert_analysis_response(result, summary_mode=summary_mode)
```

- [ ] **Step 20: Add summary branch to `_format_alert_analysis_response`**

Update the method signature (line 606) to accept `summary_mode`:

```python
    def _format_alert_analysis_response(self, analysis, summary_mode=False):
```

Add a summary branch at the top of the method, right after the `alert = analysis["alert"]` line (after line 608):

```python
        if summary_mode:
            return self._format_alert_analysis_summary(analysis)
```

Add the new summary formatting method after `_format_alert_analysis_response`:

```python
    def _format_alert_analysis_summary(self, analysis):
        """Format a compact summary of the alert analysis."""
        alert = analysis["alert"]
        parts = []

        parts.append(f"## Alert Summary ({analysis['product_name']})")
        parts.append("")
        parts.append(f"- **Name**: {alert.get('name', 'Unknown')}")
        parts.append(f"- **ID**: {alert.get('composite_id', 'N/A')}")
        parts.append(f"- **Severity**: {alert.get('severity_name', 'Unknown')}")
        parts.append(f"- **Status**: {alert.get('status', 'unknown')}")
        parts.append(f"- **Product**: {analysis['product_name']}")

        tactic = alert.get("tactic")
        technique = alert.get("technique")
        if tactic:
            parts.append(f"- **MITRE**: {tactic} / {technique or 'N/A'}")

        tags = alert.get("tags", [])
        if tags:
            parts.append(f"- **Tags**: {', '.join(tags)}")
        parts.append("")

        # Summary events — capped at 5
        events = analysis.get("events") or []
        total_events = analysis.get("events_matched", len(events))
        summary_events = events[:5]

        if summary_events:
            parts.append(f"### Related Events (showing {len(summary_events)} of {total_events})")
            parts.append("")

            # Define key fields per event type
            ngsiem_fields = ["@timestamp", "#event_simpleName", "event.action", "ComputerName", "UserName", "source.ip"]
            endpoint_fields = ["timestamp", "tactic", "technique", "filename", "cmdline"]

            is_endpoint = analysis.get("enrichment_type") == "endpoint_behaviors"
            key_fields = endpoint_fields if is_endpoint else ngsiem_fields

            for i, event in enumerate(summary_events, 1):
                field_parts = []
                for field in key_fields:
                    val = event.get(field)
                    if val is not None:
                        val_str = str(val)
                        if field == "cmdline" and len(val_str) > 200:
                            val_str = val_str[:200] + "..."
                        field_parts.append(f"{field}={val_str}")
                if field_parts:
                    parts.append(f"{i}. {' | '.join(field_parts)}")

            if total_events > 5:
                parts.append("")
                parts.append(f"_Showing {len(summary_events)} of {total_events} related events. Use summary_mode=false for full details._")
            parts.append("")

        # Endpoint behaviors summary
        behaviors = analysis.get("behaviors") or []
        if behaviors and not events:
            total_behaviors = len(behaviors)
            summary_behaviors = behaviors[:5]
            parts.append(f"### Endpoint Behaviors (showing {len(summary_behaviors)} of {total_behaviors})")
            parts.append("")
            for i, b in enumerate(summary_behaviors, 1):
                field_parts = []
                for field in ["tactic", "technique", "filename", "cmdline"]:
                    val = b.get(field)
                    if val is not None:
                        val_str = str(val)[:200]
                        field_parts.append(f"{field}={val_str}")
                if field_parts:
                    parts.append(f"{i}. {' | '.join(field_parts)}")
            parts.append("")

        if analysis.get("enrichment_note"):
            parts.append(f"> {analysis['enrichment_note']}")
            parts.append("")

        return "\n".join(parts)
```

- [ ] **Step 21: Run alert_analysis summary tests**

Run: `.venv/bin/python3 -m pytest tests/test_alert_analysis_summary.py -v`
Expected: All PASS

- [ ] **Step 22: Run full test suite**

Run: `.venv/bin/python3 -m pytest tests/ -v`
Expected: All PASS

- [ ] **Step 23: Commit**

```bash
git add modules/alerts.py tests/test_alert_analysis_summary.py
git commit -m "feat(alerts): add summary_mode for alert_analysis with event cap and field projection"
```

---

## Chunk 3: `ngsiem_query` Field Projection

> **Note:** `AlertsModule._execute_ngsiem_query` (lines 448-504 in alerts.py) is a separate internal code path used for enrichment. It does NOT need `fields` support — that's only for the user-facing `ngsiem_query` tool via `NGSIEMModule._execute_query`.

### Task 7: Add field projection unit tests

**Files:**
- Create: `tests/test_ngsiem_fields.py`

- [ ] **Step 24: Write failing tests for fields parameter**

```python
"""Tests for ngsiem_query field projection."""

import os
import re
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def ngsiem_module(mock_client):
    """Create NGSIEMModule with mocked NGSIEM service."""
    with patch("modules.ngsiem.NGSIEM") as MockNGSIEM:
        mock_ngsiem_api = MagicMock()
        MockNGSIEM.return_value = mock_ngsiem_api
        from modules.ngsiem import NGSIEMModule
        module = NGSIEMModule(mock_client)
        module.falcon = mock_ngsiem_api
        yield module, mock_ngsiem_api


class TestNGSIEMFieldProjection:
    """Tests for fields parameter on ngsiem_query."""

    def test_fields_appends_select(self, ngsiem_module):
        """fields parameter appends | select([...]) to the query."""
        module, mock_api = ngsiem_module
        mock_api.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-123"},
        }
        mock_api.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": [], "cancelled": False},
        }

        module._execute_query(
            "#event_simpleName=DnsRequest",
            fields="@timestamp,DomainName,ComputerName",
        )

        call_args = mock_api.start_search.call_args
        query_sent = call_args.kwargs.get("query_string", "") or call_args[1].get("query_string", "")
        assert "| select([@timestamp, DomainName, ComputerName])" in query_sent

    def test_fields_ignored_when_select_exists(self, ngsiem_module):
        """fields parameter is ignored if query already contains | select(...)."""
        module, mock_api = ngsiem_module
        mock_api.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-123"},
        }
        mock_api.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": [], "cancelled": False},
        }

        query = "#event_simpleName=DnsRequest | select([@timestamp])"
        result = module._execute_query(query, fields="DomainName,ComputerName")

        call_args = mock_api.start_search.call_args
        query_sent = call_args.kwargs.get("query_string", "") or call_args[1].get("query_string", "")
        # Original select preserved, no second select added
        assert "select([@timestamp])" in query_sent
        assert "DomainName" not in query_sent

    def test_fields_ignored_when_table_exists(self, ngsiem_module):
        """fields parameter is ignored if query already contains | table(...)."""
        module, mock_api = ngsiem_module
        mock_api.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-123"},
        }
        mock_api.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": [], "cancelled": False},
        }

        query = "#event_simpleName=DnsRequest | table([@timestamp])"
        result = module._execute_query(query, fields="DomainName")

        call_args = mock_api.start_search.call_args
        query_sent = call_args.kwargs.get("query_string", "") or call_args[1].get("query_string", "")
        assert "table([@timestamp])" in query_sent
        assert "DomainName" not in query_sent

    def test_fields_empty_string_no_projection(self, ngsiem_module):
        """Empty string fields parameter does not add select()."""
        module, mock_api = ngsiem_module
        mock_api.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-123"},
        }
        mock_api.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": [], "cancelled": False},
        }

        module._execute_query("#event_simpleName=DnsRequest", fields="")

        call_args = mock_api.start_search.call_args
        query_sent = call_args.kwargs.get("query_string", "") or call_args[1].get("query_string", "")
        assert "select(" not in query_sent

    def test_fields_trailing_commas_handled(self, ngsiem_module):
        """Trailing commas produce clean select() without empty fields."""
        module, mock_api = ngsiem_module
        mock_api.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-123"},
        }
        mock_api.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": [], "cancelled": False},
        }

        module._execute_query("#event_simpleName=DnsRequest", fields="@timestamp,,DomainName,")

        call_args = mock_api.start_search.call_args
        query_sent = call_args.kwargs.get("query_string", "") or call_args[1].get("query_string", "")
        assert "| select([@timestamp, DomainName])" in query_sent

    def test_field_projection_in_response(self, ngsiem_module):
        """field_projection list is included in the response dict."""
        module, mock_api = ngsiem_module
        mock_api.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-123"},
        }
        mock_api.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": [], "cancelled": False},
        }

        result = module._execute_query(
            "#event_simpleName=DnsRequest",
            fields="@timestamp,DomainName",
        )

        assert result["field_projection"] == ["@timestamp", "DomainName"]

    def test_no_fields_returns_null_projection(self, ngsiem_module):
        """Without fields parameter, field_projection is None."""
        module, mock_api = ngsiem_module
        mock_api.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-123"},
        }
        mock_api.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": [], "cancelled": False},
        }

        result = module._execute_query("#event_simpleName=DnsRequest")

        assert result.get("field_projection") is None
```

- [ ] **Step 25: Run tests to verify they fail**

Run: `.venv/bin/python3 -m pytest tests/test_ngsiem_fields.py -v`
Expected: FAIL — `_execute_query` doesn't accept `fields`

- [ ] **Step 26: Commit test file**

```bash
git add tests/test_ngsiem_fields.py
git commit -m "test: add failing tests for ngsiem_query field projection"
```

---

### Task 8: Implement ngsiem_query field projection

**Files:**
- Modify: `modules/ngsiem.py:53-58` (ngsiem_query signature)
- Modify: `modules/ngsiem.py:109-204` (_execute_query)

- [ ] **Step 27: Update ngsiem_query signature**

Add `import re` at the top of `modules/ngsiem.py` (after `import time`).

Update the `ngsiem_query` method signature (lines 53-58):

```python
    async def ngsiem_query(
        self,
        query: Annotated[str, "The NGSIEM/CQL query to execute"],
        start_time: Annotated[str, "Time range (e.g. '1h', '1d', '7d', '30d')"] = "1d",
        max_results: Annotated[int, "Maximum results to return (default: 100, max: 1000)"] = 100,
        fields: Annotated[Optional[str], "Comma-separated field names for projection (e.g. '@timestamp,DomainName,ComputerName')"] = None,
    ) -> str:
```

Add `Optional` to the imports (line 12):

```python
from typing import TYPE_CHECKING, Annotated, Optional
```

Update the call to `_execute_query` (line 62):

```python
        result = self._execute_query(query, start_time, max_results, fields=fields)
```

Add `field_projection` to the response formatting (after the truncation line, around line 76):

```python
            if result.get("field_projection"):
                lines.append(f"Field Projection: {', '.join(result['field_projection'])}")
```

- [ ] **Step 28: Update _execute_query to handle fields**

Update the `_execute_query` signature (line 109-114):

```python
    def _execute_query(
        self,
        query: str,
        start_time: str = "1d",
        max_results: int = 100,
        fields: str | None = None,
    ) -> dict:
```

Add field projection logic right before the MCP comment line (before line 117):

```python
        # Field projection — append | select([...]) if fields provided and no existing projection
        field_list = None
        if fields and fields.strip():
            field_list = [f.strip() for f in fields.split(",") if f.strip()]

        if field_list:
            # Check if query already has select() or table() as a pipe stage
            has_projection = bool(re.search(r'\|\s*(?:select|table)\s*\(', query))
            if not has_projection:
                projection = ", ".join(field_list)
                query = f"{query} | select([{projection}])"
            else:
                field_list = None  # Projection skipped — query already has select/table

        field_projection_skipped = (fields and fields.strip() and field_list is None)
```

Add `field_projection` to the success response dict (inside the `if done or cancelled:` block, around line 195-204):

```python
                    return {
                        "success": True,
                        "events_processed": events_processed,
                        "events_matched": events_matched,
                        "events_returned": len(events),
                        "results_truncated": truncated,
                        "query": query,  # Includes select() if added
                        "time_range": start_time,
                        "events": events,
                        "field_projection": field_list,
                        "field_projection_skipped": "query already contains select() or table()" if field_projection_skipped else None,
                    }
```

Also add `"field_projection": None` to the error response dicts so the key is always present.

- [ ] **Step 29: Run field projection tests**

Run: `.venv/bin/python3 -m pytest tests/test_ngsiem_fields.py -v`
Expected: All PASS

- [ ] **Step 30: Run full test suite**

Run: `.venv/bin/python3 -m pytest tests/ -v`
Expected: All PASS

- [ ] **Step 31: Commit**

```bash
git add modules/ngsiem.py tests/test_ngsiem_fields.py
git commit -m "feat(ngsiem): add fields parameter for server-side field projection via select()"
```

---

## Chunk 4: FQL Guide Update, Smoke Tests, and README

### Task 9: Update FQL syntax guides

**Files:**
- Modify: `resources/fql_guides.py:22-45` (ALERT_FQL)
- Modify: `resources/fql_guides.py:47-65` (HOST_FQL)
- Modify: `modules/alerts.py:255-256` (remove stale comment)

- [ ] **Step 32: Update ALERT_FQL in fql_guides.py**

Replace the `ALERT_FQL` string (lines 22-45) with:

```python
ALERT_FQL = """\
# Alert FQL Filter Syntax (query_alerts_v2)

## Operators
- `:` — Equals (default): `status:'new'`
- `:!` — Not equal: `status:!'closed'`
- `:>` / `:>=` / `:<` / `:<=` — Comparisons: `severity:>=40`
- `:~` — Text match (tokenized, case-insensitive): `description:~'console login'`
- `:!~` — Not text match: `description:!~'test'`
- `:*` — Wildcard: `name:*'*MCP*'` (operator `*` + value wildcards `*`)
- `:~*` — Case-insensitive wildcard: `name:~*'*mcp*'`
- `:~*!` — Case-insensitive NOT wildcard: `name:~*!'*test*'`

## Supported FQL Fields
- `severity` — Integer: 10 (Informational), 20 (Low), 30 (Medium), 40 (High), 50 (Critical)
  - Example: `severity:>=40` (HIGH and above)
- `status` — String: 'new', 'in_progress', 'closed', 'reopened'
  - Example: `status:'new'`
- `name` — Alert/detection name (supports wildcards and text match)
  - Exact: `name:'RunningAsRootContainer'`
  - Wildcard: `name:*'*MCP*'`
  - Case-insensitive wildcard: `name:~*'*mcp server*'`
- `product` — Array: 'ind' (endpoint), 'ngsiem', 'fcs' (cloud), 'ldt' (identity), 'thirdparty'
  - Example: `product:['ngsiem']`
- `created_timestamp` — ISO 8601 timestamp
  - Example: `created_timestamp:>='2024-01-01T00:00:00Z'`
  - Relative: `created_timestamp:>='now-15d'`
- `assigned_to_name` — Filter by analyst assignment
- `tags` — Alert tags
- `type` — Alert type string

## Combining Filters
Use `+` to AND filters together:
  `severity:>=40+status:'new'+product:['ngsiem']`

## Timestamp Keywords
- `now` — Current timestamp. Example: `created_timestamp:>='now-7d'+created_timestamp:<'now'`
"""
```

- [ ] **Step 33: Update HOST_FQL in fql_guides.py**

Replace the `HOST_FQL` string (lines 47-65) with:

```python
HOST_FQL = """\
# Host FQL Filter Syntax

## Operators
- `:` — Equals (default): `platform_name:'Windows'`
- `:*` — Wildcard: `hostname:*'my-host-na*'` (operator `*` + value wildcards `*`)
- `:~*` — Case-insensitive wildcard: `hostname:~*'*workstation*'`

## Common Fields
- `hostname` — Device hostname (case-insensitive)
  - Example: `hostname:'WORKSTATION-01'`
  - Wildcard: `hostname:*'RR-*'`
- `platform_name` — OS platform: 'Windows', 'Mac', 'Linux'
  - Example: `platform_name:'Windows'`
- `last_seen` — ISO 8601 timestamp for last check-in
  - Example: `last_seen:>='2024-01-01T00:00:00Z'`
  - Relative: `last_seen:>='now-7d'`
- `status` — Device status: 'normal', 'containment_pending', 'contained', 'lift_containment_pending'
  - Example: `status:'contained'`
- `tags` — Falcon Grouping Tags
  - Example: `tags:'FalconGroupingTags/Production'`

## Combining Filters
Use `+` to AND filters together:
  `platform_name:'Windows'+status:'normal'+last_seen:>='now-7d'`
"""
```

- [ ] **Step 34: Remove stale comment in alerts.py**

Remove lines 255-256 in `modules/alerts.py`:

```python
            # NOTE: `name` is NOT a valid FQL filter field for query_alerts_v2.
            # pattern_name is applied as a client-side post-filter after fetching details.
```

(These lines will already be gone after Task 2, but verify they're removed.)

- [ ] **Step 35: Run full test suite**

Run: `.venv/bin/python3 -m pytest tests/ -v`
Expected: All PASS

- [ ] **Step 36: Commit**

```bash
git add resources/fql_guides.py modules/alerts.py
git commit -m "docs(fql): add wildcard/text operators, fix name field docs, add now keyword"
```

---

### Task 10: Update smoke tests

**Files:**
- Modify: `tests/test_smoke_tools_list.py` (no tool count changes, but verify params)

- [ ] **Step 37: Verify smoke tests still pass**

The smoke tests check tool *names*, not parameter schemas. Since we're adding parameters to existing tools (not adding/removing tools), the existing smoke tests should still pass.

Run: `.venv/bin/python3 -m pytest tests/test_smoke_tools_list.py -v`
Expected: All PASS

- [ ] **Step 38: Commit (if any changes needed)**

Only commit if changes were required. If smoke tests pass as-is, skip this step.

---

### Task 11: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 39: Update get_alerts parameter docs**

In `README.md`, find the Alerts tools section (around line 166-173) and update the `get_alerts` description. After the line that says `| get_alerts | Retrieve alerts across all detection types with filtering |`, add a parameters note:

```
**Parameters:** `severity`, `time_range`, `status`, `pattern_name` (FQL wildcard), `product`, `max_results` (1-1000), `offset` (pagination), `q` (free-text search), `summary_mode`
```

- [ ] **Step 40: Update ngsiem_query parameter docs**

In `README.md`, find the NG-SIEM section (around line 157) and update:

```
**Parameters:** `query` (CQL string), `start_time` (e.g. `1h`, `1d`, `7d`, `30d`), `max_results` (1-1000), `fields` (comma-separated field names for projection)
```

- [ ] **Step 41: Commit**

```bash
git add README.md
git commit -m "docs: update README with new get_alerts and ngsiem_query parameters"
```

---

### Task 12: Final validation

- [ ] **Step 42: Run full test suite one final time**

Run: `.venv/bin/python3 -m pytest tests/ -v`
Expected: All PASS

- [ ] **Step 43: Run lint**

Run: `.venv/bin/python3 -m ruff check .`
Expected: No errors (or only pre-existing ones)

Run: `.venv/bin/python3 -m ruff format --check .`
Expected: No formatting issues

- [ ] **Step 44: Fix any lint issues and commit**

```bash
.venv/bin/python3 -m ruff format .
git add -u
git commit -m "style: apply ruff formatting"
```

(Skip if no formatting changes needed.)
