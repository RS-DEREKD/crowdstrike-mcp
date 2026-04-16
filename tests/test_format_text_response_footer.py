"""Tests for format_text_response truncation footer with triggering_pid metadata."""

from crowdstrike_mcp.utils import LARGE_RESPONSE_THRESHOLD, format_text_response


def _large_text():
    """Generate text that exceeds the truncation threshold."""
    return "x" * (LARGE_RESPONSE_THRESHOLD + 1)


class TestTruncationFooterWithTriggeringPid:
    """When triggering_pid is in metadata, footer hints record_key instead of record_index=0."""

    def test_footer_includes_record_key_hint_when_pid_known(self):
        structured = {"behaviors": [{"TargetProcessId": "288700987"}]}
        metadata = {
            "detection_id": "cust:ind:sub:288700987-10357-1549328",
            "triggering_pid": "288700987",
        }
        result = format_text_response(
            _large_text(),
            tool_name="alert_analysis",
            raw=True,
            structured_data=structured,
            metadata=metadata,
        )
        assert 'record_key="288700987"' in result
        assert "triggering process" in result.lower()

    def test_footer_still_includes_record_index_0_when_pid_known(self):
        """record_index=0 stays in footer as chronological-first hint."""
        structured = {"behaviors": [{"TargetProcessId": "288700987"}]}
        metadata = {
            "detection_id": "cust:ind:sub:288700987-10357-1549328",
            "triggering_pid": "288700987",
        }
        result = format_text_response(
            _large_text(),
            tool_name="alert_analysis",
            raw=True,
            structured_data=structured,
            metadata=metadata,
        )
        assert "record_index=0" in result

    def test_footer_unchanged_when_no_triggering_pid(self):
        """Without triggering_pid, footer retains original record_index=0 only."""
        structured = {"events": [{"source.ip": "1.2.3.4"}]}
        metadata = {"detection_id": "cust:ngsiem:cust:alert-uuid"}
        result = format_text_response(
            _large_text(),
            tool_name="alert_analysis",
            raw=True,
            structured_data=structured,
            metadata=metadata,
        )
        assert "record_index=0" in result
        assert "record_key" not in result

    def test_footer_unchanged_when_triggering_pid_is_none(self):
        structured = {"behaviors": []}
        metadata = {"detection_id": "cust:thirdparty:cust:id", "triggering_pid": None}
        result = format_text_response(
            _large_text(),
            tool_name="alert_analysis",
            raw=True,
            structured_data=structured,
            metadata=metadata,
        )
        assert "record_key" not in result

    def test_small_response_not_affected(self):
        """Short responses aren't truncated — footer changes don't apply."""
        structured = {"behaviors": [{"TargetProcessId": "288700987"}]}
        metadata = {"triggering_pid": "288700987"}
        result = format_text_response(
            "short text",
            tool_name="alert_analysis",
            raw=True,
            structured_data=structured,
            metadata=metadata,
        )
        # Short text — no truncation footer at all
        assert "RESPONSE TRUNCATED" not in result
