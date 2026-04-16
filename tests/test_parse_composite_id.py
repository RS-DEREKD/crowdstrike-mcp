"""Tests for parse_composite_id — target_process_id extraction for ind: alerts."""

from crowdstrike_mcp.utils import parse_composite_id


class TestIndAlertParsing:
    """ind: alerts encode TargetProcessId in their suffix."""

    def test_valid_ind_suffix_extracts_pid(self):
        composite_id = "bf7f666a6cb8419e:ind:7249b3df81f2:288700987-10357-1549328"
        result = parse_composite_id(composite_id)
        assert result["target_process_id"] == "288700987"

    def test_valid_ind_suffix_sets_trigger_format(self):
        composite_id = "bf7f666a6cb8419e:ind:7249b3df81f2:288700987-10357-1549328"
        result = parse_composite_id(composite_id)
        assert "ind:suffix=<pid>-<offset>-<trigger_id>" in result["trigger_format"]

    def test_malformed_suffix_one_hyphen_returns_none(self):
        """Suffix with only one hyphen is malformed — must have all 3 components."""
        composite_id = "cust:ind:sub:12345-67890"
        result = parse_composite_id(composite_id)
        assert result["target_process_id"] is None
        assert "malformed" in result["trigger_format"]

    def test_malformed_suffix_no_hyphen_returns_none(self):
        composite_id = "cust:ind:sub:nohyphens"
        result = parse_composite_id(composite_id)
        assert result["target_process_id"] is None
        assert "malformed" in result["trigger_format"]


class TestNonIndAlertParsing:
    """Non-ind: alerts get target_process_id=None with descriptive trigger_format."""

    def test_ngsiem_has_no_pid(self):
        composite_id = "cust:ngsiem:cust:indicator-uuid"
        result = parse_composite_id(composite_id)
        assert result["target_process_id"] is None
        assert "ngsiem" in result["trigger_format"]
        assert "unknown" in result["trigger_format"]

    def test_thirdparty_has_no_pid(self):
        composite_id = "cust:thirdparty:cust:alert-id"
        result = parse_composite_id(composite_id)
        assert result["target_process_id"] is None
        assert "thirdparty" in result["trigger_format"]

    def test_fcs_has_no_pid(self):
        composite_id = "cust:fcs:ioa-212:uuid"
        result = parse_composite_id(composite_id)
        assert result["target_process_id"] is None
        assert "fcs" in result["trigger_format"]

    def test_ldt_has_no_pid(self):
        composite_id = "cust:ldt:sub:det-id"
        result = parse_composite_id(composite_id)
        assert result["target_process_id"] is None
        assert "ldt" in result["trigger_format"]

    def test_unknown_prefix_has_no_pid(self):
        composite_id = "cust:unknown:sub:id"
        result = parse_composite_id(composite_id)
        assert result["target_process_id"] is None


class TestExistingKeysUnchanged:
    """New keys must not break existing callers."""

    def test_existing_keys_still_present_for_ind(self):
        composite_id = "bf7f666a:ind:7249b3df:288700987-10357-1549328"
        result = parse_composite_id(composite_id)
        assert "product_prefix" in result
        assert result["product_prefix"] == "ind"
        assert "product_type" in result
        assert result["product_type"] == "endpoint"
        assert "product_name" in result
        assert "parts" in result

    def test_existing_keys_still_present_for_ngsiem(self):
        composite_id = "cust:ngsiem:cust:indicator-uuid"
        result = parse_composite_id(composite_id)
        assert result["product_type"] == "ngsiem"
        assert "product_name" in result
        assert "parts" in result
