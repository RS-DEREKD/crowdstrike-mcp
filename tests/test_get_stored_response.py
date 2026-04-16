"""Tests for get_stored_response — record_key lookup behavior."""

import asyncio
import json

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def response_store_module(mock_client):
    """Create a ResponseStoreModule with mocked client."""
    return ResponseStoreModule(mock_client)


class TestTargetProcessIdKeyField:
    """TargetProcessId in _KEY_FIELDS enables record_key lookup on endpoint behavior stores."""

    def test_record_key_lookup_by_target_process_id(self, response_store_module):
        """record_key="288700987" finds the ProcessRollup2 record by TargetProcessId."""
        ref_id = ResponseStore.store(
            {
                "behaviors": [
                    {"TargetProcessId": "111111", "ImageFileName": "\\Device\\...\\other.exe"},
                    {
                        "TargetProcessId": "288700987",
                        "ImageFileName": "\\Device\\...\\SearchIndexer.exe",
                        "CommandLine": "SearchIndexer.exe /Embedding",
                    },
                ]
            },
            tool_name="alert_analysis",
        )
        result = asyncio.run(response_store_module.get_stored_response(ref_id=ref_id, record_key="288700987"))
        data = json.loads(result)
        assert data["TargetProcessId"] == "288700987"
        assert "SearchIndexer.exe" in data["ImageFileName"]
