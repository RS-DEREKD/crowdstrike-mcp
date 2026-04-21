"""Tests for cloud_get_risk_timeline tool."""

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest


SAMPLE_TIMELINE_BODY = {
    "resources": [
        {
            "asset": {
                "id": "crn:aws:s3:us-east-1:123456789012:bucket/example-bucket",
                "account_id": "123456789012",
                "account_name": "prod-account",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "resource_id": "example-bucket",
                "type": "AWS::S3::Bucket",
            },
            "timeline": {
                "configuration_changes": [
                    {
                        "id": "cc-001",
                        "asset_id": "crn:aws:s3:us-east-1:123456789012:bucket/example-bucket",
                        "asset_revision": 41,
                        "external_asset_type": "AWS::S3::Bucket",
                        "updated_at": "2026-04-10T11:59:00Z",
                        "changes": [
                            {
                                "action": "set",
                                "attribute": "public_access_block.block_public_acls",
                                "details": {"value": True},
                            }
                        ],
                        "resource_events": [
                            {
                                "event_name": "PutPublicAccessBlock",
                                "timestamp": "2026-04-10T11:59:00Z",
                                "user_id": "arn:aws:iam::123456789012:user/alice",
                                "user_name": "alice",
                            }
                        ],
                    },
                    {
                        "id": "cc-002",
                        "asset_id": "crn:aws:s3:us-east-1:123456789012:bucket/example-bucket",
                        "asset_revision": 42,
                        "external_asset_type": "AWS::S3::Bucket",
                        "updated_at": "2026-04-18T09:12:00Z",
                        "changes": [
                            {
                                "action": "set",
                                "attribute": "public_access_block.block_public_acls",
                                "details": {"value": False},
                            }
                        ],
                        "resource_events": [
                            {
                                "event_name": "PutPublicAccessBlock",
                                "timestamp": "2026-04-18T09:12:00Z",
                                "user_id": "arn:aws:iam::123456789012:user/bob",
                                "user_name": "bob",
                            }
                        ],
                    },
                ],
                "risks": {
                    "risk_instances": [
                        {
                            "id": "ri-100",
                            "rule_name": "S3 bucket publicly accessible",
                            "severity": "high",
                            "current_status": "open",
                            "reason": "block_public_acls disabled",
                            "first_seen": "2026-04-18T09:12:00Z",
                            "last_seen": "2026-04-21T15:00:00Z",
                            "resolved_at": None,
                            "risk_factors_categories": ["data_exposure"],
                            "events": [
                                {
                                    "event_type": "risk_reopened",
                                    "occurred_at": "2026-04-18T09:12:00Z",
                                    "details": {},
                                },
                                {
                                    "event_type": "risk_opened",
                                    "occurred_at": "2026-04-05T08:00:00Z",
                                    "details": {},
                                },
                            ],
                        },
                        {
                            "id": "ri-200",
                            "rule_name": "S3 bucket missing encryption",
                            "severity": "medium",
                            "current_status": "resolved",
                            "reason": "sse-s3 not configured",
                            "first_seen": "2026-03-01T00:00:00Z",
                            "last_seen": "2026-03-15T00:00:00Z",
                            "resolved_at": "2026-03-15T00:00:00Z",
                            "risk_factors_categories": ["encryption"],
                            "events": [
                                {
                                    "event_type": "risk_resolved",
                                    "occurred_at": "2026-03-15T00:00:00Z",
                                    "details": {},
                                },
                                {
                                    "event_type": "risk_opened",
                                    "occurred_at": "2026-03-01T00:00:00Z",
                                    "details": {},
                                },
                            ],
                        },
                    ]
                },
            },
        }
    ]
}


@pytest.fixture
def cloud_module(mock_client):
    """Create CloudSecurityModule with all falconpy classes (and APIHarnessV2) mocked."""
    with patch("crowdstrike_mcp.modules.cloud_security.CloudSecurity") as MockCS, \
         patch("crowdstrike_mcp.modules.cloud_security.CloudSecurityDetections") as MockCSD, \
         patch("crowdstrike_mcp.modules.cloud_security.CloudSecurityAssets") as MockCSA, \
         patch("crowdstrike_mcp.modules.cloud_security.APIHarnessV2") as MockHarness:
        mock_cs = MagicMock()
        mock_csd = MagicMock()
        mock_csa = MagicMock()
        mock_harness = MagicMock()
        MockCS.return_value = mock_cs
        MockCSD.return_value = mock_csd
        MockCSA.return_value = mock_csa
        MockHarness.return_value = mock_harness

        from crowdstrike_mcp.modules.cloud_security import CloudSecurityModule

        module = CloudSecurityModule(mock_client)

        def _fake_service(cls):
            name = cls.__name__
            return {
                "CloudSecurity": mock_cs,
                "CloudSecurityDetections": mock_csd,
                "CloudSecurityAssets": mock_csa,
                "APIHarnessV2": mock_harness,
            }[name]

        module._service = _fake_service
        module.harness = mock_harness
        return module


class TestGetRiskTimelineProjection:
    """Unit tests for _get_risk_timeline — projection only (no filters, no merge)."""

    def test_returns_shaped_asset_block(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(
            asset_id="crn:aws:s3:us-east-1:123456789012:bucket/example-bucket"
        )
        assert result["success"] is True
        asset = result["asset"]
        assert asset["id"] == "crn:aws:s3:us-east-1:123456789012:bucket/example-bucket"
        assert asset["cloud_provider"] == "aws"
        assert asset["account_id"] == "123456789012"
        assert asset["region"] == "us-east-1"
        assert asset["resource_id"] == "example-bucket"
        assert asset["type"] == "AWS::S3::Bucket"

    def test_projects_risk_instances(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:...")
        assert result["total_risks"] == 2
        risk = next(r for r in result["risks"] if r["id"] == "ri-100")
        assert risk["rule_name"] == "S3 bucket publicly accessible"
        assert risk["severity"] == "high"
        assert risk["current_status"] == "open"
        assert risk["first_seen"] == "2026-04-18T09:12:00Z"
        assert risk["resolved_at"] is None
        assert risk["risk_factors_categories"] == ["data_exposure"]
        assert len(risk["events"]) == 2

    def test_projects_configuration_changes(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:...")
        assert result["total_changes"] == 2
        change = next(c for c in result["changes"] if c["id"] == "cc-002")
        assert change["asset_revision"] == 42
        assert change["external_asset_type"] == "AWS::S3::Bucket"
        assert change["updated_at"] == "2026-04-18T09:12:00Z"
        assert change["changes"] == [
            {"action": "set", "attribute": "public_access_block.block_public_acls"}
        ]
        assert change["resource_events"][0]["event_name"] == "PutPublicAccessBlock"
        assert change["resource_events"][0]["user_name"] == "bob"

    def test_passes_asset_id_as_query_parameter(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        cloud_module._get_risk_timeline(asset_id="crn:example")
        # command() called exactly once with override="GET,<path>" and parameters={"id": <gcrn>}
        assert cloud_module.harness.command.call_count == 1
        _, kwargs = cloud_module.harness.command.call_args
        assert kwargs.get("override", "").startswith("GET,/cloud-security-timeline")
        assert kwargs.get("parameters", {}).get("id") == "crn:example"

    def test_full_still_unused_in_projection(self, cloud_module):
        """full=True has no effect on _get_risk_timeline projection itself.

        It's consumed by cloud_get_risk_timeline (Task 6); the projection layer ignores it.
        """
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", full=True)
        # Full fixture still projects — full is unused at this layer.
        assert result["success"] is True
        assert result["total_risks"] == 2
        assert result["total_changes"] == 2


class TestRiskTimelineFilters:
    """Client-side filter behaviour."""

    def test_risk_id_filter_keeps_only_matching_instance(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", risk_id="ri-100")
        assert result["total_risks"] == 1
        assert result["risks"][0]["id"] == "ri-100"
        # Changes untouched by risk_id filter
        assert result["total_changes"] == 2

    def test_risk_id_filter_no_match_yields_empty_risks(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", risk_id="ri-nope")
        assert result["success"] is True
        assert result["total_risks"] == 0
        assert result["risks"] == []

    def test_since_drops_older_risk_events(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        # Drop everything before 2026-04-15 → ri-200 has no remaining events (all March)
        # and ri-100 keeps one event (2026-04-18). ri-200 should be removed entirely.
        result = cloud_module._get_risk_timeline(asset_id="crn:x", since="2026-04-15T00:00:00Z")
        ri_ids = {r["id"] for r in result["risks"]}
        assert ri_ids == {"ri-100"}
        ri100 = result["risks"][0]
        assert len(ri100["events"]) == 1
        assert ri100["events"][0]["occurred_at"] == "2026-04-18T09:12:00Z"

    def test_since_drops_older_configuration_changes(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", since="2026-04-15T00:00:00Z")
        assert {c["id"] for c in result["changes"]} == {"cc-002"}

    def test_since_boundary_keeps_event_at_exact_timestamp(self, cloud_module):
        """`since` is inclusive: an event at exactly `since` is kept (>= comparison)."""
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        # ri-100 has an event at exactly 2026-04-18T09:12:00Z — must survive a since at the same instant.
        result = cloud_module._get_risk_timeline(
            asset_id="crn:x",
            since="2026-04-18T09:12:00Z",
        )
        ri100 = next(r for r in result["risks"] if r["id"] == "ri-100")
        occurred_ats = [e["occurred_at"] for e in ri100["events"]]
        assert "2026-04-18T09:12:00Z" in occurred_ats

    def test_risk_id_and_since_compose(self, cloud_module):
        """`risk_id` then `since` compose: only the matching risk survives, with only recent events."""
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(
            asset_id="crn:x",
            risk_id="ri-100",
            since="2026-04-15T00:00:00Z",
        )
        assert result["total_risks"] == 1
        ri = result["risks"][0]
        assert ri["id"] == "ri-100"
        # Only the 2026-04-18 event survives; the 2026-04-05 event is dropped by since.
        assert len(ri["events"]) == 1
        assert ri["events"][0]["occurred_at"] == "2026-04-18T09:12:00Z"
        # Changes untouched by risk_id, but since still prunes cc-001 (2026-04-10).
        assert {c["id"] for c in result["changes"]} == {"cc-002"}


class TestMergedTimeline:
    """Event-level merge: risk events + change resource_events, sorted desc by timestamp."""

    def test_timeline_contains_one_row_per_risk_event_and_resource_event(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x")
        # 2 risks x 2 events + 2 changes x 1 resource_event = 6 rows
        assert len(result["timeline"]) == 6

    def test_timeline_sorted_descending_by_timestamp(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x")
        timestamps = [row["timestamp"] for row in result["timeline"]]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_timeline_rows_carry_kind_and_source_id(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x")
        kinds = {row["kind"] for row in result["timeline"]}
        assert kinds == {"risk", "change"}
        risk_row = next(r for r in result["timeline"] if r["kind"] == "risk")
        assert "source_id" in risk_row and risk_row["source_id"].startswith("ri-")
        change_row = next(r for r in result["timeline"] if r["kind"] == "change")
        assert change_row["source_id"].startswith("cc-")

    def test_timeline_respects_max_results(self, cloud_module):
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", max_results=3)
        assert len(result["timeline"]) == 3
        # Still sorted descending
        ts = [row["timestamp"] for row in result["timeline"]]
        assert ts == sorted(ts, reverse=True)

    def test_timeline_emits_synthetic_row_for_risk_with_no_events(self, cloud_module):
        body = {
            "resources": [
                {
                    "asset": SAMPLE_TIMELINE_BODY["resources"][0]["asset"],
                    "timeline": {
                        "configuration_changes": [],
                        "risks": {
                            "risk_instances": [
                                {
                                    "id": "ri-synth",
                                    "rule_name": "silent risk",
                                    "severity": "low",
                                    "current_status": "open",
                                    "reason": "",
                                    "first_seen": "2026-04-01T00:00:00Z",
                                    "last_seen": "2026-04-20T00:00:00Z",
                                    "resolved_at": None,
                                    "risk_factors_categories": [],
                                    "events": [],
                                }
                            ]
                        },
                    },
                }
            ]
        }
        cloud_module.harness.command.return_value = {"status_code": 200, "body": body}
        result = cloud_module._get_risk_timeline(asset_id="crn:x")
        assert len(result["timeline"]) == 1
        row = result["timeline"][0]
        assert row["kind"] == "risk"
        assert row["event_type"] == "risk_current_state"
        assert row["timestamp"] == "2026-04-20T00:00:00Z"
        assert row["source_id"] == "ri-synth"
        assert row.get("synthetic") is True

    def test_max_results_applies_after_since_filter(self, cloud_module):
        """max_results caps the POST-filter merged list, not the raw body."""
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        # since drops the 2 ri-200 events (March) and the cc-001 2026-04-10 event,
        # leaving: ri-100 @ 2026-04-18 + cc-002 @ 2026-04-18 = 2 rows. max_results=1 caps to 1.
        result = cloud_module._get_risk_timeline(
            asset_id="crn:x",
            since="2026-04-15T00:00:00Z",
            max_results=1,
        )
        assert len(result["timeline"]) == 1

    def test_max_results_zero_returns_empty_timeline(self, cloud_module):
        """max_results=0 returns an empty timeline without errors."""
        cloud_module.harness.command.return_value = {
            "status_code": 200,
            "body": SAMPLE_TIMELINE_BODY,
        }
        result = cloud_module._get_risk_timeline(asset_id="crn:x", max_results=0)
        assert result["timeline"] == []
        # But the underlying projection is still intact.
        assert result["total_risks"] == 2
        assert result["total_changes"] == 2
