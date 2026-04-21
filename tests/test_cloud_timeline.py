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
