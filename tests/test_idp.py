"""Tests for Identity Protection module."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def idp_module(mock_client):
    """Create IDPModule with mocked IdentityProtection falconpy class."""
    with patch("crowdstrike_mcp.modules.idp.IdentityProtection") as MockIDP:
        mock_idp = MagicMock()
        MockIDP.return_value = mock_idp
        from crowdstrike_mcp.modules.idp import IDPModule

        module = IDPModule(mock_client)
        module._service = lambda cls: mock_idp
        module.falcon = mock_idp  # tests configure via module.falcon.graphql.return_value
        return module


class TestIdentityProtectionScopes:
    """Scope mapping for post_graphql operation exists in api_scopes."""

    def test_post_graphql_requires_all_five_scopes(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes
        scopes = get_required_scopes("post_graphql")
        assert "identity-protection-assessment:read" in scopes
        assert "identity-protection-detections:read" in scopes
        assert "identity-protection-entities:read" in scopes
        assert "identity-protection-timeline:read" in scopes
        assert "identity-protection-graphql:write" in scopes
        assert len(scopes) == 5


class TestIDPModuleScaffolding:
    """Module imports cleanly, registers zero tools until the public tool is added."""

    def test_module_instantiates(self, idp_module):
        assert idp_module is not None

    def test_module_has_falcon_client(self, idp_module):
        assert idp_module.falcon is not None
