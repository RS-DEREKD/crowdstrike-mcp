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


class TestGraphqlCallHelper:
    """_graphql_call handles both transport errors and GraphQL-level errors."""

    def test_200_with_data_returns_data(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [{"entityId": "e1"}]}}},
        }
        result = idp_module._graphql_call("query { x }", context="test")
        assert result["success"] is True
        assert result["data"]["entities"]["nodes"][0]["entityId"] == "e1"

    def test_non_200_returns_error_with_operation(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._graphql_call("query { x }", context="resolve")
        assert result["success"] is False
        # exact-match substrings that would break if someone dropped the operation name
        assert "HTTP 403" in result["error"]
        assert "resolve" in result["error"]

    def test_200_but_graphql_errors_returns_error(self, idp_module):
        """GraphQL returns 200 with a non-empty errors array on semantic failure."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {
                "data": None,
                "errors": [{"message": "Field entityId does not exist on type Foo"}],
            },
        }
        result = idp_module._graphql_call("query { x }", context="bad-field")
        assert result["success"] is False
        assert "Field entityId" in result["error"]

    def test_exception_in_falconpy_returns_error(self, idp_module):
        idp_module.falcon.graphql.side_effect = RuntimeError("connection dropped")
        result = idp_module._graphql_call("query { x }", context="boom")
        assert result["success"] is False
        assert "connection dropped" in result["error"]


class TestResolveEntities:
    """_resolve_entities builds correct GraphQL and returns entity ids."""

    def test_entity_ids_passthrough(self, idp_module):
        result = idp_module._resolve_entities(
            {"entity_ids": ["e1", "e2"], "limit": 10}
        )
        assert isinstance(result, list)
        assert set(result) == {"e1", "e2"}
        # No GraphQL call needed when only entity_ids are given
        idp_module.falcon.graphql.assert_not_called()

    def test_entity_names_triggers_graphql(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [{"entityId": "e-resolved"}]}}},
        }
        result = idp_module._resolve_entities(
            {"entity_names": ["Administrator"], "limit": 10}
        )
        assert result == ["e-resolved"]
        call = idp_module.falcon.graphql.call_args
        query = call.kwargs["body"]["query"]
        # AND of primaryDisplayNames filter present
        assert 'primaryDisplayNames:' in query
        assert '"Administrator"' in query

    def test_email_addresses_forces_user_type(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._resolve_entities(
            {"email_addresses": ["alice@corp.local"], "limit": 10}
        )
        query = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'secondaryDisplayNames:' in query
        assert 'types: [USER]' in query

    def test_ip_addresses_forces_endpoint_type(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._resolve_entities(
            {"ip_addresses": ["10.0.0.5"], "limit": 10}
        )
        query = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'types: [ENDPOINT]' in query
        assert '"10.0.0.5"' in query

    def test_user_criteria_wins_on_user_endpoint_conflict(self, idp_module):
        """When both email and IP are supplied, IPs are dropped (USER prioritised)."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._resolve_entities(
            {
                "email_addresses": ["alice@corp.local"],
                "ip_addresses": ["10.0.0.5"],
                "limit": 10,
            }
        )
        query = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'types: [USER]' in query
        assert 'types: [ENDPOINT]' not in query
        assert '"10.0.0.5"' not in query

    def test_domain_filter_adds_accounts_field(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._resolve_entities(
            {"domain_names": ["CORP.LOCAL"], "limit": 10}
        )
        query = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'domains:' in query
        assert '"CORP.LOCAL"' in query
        assert 'ActiveDirectoryAccountDescriptor' in query

    def test_returns_unique_ids(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {"entityId": "dup"}, {"entityId": "dup"}, {"entityId": "uniq"}
            ]}}},
        }
        result = idp_module._resolve_entities(
            {"entity_ids": ["dup"], "entity_names": ["X"], "limit": 10}
        )
        assert sorted(result) == ["dup", "uniq"]

    def test_graphql_error_bubbles_up_as_dict(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._resolve_entities(
            {"entity_names": ["Admin"], "limit": 10}
        )
        assert isinstance(result, dict)
        assert "error" in result
        assert "HTTP 403" in result["error"]
