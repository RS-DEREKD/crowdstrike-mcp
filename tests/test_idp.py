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


class TestEntityDetailsInvestigation:
    def test_builds_query_with_all_includes_on(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {
                    "entityId": "e1",
                    "primaryDisplayName": "Administrator",
                    "type": "USER",
                    "riskScore": 75,
                    "riskScoreSeverity": "HIGH",
                    "riskFactors": [{"type": "STALE_ACCOUNT", "severity": "HIGH"}],
                    "accounts": [{"domain": "CORP", "samAccountName": "admin"}],
                }
            ]}}},
        }
        result = idp_module._get_entity_details_batch(
            ["e1"],
            {"include_associations": True, "include_accounts": True, "include_incidents": True},
        )
        assert result["entity_count"] == 1
        assert result["entities"][0]["entityId"] == "e1"
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        # All include-blocks present
        assert "riskFactors" in q
        assert "associations" in q
        assert "openIncidents" in q
        assert "accounts" in q
        assert "ActiveDirectoryAccountDescriptor" in q

    def test_include_flags_drop_optional_sections(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._get_entity_details_batch(
            ["e1"],
            {"include_associations": False, "include_accounts": False, "include_incidents": False},
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert "associations" not in q
        assert "openIncidents" not in q
        assert "ActiveDirectoryAccountDescriptor" not in q
        # Core fields still present
        assert "riskScore" in q

    def test_handles_api_error(self, idp_module):
        """403 carries through as an error response — operation name preserved so
        scope-aware error message fires."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._get_entity_details_batch(
            ["e1"], {"include_associations": True, "include_accounts": True, "include_incidents": True}
        )
        assert "error" in result
        assert "HTTP 403" in result["error"]

    def test_entity_ids_are_json_escaped(self, idp_module):
        """Entity IDs must be json.dumps-escaped to avoid GraphQL syntax breakage."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._get_entity_details_batch(
            ['e"1', "e-2"],
            {"include_associations": True, "include_accounts": True, "include_incidents": True},
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        # Both IDs appear; embedded quote is escaped
        assert '"e-2"' in q
        assert 'e\\"1' in q or '"e\\"1"' in q or '"e1"' in q  # json.dumps escapes as \"


class TestRiskAssessmentInvestigation:
    def test_returns_risk_scores_with_factors(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {
                    "entityId": "e1",
                    "primaryDisplayName": "Admin",
                    "riskScore": 90,
                    "riskScoreSeverity": "CRITICAL",
                    "riskFactors": [
                        {"type": "ADMIN_ACCOUNT", "severity": "HIGH"},
                        {"type": "STALE_ACCOUNT", "severity": "MEDIUM"},
                    ],
                }
            ]}}},
        }
        result = idp_module._assess_risks_batch(["e1"], {"include_risk_factors": True})
        assert result["entity_count"] == 1
        ra = result["risk_assessments"][0]
        assert ra["riskScore"] == 90
        assert ra["riskScoreSeverity"] == "CRITICAL"
        assert len(ra["riskFactors"]) == 2

    def test_without_risk_factors(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._assess_risks_batch(["e1"], {"include_risk_factors": False})
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert "riskScore" in q
        assert "riskFactors" not in q

    def test_handles_api_error(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Boom"}]},
        }
        result = idp_module._assess_risks_batch(["e1"], {"include_risk_factors": True})
        assert "error" in result
        assert "HTTP 500" in result["error"]

    def test_defensive_projection_on_missing_fields(self, idp_module):
        """Missing riskScore / riskFactors → safe defaults, not KeyError."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {"entityId": "e1", "primaryDisplayName": "X"}
            ]}}},
        }
        result = idp_module._assess_risks_batch(["e1"], {"include_risk_factors": True})
        ra = result["risk_assessments"][0]
        assert ra["riskScore"] == 0
        assert ra["riskScoreSeverity"] == "LOW"
        assert ra["riskFactors"] == []


class TestTimelineInvestigation:
    def test_loops_per_entity(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"timeline": {"nodes": [], "pageInfo": {"hasNextPage": False}}}},
        }
        idp_module._get_entity_timelines_batch(["e1", "e2"], {"limit": 50})
        assert idp_module.falcon.graphql.call_count == 2

    def test_query_embeds_entity_id_and_time_range(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"timeline": {"nodes": []}}},
        }
        idp_module._get_entity_timelines_batch(
            ["e1"],
            {
                "start_time": "2026-04-01T00:00:00Z",
                "end_time": "2026-04-20T00:00:00Z",
                "event_types": ["AUDIT", "ACTIVITY"],
                "limit": 25,
            },
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert 'entityIds: ["e1"]' in q
        assert 'startTime: "2026-04-01T00:00:00Z"' in q
        assert 'endTime: "2026-04-20T00:00:00Z"' in q
        # Event types rendered as unquoted enums
        assert "categories: [AUDIT, ACTIVITY]" in q
        assert "first: 25" in q

    def test_returns_timelines_keyed_by_entity(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"timeline": {
                "nodes": [{"eventId": "ev1", "eventType": "AUDIT"}],
                "pageInfo": {"hasNextPage": False},
            }}},
        }
        result = idp_module._get_entity_timelines_batch(["e1"], {"limit": 50})
        assert result["entity_count"] == 1
        assert result["timelines"][0]["entity_id"] == "e1"
        assert result["timelines"][0]["timeline"][0]["eventId"] == "ev1"

    def test_early_exit_on_first_error(self, idp_module):
        """If entity #1 fails with 403, we don't silently keep iterating."""
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._get_entity_timelines_batch(["e1", "e2"], {"limit": 50})
        assert "error" in result
        # We bailed after the first call
        assert idp_module.falcon.graphql.call_count == 1


class TestRelationshipInvestigation:
    def test_depth_one_query_has_no_nesting(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 1, "include_risk_context": True, "limit": 50}
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        # depth=1 still contains at least one associations block
        assert q.count("associations {") >= 1

    def test_depth_three_nests_three_levels(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 3, "include_risk_context": True, "limit": 50}
        )
        q3 = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]

        # Reset and build depth=2 query for comparison
        idp_module.falcon.graphql.reset_mock()
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": True, "limit": 50}
        )
        q2 = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]

        # Reset and build depth=1 query for comparison
        idp_module.falcon.graphql.reset_mock()
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 1, "include_risk_context": True, "limit": 50}
        )
        q1 = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]

        # `{nested}` is interpolated into both EntityAssociation and
        # LocalAdminDomainEntityAssociation fragments at every level (matches
        # upstream falcon-mcp), so block counts follow 1, 3, 7 — i.e. each
        # additional level of depth doubles the previous level's new blocks.
        c1 = q1.count("associations {")
        c2 = q2.count("associations {")
        c3 = q3.count("associations {")
        assert c1 == 1, f"depth=1 expected 1 block, got {c1}"
        assert c2 == 3, f"depth=2 expected 3 blocks, got {c2}"
        assert c3 == 7, f"depth=3 expected 7 blocks, got {c3}"
        # And each depth strictly exceeds the previous — regression guard
        assert c1 < c2 < c3

    def test_without_risk_context_omits_risk_fields(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": False, "limit": 50}
        )
        q = idp_module.falcon.graphql.call_args.kwargs["body"]["query"]
        assert "riskScore" not in q
        assert "riskFactors" not in q

    def test_empty_nodes_yields_zero_associations(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": []}}},
        }
        result = idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": True, "limit": 50}
        )
        assert result["relationships"][0]["associations"] == []
        assert result["relationships"][0]["relationship_count"] == 0

    def test_handles_api_error(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": True, "limit": 50}
        )
        assert "error" in result

    def test_counts_associations_defensively_when_field_missing(self, idp_module):
        idp_module.falcon.graphql.return_value = {
            "status_code": 200,
            "body": {"data": {"entities": {"nodes": [
                {"entityId": "e1"}  # no associations field
            ]}}},
        }
        result = idp_module._analyze_relationships_batch(
            ["e1"], {"relationship_depth": 2, "include_risk_context": True, "limit": 50}
        )
        assert result["relationships"][0]["associations"] == []
        assert result["relationships"][0]["relationship_count"] == 0
