"""
Identity Protection Module — CrowdStrike Falcon Identity Protection (IDP) via GraphQL.

Tool:
  identity_investigate_entity — One-call entity investigation:
     resolve identifier(s) → run entity_details, risk_assessment, timeline_analysis,
     and/or relationship_analysis → synthesize single response.

Ported from CrowdStrike's falcon-mcp (https://github.com/CrowdStrike/falcon-mcp,
MIT-licensed). See THIRD_PARTY_NOTICES.md at the repo root.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Any, Optional

try:
    from falconpy import IdentityProtection

    IDENTITY_PROTECTION_AVAILABLE = True
except ImportError:
    IDENTITY_PROTECTION_AVAILABLE = False

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


# Allowed enum values (mirrored from upstream + CrowdStrike GraphQL schema)
VALID_INVESTIGATION_TYPES = {
    "entity_details",
    "risk_assessment",
    "timeline_analysis",
    "relationship_analysis",
}
VALID_TIMELINE_EVENT_TYPES = {
    "ACTIVITY", "NOTIFICATION", "THREAT",
    "ENTITY", "AUDIT", "POLICY", "SYSTEM",
}


class IDPModule(BaseModule):
    """Falcon Identity Protection tools (GraphQL-backed)."""

    def __init__(self, client):
        super().__init__(client)
        if not IDENTITY_PROTECTION_AVAILABLE:
            raise ImportError(
                "IdentityProtection service class not available. "
                "Ensure crowdstrike-falconpy >= 1.6.1 is installed."
            )
        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        # Tool registered in Task 7.
        pass

    # --------------------------------------------------
    # Core GraphQL helper — single place that talks to falconpy
    # --------------------------------------------------
    def _graphql_call(self, query: str, context: str) -> dict[str, Any]:
        """Run a GraphQL query. Handles transport + GraphQL-level errors.

        Returns:
            On success: {"success": True, "data": <top-level data dict>}
            On failure: {"success": False, "error": "<message>"}
        """
        try:
            svc = self._service(IdentityProtection)
            response = svc.graphql(body={"query": query})
        except Exception as exc:
            return {"success": False, "error": f"{context}: {exc}"}

        status = response.get("status_code", 0)
        body = response.get("body", {}) or {}

        # Transport-level failure (non-2xx) — defer to format_api_error for scope msg
        if not (200 <= status < 300):
            return {
                "success": False,
                "error": format_api_error(response, context=context, operation="post_graphql"),
            }

        # GraphQL-level errors can arrive on HTTP 200. Treat non-empty errors[] as failure.
        gql_errors = body.get("errors")
        if isinstance(gql_errors, list) and gql_errors:
            msgs = [
                e.get("message", str(e)) if isinstance(e, dict) else str(e)
                for e in gql_errors
            ]
            return {"success": False, "error": f"{context}: GraphQL error: {'; '.join(msgs)}"}

        return {"success": True, "data": body.get("data", {}) or {}}

    # NOTE: do NOT add a "sanitize" helper that strips backslashes/quotes.
    # `json.dumps()` already escapes GraphQL-unsafe characters correctly, and
    # stripping them silently corrupts legitimate AD values (e.g. `DOMAIN\\user`).

    # --------------------------------------------------
    # Entity resolution
    # --------------------------------------------------
    def _resolve_entities(self, identifiers: dict[str, Any]) -> list[str] | dict[str, Any]:
        """Resolve various identifier kinds to entity IDs via a single AND-combined
        GraphQL query. entity_ids pass through unchanged.

        Returns:
            list[str]: resolved entity ids (de-duplicated) on success
            dict: {"error": "..."} on GraphQL/transport failure
        """
        resolved_ids: list[str] = []

        # Direct entity IDs — no resolution needed
        direct_ids = identifiers.get("entity_ids")
        if direct_ids and isinstance(direct_ids, list):
            resolved_ids.extend(direct_ids)

        emails = identifiers.get("email_addresses")
        ips = identifiers.get("ip_addresses")
        has_user = bool(emails)
        has_endpoint = bool(ips)

        # USER and ENDPOINT types are mutually exclusive in a single `entities()` query;
        # prioritise USER because the triage workflow centres on user identity risk.
        if has_user and has_endpoint:
            self._log("WARN: email + IP supplied; dropping IP filter (USER wins)")
            ips = None
            has_endpoint = False

        query_filters: list[str] = []
        query_fields: set[str] = set()

        self._add_name_filter(identifiers.get("entity_names"), query_fields, query_filters)
        self._add_email_filter(emails, query_fields, query_filters)
        self._add_ip_filter(ips, has_user, query_fields, query_filters)
        domain_names = self._add_domain_filter(identifiers.get("domain_names"), query_fields, query_filters)

        if query_filters:
            limit = identifiers.get("limit") or 50
            fields_string = "\n                ".join(sorted(query_fields))
            if domain_names:
                fields_string += """
                accounts {
                    ... on ActiveDirectoryAccountDescriptor {
                        domain
                        samAccountName
                    }
                }"""
            query = f"""
            query {{
                entities({", ".join(query_filters)}, first: {limit}) {{
                    nodes {{
                        entityId
                        {fields_string}
                    }}
                }}
            }}
            """
            result = self._graphql_call(query, context="Failed to resolve entities")
            if not result.get("success"):
                return {"error": result["error"]}
            nodes = result["data"].get("entities", {}).get("nodes", [])
            if isinstance(nodes, list):
                resolved_ids.extend(n.get("entityId") for n in nodes if isinstance(n, dict) and n.get("entityId"))

        return sorted({i for i in resolved_ids if i})

    def _add_name_filter(self, names, fields, filters):
        if names and isinstance(names, list):
            vals = json.dumps(list(names))
            filters.append(f"primaryDisplayNames: {vals}")
            fields.add("primaryDisplayName")

    def _add_email_filter(self, emails, fields, filters):
        if emails and isinstance(emails, list):
            vals = json.dumps(list(emails))
            filters.append(f"secondaryDisplayNames: {vals}")
            filters.append("types: [USER]")
            fields.add("primaryDisplayName")
            fields.add("secondaryDisplayName")

    def _add_ip_filter(self, ips, has_user, fields, filters):
        if ips and isinstance(ips, list) and not has_user:
            vals = json.dumps(list(ips))
            filters.append(f"primaryDisplayNames: {vals}")
            filters.append("types: [ENDPOINT]")
            fields.add("primaryDisplayName")

    def _add_domain_filter(self, domains, fields, filters):
        if domains and isinstance(domains, list):
            vals = json.dumps(list(domains))
            filters.append(f"domains: {vals}")
            fields.add("primaryDisplayName")
            fields.add("secondaryDisplayName")
            return domains
        return None

    # --------------------------------------------------
    # entity_details
    # --------------------------------------------------
    def _build_entity_details_query(
        self,
        entity_ids: list[str],
        include_risk_factors: bool,
        include_associations: bool,
        include_incidents: bool,
        include_accounts: bool,
    ) -> str:
        ids_json = json.dumps(entity_ids)
        fields = [
            "entityId", "primaryDisplayName", "secondaryDisplayName",
            "type", "riskScore", "riskScoreSeverity",
        ]
        if include_risk_factors:
            fields.append("riskFactors { type severity }")
        if include_associations:
            fields.append("""
                associations {
                    bindingType
                    ... on EntityAssociation {
                        entity { entityId primaryDisplayName secondaryDisplayName type }
                    }
                    ... on LocalAdminLocalUserAssociation { accountName }
                    ... on LocalAdminDomainEntityAssociation {
                        entityType
                        entity { entityId primaryDisplayName secondaryDisplayName }
                    }
                    ... on GeoLocationAssociation {
                        geoLocation { country countryCode city cityCode latitude longitude }
                    }
                }""")
        if include_incidents:
            fields.append("""
                openIncidents(first: 10) {
                    nodes {
                        type startTime endTime
                        compromisedEntities { entityId primaryDisplayName }
                    }
                }""")
        if include_accounts:
            fields.append("""
                accounts {
                    ... on ActiveDirectoryAccountDescriptor {
                        domain samAccountName ou servicePrincipalNames
                        passwordAttributes { lastChange strength }
                        expirationTime
                    }
                    ... on SsoUserAccountDescriptor {
                        dataSource mostRecentActivity title creationTime
                        passwordAttributes { lastChange }
                    }
                    ... on AzureCloudServiceAdapterDescriptor {
                        registeredTenantType appOwnerOrganizationId
                        publisherDomain signInAudience
                    }
                    ... on CloudServiceAdapterDescriptor { dataSourceParticipantIdentifier }
                }""")
        fields_str = "\n                ".join(fields)
        return f"""
        query {{
            entities(entityIds: {ids_json}, first: 50) {{
                nodes {{
                    {fields_str}
                }}
            }}
        }}
        """

    def _get_entity_details_batch(
        self, entity_ids: list[str], options: dict[str, Any]
    ) -> dict[str, Any]:
        query = self._build_entity_details_query(
            entity_ids=entity_ids,
            include_risk_factors=True,
            include_associations=options.get("include_associations", True),
            include_incidents=options.get("include_incidents", True),
            include_accounts=options.get("include_accounts", True),
        )
        result = self._graphql_call(query, context="Failed to get entity details")
        if not result.get("success"):
            return {"error": result["error"]}
        nodes = result["data"].get("entities", {}).get("nodes", []) or []
        nodes = [n for n in nodes if isinstance(n, dict)]
        return {"entities": nodes, "entity_count": len(nodes)}

    # --------------------------------------------------
    # risk_assessment
    # --------------------------------------------------
    def _build_risk_assessment_query(self, entity_ids: list[str], include_factors: bool) -> str:
        ids_json = json.dumps(entity_ids)
        risk = "riskScore\n                riskScoreSeverity"
        if include_factors:
            risk += "\n                riskFactors { type severity }"
        return f"""
        query {{
            entities(entityIds: {ids_json}, first: 50) {{
                nodes {{
                    entityId
                    primaryDisplayName
                    {risk}
                }}
            }}
        }}
        """

    def _assess_risks_batch(self, entity_ids: list[str], options: dict[str, Any]) -> dict[str, Any]:
        query = self._build_risk_assessment_query(entity_ids, options.get("include_risk_factors", True))
        result = self._graphql_call(query, context="Failed to assess risks")
        if not result.get("success"):
            return {"error": result["error"]}
        nodes = result["data"].get("entities", {}).get("nodes", []) or []
        assessments = [
            {
                "entityId": n.get("entityId"),
                "primaryDisplayName": n.get("primaryDisplayName"),
                "riskScore": n.get("riskScore", 0),
                "riskScoreSeverity": n.get("riskScoreSeverity", "LOW"),
                "riskFactors": n.get("riskFactors", []) if isinstance(n.get("riskFactors"), list) else [],
            }
            for n in nodes if isinstance(n, dict)
        ]
        return {"risk_assessments": assessments, "entity_count": len(assessments)}

    # --------------------------------------------------
    # timeline_analysis
    # --------------------------------------------------
    _TIMELINE_FRAGMENTS = """
        ... on TimelineUserOnEndpointActivityEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineAuthenticationEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineAlertEvent {
            sourceEntity { entityId primaryDisplayName }
        }
        ... on TimelineDceRpcEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineFailedAuthenticationEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineSuccessfulAuthenticationEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineServiceAccessEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineFileOperationEvent {
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineLdapSearchEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineRemoteCodeExecutionEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineConnectorConfigurationEvent { category }
        ... on TimelineConnectorConfigurationAddedEvent { category }
        ... on TimelineConnectorConfigurationDeletedEvent { category }
        ... on TimelineConnectorConfigurationModifiedEvent { category }
    """

    def _build_timeline_query(
        self, entity_id: str,
        start_time: str | None, end_time: str | None,
        event_types: list[str] | None, limit: int,
    ) -> str:
        filters = [f'sourceEntityQuery: {{entityIds: ["{entity_id}"]}}']
        if isinstance(start_time, str) and start_time:
            filters.append(f'startTime: "{start_time}"')
        if isinstance(end_time, str) and end_time:
            filters.append(f'endTime: "{end_time}"')
        if isinstance(event_types, list) and event_types:
            filters.append(f"categories: [{', '.join(event_types)}]")
        return f"""
        query {{
            timeline({", ".join(filters)}, first: {limit}) {{
                nodes {{
                    eventId eventType eventSeverity timestamp
                    {self._TIMELINE_FRAGMENTS}
                }}
                pageInfo {{ hasNextPage endCursor }}
            }}
        }}
        """

    def _get_entity_timelines_batch(
        self, entity_ids: list[str], options: dict[str, Any]
    ) -> dict[str, Any]:
        timelines = []
        for eid in entity_ids:
            query = self._build_timeline_query(
                entity_id=eid,
                start_time=options.get("start_time"),
                end_time=options.get("end_time"),
                event_types=options.get("event_types"),
                limit=options.get("limit", 50),
            )
            result = self._graphql_call(query, context=f"Failed to get timeline for '{eid}'")
            if not result.get("success"):
                return {"error": result["error"]}
            tl = result["data"].get("timeline", {}) or {}
            timelines.append({
                "entity_id": eid,
                "timeline": tl.get("nodes", []) if isinstance(tl.get("nodes"), list) else [],
                "page_info": tl.get("pageInfo", {}) if isinstance(tl.get("pageInfo"), dict) else {},
            })
        return {"timelines": timelines, "entity_count": len(entity_ids)}

    # --------------------------------------------------
    # relationship_analysis
    # --------------------------------------------------
    def _build_relationship_query(
        self, entity_id: str, depth: int, include_risk_context: bool, limit: int
    ) -> str:
        risk_fields = ""
        if include_risk_context:
            risk_fields = """
                riskScore
                riskScoreSeverity
                riskFactors { type severity }
            """

        def associations_block(remaining: int) -> str:
            if remaining <= 0:
                return ""
            nested = associations_block(remaining - 1) if remaining > 1 else ""
            return f"""
                associations {{
                    bindingType
                    ... on EntityAssociation {{
                        entity {{
                            entityId primaryDisplayName secondaryDisplayName type
                            {risk_fields}
                            {nested}
                        }}
                    }}
                    ... on LocalAdminLocalUserAssociation {{ accountName }}
                    ... on LocalAdminDomainEntityAssociation {{
                        entityType
                        entity {{
                            entityId primaryDisplayName secondaryDisplayName type
                            {risk_fields}
                            {nested}
                        }}
                    }}
                    ... on GeoLocationAssociation {{
                        geoLocation {{ country countryCode city cityCode latitude longitude }}
                    }}
                }}
            """

        return f"""
        query {{
            entities(entityIds: ["{entity_id}"], first: {limit}) {{
                nodes {{
                    entityId primaryDisplayName secondaryDisplayName type
                    {risk_fields}
                    {associations_block(depth)}
                }}
            }}
        }}
        """

    def _analyze_relationships_batch(
        self, entity_ids: list[str], options: dict[str, Any]
    ) -> dict[str, Any]:
        relationships = []
        depth = options.get("relationship_depth", 2)
        for eid in entity_ids:
            query = self._build_relationship_query(
                entity_id=eid,
                depth=depth,
                include_risk_context=options.get("include_risk_context", True),
                limit=options.get("limit", 50),
            )
            result = self._graphql_call(query, context=f"Failed to analyze relationships for '{eid}'")
            if not result.get("success"):
                return {"error": result["error"]}
            nodes = result["data"].get("entities", {}).get("nodes", []) or []
            if nodes and isinstance(nodes[0], dict):
                associations = nodes[0].get("associations", [])
                if not isinstance(associations, list):
                    associations = []
            else:
                associations = []
            relationships.append({
                "entity_id": eid,
                "associations": associations,
                "relationship_count": len(associations),
            })
        return {"relationships": relationships, "entity_count": len(entity_ids)}
