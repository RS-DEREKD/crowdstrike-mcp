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
