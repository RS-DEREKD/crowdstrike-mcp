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
