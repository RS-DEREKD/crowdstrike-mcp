"""
Cloud Security Module — cloud risks, IOM detections, assets, and compliance.

Tools:
  cloud_get_risks            — Cloud security risks ranked by score
  cloud_get_iom_detections   — IOM detections with MITRE and remediation
  cloud_query_assets         — Cloud asset inventory across providers
  cloud_compliance_by_account — Compliance posture by account/region
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Optional

from common.errors import format_api_error
from modules.base import BaseModule
from utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

try:
    from falconpy import CloudSecurity

    CLOUD_SECURITY_AVAILABLE = True
except ImportError:
    CLOUD_SECURITY_AVAILABLE = False

try:
    from falconpy import CloudSecurityDetections

    DETECTIONS_AVAILABLE = True
except ImportError:
    DETECTIONS_AVAILABLE = False

try:
    from falconpy import CloudSecurityAssets

    ASSETS_AVAILABLE = True
except ImportError:
    ASSETS_AVAILABLE = False


class CloudSecurityModule(BaseModule):
    """Cloud security posture and detection data."""

    def __init__(self, client):
        super().__init__(client)
        self._cloud_security = None
        self._detections = None
        self._assets = None

        auth = self.client.auth_object

        if CLOUD_SECURITY_AVAILABLE:
            try:
                self._cloud_security = CloudSecurity(auth_object=auth)
            except Exception as e:
                self._log(f"CloudSecurity init failed: {e}")
        if DETECTIONS_AVAILABLE:
            try:
                self._detections = CloudSecurityDetections(auth_object=auth)
            except Exception as e:
                self._log(f"CloudSecurityDetections init failed: {e}")
        if ASSETS_AVAILABLE:
            try:
                self._assets = CloudSecurityAssets(auth_object=auth)
            except Exception as e:
                self._log(f"CloudSecurityAssets init failed: {e}")

        if not any([self._cloud_security, self._detections, self._assets]):
            raise ImportError("No cloud security FalconPy classes available. Ensure crowdstrike-falconpy >= 1.6.0 is installed.")

        available = [
            n
            for n, c in [
                ("CloudSecurity", self._cloud_security),
                ("Detections", self._detections),
                ("Assets", self._assets),
            ]
            if c
        ]
        self._log(f"Initialized ({', '.join(available)})")

    def register_resources(self, server: FastMCP) -> None:
        from resources.fql_guides import CLOUD_ASSETS_FQL, CLOUD_IOM_FQL, CLOUD_RISKS_FQL

        def _make_fn(text):
            def fn():
                return text

            return fn

        for uri, content in [
            ("falcon://fql/cloud-risks", CLOUD_RISKS_FQL),
            ("falcon://fql/cloud-iom", CLOUD_IOM_FQL),
            ("falcon://fql/cloud-assets", CLOUD_ASSETS_FQL),
        ]:
            server.resource(uri, name=uri.split("/")[-1], description=f"FQL syntax: {uri}")(_make_fn(content))
            self.resources.append(uri)

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.cloud_get_risks,
            name="cloud_get_risks",
            description=(
                "Query cloud security risks ranked by score. "
                "Shows misconfigurations, unused identities, and exposure risks "
                "across AWS/Azure/GCP with severity, status, and asset details."
            ),
        )
        self._add_tool(
            server,
            self.cloud_get_iom_detections,
            name="cloud_get_iom_detections",
            description=(
                "Query IOM (Indicator of Misconfiguration) detections from CSPM. "
                "Returns evaluations with MITRE ATT&CK mappings, compliance framework "
                "references (CIS, NIST, PCI, etc.), and remediation steps."
            ),
        )
        self._add_tool(
            server,
            self.cloud_query_assets,
            name="cloud_query_assets",
            description=(
                "Query cloud asset inventory across AWS/Azure/GCP. "
                "Returns resource details including type, region, tags, configuration, "
                "and status. Use resource_id to look up a specific asset by ID "
                "(e.g. security group, EC2 instance, RDS instance)."
            ),
        )
        self._add_tool(
            server,
            self.cloud_compliance_by_account,
            name="cloud_compliance_by_account",
            description=("Get compliance posture aggregated by account and region. Shows compliance control results with resource counts and severities."),
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def cloud_get_risks(
        self,
        severity: Annotated[Optional[str], "Filter by severity level ('critical', 'high', 'medium', 'low')"] = None,
        status: Annotated[Optional[str], "Filter by risk status ('open', 'resolved')"] = None,
        provider: Annotated[Optional[str], "Filter by cloud provider ('aws', 'azure', 'gcp')"] = None,
        account_id: Annotated[Optional[str], "Filter by specific cloud account ID"] = None,
        max_results: Annotated[int, "Maximum risks to return (default: 50)"] = 50,
    ) -> str:
        """Query cloud security risks with filtering."""
        result = self._get_cloud_risks(severity, status, provider, account_id, max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to get cloud risks: {result.get('error')}", raw=True)

        risks = result["risks"]
        lines = [
            f"Cloud Security Risks: {result['count']} returned (of {result['total']} total, sorted by score desc)",
            "",
        ]

        if not risks:
            lines.append("No cloud risks found matching the filters.")
        else:
            for i, r in enumerate(risks, 1):
                lines.append(f"{i}. [{r['severity']}] {r['rule_name']} (score: {r['score']})")
                lines.append(f"   {r['provider']} | Account: {r['account_id']} | Asset: {r['asset_type']} ({r['asset_id']})")
                lines.append(f"   Status: {r['status']} | Category: {r['service_category']}")
                if r.get("rule_description"):
                    lines.append(f"   {r['rule_description'][:200]}")
                lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    async def cloud_get_iom_detections(
        self,
        severity: Annotated[Optional[str], "Filter by severity level"] = None,
        provider: Annotated[Optional[str], "Filter by cloud provider"] = None,
        account_id: Annotated[Optional[str], "Filter by cloud account ID"] = None,
        resource_type: Annotated[Optional[str], "Filter by resource type (e.g. 'AWS::EC2::SecurityGroup')"] = None,
        max_results: Annotated[int, "Maximum detections to return (default: 20)"] = 20,
    ) -> str:
        """Query IOM detections with MITRE and compliance mappings."""
        result = self._get_iom_detections(severity, provider, account_id, resource_type, max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to get IOM detections: {result.get('error')}", raw=True)

        detections = result["detections"]
        lines = [
            f"IOM Detections: {result['count']} returned (of {result['total']} total evaluations)",
            "",
        ]

        if not detections:
            lines.append("No IOM detections found matching the filters.")
        else:
            for i, d in enumerate(detections, 1):
                lines.append(f"{i}. [{d['severity']}] {d['rule_name']} (status: {d['status']})")
                lines.append(f"   {d['cloud_provider']} | Account: {d['account_id']} | Region: {d['region']}")
                lines.append(f"   Resource: {d['resource_type']} ({d['resource_id']})")
                if d.get("mitre_technique_id"):
                    lines.append(f"   MITRE: {d['mitre_tactic']} / {d['mitre_technique']} ({d['mitre_technique_id']})")
                if d.get("compliance_controls"):
                    lines.append(f"   Compliance: {'; '.join(d['compliance_controls'][:3])}")
                if d.get("remediation"):
                    lines.append(f"   Remediation: {d['remediation'][:200]}")
                if d.get("console_url"):
                    lines.append(f"   Console: {d['console_url']}")
                lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    async def cloud_query_assets(
        self,
        provider: Annotated[Optional[str], "Filter by cloud provider"] = None,
        account_id: Annotated[Optional[str], "Filter by cloud account ID"] = None,
        resource_type: Annotated[Optional[str], "Filter by resource type (e.g. 'AWS::EC2::Instance')"] = None,
        region: Annotated[Optional[str], "Filter by region (e.g. 'us-east-1')"] = None,
        resource_id: Annotated[Optional[str], "Filter by specific resource ID"] = None,
        max_results: Annotated[int, "Maximum assets to return (default: 20)"] = 20,
    ) -> str:
        """Query cloud asset inventory."""
        result = self._query_assets(provider, account_id, resource_type, region, resource_id, max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to query assets: {result.get('error')}", raw=True)

        assets = result["assets"]
        lines = [
            f"Cloud Assets: {result['count']} returned (of {result['total']} total)",
            "",
        ]

        if not assets:
            lines.append("No assets found matching the filters.")
        else:
            for i, a in enumerate(assets, 1):
                active_str = "active" if a.get("active") else "inactive"
                lines.append(f"{i}. [{a['cloud_provider']}] {a['resource_type']} ({active_str})")
                lines.append(f"   ID: {a['resource_id']}")
                if a.get("resource_name"):
                    lines.append(f"   Name: {a['resource_name']}")
                lines.append(f"   Account: {a['account_id']} | Region: {a['region']} | Service: {a['service']}")
                if a.get("tags"):
                    tags_str = ", ".join(f"{k}={v}" for k, v in list(a["tags"].items())[:5])
                    lines.append(f"   Tags: {tags_str}")
                if a.get("cloud_context"):
                    ctx = a["cloud_context"]
                    ctx_parts = []
                    if "publicly_exposed" in ctx:
                        ctx_parts.append(f"publicly_exposed={ctx['publicly_exposed']}")
                    if ctx_parts:
                        lines.append(f"   Cloud Context: {', '.join(ctx_parts)}")
                if a.get("configuration"):
                    lines.append(f"   Configuration: {json.dumps(a['configuration'], default=str)}")
                if a.get("relationships"):
                    for rel in a["relationships"][:5]:
                        lines.append(f"   Relationship: {rel.get('relationship_name', '')} {rel.get('resource_type', '')} ({rel.get('resource_id', '')})")
                lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    async def cloud_compliance_by_account(
        self,
        max_results: Annotated[int, "Maximum entries to return (default: 50)"] = 50,
    ) -> str:
        """Get compliance posture aggregated by account and region."""
        result = self._get_compliance_by_account(max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to get compliance data: {result.get('error')}", raw=True)

        entries = result["compliance"]
        lines = [
            f"Compliance by Account: {result['count']} entries (of {result['total']} total)",
            "",
        ]

        if not entries:
            lines.append("No compliance data found.")
        else:
            for i, c in enumerate(entries, 1):
                lines.append(f"{i}. [{c['cloud_provider']}] Account: {c['account_id']} Region: {c['region']}")
                lines.append(f"   Service: {c['service']} ({c['service_category']}) | Resource: {c['resource_type']}")
                if c.get("resource_counts"):
                    lines.append(f"   Resource counts: {json.dumps(c['resource_counts'])}")
                if c.get("severities"):
                    lines.append(f"   Severities: {json.dumps(c['severities'])}")
                lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    # ------------------------------------------------------------------
    # Internal methods (logic from handlers/cloud_security.py)
    # ------------------------------------------------------------------

    def _get_cloud_risks(self, severity=None, status=None, provider=None, account_id=None, max_results=50):
        if not self._cloud_security:
            return {"success": False, "error": "CloudSecurity client not available"}
        try:
            filter_parts = []
            if severity:
                filter_parts.append(f"severity:'{severity}'")
            if status:
                filter_parts.append(f"status:'{status}'")
            if provider:
                filter_parts.append(f"cloud_provider:'{provider}'")
            if account_id:
                filter_parts.append(f"account_id:'{account_id}'")

            kwargs = {"limit": min(max_results, 100), "sort": "severity|desc"}
            if filter_parts:
                kwargs["filter"] = "+".join(filter_parts)

            r = self._cloud_security.combined_cloud_risks(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to get cloud risks", operation="combined_cloud_risks")}

            resources = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(resources))

            risks = []
            for risk in resources:
                risks.append(
                    {
                        "id": risk.get("id", ""),
                        "rule_name": risk.get("rule_name", ""),
                        "rule_description": risk.get("rule_description", "")[:300],
                        "severity": risk.get("severity", ""),
                        "score": risk.get("score", 0),
                        "status": risk.get("status", ""),
                        "provider": risk.get("provider", ""),
                        "account_id": risk.get("account_id", ""),
                        "account_name": risk.get("account_name", ""),
                        "asset_type": risk.get("asset_type", ""),
                        "asset_id": risk.get("asset_id", ""),
                        "asset_name": risk.get("asset_name", ""),
                        "asset_region": risk.get("asset_region", ""),
                        "service_category": risk.get("service_category", ""),
                        "insight_categories": risk.get("insight_categories", []),
                        "first_seen": risk.get("first_seen", ""),
                        "last_seen": risk.get("last_seen", ""),
                    }
                )

            return {"success": True, "risks": risks, "count": len(risks), "total": total}
        except Exception as e:
            return {"success": False, "error": f"Error getting cloud risks: {e}"}

    def _get_iom_detections(self, severity=None, provider=None, account_id=None, resource_type=None, max_results=20):
        if not self._detections:
            return {"success": False, "error": "CloudSecurityDetections client not available"}
        try:
            filter_parts = []
            if severity:
                filter_parts.append(f"severity:'{severity}'")
            if provider:
                filter_parts.append(f"cloud_provider:'{provider}'")
            if account_id:
                filter_parts.append(f"account_id:'{account_id}'")
            if resource_type:
                filter_parts.append(f"resource_type:'{resource_type}'")

            kwargs = {"limit": min(max_results, 100)}
            if filter_parts:
                kwargs["filter"] = "+".join(filter_parts)

            r = self._detections.query_iom_entities(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to query IOM entities", operation="query_iom_entities")}

            iom_ids = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(iom_ids))

            if not iom_ids:
                return {"success": True, "detections": [], "count": 0, "total": total}

            r2 = self._detections.get_iom_entities(ids=iom_ids)
            if r2["status_code"] != 200:
                return {"success": False, "error": format_api_error(r2, "Failed to get IOM entity details", operation="get_iom_entities")}

            entities = r2.get("body", {}).get("resources", [])

            detections = []
            for e in entities:
                cloud = e.get("cloud", {})
                resource = e.get("resource", {})
                evaluation = e.get("evaluation", {})
                rule = evaluation.get("rule", {})
                threat = rule.get("threat", {})

                detections.append(
                    {
                        "id": e.get("id", ""),
                        "cloud_provider": cloud.get("provider", ""),
                        "account_id": cloud.get("account_id", ""),
                        "region": cloud.get("region", ""),
                        "resource_type": resource.get("resource_type_name", resource.get("resource_type", "")),
                        "resource_id": resource.get("resource_id", ""),
                        "resource_tags": resource.get("tags", {}),
                        "severity": evaluation.get("severity", ""),
                        "status": evaluation.get("status", ""),
                        "rule_name": rule.get("name", ""),
                        "rule_description": rule.get("description", "")[:400],
                        "mitre_tactic": threat.get("tactic", {}).get("name", ""),
                        "mitre_technique": threat.get("technique", {}).get("name", ""),
                        "mitre_technique_id": threat.get("technique", {}).get("id", ""),
                        "remediation": rule.get("remediation", "")[:500],
                        "compliance_controls": [
                            f"{c.get('framework', '')}: {c.get('name', '')} ({c.get('requirement', '')})" for c in rule.get("controls", [])[:5]
                        ],
                        "console_url": evaluation.get("url", ""),
                    }
                )

            return {"success": True, "detections": detections, "count": len(detections), "total": total}
        except Exception as e:
            return {"success": False, "error": f"Error getting IOM detections: {e}"}

    def _query_assets(self, provider=None, account_id=None, resource_type=None, region=None, resource_id=None, max_results=20):
        if not self._assets:
            return {"success": False, "error": "CloudSecurityAssets client not available"}
        try:
            filter_parts = []
            if provider:
                filter_parts.append(f"cloud_provider:'{provider}'")
            if account_id:
                filter_parts.append(f"account_id:'{account_id}'")
            if resource_type:
                filter_parts.append(f"resource_type:'{resource_type}'")
            if region:
                filter_parts.append(f"region:'{region}'")
            if resource_id:
                filter_parts.append(f"resource_id:'{resource_id}'")

            kwargs = {"limit": min(max_results, 100)}
            if filter_parts:
                kwargs["filter"] = "+".join(filter_parts)

            r = self._assets.query_assets(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to query assets", operation="query_assets")}

            asset_ids = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(asset_ids))

            if not asset_ids:
                return {"success": True, "assets": [], "count": 0, "total": total}

            r2 = self._assets.get_assets(ids=asset_ids)
            if r2["status_code"] != 200:
                return {"success": False, "error": format_api_error(r2, "Failed to get asset details", operation="get_assets")}

            entities = r2.get("body", {}).get("resources", [])

            assets = []
            for a in entities:
                assets.append(
                    {
                        "id": a.get("id", ""),
                        "cloud_provider": a.get("cloud_provider", ""),
                        "account_id": a.get("account_id", ""),
                        "account_name": a.get("account_name", ""),
                        "region": a.get("region", ""),
                        "resource_type": a.get("resource_type_name", a.get("resource_type", "")),
                        "resource_id": a.get("resource_id", ""),
                        "resource_name": a.get("resource_name", ""),
                        "service": a.get("service", ""),
                        "service_category": a.get("service_category", ""),
                        "active": a.get("active", False),
                        "creation_time": a.get("creation_time", ""),
                        "first_seen": a.get("first_seen", ""),
                        "tags": a.get("tags", {}),
                        "configuration": a.get("configuration", {}),
                        "relationships": a.get("relationships", []),
                        "cloud_context": a.get("cloud_context", {}),
                    }
                )

            return {"success": True, "assets": assets, "count": len(assets), "total": total}
        except Exception as e:
            return {"success": False, "error": f"Error querying assets: {e}"}

    def _get_compliance_by_account(self, max_results=50):
        if not self._assets:
            return {"success": False, "error": "CloudSecurityAssets client not available"}
        try:
            r = self._assets.get_combined_compliance_by_account(limit=min(max_results, 100))
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to get compliance data", operation="get_combined_compliance_by_account")}

            resources = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(resources))

            entries = []
            for c in resources:
                entries.append(
                    {
                        "account_id": c.get("account_id", ""),
                        "account_name": c.get("account_name", ""),
                        "cloud_provider": c.get("cloud_provider", ""),
                        "region": c.get("region", ""),
                        "service": c.get("service", ""),
                        "service_category": c.get("service_category", ""),
                        "resource_type": c.get("resource_type_name", c.get("resource_type", "")),
                        "control": c.get("control", ""),
                        "resource_counts": c.get("resource_counts", {}),
                        "severities": c.get("severities", {}),
                        "last_evaluated": c.get("last_evaluated", ""),
                    }
                )

            return {"success": True, "compliance": entries, "count": len(entries), "total": total}
        except Exception as e:
            return {"success": False, "error": f"Error getting compliance: {e}"}
