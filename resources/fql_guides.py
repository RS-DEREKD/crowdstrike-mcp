"""
FQL/CQL syntax documentation exposed as MCP TextResource objects.

These resources provide self-service filter/query syntax so the AI agent can
self-correct FQL filters and CQL queries without external lookups.

Usage in modules:
  In a module's ``register_resources()``, call ``register_fql_resources(server)``
  to expose the relevant guides.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


# -- Resource content definitions --

ALERT_FQL = """\
# Alert FQL Filter Syntax (query_alerts_v2)

## Supported FQL Fields
- `severity` — Integer: 10 (Informational), 20 (Low), 30 (Medium), 40 (High), 50 (Critical)
  - Example: `severity:>=40` (HIGH and above)
- `status` — String: 'new', 'in_progress', 'closed', 'reopened'
  - Example: `status:'new'`
- `product` — Array: 'ind' (endpoint), 'ngsiem', 'fcs' (cloud), 'ldt' (identity), 'thirdparty'
  - Example: `product:['ngsiem']`
- `created_timestamp` — ISO 8601 timestamp
  - Example: `created_timestamp:>='2024-01-01T00:00:00Z'`
- `assigned_to_name` — Filter by analyst assignment
- `tags` — Alert tags
- `type` — Alert type string

## NOT Supported in FQL
- `name` — Alert name is NOT a valid FQL filter field. Use the `pattern_name` parameter
  in get_alerts for client-side name filtering instead.

## Combining Filters
Use `+` to AND filters together:
  `severity:>=40+status:'new'+product:['ngsiem']`
"""

HOST_FQL = """\
# Host FQL Filter Syntax

## Common Fields
- `hostname` — Device hostname (case-insensitive)
  - Example: `hostname:'WORKSTATION-01'`
- `platform_name` — OS platform: 'Windows', 'Mac', 'Linux'
  - Example: `platform_name:'Windows'`
- `last_seen` — ISO 8601 timestamp for last check-in
  - Example: `last_seen:>='2024-01-01T00:00:00Z'`
- `status` — Device status: 'normal', 'containment_pending', 'contained', 'lift_containment_pending'
  - Example: `status:'contained'`
- `tags` — Falcon Grouping Tags
  - Example: `tags:'FalconGroupingTags/Production'`

## Combining Filters
Use `+` to AND filters together:
  `platform_name:'Windows'+status:'normal'+last_seen:>='2024-06-01T00:00:00Z'`
"""

CLOUD_RISKS_FQL = """\
# Cloud Risk FQL Filter Syntax

## Common Fields
- `severity` — String: 'critical', 'high', 'medium', 'low'
  - Example: `severity:'critical'`
- `status` — String: 'open', 'resolved'
  - Example: `status:'open'`
- `cloud_provider` — String: 'aws', 'azure', 'gcp'
  - Example: `cloud_provider:'aws'`
- `account_id` — Cloud account ID
  - Example: `account_id:'123456789012'`

## Combining Filters
  `severity:'critical'+status:'open'+cloud_provider:'aws'`
"""

CLOUD_IOM_FQL = """\
# IOM Detection FQL Filter Syntax

## Common Fields
- `severity` — String: 'critical', 'high', 'medium', 'low'
- `cloud_provider` — String: 'aws', 'azure', 'gcp'
- `account_id` — Cloud account ID
- `resource_type` — AWS/Azure/GCP resource type
  - Example: `resource_type:'AWS::EC2::SecurityGroup'`

## Combining Filters
  `severity:'high'+cloud_provider:'aws'+resource_type:'AWS::S3::Bucket'`
"""

CLOUD_ASSETS_FQL = """\
# Cloud Asset FQL Filter Syntax

## Common Fields
- `cloud_provider` — String: 'aws', 'azure', 'gcp'
- `account_id` — Cloud account ID
- `resource_type` — Full resource type string
  - Example: `resource_type:'AWS::EC2::Instance'`
- `region` — Cloud region
  - Example: `region:'us-east-1'`
- `resource_id` — Specific resource identifier
  - Example: `resource_id:'sg-ad7c91da'`

## Combining Filters
  `cloud_provider:'aws'+region:'us-east-1'+resource_type:'AWS::EC2::Instance'`
"""

CASE_FQL = """\
# Case FQL Filter Syntax (query_case_ids)

## Supported FQL Fields
- `status` — String: 'open', 'in_progress', 'closed', 'reopened'
  - Example: `status:'open'`
- `severity` — Integer: 10 (Info), 20 (Low), 30 (Medium), 40 (High), 50 (Critical)
  - Example: `severity:>=40`
- `created_on` — ISO 8601 timestamp
  - Example: `created_on:>='2024-01-01T00:00:00Z'`
- `assigned_to_user_uuid` — UUID of assigned user
- `name` — Case name (string match)
- `tags` — Case tags

## Combining Filters
Use `+` to AND filters together:
  `status:'open'+severity:>=40`

## Sort Fields
Format: `field.direction` (e.g. `severity.desc`, `name.asc`)
Valid sort fields: `name`, `status`, `severity`, `id`
Note: `created_on` is NOT a valid sort field.
"""

CQL_SYNTAX = """\
# CQL (CrowdStrike Query Language) Syntax for NGSIEM

## Basic Structure
  `<field> <operator> <value>`

## Operators
- `=` — Exact match: `event.action = "ConsoleLogin"`
- `!=` — Not equal: `#event.outcome != "success"`
- `=~` — Regex match: `source.ip =~ /^10\\./`
- `in` — Set membership: `event.action in ["CreateUser", "DeleteUser"]`

## Field References
- Bare field: `event.action`
- Hash-prefix (reserved): `#event.outcome`
- Vendor-prefix: `Vendor.userIdentity.arn`

## Logical Operators
- `AND` / `OR` / `NOT`
- Grouping with parentheses: `(A OR B) AND C`

## Repository Filters (source selection)
- `#repo="cloudtrail"` — AWS CloudTrail logs
- `#repo="microsoft_graphapi"` — Microsoft/EntraID logs
- `#repo="3pi_google_cloud_audit_logs"` — GCP audit logs
- `#Vendor="cato"` — Cato network logs
- `source_type=github` — GitHub audit logs

## Pipes and Functions
- `| table(field1, field2)` — Select specific fields
- `| head(N)` — Limit to first N results
- `| tail(N)` — Limit to last N results
- `| sort(@timestamp, order=desc)` — Sort results
- `| groupBy(field)` — Aggregate by field
- `| count()` — Count matching events
- `| $function_name()` — Call a saved search/enrichment function

## Time Functions
- `now()` — Current timestamp
- `start` — Query start time (set by time_range parameter)

## Example Queries
```
// AWS CloudTrail — console logins
#repo="cloudtrail" event.action = "ConsoleLogin"
  | $aws_enrich_user_identity()
  | table(Vendor.userIdentity.arn, source.ip, #event.outcome)

// EntraID — failed sign-ins
#repo=microsoft_graphapi
  | operationName = "Sign-in activity"
  | resultType != "0"
  | $entraid_enrich_user_identity()

// Cross-platform — all events for a specific user
| $identity_enrich_from_email()
| normalized.email = "user@example.com"
```
"""


def register_fql_resources(server: FastMCP) -> list[str]:
    """Register all FQL/CQL documentation resources with the server.

    Returns list of registered resource URIs.
    """
    resources_list = [
        ("falcon://fql/alerts", "Alert FQL Syntax Guide", ALERT_FQL),
        ("falcon://fql/hosts", "Host FQL Syntax Guide", HOST_FQL),
        ("falcon://fql/cloud-risks", "Cloud Risk FQL Syntax Guide", CLOUD_RISKS_FQL),
        ("falcon://fql/cloud-iom", "IOM Detection FQL Syntax Guide", CLOUD_IOM_FQL),
        ("falcon://fql/cloud-assets", "Cloud Asset FQL Syntax Guide", CLOUD_ASSETS_FQL),
        ("falcon://fql/cases", "Case FQL Syntax Guide", CASE_FQL),
        ("falcon://cql/syntax", "CQL Query Syntax Reference", CQL_SYNTAX),
    ]

    def _make_fn(text):
        def fn():
            return text
        return fn

    uris = []
    for uri, name, content in resources_list:
        server.resource(uri, name=name, description=f"Documentation: {name}")(
            _make_fn(content)
        )
        uris.append(uri)

    return uris
