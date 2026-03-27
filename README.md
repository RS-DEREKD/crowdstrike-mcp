# CrowdStrike Falcon MCP Server

A modular, multi-transport [Model Context Protocol](https://modelcontextprotocol.io/) server that connects AI assistants to the CrowdStrike Falcon platform. Query NG-SIEM logs, triage alerts, inspect endpoints, manage detection rules, and audit cloud security posture — all through natural language.

**v3.0** — Modular auto-discovery architecture with 19 tools across 7 modules.

---

## Architecture

```
                          ┌─────────────────────────────────┐
                          │         MCP Client              │
                          │  (Claude Code / Claude Desktop) │
                          └──────────┬──────────────────────┘
                                     │
                          ┌──────────▼──────────────────────┐
                          │     server.py                   │
                          │  FalconMCPServer (FastMCP)      │
                          │                                 │
                          │  Transports:                    │
                          │    stdio · sse · streamable-http│
                          └──────────┬──────────────────────┘
                                     │
                          ┌──────────▼──────────────────────┐
                          │     registry.py                 │
                          │  Auto-discovers modules/        │
                          │  via pkgutil                    │
                          └──────────┬──────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
     ┌────────▼───────┐   ┌─────────▼────────┐   ┌────────▼───────┐
     │  NGSIEMModule  │   │  AlertsModule    │   │  HostsModule   │
     │  1 tool        │   │  4 tools         │   │  3 tools       │
     ├────────────────┤   ├──────────────────┤   ├────────────────┤
     │ EndpointModule │   │ CorrelationMod.  │   │ CloudRegMod.   │
     │  1 tool        │   │  4 tools         │   │  2 tools       │
     ├────────────────┤   └──────────────────┘   ├────────────────┤
     │ CloudSecMod.   │                          │                │
     │  4 tools       │                          │                │
     └───────┬────────┘                          └───────┬────────┘
             │                                           │
             └────────────────┬──────────────────────────┘
                              │
                   ┌──────────▼──────────────────────┐
                   │     client.py                   │
                   │  FalconClient                   │
                   │  Shared OAuth2 session           │
                   │  Credential resolution chain     │
                   └─────────────────────────────────┘
                              │
                   ┌──────────▼──────────────────────┐
                   │     CrowdStrike Falcon APIs     │
                   └─────────────────────────────────┘
```

### File Layout

```
mcp/
├── server.py                  # FastMCP server, CLI, multi-transport
├── crowdstrike_mcp_server.py  # Legacy entry point (thin shim → server.py)
├── client.py                  # FalconClient — shared OAuth2 + credential chain
├── registry.py                # Module auto-discovery via pkgutil
├── utils.py                   # Response formatting, credential helpers
├── requirements.txt
│
├── modules/                   # Each module = independent tool group
│   ├── base.py                # BaseModule ABC
│   ├── ngsiem.py              # CQL query execution
│   ├── alerts.py              # Alert retrieval, analysis, triage
│   ├── endpoint.py            # EDR behaviors + process trees
│   ├── hosts.py               # Device lookups + login/network history
│   ├── correlation.py         # Detection rule management
│   ├── cloud_registration.py  # Cloud account + CSPM policies
│   └── cloud_security.py      # Risks, IOMs, assets, compliance
│
├── resources/                 # MCP TextResources (syntax docs)
│   └── fql_guides.py          # FQL + CQL syntax references
│
└── common/                    # Shared infrastructure
    ├── errors.py              # Scope-aware API error handling
    ├── api_scopes.py          # Operation → required scope mapping
    └── auth_middleware.py     # ASGI API key auth for HTTP transports
```

---

## Quick Start

### 1. Install dependencies

```bash
cd mcp/
pip install -r requirements.txt
```

Dependencies: `crowdstrike-falconpy>=1.6.0`, `mcp>=1.12.1`, `uvicorn>=0.27.0`, `python-dotenv>=1.0.0`, `starlette>=0.27.0`

### 2. Configure credentials

The server resolves credentials in priority order:

| Priority | Method | Details |
|----------|--------|---------|
| 1 | Environment variables | `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL` |
| 2 | Credential file | `~/.config/falcon/credentials.json` |

**Credential file format:**
```json
{
    "falcon_client_id": "your_client_id",
    "falcon_client_secret": "your_client_secret",
    "base_url": "US1"
}
```

Supported `base_url` values: `US1`, `US2`, `EU1`, `USGOV1`, `USGOV2`

### 3. Connect to an MCP client

**Claude Code** (`.mcp.json` at project root):
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "/path/to/.venv/bin/python3",
      "args": ["/path/to/mcp/crowdstrike_mcp_server.py"]
    }
  }
}
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "python3",
      "args": ["/path/to/mcp/server.py"]
    }
  }
}
```

---

## Tools Reference

### NG-SIEM — `modules/ngsiem.py`

| Tool | Description |
|------|-------------|
| `ngsiem_query` | Execute CQL queries across all CrowdStrike logs (search-all repository) |

**Parameters:** `query` (CQL string), `start_time` (e.g. `1h`, `1d`, `7d`, `30d`), `max_results` (1-1000)

```
"Show me failed console logins in the last 24 hours"
→ ngsiem_query(query='#repo="cloudtrail" event.action="ConsoleLogin" #event.outcome!="success"', start_time="1d")
```

### Alerts — `modules/alerts.py`

| Tool | Description |
|------|-------------|
| `get_alerts` | Retrieve alerts across all detection types with filtering |
| `alert_analysis` | Deep-dive analysis with MITRE ATT&CK context and related events |
| `ngsiem_alert_analysis` | Alias for `alert_analysis` |
| `update_alert_status` | Change alert status, add comments and tags |

**Detection types supported:** Endpoint (`ind`), NG-SIEM (`ngsiem`), Cloud Security (`fcs`), Identity (`ldt`), Third-party (`thirdparty`)

Each alert analysis routes to type-specific enrichment:
- **NG-SIEM alerts** — retrieves related events via indicator/detection two-step lookup
- **Endpoint alerts** — fetches EDR behaviors with process trees and MITRE techniques
- **Cloud/Identity/Third-party** — extracts metadata from alert payload

### Hosts — `modules/hosts.py`

| Tool | Description |
|------|-------------|
| `host_lookup` | Device details: OS, agent version, containment status, policies |
| `host_login_history` | Recent login events for a device |
| `host_network_history` | Network address history for a device |

### Correlation Rules — `modules/correlation.py`

| Tool | Description |
|------|-------------|
| `correlation_list_rules` | List detection/correlation rules with optional name search |
| `correlation_get_rule` | Full rule details: CQL filter, severity, MITRE mapping |
| `correlation_update_rule` | Enable/disable rules with audit comment |
| `correlation_export_rule` | Export rule in structured format |

### Cloud Registration — `modules/cloud_registration.py`

| Tool | Description |
|------|-------------|
| `cloud_list_accounts` | List registered AWS/Azure accounts and their status |
| `cloud_policy_settings` | CSPM policy settings and compliance benchmarks |

### Cloud Security — `modules/cloud_security.py`

| Tool | Description |
|------|-------------|
| `cloud_get_risks` | Cloud risks ranked by score (misconfigs, unused identities, exposure) |
| `cloud_get_iom_detections` | Indicator of Misconfiguration detections with remediation steps |
| `cloud_query_assets` | Cloud asset inventory across AWS/Azure/GCP |
| `cloud_compliance_by_account` | Compliance posture aggregated by account and region |

---

## MCP Resources

The server exposes FQL and CQL syntax documentation as MCP TextResources. AI assistants can read these to self-correct filter syntax without external lookups.

| URI | Content |
|-----|---------|
| `falcon://fql/alerts` | Alert FQL filter syntax (severity, status, product, timestamp) |
| `falcon://fql/hosts` | Host FQL filter syntax (hostname, platform, containment) |
| `falcon://fql/cloud-risks` | Cloud risk filter syntax |
| `falcon://fql/cloud-iom` | IOM detection filter syntax |
| `falcon://fql/cloud-assets` | Cloud asset filter syntax |
| `falcon://cql/syntax` | CQL query language reference for NG-SIEM |

---

## Multi-Transport Support

### stdio (default)

Standard MCP transport for CLI tools like Claude Code. No additional configuration needed.

```bash
python server.py
# or
python server.py --transport stdio
```

### SSE (Server-Sent Events)

HTTP-based transport for web clients and remote connections.

```bash
python server.py --transport sse --port 8000
```

### Streamable HTTP

Newer HTTP transport with bidirectional streaming.

```bash
python server.py --transport streamable-http --port 8000
```

### HTTP Authentication

For SSE and streamable-http transports, enable API key authentication:

```bash
python server.py --transport sse --api-key "your-secret-key"
```

Clients must include the `x-api-key` header in requests. Authentication uses constant-time comparison to prevent timing attacks.

---

## CLI Reference

```
python server.py [OPTIONS]
```

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--transport` | `FALCON_MCP_TRANSPORT` | `stdio` | Transport: `stdio`, `sse`, `streamable-http` |
| `--modules` | `FALCON_MCP_MODULES` | all | Comma-separated module list |
| `--debug` | `FALCON_MCP_DEBUG` | false | Enable debug logging |
| `--host` | `FALCON_MCP_HOST` | `127.0.0.1` | HTTP bind address |
| `--port` | `FALCON_MCP_PORT` | `8000` | HTTP port |
| `--api-key` | `FALCON_MCP_API_KEY` | — | API key for HTTP auth |

### Selective Module Loading

Load only the modules you need to reduce attack surface and startup time:

```bash
# SOC triage workflow — just alerts, NGSIEM, and hosts
python server.py --modules ngsiem,alerts,hosts

# Cloud security audit
python server.py --modules cloudsecurity,cloudregistration

# Detection engineering
python server.py --modules ngsiem,correlation
```

**Available module names:** `alerts`, `casemanagement`, `cloudsecurity`, `cloudregistration`, `correlation`, `hosts`, `ngsiem`, `response`

---

## Permissions

The server uses a two-layer permission model: **server-side visibility** controls which tools exist, and **client-side presets** control which tools require user approval.

### Server-Side: `--allow-writes`

By default, the server runs in **read-only mode**. Write tools (alert updates, containment, rule changes) are not registered and don't appear in the tool list.

To enable write tools:

```bash
python server.py --allow-writes
```

Or via environment variable:

```bash
FALCON_MCP_ALLOW_WRITES=true python server.py
```

#### .mcp.json examples

**Read-only (default, recommended):**
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": ".venv/bin/python3",
      "args": ["server.py"]
    }
  }
}
```

**With write tools enabled:**
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": ".venv/bin/python3",
      "args": ["server.py", "--allow-writes"]
    }
  }
}
```

**Minimal — only NGSIEM and host lookups:**
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": ".venv/bin/python3",
      "args": ["server.py", "--modules", "ngsiem,hosts"]
    }
  }
}
```

### Client-Side: Permission Presets

Four Claude Code permission presets are included in `.claude/`:

| Preset | Use Case | Auto-allowed | Prompts For |
|--------|----------|-------------|-------------|
| `permissions-minimal.json` | Query-only analyst | ngsiem_query, host_lookup | Everything else |
| `permissions-readonly.json` | Read-only (default) | All read tools | All write tools |
| `permissions-standard.json` | SOC triage analyst | All read + alert/case updates | Containment, rule changes |
| `permissions-full.json` | Admin / full trust | All tools | Nothing |

To switch presets:

```bash
cp .claude/permissions-standard.json .claude/settings.json
```

### How the Layers Compose

| Control | What it does |
|---------|-------------|
| `--modules` | Which modules load at all |
| `--allow-writes` | Whether write tools register within loaded modules |
| `.claude/settings.json` | Whether Claude Code prompts before calling a tool |

All three are independent. A tool must pass all applicable gates to execute without prompting.

### Write Tools

These tools require `--allow-writes` to be visible:

| Tool | Module | What it does |
|------|--------|-------------|
| `update_alert_status` | alerts | Change alert status, add comments/tags |
| `correlation_update_rule` | correlation | Enable/disable detection rules |
| `correlation_import_to_iac` | correlation | Export rules to IaC YAML |
| `host_contain` | response | Network-isolate a host |
| `host_lift_containment` | response | Lift network isolation |
| `case_create` | case_management | Create a new case |
| `case_update` | case_management | Update case fields |
| `case_add_alert_evidence` | case_management | Attach alerts to a case |
| `case_add_event_evidence` | case_management | Attach events to a case |
| `case_add_tags` | case_management | Add tags to a case |
| `case_delete_tags` | case_management | Remove tags from a case |
| `case_upload_file` | case_management | Upload file to a case |

---

## Key Features

### Query Audit Trail

All NG-SIEM queries are automatically tagged with a timestamp comment for compliance and attribution:

```cql
// MCP Query - 2025-09-04T15:30:45.123456
#repo="cloudtrail" event.action = "ConsoleLogin"
```

### Scope-Aware Error Handling

When the API returns a 403 Forbidden, the error message includes the specific API scopes needed to resolve it:

```
HTTP 403: Insufficient permissions for query_alerts_v2.
Required scopes: alerts:read
Resolution: Add the required scopes to your API client in the CrowdStrike console.
```

### Graceful Module Degradation

Each module is imported independently with try/except. If a module fails to load (missing FalconPy service class, insufficient permissions, etc.), the remaining modules continue to function normally.

### Large Response Handling

Responses exceeding 20KB are automatically written to temporary files with a truncated summary returned to the AI assistant, preventing context window overflow.

### Shared OAuth2 Session

All modules share a single `OAuth2` token through `FalconClient.auth_object`. This means one authentication handshake for all 19 tools, regardless of how many FalconPy service classes are instantiated.

---

## Required API Scopes

### By Tool

| Tool | Module | Required Scopes | Notes |
|------|--------|----------------|-------|
| `ngsiem_query` | NG-SIEM | `ngsiem:read` | `ngsiem:write` only needed for timeout cleanup |
| `get_alerts` | Alerts | `alerts:read` | |
| `alert_analysis` | Alerts | `alerts:read` | |
| `ngsiem_alert_analysis` | Alerts | `alerts:read` | Alias for `alert_analysis` |
| `update_alert_status` | Alerts | `alerts:write` | Only write tool for alerts |
| `endpoint_get_behaviors` | Endpoint | `detects:read` | |
| `host_lookup` | Hosts | `hosts:read` | |
| `host_login_history` | Hosts | `hosts:read` | |
| `host_network_history` | Hosts | `hosts:read` | |
| `correlation_list_rules` | Correlation | `correlation-rules:read` | |
| `correlation_get_rule` | Correlation | `correlation-rules:read` | |
| `correlation_update_rule` | Correlation | `correlation-rules:write` | Enable/disable only, no create/delete |
| `correlation_export_rule` | Correlation | `correlation-rules:read` | |
| `cloud_list_accounts` | Cloud Registration | `cspm-registration:read` | |
| `cloud_policy_settings` | Cloud Registration | `cspm-registration:read` | |
| `cloud_get_risks` | Cloud Security | `cloud-security:read` | |
| `cloud_get_iom_detections` | Cloud Security | `cloud-security-detections:read` | |
| `cloud_query_assets` | Cloud Security | `cloud-security-assets:read` | |
| `cloud_compliance_by_account` | Cloud Security | `cloud-security-assets:read` | |
| `case_query` | Case Management | `cases:read` | |
| `case_get` | Case Management | `cases:read` | |
| `case_get_fields` | Case Management | `cases:read` | |
| `case_create` | Case Management | `cases:read` | Uses POST but reads/creates |
| `case_update` | Case Management | `cases:write` | |
| `case_add_alert_evidence` | Case Management | `cases:write` | |
| `case_add_event_evidence` | Case Management | `cases:write` | |
| `case_add_tags` | Case Management | `cases:write` | |
| `case_delete_tags` | Case Management | `cases:write` | |
| `case_upload_file` | Case Management | `cases:write` | |

### Minimum Scopes by Workflow

| Workflow | Scopes |
|----------|--------|
| **SOC triage** (read-only) | `alerts:read`, `ngsiem:read`, `hosts:read`, `detects:read` |
| **SOC triage** (with status updates) | Above + `alerts:write`, `cases:read`, `cases:write` |
| **Detection engineering** | `ngsiem:read`, `correlation-rules:read`, `correlation-rules:write` |
| **Cloud security audit** | `cspm-registration:read`, `cloud-security:read`, `cloud-security-detections:read`, `cloud-security-assets:read` |
| **Full access** | All scopes above |

---

## Adding a New Module

1. Create `modules/your_module.py` with a class extending `BaseModule`:

```python
from modules.base import BaseModule

class YourModule(BaseModule):
    def __init__(self, client):
        super().__init__(client)
        # Create FalconPy service using shared auth
        self.service = SomeService(auth_object=self.client.auth_object)

    def register_tools(self, server):
        self._add_tool(server, self.your_tool, name="your_tool",
                       description="What this tool does")

    async def your_tool(self, param: Annotated[str, "Description"]) -> str:
        # Implementation
        return format_text_response(result, raw=True)
```

2. That's it. The registry auto-discovers any class ending in `Module` that extends `BaseModule`.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| **Credentials not found** | Check `~/.config/falcon/credentials.json` exists, or set `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` env vars |
| **403 Forbidden** | Add the required API scopes listed in the error message to your CrowdStrike API client |
| **Module failed to load** | Check stderr for `[registry] Failed to instantiate ...` — usually a missing FalconPy service class or dependency |
| **Query timeout** | NG-SIEM queries timeout after 120s. Simplify the query or narrow the time range |
| **Import error** | Run `pip install -r requirements.txt` — requires `crowdstrike-falconpy>=1.6.0` and `mcp>=1.12.1` |
| **SSE connection refused** | Ensure `--host 0.0.0.0` if connecting from a different machine (default binds to localhost only) |

---

## Security

- Credentials are resolved at runtime from env vars or local files — never hardcoded
- HTTP transports support API key authentication with constant-time comparison
- All NG-SIEM queries carry audit trail timestamps for compliance attribution
- Input sanitization strips control characters and truncates oversized values
- The `update_alert_status` tool is the only write operation against live alert state
- `correlation_update_rule` can enable/disable rules but cannot create or delete them
- Defensive security focus only — no offensive capabilities
