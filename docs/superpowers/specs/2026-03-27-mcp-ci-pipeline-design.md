# MCP Server CI Pipeline Design

## Goal

Add a GitHub Actions CI pipeline to the CrowdStrike MCP server that validates code quality, runs unit tests, and smoke-tests the MCP tool registration — all without API credentials.

## Trigger

- Pull request to `master`
- Push to `master`

## Jobs

Three parallel jobs on `ubuntu-latest`, Python 3.11:

### 1. Lint (`ruff`)

Runs `ruff check .` and `ruff format --check .` to enforce consistent style.

**Config:** `ruff.toml` at repo root with:
- `line-length = 120` (matches existing code style)
- `target-version = "py311"`
- Minimal rule set: default (`E`, `F`) + `I` (import sorting)

### 2. Test (`pytest`)

Runs `pytest tests/ -v` — the existing 46 unit tests. All tests use `mock_client` fixture; no API credentials needed.

### 3. Smoke: tools/list verification

The highest-value test. Starts the MCP server with mocked authentication and calls `tools/list` through the MCP protocol to verify:

1. **Read-only mode (default):** All read tools are registered. Zero write tools appear.
2. **Write mode (`allow_writes=True`):** All read tools + all 12 write tools are registered.
3. **Tool names are stable:** The exact set of expected tool names matches a known list — catches accidental renames, missing tools from broken modules, or write tools leaking.

**Implementation approach:** The smoke test does NOT need to start a subprocess or use stdio transport. It instantiates `FalconMCPServer` internals directly:
- Mock `FalconClient` and `FalconClient.authenticate()`
- Call `get_available_modules(mock_client, allow_writes=False/True)`
- Call `module.register_tools(mock_server)` for each module
- Assert tool names against expected sets

This is simpler and faster than spawning a real MCP client/server pair, and tests the same registration logic.

**Expected tool sets:**

Read tools (always registered):
```
get_alerts, alert_analysis, ngsiem_alert_analysis, ngsiem_query,
host_lookup, host_login_history, host_network_history,
correlation_list_rules, correlation_get_rule, correlation_export_rule,
case_query, case_get, case_get_fields,
cloud_list_accounts, cloud_policy_settings, cloud_get_risks,
cloud_get_iom_detections, cloud_query_assets, cloud_compliance_by_account
```

Write tools (only with `allow_writes=True`):
```
update_alert_status, correlation_update_rule, correlation_import_to_iac,
host_contain, host_lift_containment,
case_create, case_update, case_add_alert_evidence,
case_add_event_evidence, case_add_tags, case_delete_tags, case_upload_file
```

## Files

| File | Purpose |
|------|---------|
| `ruff.toml` | Ruff linter/formatter config |
| `requirements-dev.txt` | Dev dependencies: `ruff`, `pytest` |
| `.github/workflows/ci.yml` | GitHub Actions workflow (3 parallel jobs) |
| `tests/test_smoke_tools_list.py` | Smoke test for tool registration |

## Dependencies

- `ruff` — linting and formatting (dev only)
- `pytest` — already in use, add to dev requirements for CI

No new runtime dependencies.

## Out of scope

- End-to-end tests requiring Falcon API credentials
- Type checking (`mypy`) — can add later
- Schema snapshot files — the smoke test hardcodes expected tool names, which is simpler and sufficient
- Deploy/release automation
