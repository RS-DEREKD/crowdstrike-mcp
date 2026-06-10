# crowdstrike-mcp — Pip-Installable MCP Server Packaging

> **Status:** Approved
> **Date:** 2026-04-14
> **Scope:** crowdstrike-mcp repo only

## Goal

Package the CrowdStrike Falcon MCP Server as a pip-installable Python package. After this work, `pip install crowdstrike-mcp` gives users the `crowdstrike-mcp` CLI command, replacing `python server.py`.

## Current State

- Entry point: `python server.py` (with CLI flags for transport, port, modules, etc.)
- Legacy shim: `crowdstrike_mcp_server.py` (backward compatibility, delegates to `server.py`)
- No `pyproject.toml` — dependencies managed via `requirements.txt` and `requirements-dev.txt`
- All source files at repo root (server.py, client.py, registry.py, utils.py, response_store.py)
- `modules/` and `common/` directories at repo root
- `resources/` directory with MCP TextResources
- Already has: CI (lint + test + smoke + release), Dockerfile, ruff config, pytest config
- Version 3.1.0, well-structured, ~6.5K lines

## Target State

```
crowdstrike-mcp/                   # repo root
├── src/crowdstrike_mcp/           # the pip package
│   ├── __init__.py                # __version__ = "3.1.0"
│   ├── server.py                  # FastMCP orchestrator + CLI
│   ├── client.py                  # FalconClient shared OAuth2 session
│   ├── registry.py                # BaseModule auto-discovery
│   ├── utils.py                   # Response formatting, credential helpers
│   ├── response_store.py          # In-memory ring buffer
│   ├── modules/                   # 8 tool modules (auto-discovered)
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── ngsiem.py
│   │   ├── alerts.py
│   │   ├── hosts.py
│   │   ├── correlation.py
│   │   ├── cloud_registration.py
│   │   ├── cloud_security.py
│   │   ├── case_management.py
│   │   ├── cao_hunting.py
│   │   ├── response.py
│   │   └── spotlight.py
│   ├── common/                    # Shared infrastructure
│   │   ├── __init__.py
│   │   ├── errors.py
│   │   ├── auth_middleware.py
│   │   ├── session_auth.py
│   │   ├── api_scopes.py
│   │   └── health.py
│   └── resources/                 # MCP TextResources (FQL/CQL guides)
├── tests/                         # updated imports
├── pyproject.toml                 # package metadata, deps, entry points
├── Dockerfile                     # updated for pip install
├── ruff.toml                      # stays
├── README.md                      # updated install instructions
└── LICENSE                        # stays (MIT)
```

## Package Metadata (pyproject.toml)

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "crowdstrike-mcp"
version = "3.1.0"
description = "MCP server for the CrowdStrike Falcon platform"
readme = "README.md"
license = "MIT"
requires-python = ">=3.11"
authors = [{ name = "Will Webster" }]
keywords = ["crowdstrike", "falcon", "mcp", "security", "model-context-protocol"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Information Technology",
    "Topic :: Security",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]
dependencies = [
    "crowdstrike-falconpy>=1.6.1",
    "mcp>=1.12.1",
    "uvicorn>=0.27.0",
    "python-dotenv>=1.0.0",
    "starlette>=0.27.0",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = ["pytest>=9.0.0", "ruff>=0.8.0"]

[project.scripts]
crowdstrike-mcp = "crowdstrike_mcp.server:main"

[tool.hatch.build.targets.wheel]
packages = ["src/crowdstrike_mcp"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

## Migration Details

### Import Path Changes

All internal imports change from bare module names to `crowdstrike_mcp.*`:

| Before | After |
|--------|-------|
| `from client import FalconClient` | `from crowdstrike_mcp.client import FalconClient` |
| `from registry import ModuleRegistry` | `from crowdstrike_mcp.registry import ModuleRegistry` |
| `from utils import format_response` | `from crowdstrike_mcp.utils import format_response` |
| `from common.errors import format_error` | `from crowdstrike_mcp.common.errors import format_error` |
| `from modules.base import BaseModule` | `from crowdstrike_mcp.modules.base import BaseModule` |

### Module Auto-Discovery Update

`registry.py` uses `pkgutil.iter_modules()` to find tool modules. The scan path changes from `modules` to `crowdstrike_mcp.modules`. The `__path__` reference in the scan needs updating to use the package's `modules` subpackage.

### Legacy Shim Removal

`crowdstrike_mcp_server.py` is deleted. It was a backward-compatibility shim from an earlier rename. Users who reference it in `.mcp.json` configs need to update to the `crowdstrike-mcp` CLI entry point.

### Dockerfile Update

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .
ENTRYPOINT ["crowdstrike-mcp"]
```

### CI Updates

- `pip install -e .[dev]` replaces `pip install -r requirements.txt && pip install -r requirements-dev.txt`
- Smoke test uses `crowdstrike-mcp --help` or imports `crowdstrike_mcp`
- Release workflow: update for package-based build if publishing artifacts

### MCP Client Configuration

Updated `.mcp.json` examples in README:

```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "crowdstrike-mcp",
      "args": ["--allow-writes"]
    }
  }
}
```

Or with explicit venv path:
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "/path/to/venv/bin/crowdstrike-mcp",
      "args": ["--allow-writes"]
    }
  }
}
```

### TextResource Bundling

MCP TextResources in `resources/` are bundled inside the package at `crowdstrike_mcp/resources/`. The server loads them using `importlib.resources` or `__file__`-relative paths instead of CWD-relative paths.

## What Does NOT Change

- Module architecture (BaseModule, auto-discovery, read/write tiers)
- FalconClient shared session pattern
- ResponseStore ring buffer
- All 19+ tools and their parameters
- Multi-transport support (stdio, SSE, streamable-http)
- Permission model (--allow-writes, client presets)
- API scope mapping
- Health check endpoint
- HTTP auth middleware

## Out of Scope

- PyPI publishing (future — for now `pip install git+https://...`)
- New tool modules
- Protocol changes
