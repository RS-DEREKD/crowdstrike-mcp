# CrowdStrike MCP Server — Pip Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package the CrowdStrike MCP server as a pip-installable Python package with a `crowdstrike-mcp` CLI entry point.

**Architecture:** Move all source files from repo root into `src/crowdstrike_mcp/`, add `pyproject.toml` with hatchling build backend, update all bare imports to absolute package imports, update CI and Dockerfile.

**Tech Stack:** Python 3.11+, hatchling, FastMCP, Click (existing argparse stays — no CLI framework change needed)

---

### File Map

**Create:**
- `pyproject.toml` — Package metadata, dependencies, entry point
- `src/crowdstrike_mcp/__init__.py` — Package root with `__version__`

**Move (git mv):**
- `server.py` → `src/crowdstrike_mcp/server.py`
- `client.py` → `src/crowdstrike_mcp/client.py`
- `registry.py` → `src/crowdstrike_mcp/registry.py`
- `utils.py` → `src/crowdstrike_mcp/utils.py`
- `response_store.py` → `src/crowdstrike_mcp/response_store.py`
- `modules/` → `src/crowdstrike_mcp/modules/`
- `common/` → `src/crowdstrike_mcp/common/`
- `resources/` → `src/crowdstrike_mcp/resources/`

**Delete:**
- `crowdstrike_mcp_server.py` (legacy shim)
- `requirements.txt` (replaced by pyproject.toml)
- `requirements-dev.txt` (replaced by pyproject.toml [dev] extra)

**Modify:**
- Every `.py` file under `src/crowdstrike_mcp/` — import path updates
- `tests/conftest.py` — remove sys.path manipulation
- All test files — update import paths and mock targets
- `.github/workflows/ci.yml` — use `pip install -e .[dev]`
- `.github/workflows/release.yml` — use `pip install .`, update Docker build
- `Dockerfile` — use `pip install .`
- `README.md` — update install/usage instructions
- `pytest.ini` — may need testpaths update

---

### Task 1: Create package skeleton and pyproject.toml

**Files:**
- Create: `pyproject.toml`
- Create: `src/crowdstrike_mcp/__init__.py`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p src/crowdstrike_mcp
```

- [ ] **Step 2: Create `src/crowdstrike_mcp/__init__.py`**

```python
"""CrowdStrike Falcon MCP Server."""

__version__ = "3.1.0"
```

- [ ] **Step 3: Create `pyproject.toml`**

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

[tool.ruff]
target-version = "py311"
line-length = 155
select = ["E", "F", "I"]
```

- [ ] **Step 4: Verify skeleton installs**

Run: `pip install -e . 2>&1 | tail -5`
Expected: `Successfully installed crowdstrike-mcp-3.1.0`

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/crowdstrike_mcp/__init__.py
git commit -m "feat: add pyproject.toml and package skeleton"
```

---

### Task 2: Move source files into package

**Files:**
- Move: all `.py` files from repo root and `modules/`, `common/`, `resources/` directories

- [ ] **Step 1: Move root-level source files**

```bash
git mv server.py src/crowdstrike_mcp/server.py
git mv client.py src/crowdstrike_mcp/client.py
git mv registry.py src/crowdstrike_mcp/registry.py
git mv utils.py src/crowdstrike_mcp/utils.py
git mv response_store.py src/crowdstrike_mcp/response_store.py
```

- [ ] **Step 2: Move directories**

```bash
git mv modules/ src/crowdstrike_mcp/modules/
git mv common/ src/crowdstrike_mcp/common/
git mv resources/ src/crowdstrike_mcp/resources/
```

- [ ] **Step 3: Remove legacy shim**

```bash
git rm crowdstrike_mcp_server.py
```

- [ ] **Step 4: Remove requirements files (replaced by pyproject.toml)**

```bash
git rm requirements.txt requirements-dev.txt
```

- [ ] **Step 5: Commit the move**

```bash
git commit -m "refactor: move source files into src/crowdstrike_mcp/ package"
```

---

### Task 3: Update imports in server.py, client.py, registry.py, utils.py, response_store.py

**Files:**
- Modify: `src/crowdstrike_mcp/server.py`
- Modify: `src/crowdstrike_mcp/client.py`
- Modify: `src/crowdstrike_mcp/registry.py`
- Modify: `src/crowdstrike_mcp/utils.py`
- Modify: `src/crowdstrike_mcp/response_store.py`

- [ ] **Step 1: Update `server.py` imports**

Remove the `sys.path.insert(0, ...)` line (around line 32-34).

Replace bare imports:
```python
# Before:
from client import FalconClient
from registry import get_available_modules, get_module_names

# After:
from crowdstrike_mcp.client import FalconClient
from crowdstrike_mcp.registry import get_available_modules, get_module_names
```

Also update any `from common.` or `from modules.` imports:
```python
# Before:
from common.session_auth import session_auth_middleware
from common.health import with_health_check
from common.auth_middleware import auth_middleware

# After:
from crowdstrike_mcp.common.session_auth import session_auth_middleware
from crowdstrike_mcp.common.health import with_health_check
from crowdstrike_mcp.common.auth_middleware import auth_middleware
```

- [ ] **Step 2: Update `registry.py` imports**

```python
# Before:
from modules.base import BaseModule

# After:
from crowdstrike_mcp.modules.base import BaseModule
```

Update `discover_module_classes()` to use the package path:
```python
# Before:
import modules as _pkg
for importer, module_name, is_pkg in pkgutil.iter_modules(_pkg.__path__):
    mod = importlib.import_module(f"modules.{module_name}")

# After:
import crowdstrike_mcp.modules as _pkg
for importer, module_name, is_pkg in pkgutil.iter_modules(_pkg.__path__):
    mod = importlib.import_module(f"crowdstrike_mcp.modules.{module_name}")
```

- [ ] **Step 3: Update `utils.py` imports**

```python
# Before:
from response_store import ResponseStore

# After:
from crowdstrike_mcp.response_store import ResponseStore
```

- [ ] **Step 4: Update `client.py`**

`client.py` only imports from `falconpy` (external) and stdlib — likely no changes needed. Verify and confirm.

- [ ] **Step 5: Update `response_store.py`**

`response_store.py` uses only stdlib imports — likely no changes needed. Verify and confirm.

- [ ] **Step 6: Commit**

```bash
git commit -am "refactor: update imports in top-level package files"
```

---

### Task 4: Update imports in modules/

**Files:**
- Modify: `src/crowdstrike_mcp/modules/base.py`
- Modify: All module files (`alerts.py`, `ngsiem.py`, `hosts.py`, `correlation.py`, `cloud_security.py`, `cloud_registration.py`, `case_management.py`, `cao_hunting.py`, `spotlight.py`, `response.py`)
- Modify or Delete: `src/crowdstrike_mcp/modules/response_store.py` (alias file)

- [ ] **Step 1: Update `modules/base.py`**

```python
# Before:
from client import FalconClient

# After:
from crowdstrike_mcp.client import FalconClient
```

- [ ] **Step 2: Update module files — pattern**

Every module file follows the same pattern. Apply to each:

```python
# Before (typical module):
from modules.base import BaseModule
from common.errors import format_api_error
from utils import format_text_response, sanitize_input
from resources.fql_guides import ALERT_FQL

# After:
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.utils import format_text_response, sanitize_input
from crowdstrike_mcp.resources.fql_guides import ALERT_FQL
```

Files to update (apply the pattern to each):
- `alerts.py` — imports: `modules.base`, `common.errors`, `utils`, `resources.fql_guides`
- `ngsiem.py` — imports: `modules.base`, `utils`, `resources.fql_guides`
- `hosts.py` — imports: `modules.base`, `common.errors`, `utils`, `resources.fql_guides`
- `correlation.py` — imports: `modules.base`, `common.errors`, `utils`
- `cloud_security.py` — imports: `modules.base`, `common.errors`, `utils`
- `cloud_registration.py` — imports: `modules.base`, `common.errors`, `utils`
- `case_management.py` — imports: `modules.base`, `common.errors`, `utils`
- `cao_hunting.py` — imports: `modules.base`, `common.errors`, `utils`
- `spotlight.py` — imports: `modules.base`, `common.errors`, `utils`
- `response.py` — imports: `modules.base`, `common.errors`, `utils`

- [ ] **Step 3: Handle `modules/response_store.py` alias**

This file is an alias/re-export that points to the root `response_store.py`. Check its content — if it's just `from response_store import ResponseStore`, update to `from crowdstrike_mcp.response_store import ResponseStore`. If any module imports from `modules.response_store`, update those too.

- [ ] **Step 4: Commit**

```bash
git commit -am "refactor: update imports in all module files"
```

---

### Task 5: Update imports in common/

**Files:**
- Modify: `src/crowdstrike_mcp/common/errors.py`
- Modify: `src/crowdstrike_mcp/common/session_auth.py`
- Modify: `src/crowdstrike_mcp/common/health.py`
- Modify: `src/crowdstrike_mcp/common/auth_middleware.py`
- Modify: `src/crowdstrike_mcp/common/api_scopes.py`

- [ ] **Step 1: Update `common/session_auth.py`**

```python
# Before:
from client import FalconClient
from modules.base import _session_client

# After:
from crowdstrike_mcp.client import FalconClient
from crowdstrike_mcp.modules.base import _session_client
```

- [ ] **Step 2: Update `common/errors.py`**

```python
# Before (if it imports api_scopes):
from common.api_scopes import get_required_scopes

# After:
from crowdstrike_mcp.common.api_scopes import get_required_scopes
```

Check actual imports — `errors.py` may only use stdlib. Update any internal references found.

- [ ] **Step 3: Check remaining common/ files**

`health.py`, `auth_middleware.py`, `api_scopes.py` — check if they import from other internal modules. Update any `from client import`, `from common.`, `from modules.`, or `from utils import` patterns.

- [ ] **Step 4: Commit**

```bash
git commit -am "refactor: update imports in common/ files"
```

---

### Task 6: Update tests

**Files:**
- Modify: `tests/conftest.py`
- Modify: All test files in `tests/`

- [ ] **Step 1: Update `tests/conftest.py`**

Remove the `sys.path.insert` line:
```python
# Remove this line:
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
```

Update fixture imports:
```python
# Before:
from response_store import ResponseStore

# After:
from crowdstrike_mcp.response_store import ResponseStore
```

- [ ] **Step 2: Update test imports and mock targets**

Each test file needs two types of changes:

**Import updates:**
```python
# Before:
from server import FalconMCPServer
from client import FalconClient

# After:
from crowdstrike_mcp.server import FalconMCPServer
from crowdstrike_mcp.client import FalconClient
```

**Mock target updates** (critical — mocks must reference the new paths):
```python
# Before:
_FALCONPY_PATCHES = [
    "modules.alerts.Alerts",
    "modules.ngsiem.NGSIEM",
    "modules.hosts.Hosts",
]

# After:
_FALCONPY_PATCHES = [
    "crowdstrike_mcp.modules.alerts.Alerts",
    "crowdstrike_mcp.modules.ngsiem.NGSIEM",
    "crowdstrike_mcp.modules.hosts.Hosts",
]
```

Apply to all test files:
- `test_smoke_tools_list.py` — imports + FalconPy patches
- `test_tool_permissions.py` — imports + patches
- `test_alerts_endpoint_enrichment.py`
- `test_cao_hunting.py`
- `test_case_management_new_tools.py`
- `test_correlation_import.py`
- `test_correlation_templates.py`
- `test_endpoint_removed.py`
- `test_response_module.py`
- `test_spotlight.py`

- [ ] **Step 3: Run tests**

```bash
pip install -e .[dev]
pytest tests/ -v --tb=short
```

Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git commit -am "refactor: update test imports for package structure"
```

---

### Task 7: Update CI, Dockerfile, and ruff config

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `Dockerfile`
- Modify: `ruff.toml`
- Delete: `pytest.ini` (moved to pyproject.toml)

- [ ] **Step 1: Update `.github/workflows/ci.yml`**

Replace dependency installation:
```yaml
# Before:
- name: Install dependencies
  run: pip install -r requirements.txt pytest

# After:
- name: Install dependencies
  run: pip install -e .[dev]
```

Update ruff source path if it references specific directories:
```yaml
# Before:
- run: ruff check .

# After (if needed to scope to source):
- run: ruff check src/ tests/
```

- [ ] **Step 2: Update `.github/workflows/release.yml`**

Same dependency change. Also update any version-checking logic that references `client.py` — it's now at `src/crowdstrike_mcp/client.py`.

Docker build section:
```yaml
# The Dockerfile handles the pip install internally, so just verify
# the COPY context is correct (it copies the whole repo)
```

- [ ] **Step 3: Update `Dockerfile`**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .
RUN useradd -r -s /bin/false mcp
USER mcp
EXPOSE 8000
ENTRYPOINT ["crowdstrike-mcp", "--transport", "streamable-http", "--host", "0.0.0.0"]
```

Key changes:
- `COPY . .` then `pip install .` (replaces COPY requirements.txt + COPY .)
- `ENTRYPOINT` uses `crowdstrike-mcp` CLI (replaces `python server.py`)

- [ ] **Step 4: Delete `pytest.ini`**

Config is now in `pyproject.toml`. Remove standalone file:
```bash
git rm pytest.ini
```

- [ ] **Step 5: Update `ruff.toml`**

Add src directory configuration:
```toml
[lint]
select = ["E", "F", "I"]

[lint.isort]
known-first-party = ["crowdstrike_mcp"]
```

- [ ] **Step 6: Run CI checks locally**

```bash
ruff check src/ tests/
ruff format --check src/ tests/
pytest tests/ -v --tb=short
```

Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git commit -am "chore: update CI, Dockerfile, and tooling for package structure"
```

---

### Task 8: Sync `__version__` with `SERVER_VERSION`

**Files:**
- Modify: `src/crowdstrike_mcp/client.py`
- Modify: `src/crowdstrike_mcp/__init__.py`

- [ ] **Step 1: Update `client.py` to read version from package**

```python
# Before:
SERVER_VERSION = "3.1.0"

# After:
from crowdstrike_mcp import __version__ as SERVER_VERSION
```

This ensures the version is defined in one place (`__init__.py`) and the release workflow's version check still works via `SERVER_VERSION`.

- [ ] **Step 2: Verify release workflow version check still works**

Read the release workflow's version-check step. If it greps `client.py` for `SERVER_VERSION`, update the grep pattern or path. If it imports the module, it should work automatically.

- [ ] **Step 3: Commit**

```bash
git commit -am "refactor: single version source in __init__.py"
```

---

### Task 9: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update installation instructions**

```markdown
## Quick Start

### Installation

```bash
pip install git+https://github.com/willwebster5/crowdstrike-mcp.git
```

Or for development:
```bash
git clone https://github.com/willwebster5/crowdstrike-mcp.git
cd crowdstrike-mcp
pip install -e .[dev]
```
```

- [ ] **Step 2: Update MCP client configuration examples**

```markdown
### Claude Code

Add to `.mcp.json`:
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
```

Replace any `python server.py` references with `crowdstrike-mcp`.

- [ ] **Step 3: Update file structure diagram**

Replace the root-level file listing with the new `src/crowdstrike_mcp/` package structure.

- [ ] **Step 4: Update Docker usage**

```markdown
### Docker

```bash
docker build -t crowdstrike-mcp .
docker run -p 8000:8000 \
  -e FALCON_CLIENT_ID=... \
  -e FALCON_CLIENT_SECRET=... \
  crowdstrike-mcp
```
```

- [ ] **Step 5: Remove references to `crowdstrike_mcp_server.py`**

Search for any mention of the legacy shim and remove.

- [ ] **Step 6: Commit**

```bash
git commit -am "docs: update README for pip-installable package"
```

---

### Task 10: Final verification

- [ ] **Step 1: Clean install test**

```bash
pip uninstall crowdstrike-mcp -y
pip install -e .[dev]
crowdstrike-mcp --help
```

Expected: Help output showing transport, module, and permission flags.

- [ ] **Step 2: Run full test suite**

```bash
pytest tests/ -v --tb=short
```

Expected: All tests pass.

- [ ] **Step 3: Lint check**

```bash
ruff check src/ tests/
ruff format --check src/ tests/
```

Expected: Clean.

- [ ] **Step 4: Verify no stale imports**

```bash
grep -r "^from client import\|^from registry import\|^from utils import\|^from response_store import\|^from modules\.\|^from common\.\|^from resources\." src/ tests/ --include="*.py" | grep -v crowdstrike_mcp
```

Expected: No output (all bare imports should be gone).

- [ ] **Step 5: Commit any fixes, tag if clean**

If all checks pass, the packaging is complete.
