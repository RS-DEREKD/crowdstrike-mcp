# Remote-Ready MCP Server with Per-Client Authentication

**Date:** 2026-04-09
**Version:** 3.1.0
**Status:** Approved
**Scope:** CrowdStrike MCP Server (`crowdstrike-mcp`)

## Problem

The MCP server currently runs locally via stdio transport with a single set of CrowdStrike API credentials read from `~/.config/falcon/credentials.json`. This prevents:

- Remote access from platforms like Databricks, Cursor, or other MCP clients
- Multi-client usage where each caller has their own Falcon API credentials and scopes
- Credential-less server deployment where the server itself holds no standing permissions

## Solution

Add per-client authentication for HTTP transports (streamable-http, SSE) while preserving the existing stdio mode unchanged. Each connecting client supplies their own CrowdStrike API credentials via HTTP headers. The server performs OAuth on their behalf, caches the session, and isolates auth per-request using Python's `contextvars`.

### Design Principles

1. **stdio is untouched** — local Claude Code usage works exactly as before
2. **Server is credential-less** — in HTTP mode, no Falcon creds on the server
3. **Per-client isolation** — one client's auth never bleeds into another's
4. **Standard MCP patterns** — credentials in client config headers, same as Datadog/GitHub MCP servers

## Architecture

### Auth Flow

```
stdio transport:
  ~/.config/falcon/credentials.json → FalconClient (startup) → shared auth

HTTP transport:
  Client headers (X-Falcon-Client-Id, X-Falcon-Client-Secret, X-Falcon-Base-Url)
    → session_auth_middleware extracts creds
    → hash(creds) → check client cache (25 min TTL)
    → cache miss: create FalconClient, authenticate(), cache on success
    → ContextVar(_session_client) = cached client
    → FastMCP handler → tool function → _get_auth() reads ContextVar
```

### Middleware Stack (HTTP mode)

```
Request
  → health_check_wrapper      (outermost — no auth, intercepts /health)
  → auth_middleware            (API key gate — X-Api-Key header, optional)
  → session_auth_middleware    (Falcon cred extraction, OAuth, ContextVar)
  → FastMCP streamable_http_app  (serves on /mcp)
```

### ContextVar Pattern

```python
from contextvars import ContextVar

_session_client: ContextVar[FalconClient | None] = ContextVar("_session_client", default=None)
```

**Canonical location:** `_session_client` is defined in `modules/base.py` (single source of truth). `common/session_auth.py` imports it: `from modules.base import _session_client`.

Each asyncio task gets its own context copy. No cross-request bleed. No explicit cleanup needed — but a comment explaining this is required in the implementation.

## Components

### 1. `client.py` — FalconClient Changes

**`FalconClient.deferred()` classmethod:**
- Creates a hollow instance with no credentials and no auth
- Used in HTTP mode so modules can construct without crashing
- `auth_object` property raises `RuntimeError` if accessed on a deferred client (safety net)

```python
@classmethod
def deferred(cls) -> "FalconClient":
    """Create a credential-less instance for HTTP mode.
    Modules construct normally but must use _get_auth() at call time.
    """
    instance = cls.__new__(cls)
    instance._client_id = None
    instance._client_secret = None
    instance._base_url = None
    instance._auth = None
    instance._deferred = True
    return instance
```

The normal `__init__` path must also set `self._deferred = False` explicitly, so the guard can use `self._deferred` directly instead of `getattr`. The `getattr` fallback in the property is defensive but the explicit init makes intent clear to readers.

**`auth_object` property must be guarded** — the existing property lazily creates an `OAuth2` session, which would pass `None` credentials on a deferred client and produce confusing FalconPy errors. Add an explicit guard:

```python
@property
def auth_object(self) -> OAuth2:
    """Lazily create and cache a shared OAuth2 session."""
    if getattr(self, '_deferred', False):
        raise RuntimeError(
            "Cannot access auth_object on a deferred FalconClient. "
            "Use BaseModule._get_auth() which resolves from the session ContextVar."
        )
    if self._auth is None:
        self._auth = OAuth2(
            client_id=self._client_id,
            client_secret=self._client_secret,
            base_url=self._base_url,
            user_agent=USER_AGENT,
        )
    return self._auth
```

This ensures that any module accidentally accessing `self.client.auth_object` in HTTP mode gets a clear error pointing to the correct pattern, rather than a cryptic FalconPy failure.

### 2. `modules/base.py` — BaseModule Changes

**New `_get_auth()` method:**
```python
def _get_auth(self) -> OAuth2:
    """Get auth — session-scoped (HTTP) or instance-level (stdio)."""
    session = _session_client.get()
    if session is not None:
        return session.auth_object
    return self.client.auth_object
```

**New `_service(cls)` helper:**
```python
def _service(self, cls):
    """Create a FalconPy service for the current auth context."""
    return cls(auth_object=self._get_auth())
```

FalconPy service construction is lightweight (stores the auth reference, no HTTP call), so per-call creation without caching is acceptable. The expensive OAuth token exchange is cached at the middleware level.

### 3. `common/session_auth.py` — New Middleware

**Responsibilities:**
1. Extract `X-Falcon-Client-Id`, `X-Falcon-Client-Secret`, `X-Falcon-Base-Url` from request headers
2. Return 401 if credentials are missing (with clear error listing required headers)
3. Hash credentials: `sha256(f"{client_id}:{client_secret}:{base_url}")` — delimiter prevents concatenation collisions
4. Check client cache — `dict[str, tuple[FalconClient, float]]` keyed by hash
5. Cache miss: create `FalconClient`, call `authenticate()`, cache only on success
6. Set `_session_client` ContextVar
7. Proceed to inner app

**Client cache:**
- TTL: 25 minutes (inside CrowdStrike's 30-minute token window)
- Lazy eviction on access (no background thread)
- Max 100 entries — LRU eviction on overflow (evict least-recently-accessed, not oldest-inserted)
- Plain dict — safe for single-threaded asyncio; each uvicorn worker gets its own cache (documented)
- Failed auth never cached

**Scope handling:**
- Must handle both `scope["type"] == "http"` and `scope["type"] == "websocket"` (FastMCP's streamable-http may use WebSocket upgrades)
- **Note:** The existing `auth_middleware` (API key gate) only checks `scope["type"] == "http"` and passes WebSocket connections through unauthenticated. This must be fixed in the same change — update `auth_middleware` to also validate `X-Api-Key` on WebSocket connections

**Auth failure responses:**
- Missing headers → 401 `{"error": "Missing required headers: X-Falcon-Client-Id, X-Falcon-Client-Secret"}`
- Bad credentials → 401 `{"error": "CrowdStrike authentication failed: <details>", "required_scopes": [...]}`

### 4. `common/health.py` — Health Check Wrapper

**Outermost ASGI wrapper** — intercepts `/health` before any middleware:

```python
def with_health_check(app, version: str, transport: str):
    async def wrapper(scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/health":
            response = JSONResponse({
                "status": "ok",
                "transport": transport,
                "version": version,
            })
            await response(scope, receive, send)
            return
        await app(scope, receive, send)
    return wrapper
```

Returns 200 with server metadata. No auth required.

### 5. `server.py` — Transport-Aware Startup

**`FalconMCPServer.__init__` changes:**

```python
if transport == "stdio":
    # Current behavior: FalconClient resolves creds via chain
    # (constructor params → env vars → ~/.config/falcon/credentials.json)
    self.client = FalconClient()
    self.client.authenticate()
else:
    # HTTP mode: credential-less startup
    self.client = FalconClient.deferred()
    self._log("HTTP mode: server is credential-less, per-client auth via headers")
```

**`_run_http()` changes — middleware composition:**

```python
def _run_http(self, transport_type: str):
    # FastMCP streamable-http serves at /mcp by default; SSE serves at /sse
    if transport_type == "sse":
        app = self.server.sse_app()
    else:
        app = self.server.streamable_http_app()

    # Layer 1: per-session Falcon auth (innermost)
    app = session_auth_middleware(app)

    # Layer 2: server access gate (optional)
    if self.api_key:
        app = auth_middleware(app, self.api_key)

    # Layer 3: health check (outermost, no auth)
    app = with_health_check(app, version=SERVER_VERSION, transport=transport_type)

    uvicorn.run(app, host=self.host, port=self.port)
```

The same middleware stack applies to both SSE and streamable-http transports. Both get per-session auth, API key gating, and health checks.

### 6. Module Refactor (8 of 9 Modules)

**Pattern — before:**
```python
def __init__(self, client):
    super().__init__(client)
    self.falcon = SomeService(auth_object=self.client.auth_object)

def _some_method(self):
    response = self.falcon.some_api_call(...)
```

**Pattern — after:**
```python
def __init__(self, client):
    super().__init__(client)
    # No FalconPy service creation

def _some_method(self):
    falcon = self._service(SomeService)  # assign once, reuse in method
    response = falcon.some_api_call(...)
```

**Module-by-module:**

| Module | Services to convert | Notes |
|--------|---|---|
| `alerts.py` | `Alerts`, `NGSIEM` | NGSIEM is optional (try/except stays, moves to call site) |
| `ngsiem.py` | `NGSIEM` | Straightforward |
| `hosts.py` | `Hosts` | Straightforward |
| `response.py` | `Hosts` | Straightforward |
| `correlation.py` | `CorrelationRules` or `APIHarnessV2` | `_get_correlation_service()` helper for fallback logic |
| `case_management.py` | `CaseManagement` | Straightforward |
| `cloud_registration.py` | `CSPMRegistration` | Straightforward |
| `cloud_security.py` | `CloudSecurity`, `CloudSecurityDetections`, `CloudSecurityAssets` | 3 optional services, availability checks at call site |
| `response_store.py` | None | No changes |

**`correlation.py` special case:**
```python
def _get_correlation_service(self):
    cls = CorrelationRules if CORRELATION_AVAILABLE else APIHarnessV2
    return self._service(cls)
```

**Multi-call methods:** Assign service to a local variable at method top, reuse throughout:
```python
def _lookup(self, hostname=None, device_id=None):
    hosts = self._service(Hosts)
    # Use hosts for all API calls in this method
    response = hosts.query_devices_by_filter(...)
    details = hosts.get_device_details(...)
```

## Deployment

### Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN useradd -r -s /bin/false mcp
COPY . .
USER mcp
EXPOSE 8000
ENTRYPOINT ["python", "server.py", "--transport", "streamable-http", "--host", "0.0.0.0"]
```

- No credentials baked in
- Non-root user
- Port, API key, allow-writes, modules configurable via env vars
- Requires `.dockerignore` (exclude `.venv/`, `.git/`, `__pycache__/`, `tests/`, `docs/`)

### .dockerignore

```
.venv/
.git/
__pycache__/
*.pyc
tests/
docs/
.github/
.claude/
.ruff_cache/
*.egg-info/
```

### TLS

The server does not terminate TLS. Use a reverse proxy (nginx, caddy, traefik) or cloud load balancer (ALB, Cloud Run, GKE ingress) for HTTPS. **HTTPS is required for production** — credentials transit in headers.

### Client Configuration

**Claude Code (`.mcp.json`) — recommended pattern with env var interpolation:**
```json
{
  "crowdstrike": {
    "type": "streamable-http",
    "url": "https://falcon-mcp.internal:8000/mcp",
    "headers": {
      "X-Api-Key": "${FALCON_MCP_API_KEY}",
      "X-Falcon-Client-Id": "${FALCON_CLIENT_ID}",
      "X-Falcon-Client-Secret": "${FALCON_CLIENT_SECRET}",
      "X-Falcon-Base-Url": "${FALCON_BASE_URL:-US2}"
    }
  }
}
```

Claude Code supports `${VAR}` and `${VAR:-default}` syntax in `.mcp.json` headers.

**Cursor (`mcp.json`):**
```json
{
  "mcpServers": {
    "crowdstrike": {
      "type": "streamable-http",
      "url": "https://falcon-mcp.internal:8000/mcp",
      "headers": {
        "X-Api-Key": "server-access-key",
        "X-Falcon-Client-Id": "...",
        "X-Falcon-Client-Secret": "...",
        "X-Falcon-Base-Url": "US2"
      }
    }
  }
}
```

**Databricks (external MCP connection):**
- Create Unity Catalog HTTP connection with "Is MCP connection" enabled
- URL: `https://falcon-mcp.internal:8000/mcp`
- Auth: Custom headers via connection configuration

### stdio Mode (Unchanged)

```json
{
  "crowdstrike": {
    "command": "python",
    "args": ["/path/to/crowdstrike-mcp/server.py"],
    "env": {
      "FALCON_CLIENT_ID": "...",
      "FALCON_CLIENT_SECRET": "...",
      "FALCON_BASE_URL": "US2"
    }
  }
}
```

Or with `~/.config/falcon/credentials.json` (current behavior, no config changes needed).

## Security Model

| Layer | Control | Purpose |
|-------|---------|---------|
| TLS | HTTPS via reverse proxy/LB | Encrypt credentials in transit |
| API key gate | `X-Api-Key` header (optional) | Restrict who can connect to the server |
| Per-client Falcon auth | `X-Falcon-Client-Id` + `X-Falcon-Client-Secret` | Each client authenticates with their own scopes |
| CrowdStrike API scopes | Falcon API client permissions | Limit what each client can do (server doesn't escalate) |
| Read-only default | `--allow-writes` flag | Write tools require explicit opt-in |
| Containment exclusions | Tag/hostname/device-id exclusion lists | Safety net for critical infrastructure |

## Not In Scope (v3.1.0)

- **Rate limiting / concurrency limits** — CrowdStrike has API rate limits. In HTTP mode with N concurrent clients, each makes independent API calls. Acknowledged as a future concern; not solved here.
- **Kubernetes / ECS manifests** — Deployment-specific, not part of the server repo.
- **CI/CD changes** — Existing CI tests stdio mode, still works. HTTP mode testing is a follow-up.
- **DNS / networking setup** — Infrastructure-specific.
- **Bearer token auth** — Future enhancement where clients pre-authenticate and pass a short-lived token instead of raw credentials. Would reduce credential exposure on the wire.

## Backward Compatibility

- **stdio mode:** Zero changes. Reads local creds, authenticates at startup, single shared client.
- **Tool signatures:** Unchanged. No tool additions or removals.
- **MCP resources:** Unchanged.
- **Response format:** Unchanged.
- **Configuration:** All new env vars are optional; existing ones work as before.

## Version

3.0.0 → 3.1.0 (new feature, fully backward compatible)

## Files Changed

| File | Change Type | Description |
|------|-------------|-------------|
| `client.py` | Modified | Add `FalconClient.deferred()` classmethod, guard `auth_object` property, bump `SERVER_VERSION` to 3.1.0 |
| `modules/base.py` | Modified | Add `_get_auth()`, `_service()`, import ContextVar |
| `modules/alerts.py` | Modified | Remove `__init__` service creation, use `_service()` |
| `modules/ngsiem.py` | Modified | Same pattern |
| `modules/hosts.py` | Modified | Same pattern |
| `modules/response.py` | Modified | Same pattern |
| `modules/correlation.py` | Modified | Same pattern + `_get_correlation_service()` |
| `modules/case_management.py` | Modified | Same pattern |
| `modules/cloud_registration.py` | Modified | Same pattern |
| `modules/cloud_security.py` | Modified | Same pattern (3 services) |
| `server.py` | Modified | Transport-aware startup, middleware composition |
| `common/auth_middleware.py` | Modified | Add WebSocket scope handling to API key gate |
| `common/session_auth.py` | New | Per-session Falcon auth middleware + client cache |
| `common/health.py` | New | Health check ASGI wrapper |
| `Dockerfile` | New | Container packaging |
| `.dockerignore` | New | Build context exclusions |
| `modules/response_store.py` | No change | No FalconPy services — unaffected |
| `README.md` | Modified | Add remote deployment section |
