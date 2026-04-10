# Remote-Ready MCP Server Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-client authentication for HTTP transports so the MCP server can run remotely and credential-less, while preserving existing stdio mode unchanged.

**Architecture:** ContextVar-based per-session FalconClient, middleware stack for HTTP auth, lazy FalconPy service creation in modules. Clients supply Falcon API credentials via HTTP headers; the server performs OAuth on their behalf and caches sessions.

**Tech Stack:** Python 3.12, FastMCP (mcp SDK), FalconPy, uvicorn, starlette, contextvars

**Spec:** `docs/superpowers/specs/2026-04-09-remote-mcp-server-design.md`

---

## Chunk 1: Foundation (client.py + base.py + infrastructure tests)

### Task 1: FalconClient.deferred() and auth_object guard

**Files:**
- Modify: `client.py:32-103`
- Test: `tests/test_client_deferred.py`

- [ ] **Step 1: Write failing tests for deferred client**

```python
# tests/test_client_deferred.py
"""Tests for FalconClient.deferred() and auth_object guard."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client import FalconClient


class TestFalconClientDeferred:
    """Verify deferred client behavior for HTTP mode."""

    def test_deferred_creates_instance_without_credentials(self):
        """deferred() should create a FalconClient with no creds."""
        client = FalconClient.deferred()
        assert client._client_id is None
        assert client._client_secret is None
        assert client._base_url is None
        assert client._deferred is True

    def test_deferred_auth_object_raises_runtime_error(self):
        """Accessing auth_object on a deferred client must raise RuntimeError."""
        client = FalconClient.deferred()
        with pytest.raises(RuntimeError, match="deferred FalconClient"):
            _ = client.auth_object

    def test_normal_client_has_deferred_false(self):
        """Normal FalconClient.__init__ sets _deferred = False."""
        client = FalconClient(
            client_id="test_id",
            client_secret="test_secret",
            base_url="US1",
        )
        assert client._deferred is False

    def test_deferred_does_not_call_init(self):
        """deferred() uses __new__, so _resolve_credentials is never called."""
        # This should not raise ValueError about missing credentials
        client = FalconClient.deferred()
        assert client._auth is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_client_deferred.py -v`
Expected: FAIL — `FalconClient` has no `deferred()` method, no `_deferred` attribute

- [ ] **Step 3: Implement FalconClient.deferred() and guards**

In `client.py`:

1. Add `self._deferred = False` to `__init__` (after line 46, after `self._auth` assignment):
```python
self._deferred = False
```

2. Add the `deferred()` classmethod after `__init__` (before the `auth_object` property):
```python
@classmethod
def deferred(cls) -> "FalconClient":
    """Create a credential-less instance for HTTP mode.

    Modules construct normally but must use BaseModule._get_auth()
    at call time instead of self.client.auth_object.
    """
    instance = cls.__new__(cls)
    instance._client_id = None
    instance._client_secret = None
    instance._base_url = None
    instance._auth = None
    instance._deferred = True
    return instance
```

3. Add guard to `auth_object` property (replace lines 52-62):
```python
@property
def auth_object(self) -> OAuth2:
    """Lazily create and cache a shared OAuth2 session."""
    if self._deferred:
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_client_deferred.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Run existing tests to verify no regressions**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All existing tests PASS

- [ ] **Step 6: Commit**

```bash
git add client.py tests/test_client_deferred.py
git commit -m "feat: add FalconClient.deferred() for credential-less HTTP mode"
```

---

### Task 2: BaseModule ContextVar, _get_auth(), and _service()

**Files:**
- Modify: `modules/base.py:1-88`
- Test: `tests/test_base_module_auth.py`

- [ ] **Step 1: Write failing tests for _get_auth() and _service()**

```python
# tests/test_base_module_auth.py
"""Tests for BaseModule._get_auth() and _service() — ContextVar auth resolution."""

import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.base import BaseModule, _session_client


class ConcreteModule(BaseModule):
    """Minimal concrete subclass for testing."""

    def register_tools(self, server):
        pass


class TestGetAuth:
    """Verify _get_auth() resolves session vs instance auth."""

    def test_returns_instance_auth_when_no_session(self):
        """Without a ContextVar session, falls back to self.client.auth_object."""
        client = MagicMock()
        module = ConcreteModule(client)
        result = module._get_auth()
        assert result is client.auth_object

    def test_returns_session_auth_when_session_set(self):
        """With a ContextVar session, returns the session's auth_object."""
        instance_client = MagicMock()
        session_client = MagicMock()

        module = ConcreteModule(instance_client)

        token = _session_client.set(session_client)
        try:
            result = module._get_auth()
            assert result is session_client.auth_object
            assert result is not instance_client.auth_object
        finally:
            _session_client.reset(token)

    def test_session_cleared_falls_back_to_instance(self):
        """After resetting the ContextVar, falls back to instance auth."""
        instance_client = MagicMock()
        session_client = MagicMock()

        module = ConcreteModule(instance_client)

        token = _session_client.set(session_client)
        _session_client.reset(token)

        result = module._get_auth()
        assert result is instance_client.auth_object


class TestService:
    """Verify _service() creates FalconPy service classes with correct auth."""

    def test_creates_service_with_current_auth(self):
        """_service(cls) should call cls(auth_object=<current auth>)."""
        client = MagicMock()
        module = ConcreteModule(client)

        MockService = MagicMock()
        result = module._service(MockService)

        MockService.assert_called_once_with(auth_object=client.auth_object)
        assert result is MockService.return_value

    def test_creates_service_with_session_auth(self):
        """When session is set, _service() uses session auth."""
        instance_client = MagicMock()
        session_client = MagicMock()

        module = ConcreteModule(instance_client)

        token = _session_client.set(session_client)
        try:
            MockService = MagicMock()
            module._service(MockService)
            MockService.assert_called_once_with(auth_object=session_client.auth_object)
        finally:
            _session_client.reset(token)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_base_module_auth.py -v`
Expected: FAIL — `_session_client` not importable, `_get_auth` / `_service` not defined

- [ ] **Step 3: Implement ContextVar, _get_auth(), _service() in base.py**

In `modules/base.py`:

1. Add imports at the top (after `from __future__ import annotations`):
```python
from contextvars import ContextVar
```

2. Add ContextVar before the class definition (after `_VALID_TIERS`):
```python
# Per-session FalconClient for HTTP transports. Set by session_auth_middleware.
# Each asyncio task gets its own context copy, so concurrent requests are isolated.
# Canonical location — common/session_auth.py imports this.
_session_client: ContextVar["FalconClient | None"] = ContextVar("_session_client", default=None)
```

3. Add `_get_auth()` and `_service()` methods to `BaseModule` (after `register_resources`, before `_add_tool`):
```python
def _get_auth(self):
    """Get auth object — session-scoped (HTTP) or instance-level (stdio).

    In HTTP mode, session_auth_middleware sets _session_client ContextVar
    per-request. In stdio mode, the ContextVar is unset and we fall back
    to the instance-level client passed at construction.
    """
    session = _session_client.get()
    if session is not None:
        return session.auth_object
    return self.client.auth_object

def _service(self, cls):
    """Create a FalconPy service class bound to the current auth context.

    FalconPy service construction is lightweight (stores auth reference,
    no HTTP call). The expensive OAuth token exchange is cached by the
    FalconClient's OAuth2 instance.
    """
    return cls(auth_object=self._get_auth())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_base_module_auth.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Run all tests to verify no regressions**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add modules/base.py tests/test_base_module_auth.py
git commit -m "feat: add ContextVar auth resolution to BaseModule"
```

---

### Task 2.5: Add pytest-asyncio dependency

Tasks 3-5 use `@pytest.mark.asyncio` for async test methods. The existing test suite has no async tests, so `pytest-asyncio` must be installed and configured.

**Files:**
- Modify: `requirements-dev.txt`
- Modify: `pytest.ini`

- [ ] **Step 1: Add pytest-asyncio to dev dependencies**

Add to `requirements-dev.txt`:
```
pytest-asyncio>=0.23.0
```

- [ ] **Step 2: Configure asyncio mode in pytest.ini**

Add `asyncio_mode = auto` to `pytest.ini`:
```ini
[pytest]
testpaths = tests
pythonpath = .
asyncio_mode = auto
```

- [ ] **Step 3: Install and verify**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && pip install pytest-asyncio>=0.23.0`
Expected: Successfully installed

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All existing tests PASS

- [ ] **Step 4: Commit**

```bash
git add requirements-dev.txt pytest.ini
git commit -m "chore: add pytest-asyncio for async test support"
```

---

### Task 3: Health check ASGI wrapper

**Files:**
- Create: `common/health.py`
- Test: `tests/test_health_check.py`

- [ ] **Step 1: Write failing test for health check**

```python
# tests/test_health_check.py
"""Tests for the /health endpoint ASGI wrapper."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.health import with_health_check


class MockASGIApp:
    """Tracks whether the inner app was called."""

    def __init__(self):
        self.called = False

    async def __call__(self, scope, receive, send):
        self.called = True


async def _capture_response(app, path="/health", scope_type="http"):
    """Helper to invoke an ASGI app and capture the response status + body."""
    scope = {"type": scope_type, "path": path, "method": "GET"}
    status_code = None
    body_parts = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        nonlocal status_code
        if message["type"] == "http.response.start":
            status_code = message["status"]
        elif message["type"] == "http.response.body":
            body_parts.append(message.get("body", b""))

    await app(scope, receive, send)
    body = json.loads(b"".join(body_parts))
    return status_code, body


@pytest.mark.asyncio
class TestHealthCheck:

    async def test_health_returns_200_with_metadata(self):
        """GET /health returns 200 with status, transport, version."""
        inner = MockASGIApp()
        app = with_health_check(inner, version="3.1.0", transport="streamable-http")

        status, body = await _capture_response(app, path="/health")

        assert status == 200
        assert body["status"] == "ok"
        assert body["version"] == "3.1.0"
        assert body["transport"] == "streamable-http"
        assert inner.called is False  # inner app should NOT be reached

    async def test_non_health_path_passes_through(self):
        """Non-/health requests pass through to inner app."""
        inner = MockASGIApp()
        app = with_health_check(inner, version="3.1.0", transport="streamable-http")

        scope = {"type": "http", "path": "/mcp", "method": "POST"}
        await app(scope, lambda: None, lambda msg: None)

        assert inner.called is True

    async def test_websocket_passes_through(self):
        """WebSocket connections pass through (health is HTTP only)."""
        inner = MockASGIApp()
        app = with_health_check(inner, version="3.1.0", transport="streamable-http")

        scope = {"type": "websocket", "path": "/health"}
        await app(scope, lambda: None, lambda msg: None)

        assert inner.called is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_health_check.py -v`
Expected: FAIL — `common.health` module does not exist

- [ ] **Step 3: Implement health check wrapper**

```python
# common/health.py
"""ASGI wrapper that intercepts /health before the middleware stack.

Sits outermost in the middleware chain so health checks bypass auth.
"""

from starlette.responses import JSONResponse


def with_health_check(app, version: str, transport: str):
    """Wrap an ASGI app with a /health endpoint.

    Args:
        app: The ASGI application to wrap.
        version: Server version string for the response body.
        transport: Transport type (e.g. "streamable-http", "sse").

    Returns:
        A new ASGI app that intercepts GET /health.
    """

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

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_health_check.py -v`
Expected: All 3 tests PASS (requires pytest-asyncio from Task 2.5)

- [ ] **Step 5: Commit**

```bash
git add common/health.py tests/test_health_check.py
git commit -m "feat: add /health endpoint ASGI wrapper"
```

---

### Task 4: Session auth middleware with client cache

**Files:**
- Create: `common/session_auth.py`
- Test: `tests/test_session_auth.py`

- [ ] **Step 1: Write failing tests for session auth middleware**

```python
# tests/test_session_auth.py
"""Tests for per-session Falcon auth middleware and client cache."""

import hashlib
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.session_auth import (
    SESSION_CACHE_MAX_SIZE,
    SESSION_CACHE_TTL,
    _client_cache,
    session_auth_middleware,
)
from modules.base import _session_client


async def _make_request(app, headers=None, scope_type="http", path="/mcp"):
    """Helper to send a request through the middleware and capture response."""
    if headers is None:
        headers = []
    else:
        headers = [(k.lower().encode(), v.encode()) for k, v in headers.items()]

    scope = {"type": scope_type, "path": path, "headers": headers}
    status_code = None
    body_parts = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        nonlocal status_code
        if message["type"] == "http.response.start":
            status_code = message["status"]
        elif message["type"] == "http.response.body":
            body_parts.append(message.get("body", b""))

    await app(scope, receive, send)

    body = None
    if body_parts:
        try:
            body = json.loads(b"".join(body_parts))
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = b"".join(body_parts)

    return status_code, body


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the client cache between tests."""
    _client_cache.clear()
    yield
    _client_cache.clear()


class TestMissingCredentials:

    @pytest.mark.asyncio
    async def test_missing_all_headers_returns_401(self):
        """Request with no Falcon headers returns 401."""
        inner = MagicMock()
        app = session_auth_middleware(inner)

        status, body = await _make_request(app, headers={})
        assert status == 401
        assert "Missing required" in body["error"]

    @pytest.mark.asyncio
    async def test_missing_secret_returns_401(self):
        """Request with only client_id returns 401."""
        inner = MagicMock()
        app = session_auth_middleware(inner)

        status, body = await _make_request(app, headers={
            "X-Falcon-Client-Id": "test_id",
        })
        assert status == 401


class TestSuccessfulAuth:

    @pytest.mark.asyncio
    async def test_valid_credentials_pass_through(self):
        """Valid credentials create a FalconClient, set ContextVar, call inner app."""
        inner_called = False

        async def inner_app(scope, receive, send):
            nonlocal inner_called
            inner_called = True
            # Verify the ContextVar is set during the inner app call
            session = _session_client.get()
            assert session is not None

        app = session_auth_middleware(inner_app)

        with patch("common.session_auth.FalconClient") as MockClient:
            mock_instance = MagicMock()
            MockClient.return_value = mock_instance

            await _make_request(app, headers={
                "X-Falcon-Client-Id": "test_id",
                "X-Falcon-Client-Secret": "test_secret",
                "X-Falcon-Base-Url": "US2",
            })

        assert inner_called is True

    @pytest.mark.asyncio
    async def test_credentials_cached_on_second_request(self):
        """Second request with same creds reuses cached FalconClient."""
        async def inner_app(scope, receive, send):
            pass

        app = session_auth_middleware(inner_app)
        headers = {
            "X-Falcon-Client-Id": "test_id",
            "X-Falcon-Client-Secret": "test_secret",
            "X-Falcon-Base-Url": "US2",
        }

        with patch("common.session_auth.FalconClient") as MockClient:
            mock_instance = MagicMock()
            MockClient.return_value = mock_instance

            await _make_request(app, headers=headers)
            await _make_request(app, headers=headers)

            # FalconClient should only be created once (cached on second call)
            assert MockClient.call_count == 1


class TestAuthFailure:

    @pytest.mark.asyncio
    async def test_bad_credentials_return_401(self):
        """FalconClient.authenticate() failure returns 401."""
        async def inner_app(scope, receive, send):
            pass

        app = session_auth_middleware(inner_app)

        with patch("common.session_auth.FalconClient") as MockClient:
            mock_instance = MagicMock()
            mock_instance.authenticate.side_effect = RuntimeError("Auth failed: bad creds")
            MockClient.return_value = mock_instance

            status, body = await _make_request(app, headers={
                "X-Falcon-Client-Id": "bad_id",
                "X-Falcon-Client-Secret": "bad_secret",
            })

        assert status == 401
        assert "Auth failed" in body["error"]

    @pytest.mark.asyncio
    async def test_failed_auth_not_cached(self):
        """Failed auth attempts should NOT be cached."""
        async def inner_app(scope, receive, send):
            pass

        app = session_auth_middleware(inner_app)
        headers = {
            "X-Falcon-Client-Id": "bad_id",
            "X-Falcon-Client-Secret": "bad_secret",
        }

        with patch("common.session_auth.FalconClient") as MockClient:
            mock_instance = MagicMock()
            mock_instance.authenticate.side_effect = RuntimeError("Auth failed")
            MockClient.return_value = mock_instance

            await _make_request(app, headers=headers)
            await _make_request(app, headers=headers)

            # Should attempt auth each time (not cached)
            assert MockClient.call_count == 2


class TestCacheTTL:

    @pytest.mark.asyncio
    async def test_expired_cache_entry_triggers_reauth(self):
        """Expired cache entries should be evicted and re-authenticated."""
        async def inner_app(scope, receive, send):
            pass

        app = session_auth_middleware(inner_app)
        headers = {
            "X-Falcon-Client-Id": "test_id",
            "X-Falcon-Client-Secret": "test_secret",
        }

        with patch("common.session_auth.FalconClient") as MockClient:
            mock_instance = MagicMock()
            MockClient.return_value = mock_instance

            await _make_request(app, headers=headers)
            assert MockClient.call_count == 1

            # Manually expire the cache entry (3-tuple: client, expiry, last_access)
            for key in _client_cache:
                _client_cache[key] = (_client_cache[key][0], time.time() - 1, _client_cache[key][2])

            await _make_request(app, headers=headers)
            assert MockClient.call_count == 2


class TestWebSocketScope:

    @pytest.mark.asyncio
    async def test_websocket_also_requires_auth(self):
        """WebSocket connections must also provide Falcon credentials."""
        inner = MagicMock()
        app = session_auth_middleware(inner)

        # WebSocket with no headers — should get a close frame or 401-equivalent
        # Note: for websocket scope, middleware should reject by closing the connection
        # We test by verifying the inner app is NOT called
        scope = {"type": "websocket", "path": "/mcp", "headers": []}
        called = False

        async def inner_ws(s, r, snd):
            nonlocal called
            called = True

        app_ws = session_auth_middleware(inner_ws)
        # For websocket, the middleware should send a close or not call inner
        # Implementation detail: we accept either behavior as long as inner is not called
        try:
            await app_ws(scope, lambda: {"type": "websocket.connect"}, lambda msg: None)
        except Exception:
            pass  # Some implementations may raise

        # The inner app should not have been called without credentials
        assert called is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_session_auth.py -v`
Expected: FAIL — `common.session_auth` does not exist

- [ ] **Step 3: Implement session auth middleware**

```python
# common/session_auth.py
"""Per-session Falcon auth middleware for HTTP transports.

Extracts CrowdStrike API credentials from request headers, creates
a FalconClient per unique credential set (cached with TTL), and sets
the _session_client ContextVar so tool functions resolve per-session auth.
"""

import hashlib
import time

from starlette.requests import Request
from starlette.responses import JSONResponse

from client import FalconClient
from modules.base import _session_client

# Cache config
SESSION_CACHE_TTL = 25 * 60  # 25 minutes (inside CrowdStrike's 30-min token window)
SESSION_CACHE_MAX_SIZE = 100

# Cache: hash -> (FalconClient, expiry_timestamp, last_access_time)
_client_cache: dict[str, tuple[FalconClient, float, float]] = {}

# Required headers
_REQUIRED_HEADERS = ("x-falcon-client-id", "x-falcon-client-secret")


def _cache_key(client_id: str, client_secret: str, base_url: str) -> str:
    """Generate a cache key from credentials. Delimiter prevents collisions."""
    raw = f"{client_id}:{client_secret}:{base_url}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _evict_lru():
    """Evict the least-recently-accessed entry if cache exceeds max size."""
    if len(_client_cache) >= SESSION_CACHE_MAX_SIZE:
        lru_key = min(_client_cache, key=lambda k: _client_cache[k][2])
        del _client_cache[lru_key]


def session_auth_middleware(app):
    """Wrap an ASGI app with per-session Falcon credential authentication.

    Extracts X-Falcon-Client-Id, X-Falcon-Client-Secret, and optionally
    X-Falcon-Base-Url from request headers. Creates and caches a
    FalconClient per unique credential set.

    Args:
        app: The ASGI application to protect.

    Returns:
        A new ASGI app that authenticates before delegating.
    """

    async def middleware(scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await app(scope, receive, send)
            return

        # Extract headers
        headers = dict(scope.get("headers", []))
        client_id = headers.get(b"x-falcon-client-id", b"").decode()
        client_secret = headers.get(b"x-falcon-client-secret", b"").decode()
        base_url = headers.get(b"x-falcon-base-url", b"").decode() or "US1"

        # Check required headers
        if not client_id or not client_secret:
            if scope["type"] == "http":
                response = JSONResponse(
                    {"error": "Missing required headers: X-Falcon-Client-Id, X-Falcon-Client-Secret"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return
            else:
                # WebSocket: send close frame
                await send({"type": "websocket.close", "code": 4001, "reason": "Missing Falcon credentials"})
                return

        # Check cache
        key = _cache_key(client_id, client_secret, base_url)
        now = time.time()

        cached = _client_cache.get(key)
        if cached is not None:
            client, expiry, _ = cached
            if now < expiry:
                # Update last access time for LRU
                _client_cache[key] = (client, expiry, now)
                token = _session_client.set(client)
                try:
                    await app(scope, receive, send)
                finally:
                    _session_client.reset(token)
                return
            else:
                # Expired
                del _client_cache[key]

        # Cache miss — create and authenticate
        try:
            client = FalconClient(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
            )
            client.authenticate()
        except (ValueError, RuntimeError) as e:
            if scope["type"] == "http":
                response = JSONResponse(
                    {"error": f"CrowdStrike authentication failed: {e}"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return
            else:
                await send({"type": "websocket.close", "code": 4002, "reason": str(e)})
                return

        # Cache on success, evict LRU if needed
        _evict_lru()
        _client_cache[key] = (client, now + SESSION_CACHE_TTL, now)

        token = _session_client.set(client)
        try:
            await app(scope, receive, send)
        finally:
            _session_client.reset(token)

    return middleware
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_session_auth.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add common/session_auth.py tests/test_session_auth.py
git commit -m "feat: add per-session Falcon auth middleware with client cache"
```

---

### Task 5: Fix auth_middleware WebSocket scope gap

**Files:**
- Modify: `common/auth_middleware.py:14-39`
- Test: `tests/test_auth_middleware_ws.py`

- [ ] **Step 1: Write failing test for WebSocket auth**

```python
# tests/test_auth_middleware_ws.py
"""Tests for auth_middleware WebSocket scope handling."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.auth_middleware import auth_middleware


@pytest.mark.asyncio
class TestAuthMiddlewareWebSocket:

    async def test_websocket_without_api_key_is_rejected(self):
        """WebSocket connections without valid API key should be rejected."""
        inner_called = False

        async def inner_app(scope, receive, send):
            nonlocal inner_called
            inner_called = True

        app = auth_middleware(inner_app, "valid-key")

        scope = {"type": "websocket", "path": "/mcp", "headers": []}
        close_sent = False

        async def send(message):
            nonlocal close_sent
            if message.get("type") == "websocket.close":
                close_sent = True

        try:
            await app(scope, lambda: {"type": "websocket.connect"}, send)
        except Exception:
            pass

        assert inner_called is False

    async def test_websocket_with_valid_api_key_passes_through(self):
        """WebSocket connections with valid API key should pass through."""
        inner_called = False

        async def inner_app(scope, receive, send):
            nonlocal inner_called
            inner_called = True

        app = auth_middleware(inner_app, "valid-key")

        scope = {
            "type": "websocket",
            "path": "/mcp",
            "headers": [(b"x-api-key", b"valid-key")],
        }

        await app(scope, lambda: {"type": "websocket.connect"}, lambda msg: None)
        assert inner_called is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_auth_middleware_ws.py -v`
Expected: FAIL — WebSocket connections currently bypass auth

- [ ] **Step 3: Update auth_middleware to handle WebSocket scope**

Replace the `auth_middleware` function in `common/auth_middleware.py`:

```python
def auth_middleware(app, api_key: str):
    """Wrap an ASGI app with API key header validation.

    Validates the ``x-api-key`` header on both HTTP and WebSocket
    connections using constant-time comparison.

    Args:
        app: The ASGI application to protect.
        api_key: Expected value of the ``x-api-key`` header.

    Returns:
        A new ASGI app that checks the header before delegating.
    """

    async def middleware(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = dict(scope.get("headers", []))
            provided = headers.get(b"x-api-key", b"").decode()

            if not secrets.compare_digest(provided, api_key):
                if scope["type"] == "http":
                    response = JSONResponse(
                        {"error": "Invalid or missing API key"},
                        status_code=401,
                    )
                    await response(scope, receive, send)
                    return
                else:
                    # WebSocket: reject with close frame
                    await send({"type": "websocket.close", "code": 4003, "reason": "Invalid or missing API key"})
                    return

        await app(scope, receive, send)

    return middleware
```

Note: The existing code uses `Request(scope, receive)` to extract headers. The new version reads headers directly from scope (like `session_auth_middleware`) for consistency and to support WebSocket scope which doesn't work with `Request`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_auth_middleware_ws.py -v`
Expected: All tests PASS

- [ ] **Step 5: Run all tests to verify no regressions**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add common/auth_middleware.py tests/test_auth_middleware_ws.py
git commit -m "fix: add WebSocket scope handling to API key middleware"
```

---

## Chunk 2: Module Refactor (8 modules — lazy service creation)

All 8 modules follow the same mechanical pattern. Remove FalconPy service creation from `__init__`, use `self._service(ClassName)` in internal methods.

### Task 6: Refactor ngsiem.py (simplest module — validate pattern)

**Files:**
- Modify: `modules/ngsiem.py:24-31`
- Test: existing `tests/test_ngsiem_fields.py` + smoke test

- [ ] **Step 1: Refactor ngsiem.py**

In `modules/ngsiem.py`:

Remove from `__init__` (line 29):
```python
self.falcon = NGSIEM(auth_object=self.client.auth_object)
```

In `_execute_query` (line 119), replace `self.falcon` with a local variable at the method top:
```python
def _execute_query(self, query, start_time="1d", max_results=100, fields=None):
    falcon = self._service(NGSIEM)
    # ... rest of method uses falcon instead of self.falcon
```

There are 4 references to `self.falcon` in `_execute_query` (lines 148, 194, 242, 247). Replace each with `falcon`.

- [ ] **Step 2: Run smoke test to verify tools still register**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_smoke_tools_list.py -v`
Expected: All tests PASS

- [ ] **Step 3: Run all tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add modules/ngsiem.py
git commit -m "refactor: lazy service creation in NGSIEMModule"
```

---

### Task 7: Refactor hosts.py

**Files:**
- Modify: `modules/hosts.py:30-38`

- [ ] **Step 1: Refactor hosts.py**

Remove from `__init__` (line 37):
```python
self.hosts = Hosts(auth_object=self.client.auth_object)
```

In `_lookup` (line 180): add `hosts = self._service(Hosts)` at the top, replace `self.hosts` → `hosts` (lines 190, 197).

In `_get_login_history` (line 238): add `hosts = self._service(Hosts)` at the top, replace `self.hosts` → `hosts` (line 240).

In `_get_network_history` (line 248): add `hosts = self._service(Hosts)` at the top, replace `self.hosts` → `hosts` (line 250).

- [ ] **Step 2: Run smoke + all tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add modules/hosts.py
git commit -m "refactor: lazy service creation in HostsModule"
```

---

### Task 8: Refactor response.py

**Files:**
- Modify: `modules/response.py:50-64`

- [ ] **Step 1: Refactor response.py**

Remove from `__init__` (line 57):
```python
self.hosts = Hosts(auth_object=self.client.auth_object)
```

In `_get_device` (line 167): add `hosts = self._service(Hosts)` at top, replace `self.hosts` → `hosts` (line 170).

In `_execute_containment` (line 262): add `hosts = self._service(Hosts)` at top, replace `self.hosts` → `hosts` (line 268).

- [ ] **Step 2: Run tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add modules/response.py
git commit -m "refactor: lazy service creation in ResponseModule"
```

---

### Task 9: Refactor case_management.py

**Files:**
- Modify: `modules/case_management.py:33-39`

- [ ] **Step 1: Refactor case_management.py**

Remove from `__init__` (line 38):
```python
self.falcon = CaseManagement(auth_object=self.client.auth_object)
```

Add `falcon = self._service(CaseManagement)` at the top of each internal method that uses `self.falcon`, and replace `self.falcon` → `falcon`:
- `_query_cases` (line 436)
- `_get_cases` (line 513)
- `_create_case` (line 535)
- `_update_case` (line 580)
- `_add_alert_evidence` (line 633)
- `_add_event_evidence` (line 655)
- `_add_tags` (line 677)
- `_delete_tags` (line 696)
- `_upload_file` (line 715)
- `_get_fields` (line 740)

- [ ] **Step 2: Run tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add modules/case_management.py
git commit -m "refactor: lazy service creation in CaseManagementModule"
```

---

### Task 10: Refactor cloud_registration.py

**Files:**
- Modify: `modules/cloud_registration.py:28-36`

- [ ] **Step 1: Refactor cloud_registration.py**

Remove from `__init__` (line 35):
```python
self.cspm = CSPMRegistration(auth_object=self.client.auth_object)
```

Add `cspm = self._service(CSPMRegistration)` at top of:
- `_list_accounts` (line 143): replace `self.cspm` → `cspm` (lines 148, 170)
- `_get_policy_settings` (line 201): replace `self.cspm` → `cspm` (line 207)

- [ ] **Step 2: Run tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add modules/cloud_registration.py
git commit -m "refactor: lazy service creation in CloudRegistrationModule"
```

---

### Task 11: Refactor cloud_security.py (3 optional services)

**Files:**
- Modify: `modules/cloud_security.py:45-84`

- [ ] **Step 1: Refactor cloud_security.py**

Remove from `__init__` (lines 50-84) all service creation and availability checks. Replace with:
```python
def __init__(self, client):
    super().__init__(client)
    if not any([CLOUD_SECURITY_AVAILABLE, DETECTIONS_AVAILABLE, ASSETS_AVAILABLE]):
        raise ImportError("No cloud security FalconPy classes available.")
    available = [n for n, a in [
        ("CloudSecurity", CLOUD_SECURITY_AVAILABLE),
        ("Detections", DETECTIONS_AVAILABLE),
        ("Assets", ASSETS_AVAILABLE),
    ] if a]
    self._log(f"Initialized ({', '.join(available)})")
```

In each internal method, replace the instance attribute check + usage with availability check + `_service()`:

- `_get_cloud_risks`: replace `if not self._cloud_security` → `if not CLOUD_SECURITY_AVAILABLE`, then `cs = self._service(CloudSecurity)` and use `cs` instead of `self._cloud_security`
- `_get_iom_detections`: replace `if not self._detections` → `if not DETECTIONS_AVAILABLE`, then `det = self._service(CloudSecurityDetections)` and use `det` instead of `self._detections`
- `_query_assets`: replace `if not self._assets` → `if not ASSETS_AVAILABLE`, then `assets = self._service(CloudSecurityAssets)` and use `assets` instead of `self._assets`
- `_get_compliance_by_account`: same pattern with `CloudSecurityAssets`

- [ ] **Step 2: Run tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add modules/cloud_security.py
git commit -m "refactor: lazy service creation in CloudSecurityModule"
```

---

### Task 12: Refactor alerts.py (2 services, one optional)

**Files:**
- Modify: `modules/alerts.py:46-60`

- [ ] **Step 1: Read the full alerts.py to identify all self.alerts and self._ngsiem references**

Read: `modules/alerts.py`

Identify every method that uses `self.alerts` or `self._ngsiem` and convert each.

- [ ] **Step 2: Refactor alerts.py**

Remove from `__init__` (lines 51-59):
```python
self.alerts = Alerts(auth_object=self.client.auth_object)
self._ngsiem = None
if _NGSIEM_AVAILABLE:
    try:
        self._ngsiem = NGSIEM(auth_object=self.client.auth_object)
    except Exception as e:
        self._log(f"NGSIEM enrichment not available: {e}")
```

Replace with:
```python
# Services created lazily via self._service() at call time
```

In each internal method:
- Replace `self.alerts` → `alerts = self._service(Alerts)` at method top, then use `alerts`
- Replace `self._ngsiem` availability checks:
  ```python
  # Before:
  if self._ngsiem:
      result = self._ngsiem.some_call(...)

  # After:
  if _NGSIEM_AVAILABLE:
      ngsiem = self._service(NGSIEM)
      result = ngsiem.some_call(...)
  ```

- [ ] **Step 3: Run tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add modules/alerts.py
git commit -m "refactor: lazy service creation in AlertsModule"
```

---

### Task 13: Refactor correlation.py (conditional fallback + _get_correlation_service)

**Files:**
- Modify: `modules/correlation.py:44-74`

- [ ] **Step 1: Refactor correlation.py**

Remove from `__init__` (lines 49-73) all the conditional service creation and `_init_harness`. Replace with:
```python
def __init__(self, client):
    super().__init__(client)
    if not CORRELATION_AVAILABLE and not HARNESS_AVAILABLE:
        raise ImportError("Neither falconpy.CorrelationRules nor falconpy.APIHarnessV2 available.")
    self._use_harness = not CORRELATION_AVAILABLE
    # ... keep _detections_repo_path setup unchanged
```

Add `_get_correlation_service()`:
```python
def _get_correlation_service(self):
    """Get the correlation API service, preferring CorrelationRules over Uber class."""
    cls = CorrelationRules if CORRELATION_AVAILABLE else APIHarnessV2
    return self._service(cls)
```

Remove `_init_harness()` method entirely.

In each internal method, replace `self.falcon` with:
```python
falcon = self._get_correlation_service()
```

Methods to update: `_list_rules`, `_get_rules`, `_update_rule`.

- [ ] **Step 2: Run tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add modules/correlation.py
git commit -m "refactor: lazy service creation in CorrelationModule"
```

---

### Task 14: Run full smoke test and verify all modules register

- [ ] **Step 1: Run smoke test**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_smoke_tools_list.py -v`
Expected: All 4 tests PASS — same tool sets as before

- [ ] **Step 2: Run full test suite**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 3: Run linter**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && ruff check . && ruff format --check .`
Expected: No issues

---

## Chunk 3: Server Integration & Deployment

### Task 15: Transport-aware server startup and middleware composition

**Files:**
- Modify: `server.py:46-127`
- Modify: `client.py:29` (version bump)
- Test: `tests/test_server_transport.py`

- [ ] **Step 1: Write failing tests for transport-aware startup**

```python
# tests/test_server_transport.py
"""Tests for transport-aware FalconMCPServer startup."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestTransportAwareStartup:

    @patch("server.get_available_modules", return_value=[])
    @patch("server.FalconClient")
    def test_stdio_creates_real_client(self, MockClient, mock_modules):
        """stdio transport creates a real FalconClient and authenticates."""
        mock_instance = MagicMock()
        mock_instance._deferred = False
        MockClient.return_value = mock_instance

        from server import FalconMCPServer

        server = FalconMCPServer(transport="stdio")

        MockClient.assert_called_once()
        mock_instance.authenticate.assert_called_once()

    @patch("server.get_available_modules", return_value=[])
    @patch("server.FalconClient")
    def test_http_creates_deferred_client(self, MockClient, mock_modules):
        """streamable-http transport creates a deferred (credential-less) client."""
        deferred_instance = MagicMock()
        deferred_instance._deferred = True
        MockClient.deferred.return_value = deferred_instance

        from server import FalconMCPServer

        server = FalconMCPServer(transport="streamable-http")

        MockClient.deferred.assert_called_once()
        deferred_instance.authenticate.assert_not_called()

    @patch("server.get_available_modules", return_value=[])
    @patch("server.FalconClient")
    def test_sse_creates_deferred_client(self, MockClient, mock_modules):
        """SSE transport also creates a deferred client."""
        deferred_instance = MagicMock()
        deferred_instance._deferred = True
        MockClient.deferred.return_value = deferred_instance

        from server import FalconMCPServer

        server = FalconMCPServer(transport="sse")

        MockClient.deferred.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/test_server_transport.py -v`
Expected: FAIL — server always creates a real FalconClient

- [ ] **Step 3: Update server.py**

In `FalconMCPServer.__init__`, replace the client creation block (lines 68-74):

```python
# Before:
self.client = FalconClient(
    client_id=client_id,
    client_secret=client_secret,
    base_url=base_url,
)
self.client.authenticate()

# After:
if transport == "stdio":
    self.client = FalconClient(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
    )
    self.client.authenticate()
else:
    self.client = FalconClient.deferred()
    self._log("HTTP mode: credential-less startup, per-client auth via headers")
```

Update `_run_http()` (lines 110-127) to compose the full middleware stack:

```python
def _run_http(self, transport_type: str):
    """Start an HTTP-based transport with auth middleware stack."""
    import uvicorn

    from client import SERVER_VERSION
    from common.health import with_health_check
    from common.session_auth import session_auth_middleware

    if transport_type == "sse":
        app = self.server.sse_app()
    else:
        app = self.server.streamable_http_app()

    # Layer 1: per-session Falcon auth (innermost)
    app = session_auth_middleware(app)

    # Layer 2: server access gate (optional)
    if self.api_key:
        from common.auth_middleware import auth_middleware

        app = auth_middleware(app, self.api_key)
        self._log(f"API key authentication enabled for {transport_type}")

    # Layer 3: health check (outermost, no auth)
    app = with_health_check(app, version=SERVER_VERSION, transport=transport_type)

    self._log(f"Starting {transport_type} transport on {self.host}:{self.port}")
    uvicorn.run(app, host=self.host, port=self.port)
```

- [ ] **Step 4: Bump version in client.py**

In `client.py` line 29, change:
```python
SERVER_VERSION = "3.0.0"
```
to:
```python
SERVER_VERSION = "3.1.0"
```

- [ ] **Step 5: Run tests**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add server.py client.py tests/test_server_transport.py
git commit -m "feat: transport-aware startup with middleware composition"
```

---

### Task 16: Dockerfile and .dockerignore

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

- [ ] **Step 1: Create Dockerfile**

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

- [ ] **Step 2: Create .dockerignore**

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

- [ ] **Step 3: Verify Dockerfile builds (if Docker available)**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && docker build -t crowdstrike-mcp:test . 2>&1 | tail -5`
Expected: Successfully built (or skip if Docker not available)

- [ ] **Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "feat: add Dockerfile and .dockerignore for remote deployment"
```

---

### Task 17: Final validation and lint

- [ ] **Step 1: Run full test suite**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 2: Run linter**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && ruff check . && ruff format --check .`
Expected: No issues. If there are format issues, run `ruff format .` and commit.

- [ ] **Step 3: Verify stdio mode still works (manual smoke test)**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && timeout 5 python server.py 2>&1 || true`
Expected: Should show `[FalconMCPServer] Registered N tools...` then `Starting stdio transport` (will hang waiting for stdin, timeout kills it). This confirms stdio startup path is unbroken.

- [ ] **Step 4: Final commit if any lint fixes were needed**

```bash
git add -A && git commit -m "style: lint fixes"
```
