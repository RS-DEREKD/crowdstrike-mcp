"""
Per-session Falcon authentication middleware for HTTP transports.

Extracts CrowdStrike API credentials from request headers, authenticates
via OAuth2, caches sessions, and sets a ContextVar for per-request isolation.
"""

import hashlib
import sys
import time

from starlette.responses import JSONResponse

from crowdstrike_mcp.client import FalconClient
from crowdstrike_mcp.modules.base import _session_client

# Client cache: hash(creds) → (FalconClient, last_access_time)
_client_cache: dict[str, tuple[FalconClient, float]] = {}
_CACHE_TTL = 25 * 60  # 25 minutes (inside CrowdStrike's 30-min token window)
_CACHE_MAX = 100


def _evict_stale():
    """Remove expired entries from the client cache."""
    now = time.time()
    expired = [k for k, (_, ts) in _client_cache.items() if now - ts > _CACHE_TTL]
    for k in expired:
        del _client_cache[k]


def _evict_lru():
    """Evict least-recently-accessed entry when cache exceeds max size."""
    if len(_client_cache) >= _CACHE_MAX:
        oldest_key = min(_client_cache, key=lambda k: _client_cache[k][1])
        del _client_cache[oldest_key]


def _extract_headers(scope) -> tuple[str | None, str | None, str | None]:
    """Extract Falcon credential headers from ASGI scope."""
    headers = dict((k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in scope.get("headers", []))
    return (
        headers.get("x-falcon-client-id"),
        headers.get("x-falcon-client-secret"),
        headers.get("x-falcon-base-url"),
    )


def session_auth_middleware(app):
    """ASGI middleware that authenticates per-client Falcon credentials.

    Extracts X-Falcon-Client-Id, X-Falcon-Client-Secret, and X-Falcon-Base-Url
    from request headers. Authenticates via OAuth2, caches the session, and
    sets the _session_client ContextVar for the request duration.
    """

    async def middleware(scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await app(scope, receive, send)
            return

        client_id, client_secret, base_url = _extract_headers(scope)

        if not client_id or not client_secret:
            response = JSONResponse(
                {"error": "Missing required headers: X-Falcon-Client-Id, X-Falcon-Client-Secret"},
                status_code=401,
            )
            await response(scope, receive, send)
            return

        base_url = base_url or "US1"
        cache_key = hashlib.sha256(f"{client_id}:{client_secret}:{base_url}".encode()).hexdigest()

        # Check cache (with lazy eviction)
        _evict_stale()

        if cache_key in _client_cache:
            cached_client, _ = _client_cache[cache_key]
            _client_cache[cache_key] = (cached_client, time.time())
        else:
            # Cache miss — authenticate
            _evict_lru()
            try:
                new_client = FalconClient(
                    client_id=client_id,
                    client_secret=client_secret,
                    base_url=base_url,
                )
                new_client.authenticate()
                _client_cache[cache_key] = (new_client, time.time())
                cached_client = new_client
                print(f"[SessionAuth] Authenticated new client (base_url={base_url})", file=sys.stderr)
            except (RuntimeError, ValueError) as e:
                response = JSONResponse(
                    {"error": f"CrowdStrike authentication failed: {e}"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return

        # Set ContextVar for this request
        token = _session_client.set(cached_client)
        try:
            await app(scope, receive, send)
        finally:
            _session_client.reset(token)

    return middleware
