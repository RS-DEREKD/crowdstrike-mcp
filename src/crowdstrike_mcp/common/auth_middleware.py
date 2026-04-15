"""
ASGI middleware for API key authentication on HTTP transports (SSE, streamable-http).

When the MCP server is exposed over HTTP (not stdio), this middleware
validates an ``x-api-key`` header using constant-time comparison.
"""

import secrets

from starlette.requests import Request
from starlette.responses import JSONResponse


def auth_middleware(app, api_key: str):
    """Wrap an ASGI app with API key header validation.

    Args:
        app: The ASGI application to protect.
        api_key: Expected value of the ``x-api-key`` header.

    Returns:
        A new ASGI app that checks the header before delegating.
    """

    async def middleware(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            request = Request(scope, receive)
            provided = request.headers.get("x-api-key", "")
            if not secrets.compare_digest(provided, api_key):
                response = JSONResponse(
                    {"error": "Invalid or missing API key"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return

        await app(scope, receive, send)

    return middleware
