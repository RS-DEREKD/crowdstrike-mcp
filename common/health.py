"""
Health check ASGI wrapper — intercepts /health before any middleware.
"""

from starlette.responses import JSONResponse


def with_health_check(app, version: str, transport: str):
    """Wrap an ASGI app with a /health endpoint that bypasses all auth.

    Args:
        app: The ASGI application to wrap.
        version: Server version string.
        transport: Transport type (sse, streamable-http).

    Returns:
        A new ASGI app that intercepts /health requests.
    """

    async def wrapper(scope, receive, send):
        if scope["type"] == "http" and scope.get("path") == "/health":
            response = JSONResponse(
                {
                    "status": "ok",
                    "transport": transport,
                    "version": version,
                }
            )
            await response(scope, receive, send)
            return
        await app(scope, receive, send)

    return wrapper
