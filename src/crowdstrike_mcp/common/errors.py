"""
Scope-aware error handling for CrowdStrike API responses.

Replaces BaseHandler._api_error() with richer context: on 403 errors,
looks up the required API scopes and includes resolution guidance.
"""

from typing import Any

from crowdstrike_mcp.common.api_scopes import get_required_scopes


def handle_api_response(response: dict, operation: str | None = None) -> dict[str, Any]:
    """Extract resources from a FalconPy response, or return an error dict.

    Args:
        response: Raw FalconPy response dict.
        operation: Optional FalconPy operation name for scope-aware 403 messages.

    Returns:
        On success: ``{"success": True, "resources": [...]}``
        On failure: ``{"success": False, "error": "..."}``
    """
    status = response.get("status_code", 0)

    if 200 <= status < 300:
        resources = response.get("body", {}).get("resources", [])
        return {"success": True, "resources": resources}

    return {"success": False, "error": format_api_error(response, operation=operation)}


def format_api_error(
    response: dict,
    context: str = "",
    operation: str | None = None,
) -> str:
    """Build a human-readable error string from a FalconPy response.

    On HTTP 403, appends the required API scopes (if known) so the user
    can fix their API client permissions without guessing.

    Args:
        response: Raw FalconPy response dict.
        context: Optional prefix like ``"Failed to query alerts"``.
        operation: Optional FalconPy operation name for scope lookup.
    """
    status = response.get("status_code", "unknown")
    parts: list[str] = [f"HTTP {status}"]

    # Extract error messages from body.errors
    body = response.get("body", {})
    errors = body.get("errors", [])
    if isinstance(errors, list):
        msgs = []
        for e in errors:
            if isinstance(e, dict) and "message" in e:
                msgs.append(e["message"])
            else:
                msgs.append(str(e))
        if msgs:
            parts.append(": ".join(msgs))

    error_msg = " — ".join(parts) if len(parts) > 1 else parts[0]

    # Scope-aware 403 guidance
    if status == 403 and operation:
        scopes = get_required_scopes(operation)
        if scopes:
            error_msg += (
                f"\n\nRequired API scopes for '{operation}': {', '.join(scopes)}"
                "\nCheck your API client permissions in the CrowdStrike console "
                "(Support & Resources > API Clients & Keys)."
            )

    if context:
        error_msg = f"{context}: {error_msg}"

    return error_msg
