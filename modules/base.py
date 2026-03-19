"""
BaseModule — abstract base class for all MCP tool modules.

Each module:
  - Receives a shared ``FalconClient`` instance
  - Registers its tools (and optionally resources) with a FastMCP server
  - Creates FalconPy service classes using ``self.client.auth_object``
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from client import FalconClient
    from mcp.server.fastmcp import FastMCP


class BaseModule(ABC):
    """Abstract base class for CrowdStrike MCP modules."""

    def __init__(self, client: FalconClient):
        self.client = client
        self.tools: list[str] = []
        self.resources: list[str] = []

    @abstractmethod
    def register_tools(self, server: FastMCP) -> None:
        """Register this module's tools with the FastMCP server.

        Subclasses must implement this to add their tools via ``_add_tool()``.
        """
        ...

    def register_resources(self, server: FastMCP) -> None:
        """Register this module's MCP resources (optional).

        Override in subclasses that expose FQL guides or other resources.
        """

    def _add_tool(
        self,
        server: FastMCP,
        method: Callable,
        name: str,
        description: str | None = None,
    ) -> None:
        """Register a tool function with the server and track it.

        Args:
            server: The FastMCP server instance.
            method: The async or sync callable to register.
            name: Tool name (e.g. ``"ngsiem_query"``).
            description: Optional tool description override.
        """
        kwargs = {"name": name}
        if description:
            kwargs["description"] = description
        server.tool(**kwargs)(method)
        self.tools.append(name)

    def _add_resource(self, server: FastMCP, resource) -> None:
        """Register an MCP resource and track its URI."""
        server.add_resource(resource)
        uri = getattr(resource, "uri", str(resource))
        self.resources.append(str(uri))

    def _log(self, message: str) -> None:
        """Log to stderr for MCP server debugging."""
        print(f"[{self.__class__.__name__}] {message}", file=sys.stderr)
