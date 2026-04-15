"""CrowdStrike Falcon MCP Server."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("crowdstrike-mcp")
except PackageNotFoundError:
    # Package is not installed (running from source without pip install -e)
    try:
        from crowdstrike_mcp._version import __version__  # type: ignore[no-redef]
    except ImportError:
        __version__ = "0.0.0.dev0"
