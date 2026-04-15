"""Shared fixtures for MCP server unit tests."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_client():
    """Create a mock FalconClient with a mock auth_object."""
    client = MagicMock()
    client.auth_object = MagicMock()
    return client


@pytest.fixture
def mock_hosts_api():
    """Create a mock Hosts FalconPy service class."""
    return MagicMock()


@pytest.fixture
def mock_ngsiem_api():
    """Create a mock NGSIEM FalconPy service class."""
    return MagicMock()


@pytest.fixture(autouse=True)
def reset_response_store():
    """Reset ResponseStore between tests to prevent state leakage."""
    from crowdstrike_mcp.response_store import ResponseStore

    ResponseStore._reset()
    yield
    ResponseStore._reset()
