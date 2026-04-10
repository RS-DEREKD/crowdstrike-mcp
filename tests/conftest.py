"""Shared fixtures for MCP server unit tests."""

import os
import sys
from unittest.mock import MagicMock

import pytest

# Ensure the MCP server root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


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
    from response_store import ResponseStore

    ResponseStore._reset()
    yield
    ResponseStore._reset()
