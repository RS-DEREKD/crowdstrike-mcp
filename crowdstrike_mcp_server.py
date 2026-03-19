#!/usr/bin/env python3
"""
CrowdStrike Falcon MCP Server — Legacy Entry Point

This file is a thin shim that delegates to the new modular server (server.py).
Existing .mcp.json configurations that reference this file continue to work
unchanged.

For new usage, prefer running server.py directly:
  python server.py                         # stdio (default)
  python server.py --transport sse         # SSE over HTTP
  python server.py --modules ngsiem,alerts # Selective modules
"""

import os
import sys

# Ensure the mcp/ directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server import main

if __name__ == "__main__":
    main()
