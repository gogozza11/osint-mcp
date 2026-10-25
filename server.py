#!/usr/bin/env python3
"""Entrypoint for the OSINT MCP server (stdio transport)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from osint_mcp.app import mcp  # noqa: E402

if __name__ == "__main__":
    mcp.run(transport="stdio")
