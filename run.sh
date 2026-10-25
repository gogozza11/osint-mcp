#!/usr/bin/env bash
# Manual launcher for the OSINT MCP server (stdio transport).
set -euo pipefail
cd "$(dirname "$0")"
exec "${PYTHON:-python3}" server.py
