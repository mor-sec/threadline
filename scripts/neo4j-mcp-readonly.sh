#!/usr/bin/env bash
# Read-only Neo4j MCP server for Claude Code / Claude Desktop. Credentials come from .env.
set -euo pipefail
cd "$(dirname "$0")/.."
exec .venv/bin/python -m threadline.mcp
