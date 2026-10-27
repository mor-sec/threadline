"""Start the official Neo4j MCP server read-only, with the read credentials from .env.

Secrets reach the server through its environment, never through MCP client config or argv.
"""

import os
import shutil
from pathlib import Path

from .cli import _settings

SERVER = "neo4j-mcp-server"


def server_env() -> dict[str, str]:
    s = _settings()
    return {
        **os.environ,
        "NEO4J_MCP_URI": s.neo4j_uri,
        "NEO4J_MCP_DATABASE": s.neo4j_database,
        "NEO4J_MCP_USERNAME": s.neo4j_read_username,
        "NEO4J_MCP_PASSWORD": s.neo4j_read_password.get_secret_value(),
        "NEO4J_MCP_READ_ONLY": "true",
        "NEO4J_MCP_TELEMETRY": "false",
    }


def main() -> None:
    # Claude Desktop starts servers with a minimal PATH; uv tool installs to ~/.local/bin.
    binary = shutil.which(SERVER) or str(Path.home() / ".local/bin" / SERVER)
    os.execve(binary, [binary], server_env())


if __name__ == "__main__":
    main()
