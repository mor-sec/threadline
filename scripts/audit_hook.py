#!/usr/bin/env python3
"""Claude Code hook: append every Neo4j MCP query to logs/audit.jsonl (PLAN §10).

PreToolUse records the attempt (including ones the server will refuse) and fails closed:
if the audit line can't be written, the query is blocked. PostToolUse records the row count.
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

LOG = Path(__file__).resolve().parent.parent / "logs" / "audit.jsonl"


def rows(response) -> int | None:
    """Row count from the MCP result text (a JSON array), if it parses."""
    try:
        items = response if isinstance(response, list) else response.get("content", [])
        return len(json.loads(items[0]["text"]))
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return None


def main() -> int:
    event = json.load(sys.stdin)
    pre = event["hook_event_name"] == "PreToolUse"
    entry = {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "path": "mcp",
        "event": "attempt" if pre else "result",
        "tool": event.get("tool_name"),
        "toolUseId": event.get("tool_use_id"),
        "sessionId": event.get("session_id"),
    }
    if pre:
        entry |= {"query": event["tool_input"].get("query"),
                  "params": event["tool_input"].get("params")}
    else:
        entry["rows"] = rows(event.get("tool_response"))
    try:
        LOG.parent.mkdir(exist_ok=True)
        with LOG.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError as e:
        print(f"audit log unavailable ({e}); query blocked", file=sys.stderr)
        return 2 if pre else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
