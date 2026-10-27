import json
import shutil
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).parent.parent / "scripts" / "audit_hook.py"
PRE = {"hook_event_name": "PreToolUse", "tool_name": "mcp__neo4j-threadline__read-cypher",
       "tool_use_id": "t1", "tool_input": {"query": "CYPHER 25 RETURN $x AS x", "params": {"x": 1}}}
POST = {"hook_event_name": "PostToolUse", "tool_name": "mcp__neo4j-threadline__read-cypher",
        "tool_use_id": "t1", "tool_response": [{"type": "text", "text": '[{"x": 1}, {"x": 2}]'}]}


def run(hook, event):
    return subprocess.run([sys.executable, hook], input=json.dumps(event), text=True,
                          capture_output=True).returncode


def install(tmp_path):
    (tmp_path / "scripts").mkdir()
    return shutil.copy(HOOK, tmp_path / "scripts")  # logs/ then lands under tmp_path


def test_records_query_and_row_count(tmp_path):
    hook = install(tmp_path)
    assert run(hook, PRE) == 0 and run(hook, POST) == 0
    pre, post = (json.loads(line) for line in (tmp_path / "logs/audit.jsonl").read_text().splitlines())
    assert pre["query"] == PRE["tool_input"]["query"] and pre["params"] == {"x": 1}
    assert post["rows"] == 2 and post["toolUseId"] == pre["toolUseId"]


def test_blocks_the_query_when_the_log_cannot_be_written(tmp_path):
    hook = install(tmp_path)
    (tmp_path / "logs").write_text("not a directory")
    assert run(hook, PRE) == 2
