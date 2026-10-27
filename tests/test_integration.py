"""Load the sample estate into a local Neo4j and check the four target questions."""

import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import pytest
from conftest import AS_OF, SCALE, TEST_DB
from neo4j.exceptions import ClientError

from threadline.db import read
from threadline.graphrag.templates import TEMPLATES
from threadline.ingest import pipeline
from threadline.model.nodes import UTC

pytestmark = pytest.mark.integration
DB = TEST_DB
ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="module")
def loaded(neo4j_test, tmp_path_factory, monkeypatch_module):
    monkeypatch_module.chdir(tmp_path_factory.mktemp("run"))  # reports/ goes to a temp dir
    first = pipeline.run(neo4j_test, DB, "sample", AS_OF, scale=SCALE, log=lambda *_: None)
    second = pipeline.run(neo4j_test, DB, "sample", AS_OF, scale=SCALE, log=lambda *_: None)
    _, ctx = pipeline.build("sample", AS_OF, scale=SCALE)
    return neo4j_test, first, second, ctx.estate.story


@pytest.fixture(scope="module")
def monkeypatch_module():
    with pytest.MonkeyPatch.context() as mp:
        yield mp


def query(driver, name, unlimited=False):
    t = TEMPLATES[name]
    cypher = t.cypher.replace("LIMIT 25", "") if unlimited else t.cypher
    return read(driver, DB, cypher, t.params(org_id="org-kestrel", now=datetime.now(UTC)))


def test_reload_is_idempotent(loaded):
    _, first, second, _ = loaded
    without_runs = {k: v for k, v in first["labels"].items() if k != "IngestRun"}
    assert without_runs == {k: v for k, v in second["labels"].items() if k != "IngestRun"}
    assert first["relationships"] == second["relationships"]
    assert second["passed"] and not second["droppedRelationships"]


def test_q1_story_actor_exposure(loaded):
    driver, *_, story = loaded
    top = query(driver, "q1")[0]
    assert top["hostname"] == story["vpn_host"] and top["techniqueId"] == "T1190"
    assert "FIN7" in top["actors"] and story["vpn_cve"] in top["cves"] and top["mitigations"]


def test_q2_story_attack_path(loaded):
    driver, *_, story = loaded
    row = next(r for r in query(driver, "q2") if r["entryUser"] == story["phished_user"])
    assert row["hops"] == 4 and "HAS_SESSION" in row["pathRelTypes"]
    assert story["crown_jewel"] in row["crownJewels"]


def test_q3_kev_without_edr(loaded):
    driver, *_, story = loaded
    rows = {r["hostname"]: r for r in query(driver, "q3", unlimited=True)}
    assert rows[story["vpn_host"]]["edr"] == "none"
    assert rows[story["stale_edr_host"]]["edr"] == "stale"
    assert rows[story["unmanaged_host"]]["unmanaged"]


def test_q4_changes_since_last_week(loaded):
    driver, *_, story = loaded
    changes = {r["change"]: r for r in query(driver, "q4")}
    assert {"new finding", "fixed"} <= set(changes)
    assert changes["new internet-facing asset"]["examples"][0]["hostname"] == \
        story["new_internet_host"]


def test_query_path_rejects_writes(loaded):
    driver, *_ = loaded
    with pytest.raises(ClientError, match="read access mode"):
        read(driver, DB, "CREATE (:ShouldNotExist)")


@pytest.fixture(scope="module")
def mcp(loaded):
    """The read-only MCP server via the same wrapper Claude Code uses, pointed at the test DB."""
    if not shutil.which("neo4j-mcp-server"):
        pytest.skip("uv tool install neo4j-mcp-server")
    password = os.environ.get("NEO4J_TEST_PASSWORD", "threadline-local-dev")
    env = {**os.environ, "NEO4J_URI": os.environ["NEO4J_TEST_URI"], "NEO4J_DATABASE": DB,
           "NEO4J_READ_USERNAME": "neo4j", "NEO4J_READ_PASSWORD": password,
           "NEO4J_WRITE_USERNAME": "unused", "NEO4J_WRITE_PASSWORD": "unused"}
    proc = subprocess.Popen([str(ROOT / "scripts/neo4j-mcp-readonly.sh")], env=env, text=True,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    ids = iter(range(1, 1000))

    def call(method, params=None):
        msg = {"jsonrpc": "2.0", "id": next(ids), "method": method, "params": params or {}}
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())["result"]

    call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "pytest", "version": "0"}})
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    yield call
    proc.terminate()
    proc.wait()


def test_mcp_exposes_only_read_tools(mcp):
    assert {t["name"] for t in mcp("tools/list")["tools"]} == {"get-schema", "read-cypher"}


def test_mcp_refuses_writes(mcp, loaded):
    driver, *_ = loaded
    r = mcp("tools/call", {"name": "read-cypher",
                           "arguments": {"query": "CREATE (:ShouldNotExist) RETURN 1"}})
    assert r["isError"]
    assert read(driver, DB, "MATCH (n:ShouldNotExist) RETURN count(n) AS c")[0]["c"] == 0


def test_mcp_answers_a_template_query(mcp, loaded):
    *_, story = loaded
    t = TEMPLATES["q1"]
    params = t.params(org_id="org-kestrel", now=datetime.now(UTC))
    r = mcp("tools/call", {"name": "read-cypher", "arguments": {"query": t.cypher,
                                                                 "params": params}})
    assert not r.get("isError")
    assert json.loads(r["content"][0]["text"])[0]["hostname"] == story["vpn_host"]
