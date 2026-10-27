"""Load the sample estate into a local Neo4j and check the four target questions."""

from datetime import datetime

import pytest
from conftest import AS_OF, SCALE
from neo4j.exceptions import ClientError

from threadline.db import read
from threadline.graphrag.templates import TEMPLATES
from threadline.ingest import pipeline
from threadline.model.nodes import UTC

pytestmark = pytest.mark.integration
DB = "neo4j"


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
