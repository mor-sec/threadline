from datetime import UTC as STDLIB_UTC
from datetime import datetime

import pytest
from pydantic import ValidationError

from threadline.ingest.loader import node_query, rel_query
from threadline.model import schema
from threadline.model.nodes import NODE_TYPES, UTC, Asset, Vulnerability, rel

T = datetime(2026, 10, 27, 12, tzinfo=STDLIB_UTC)
PROV = {"source": "test", "firstSeen": T, "lastSeen": T}


def asset(**kw):
    return Asset(**{"assetId": "a1", "hostname": "h", "assetType": "server", "criticality": 3,
                    **PROV, **kw})


def test_times_are_coerced_to_named_utc_zone():
    assert asset().firstSeen.tzinfo is UTC


def test_naive_datetime_rejected():
    with pytest.raises(ValidationError, match="naive"):
        asset(firstSeen=datetime(2026, 1, 1))


def test_unknown_extra_label_rejected():
    with pytest.raises(ValidationError, match="does not allow"):
        asset(labels=frozenset({"Admin"}))


def test_props_skip_unknowns_and_provenance_times():
    props = Vulnerability(cveId="CVE-1", epssScore=0.5, **PROV).props()
    assert props == {"cveId": "CVE-1", "epssScore": 0.5, "source": "test", "confidence": 80}


def test_relationship_outside_schema_rejected():
    with pytest.raises(ValidationError, match="not in schema"):
        rel("ADMIN_TO", ("Asset", "a1"), ("Identity", "u1"), **PROV)


def test_relationship_datetime_props_coerced():
    r = rel("COVERED_BY", asset(), ("SecurityTool", "mde"), props={"lastCheckIn": T}, **PROV)
    assert r.props["lastCheckIn"].tzinfo is UTC


def test_every_node_type_has_a_uniqueness_constraint():
    stmts = schema.statements()
    assert all("IF NOT EXISTS" in s for s in stmts)
    for label, cls in NODE_TYPES.items():
        assert any(f"(n:{label}) REQUIRE n.{cls.KEY} IS UNIQUE" in s for s in stmts), label


def test_loader_cypher_is_built_from_model_constants():
    assert "MERGE (n:Asset {assetId: row.key})" in node_query(Asset)
    q = rel_query("Asset", "HAS_FINDING", "Finding")
    assert "MATCH (s:Asset {assetId: row.start})" in q and "MERGE (s)-[r:HAS_FINDING]->(e)" in q
