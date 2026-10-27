"""Offline checks of the full sample build: determinism, referential integrity, the story."""

import json

from conftest import AS_OF, SCALE

from threadline.ingest import feeds, synthetic
from threadline.ingest.synthetic import ALERT_TYPES


def keys(batch, label):
    return {n.key for n in batch.nodes if n.LABEL == label}


def rels(batch, typ):
    return {(r.start, r.end) for r in batch.rels if r.type == typ}


def test_same_seed_gives_identical_estate():
    a = synthetic.generate(AS_OF, seed=42, scale=0.05)
    b = synthetic.generate(AS_OF, seed=42, scale=0.05)
    for field in ("cmdb", "tenable", "defender_devices", "entra", "sentinel", "opencti", "story"):
        assert json.dumps(getattr(a, field), default=str) == json.dumps(getattr(b, field),
                                                                        default=str), field


def test_every_relationship_endpoint_exists(sample):
    batch, _ = sample
    nodes = {(n.LABEL, n.key) for n in batch.nodes}
    missing = {(r.type, r.endLabel) for r in batch.rels
               if (r.startLabel, r.start) not in nodes or (r.endLabel, r.end) not in nodes}
    assert not missing


def test_alert_techniques_exist_in_attack():
    ids = {o.get("external_id") for o in feeds.attack()["objects"]}
    for _, tech, sub, *_ in ALERT_TYPES:
        assert tech in ids and (sub is None or sub in ids)


def test_story_is_planted(sample):
    batch, ctx = sample
    story, res = ctx.estate.story, ctx.assets
    vpn = res.lookup(host=story["vpn_host"])
    vpn_node = next(n for n in batch.nodes if n.LABEL == "Asset" and n.key == vpn)
    assert "InternetFacing" in vpn_node.labels
    assert any(f.LABEL == "Finding" and f.findingId.startswith(f"{vpn}:{story['vpn_cve']}")
               and f.status == "open" for f in batch.nodes)
    assert (story["vpn_cve"], "T1190") in rels(batch, "EXPLOITED_BY")
    assert ("G0046", "Financial Services") in rels(batch, "TARGETS")

    ids = ctx.identity_by_upn
    ws = res.lookup(host=story["phished_workstation"])
    da = ids[story["domain_admin"]]
    assert (ids[story["phished_user"]], ws) in rels(batch, "CAN_ACCESS")
    assert (ws, da) in rels(batch, "HAS_SESSION")
    da_groups = {g for (m, g) in rels(batch, "MEMBER_OF") if m == da}
    crown = res.lookup(host=story["crown_jewel"])
    assert any((g, crown) in rels(batch, "ADMIN_TO") for g in da_groups)


def test_untrusted_text_is_flagged(sample):
    batch, _ = sample
    flagged = [n for n in batch.nodes if n.LABEL in ("Report", "Alert") and n.suspicious]
    assert {n.LABEL for n in flagged} == {"Report", "Alert"} or SCALE < 0.05
    assert batch.issues["opencti: report text looks like prompt injection"] == 1
