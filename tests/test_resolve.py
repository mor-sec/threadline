import random
from datetime import UTC, datetime

from threadline.ingest.base import SourceAsset
from threadline.ingest.resolve import build_assets, is_public, resolve

T = datetime(2026, 10, 27, tzinfo=UTC)


def rec(source, sid, **kw):
    return SourceAsset(source=source, sourceId=sid, firstSeen=T, lastSeen=T, **kw)


CMDB = rec("servicenow", "sys1", hostname="app01", fqdn="app01.corp.example", ip="10.0.0.5",
           mac="02:00:00:00:00:01", attrs={"criticality": 4, "businessUnit": "RB"})
EDR = rec("defender", "dev1", hostname="app01", fqdn="APP01.corp.example.", ip="10.0.0.5")
SCAN = rec("tenable", "u1", hostname="APP01", ip="10.0.0.99", mac="02-00-00-00-00-01")


def test_strong_and_hostname_matches_merge_into_the_cmdb_asset():
    res = resolve([CMDB, EDR, SCAN])
    assert set(res.clusters) == {"sys1"}
    assert res.method["defender:dev1"] == "strong:fqdn"
    assert res.method["tenable:u1"] == "strong:mac"


def test_hostname_only_match_merges_when_nothing_conflicts():
    scan = rec("tenable", "u2", hostname="APP01")
    res = resolve([CMDB, scan])
    assert res.asset_of["tenable:u2"] == "sys1"
    assert res.method["tenable:u2"] == "hostname"


def test_same_short_name_different_fqdn_is_not_merged():
    dmz = rec("defender", "dev2", hostname="app01", fqdn="app01.dmz.example")
    res = resolve([CMDB, dmz])
    assert len(res.clusters) == 2


def test_shared_ip_only_becomes_a_candidate_not_a_merge():
    other = rec("defender", "dev3", hostname="ws42", fqdn="ws42.corp.example", ip="10.0.0.5")
    res = resolve([CMDB, other])
    assert len(res.clusters) == 2
    assert ("defender:dev3", "sys1", 0.3) in res.candidates
    assert res.lookup(ip="10.0.0.5") is None  # ambiguous IPs never resolve


def test_asset_without_cmdb_record_is_unmanaged_with_stable_id():
    rogue = rec("tenable", "u9", hostname="nas01", mac="02:00:00:00:00:09")
    batch = build_assets(resolve([CMDB, rogue]))
    unmanaged = [n for n in batch.nodes if n.LABEL == "Asset" and "Unmanaged" in n.labels]
    assert len(unmanaged) == 1 and unmanaged[0].assetId.startswith("asset-")
    assert unmanaged[0].assetId == build_assets(resolve([rogue])).nodes[0].assetId


def test_resolution_ignores_input_order():
    records = [CMDB, EDR, SCAN, rec("tenable", "u9", hostname="nas01", mac="02:00:00:00:00:09")]
    shuffled = records[:]
    random.Random(1).shuffle(shuffled)
    assert resolve(records).asset_of == resolve(shuffled).asset_of


def test_public_ip_rules():
    assert is_public("198.51.100.7") and not is_public("10.1.2.3") and not is_public("192.168.1.1")
