"""Entity resolution: many source views of a host -> one canonical Asset (PLAN §5.3).

Deterministic, so reruns give the same assetIds:
  strong   same cloud instance id, serial, MAC or FQDN            -> merged
  medium   same short hostname, no conflicting strong identifier   -> merged
  weak     same IP only (DHCP/NAT reuse)                          -> POSSIBLY_SAME_AS candidate
"""

import hashlib
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass

from ..model.nodes import Asset, AssetRecord, IpAddress, rel
from .base import Batch, SourceAsset

CMDB_SOURCE = "servicenow"
STRONG = ("cloudInstanceId", "serial", "mac", "fqdn")
CONFIDENCE = {"strong": 95, "hostname": 70, "single": 100}
WEAK_IP_SCORE = 0.3
# Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) count as public on purpose:
# the synthetic estate uses them as stand-ins for internet addresses.
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (addr.is_loopback or addr.is_link_local or any(addr in n for n in _PRIVATE))


def _norm_mac(mac: str) -> str | None:
    digits = re.sub(r"[^0-9a-f]", "", mac.lower())
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)) if len(digits) == 12 else None


def short_name(name: str | None) -> str | None:
    if not name:
        return None
    return name.strip().lower().rstrip(".").split(".")[0] or None


def _strong(r: SourceAsset) -> dict[str, str]:
    vals = {
        "cloudInstanceId": r.cloudInstanceId,
        "serial": r.serial.upper() if r.serial else None,
        "mac": _norm_mac(r.mac) if r.mac else None,
        "fqdn": r.fqdn.lower().rstrip(".") if r.fqdn and "." in r.fqdn else None,
    }
    return {k: v for k, v in vals.items() if v}


class _UnionFind:
    def __init__(self, keys):
        self.parent = {k: k for k in keys}

    def find(self, k: str) -> str:
        while self.parent[k] != k:
            self.parent[k] = self.parent[self.parent[k]]
            k = self.parent[k]
        return k

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            lo, hi = sorted((ra, rb))
            self.parent[hi] = lo  # smallest key stays root: deterministic


def _conflict(groups: list[list[str]], strong: dict[str, dict[str, str]]) -> bool:
    """Two groups conflict if both know an identifier type and share no value for it."""
    for attr in STRONG:
        sets = [{strong[k][attr] for k in g if attr in strong[k]} for g in groups]
        sets = [s for s in sets if s]
        if any(a.isdisjoint(b) for i, a in enumerate(sets) for b in sets[i + 1 :]):
            return True
    return False


@dataclass
class Resolution:
    clusters: dict[str, list[SourceAsset]]  # assetId -> records
    asset_of: dict[str, str]  # recordKey -> assetId
    method: dict[str, str]  # recordKey -> strong:<attr> | hostname | single
    candidates: list[tuple[str, str, float]]  # (recordKey, other assetId, score)
    by_name: dict[str, str]  # unambiguous fqdn / short hostname -> assetId
    by_ip: dict[str, str]  # unambiguous ip -> assetId

    def lookup(self, host: str | None = None, ip: str | None = None) -> str | None:
        if host:
            h = host.strip().lower().rstrip(".")
            if aid := self.by_name.get(h) or self.by_name.get(short_name(h) or ""):
                return aid
        return self.by_ip.get(ip) if ip else None


def resolve(records: list[SourceAsset]) -> Resolution:
    recs = {r.recordKey: r for r in records}
    strong = {k: _strong(r) for k, r in recs.items()}
    uf = _UnionFind(recs)
    linked_by: dict[str, str] = {}

    index: dict[tuple[str, str], list[str]] = defaultdict(list)
    for k in sorted(recs):
        for attr, v in strong[k].items():
            index[(attr, v)].append(k)
    for (attr, _), keys in sorted(index.items()):
        if len(keys) > 1:
            for k in keys:
                linked_by.setdefault(k, f"strong:{attr}")
                uf.union(keys[0], k)

    groups: dict[str, list[str]] = defaultdict(list)
    for k in sorted(recs):
        groups[uf.find(k)].append(k)
    by_short: dict[str, list[str]] = defaultdict(list)
    for k in sorted(recs):
        if s := short_name(recs[k].hostname or recs[k].fqdn):
            by_short[s].append(k)
    for keys in by_short.values():
        roots = sorted({uf.find(k) for k in keys})
        if len(roots) < 2 or _conflict([groups[r] for r in roots], strong):
            continue
        for r in roots[1:]:
            uf.union(roots[0], r)
            groups[roots[0]] += groups.pop(r)
        for k in keys:
            linked_by.setdefault(k, "hostname")

    clusters: dict[str, list[SourceAsset]] = {}
    asset_of: dict[str, str] = {}
    for keys in groups.values():
        aid = _asset_id([recs[k] for k in keys], [strong[k] for k in keys])
        clusters[aid] = [recs[k] for k in sorted(keys)]
        for k in keys:
            asset_of[k] = aid

    names: dict[str, set[str]] = defaultdict(set)
    ips: dict[str, set[str]] = defaultdict(set)
    for k, r in recs.items():
        for n in (r.fqdn, r.hostname):
            if n:
                names[n.lower().rstrip(".")].add(asset_of[k])
                names[short_name(n) or ""].add(asset_of[k])
        if r.ip:
            ips[r.ip].add(asset_of[k])

    candidates = sorted(
        {
            (k, other, WEAK_IP_SCORE)
            for k, r in recs.items()
            if r.ip and len(ips[r.ip]) > 1
            for other in ips[r.ip]
            if other != asset_of[k]
        }
    )
    return Resolution(
        clusters=clusters,
        asset_of=asset_of,
        method={k: linked_by.get(k, "single") for k in recs},
        candidates=candidates,
        by_name={n: next(iter(a)) for n, a in names.items() if n and len(a) == 1},
        by_ip={ip: next(iter(a)) for ip, a in ips.items() if len(a) == 1},
    )


def _asset_id(records: list[SourceAsset], strong: list[dict[str, str]]) -> str:
    cmdb = sorted(r.sourceId for r in records if r.source == CMDB_SOURCE)
    if cmdb:
        return cmdb[0]
    idents = sorted(v for s in strong for v in s.values()) or sorted(r.recordKey for r in records)
    return "asset-" + hashlib.sha1(idents[0].encode()).hexdigest()[:12]


def build_assets(res: Resolution) -> Batch:
    """Asset, AssetRecord and IpAddress nodes plus their relationships from a Resolution."""
    out = Batch()
    for aid, recs in sorted(res.clusters.items()):
        cmdb = next((r for r in recs if r.source == CMDB_SOURCE), None)
        attrs: dict = {}
        for r in sorted(recs, key=lambda r: r.source != CMDB_SOURCE):  # CMDB attributes win
            for k, v in r.attrs.items():
                attrs.setdefault(k, v)
        hostname = short_name(cmdb.hostname if cmdb else None) or next(
            short_name(r.hostname or r.fqdn) for r in recs if r.hostname or r.fqdn
        )
        fqdn = next((r.fqdn.lower() for r in sorted(recs, key=lambda r: r.source != CMDB_SOURCE)
                     if r.fqdn and "." in r.fqdn), None)
        ips = sorted({r.ip for r in recs if r.ip})
        labels = {
            name
            for name, on in (
                ("InternetFacing", attrs.get("internetFacing") or any(map(is_public, ips))),
                ("CrownJewel", attrs.get("crownJewel")),
                ("Unmanaged", cmdb is None),
            )
            if on
        }
        first, last = min(r.firstSeen for r in recs), max(r.lastSeen for r in recs)
        asset = Asset(
            assetId=aid,
            hostname=hostname,
            fqdn=fqdn,
            assetType=attrs.get("assetType", "unknown"),
            os=attrs.get("os"),
            criticality=attrs.get("criticality", 3),
            owner=attrs.get("owner"),
            labels=frozenset(labels),
            unsetLabels=Asset.EXTRA_LABELS - labels,
            source="entity-resolution",
            confidence=100 if cmdb else 60,
            firstSeen=first,
            lastSeen=last,
        )
        out.nodes.append(asset)
        prov = {"source": "entity-resolution", "firstSeen": first, "lastSeen": last}
        if bu := attrs.get("businessUnit"):
            out.rels.append(rel("BELONGS_TO", asset, ("BusinessUnit", bu), confidence=90, **prov))
        for ip in ips:
            node = IpAddress(
                address=ip,
                version=ipaddress.ip_address(ip).version,
                labels=frozenset({"Public"} if is_public(ip) else ()),
                **prov,
            )
            out.nodes.append(node)
            out.rels.append(rel("HAS_IP", asset, node, **prov))
        for r in recs:
            record = AssetRecord(
                recordKey=r.recordKey,
                hostname=r.hostname,
                fqdn=r.fqdn,
                ip=r.ip,
                mac=r.mac,
                serial=r.serial,
                cloudInstanceId=r.cloudInstanceId,
                source=r.source,
                confidence=100,
                firstSeen=r.firstSeen,
                lastSeen=r.lastSeen,
            )
            method = res.method[r.recordKey]
            out.nodes.append(record)
            out.rels.append(
                rel(
                    "RESOLVES_TO",
                    record,
                    asset,
                    props={"method": method},
                    source="entity-resolution",
                    confidence=CONFIDENCE[method.split(":")[0]],
                    firstSeen=r.firstSeen,
                    lastSeen=r.lastSeen,
                )
            )
    for key, other, score in res.candidates:
        r = next(r for r in res.clusters[res.asset_of[key]] if r.recordKey == key)
        out.rels.append(
            rel(
                "POSSIBLY_SAME_AS",
                ("AssetRecord", key),
                ("Asset", other),
                props={"reason": "shared ip"},
                source="entity-resolution",
                confidence=int(score * 100),
                firstSeen=r.firstSeen,
                lastSeen=r.lastSeen,
            )
        )
    out.issues["entity-resolution: possible duplicates (ip only)"] = len(res.candidates)
    return out
