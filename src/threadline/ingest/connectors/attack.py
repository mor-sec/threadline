"""MITRE ATT&CK Enterprise (STIX 2.1): tactics, techniques, groups, software, mitigations."""

from ...model.nodes import (
    REL_SCHEMA,
    Mitigation,
    Node,
    Software,
    Tactic,
    Technique,
    ThreatActor,
    rel,
)
from .. import feeds
from ..base import Batch, Connector, Context

REL_TYPES = {"uses": "USES", "mitigates": "MITIGATES", "subtechnique-of": "SUBTECHNIQUE_OF"}
ID_PREFIX = {"x-mitre-tactic": "TA", "attack-pattern": "T", "intrusion-set": "G",
             "malware": "S", "tool": "S", "course-of-action": "M"}


class AttackConnector(Connector):
    name = "attack"

    def extract(self, ctx: Context) -> dict:
        if ctx.mode == "live":
            raise NotImplementedError("live ATT&CK download arrives in phase 4; use --mode sample")
        return feeds.attack()

    def transform(self, raw: dict, ctx: Context) -> Batch:
        out = Batch()
        prov = {"source": "mitre-attack", "confidence": 100, "firstSeen": ctx.as_of,
                "lastSeen": ctx.as_of}
        version = raw["attack_version"]
        matrix = next(o for o in raw["objects"] if o["type"] == "x-mitre-matrix")
        order = {ref: i for i, ref in enumerate(matrix.get("tactic_refs", []))}
        key_of: dict[str, tuple[str, str]] = {}
        tactic_by_short: dict[str, str] = {}
        phases: dict[str, list[str]] = {}

        for o in raw["objects"]:
            kind, eid = o["type"], o.get("external_id")
            if kind == "x-mitre-matrix":
                continue
            if not eid or not eid.startswith(ID_PREFIX[kind]):
                out.issues[f"attack: {kind} without a valid ATT&CK id"] += 1
                continue
            node: Node
            if kind == "x-mitre-tactic":
                node = Tactic(tacticId=eid, name=o["name"], shortName=o["x_mitre_shortname"],
                              matrixOrder=order.get(o["id"], 99), **prov)
                tactic_by_short[o["x_mitre_shortname"]] = eid
            elif kind == "attack-pattern":
                node = Technique(
                    techniqueId=eid, name=o["name"], description=o.get("description"),
                    platforms=o.get("x_mitre_platforms", []), stixId=o["id"],
                    attackVersion=version, url=o.get("url"),
                    labels=frozenset({"SubTechnique"} if o.get("x_mitre_is_subtechnique") else ()),
                    **prov,
                )
                phases[eid] = o.get("kill_chain_phases", [])
            elif kind == "intrusion-set":
                aliases = o.get("aliases", [])
                node = ThreatActor(actorId=eid, name=o["name"], aliases=aliases,
                                   aliasText=" ".join(aliases), description=o.get("description"),
                                   stixId=o["id"], **prov)
            elif kind in ("malware", "tool"):
                node = Software(softwareId=eid, name=o["name"], softwareType=kind,
                                description=o.get("description"), **prov)
            else:
                node = Mitigation(mitigationId=eid, name=o["name"],
                                  description=o.get("description"), **prov)
            out.nodes.append(node)
            key_of[o["id"]] = (node.LABEL, node.key)

        for tid, shorts in phases.items():
            for short in shorts:
                out.rels.append(rel("IN_TACTIC", ("Technique", tid),
                                    ("Tactic", tactic_by_short[short]), **prov))
        for r in raw["relationships"]:
            src, dst = key_of.get(r["source_ref"]), key_of.get(r["target_ref"])
            typ = REL_TYPES[r["relationship_type"]]
            if src and dst and (src[0], typ, dst[0]) in REL_SCHEMA:
                out.rels.append(rel(typ, src, dst, **prov))
        return out
