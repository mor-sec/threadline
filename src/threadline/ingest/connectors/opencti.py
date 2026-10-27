"""OpenCTI as a STIX 2.1 bundle: actors, sector targeting, reports, indicators."""

import re

from ...model.nodes import Indicator, Node, Report, Sector, ThreatActor, Vulnerability, rel
from ..base import Batch, Connector, Context, looks_like_injection, parse_ts

TLP_BY_ID = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
}
_PATTERN = re.compile(r"\[([a-z0-9-]+):value\s*=\s*'([^']+)'\]")


def _mitre_id(obj: dict) -> str | None:
    return next((r.get("external_id") for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"), None)


class OpenCtiConnector(Connector):
    name = "opencti"

    def extract(self, ctx: Context) -> dict:
        self.sample_or_live(ctx)
        return ctx.estate.opencti

    def transform(self, raw: dict, ctx: Context) -> Batch:
        out = Batch()
        prov = {"source": "opencti", "firstSeen": ctx.as_of, "lastSeen": ctx.as_of}
        key_of: dict[str, tuple[str, str]] = {}
        for o in raw["objects"]:
            kind = o["type"]
            node: Node | None = None
            if kind == "identity" and o.get("identity_class") == "class":
                node = Sector(name=o["name"], **prov)
            elif kind == "intrusion-set":
                aliases = o.get("aliases", [])
                node = ThreatActor(actorId=_mitre_id(o) or o["id"], name=o["name"],
                                   aliases=aliases, aliasText=" ".join(aliases),
                                   confidence=o.get("confidence", 70), **prov)
            elif kind == "attack-pattern" and (tid := _mitre_id(o)):
                key_of[o["id"]] = ("Technique", tid)  # owned by the ATT&CK connector
            elif kind == "vulnerability":
                node = Vulnerability(cveId=o["name"], **prov)
            elif kind == "report":
                tlp = next((TLP_BY_ID[m] for m in o.get("object_marking_refs", [])
                            if m in TLP_BY_ID), "TLP:CLEAR")
                text = o.get("description", "")
                node = Report(reportId=o["id"], title=o["name"], published=parse_ts(o["published"]),
                              summary=text, tlp=tlp, suspicious=looks_like_injection(text),
                              **prov)
                if node.suspicious:
                    out.issues["opencti: report text looks like prompt injection"] += 1
            elif kind == "indicator":
                if m := _PATTERN.fullmatch(o["pattern"].strip()):
                    node = Indicator(indicatorId=f"{m[1]}:{m[2]}", indicatorType=m[1],
                                     value=m[2], pattern=o["pattern"], confidence=60, **prov)
                else:
                    out.issues["opencti: indicator pattern not supported"] += 1
            if node:
                out.nodes.append(node)
                key_of[o["id"]] = (node.LABEL, node.key)

        types = {"targets": "TARGETS", "uses": "USES", "indicates": "ATTRIBUTED_TO"}
        for o in raw["objects"]:
            if o["type"] == "relationship" and o["relationship_type"] in types:
                src, dst = key_of.get(o["source_ref"]), key_of.get(o["target_ref"])
                if src and dst:
                    out.rels.append(rel(types[o["relationship_type"]], src, dst,
                                        confidence=o.get("confidence", 70), **prov))
            elif o["type"] == "report":
                for ref in o.get("object_refs", []):
                    if (dst := key_of.get(ref)) and dst[0] in ("ThreatActor", "Technique",
                                                               "Vulnerability"):
                        out.rels.append(rel("MENTIONS", ("Report", o["id"]), dst, **prov))
        return out
