"""CISA Known Exploited Vulnerabilities catalog."""

from datetime import date

from ...model.nodes import Vulnerability, rel
from .. import feeds
from ..base import Batch, Connector, Context

EDGE_VENDORS = {"Ivanti", "Fortinet", "Citrix", "Palo Alto Networks", "SonicWall", "F5",
                "Cisco", "Juniper", "Check Point", "Zyxel", "Pulse Secure", "Atlassian"}


def exploited_by(v: dict) -> str:
    # shortcut: keyword heuristic stands in for CTID's KEV->ATT&CK mappings; replaced in phase 4.
    name = v.get("vulnerabilityName", "").lower()
    if v["vendorProject"] in EDGE_VENDORS:
        return "T1190"  # Exploit Public-Facing Application
    if "privilege escalation" in name or "elevation of privilege" in name:
        return "T1068"  # Exploitation for Privilege Escalation
    return "T1203"  # Exploitation for Client Execution


class KevConnector(Connector):
    name = "kev"

    def extract(self, ctx: Context) -> dict:
        if ctx.mode == "live":
            raise NotImplementedError("live KEV feed arrives in phase 4; use --mode sample")
        return feeds.kev()

    def transform(self, raw: dict, ctx: Context) -> Batch:
        out = Batch()
        prov = {"source": "cisa-kev", "firstSeen": ctx.as_of, "lastSeen": ctx.as_of}
        for v in raw["vulnerabilities"]:
            node = Vulnerability(
                cveId=v["cveID"],
                name=v.get("vulnerabilityName"),
                vendorProject=v.get("vendorProject"),
                product=v.get("product"),
                kevDateAdded=date.fromisoformat(v["dateAdded"]),
                kevDueDate=date.fromisoformat(v["dueDate"]) if v.get("dueDate") else None,
                kevRansomware=v.get("knownRansomwareCampaignUse") == "Known",
                labels=frozenset({"KEV"}),
                confidence=100,
                **prov,
            )
            out.nodes.append(node)
            out.rels.append(rel("EXPLOITED_BY", node, ("Technique", exploited_by(v)),
                                props={"method": "vendor-keyword-heuristic"}, confidence=30,
                                **prov))
        return out
