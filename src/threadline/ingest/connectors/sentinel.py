"""Microsoft Sentinel SecurityAlert: alerts, the assets/identities involved, techniques, TI matches."""

import json

from ...model.nodes import Alert, rel
from ..base import Batch, Connector, Context, looks_like_injection, parse_ts


class SentinelConnector(Connector):
    name = "sentinel"

    def extract(self, ctx: Context) -> list[dict]:
        self.sample_or_live(ctx)
        return ctx.estate.sentinel

    def transform(self, raw: list[dict], ctx: Context) -> Batch:
        out = Batch()
        for a in raw:
            when = parse_ts(a["TimeGenerated"])
            prov = {"source": self.name, "confidence": 80, "firstSeen": when, "lastSeen": when}
            alert = Alert(
                alertId=a["SystemAlertId"], title=a["AlertName"], severity=a["AlertSeverity"],
                status=a["Status"], createdAt=when, description=a["Description"],
                productName=a["ProductName"], suspicious=looks_like_injection(a["Description"]),
                **prov,
            )
            out.nodes.append(alert)
            if alert.suspicious:
                out.issues["sentinel: alert text looks like prompt injection"] += 1
            entities = json.loads(a["Entities"])
            ips = [e["Address"] for e in entities if e["Type"] == "ip"]
            for e in entities:
                if e["Type"] == "host":
                    host = e["HostName"] + (f".{e['DnsDomain']}" if e.get("DnsDomain") else "")
                    if asset := ctx.assets.lookup(host=host):
                        out.rels.append(rel("OBSERVED_ON", alert, ("Asset", asset), **prov))
                    else:
                        out.issues["sentinel: host entity not resolved to an asset"] += 1
                elif e["Type"] == "account":
                    upn = f"{e['Name']}@{e['UPNSuffix']}".lower() if e.get("UPNSuffix") else ""
                    if identity := e.get("AadUserId") or ctx.identity_by_upn.get(upn):
                        out.rels.append(rel("INVOLVES", alert, ("Identity", identity), **prov))
                    else:
                        out.issues["sentinel: account entity not resolved to an identity"] += 1
            # Sub-techniques are more specific; fall back to the parent technique ids.
            for tid in json.loads(a["SubTechniques"]) or json.loads(a["Techniques"]):
                out.rels.append(rel("INDICATES", alert, ("Technique", tid), **prov))
            if a["AlertName"].startswith("TI map"):
                for ip in ips:
                    out.rels.append(rel("MATCHED", alert, ("Indicator", f"ipv4-addr:{ip}"),
                                        **prov))
        return out
