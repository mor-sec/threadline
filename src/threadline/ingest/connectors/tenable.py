"""Tenable vulnerability export: scanned hosts and their findings."""

from ...model.nodes import Finding, Vulnerability, rel
from ..base import Batch, Connector, Context, SourceAsset, parse_ts


class TenableConnector(Connector):
    name = "tenable"

    def extract(self, ctx: Context) -> list[dict]:
        self.sample_or_live(ctx)
        return ctx.estate.tenable

    def asset_records(self, raw: list[dict], ctx: Context) -> list[SourceAsset]:
        seen: dict[str, dict] = {}
        for row in raw:
            a = row["asset"]
            first, last = parse_ts(row["first_found"]), parse_ts(row["last_found"])
            if a["uuid"] in seen:
                s = seen[a["uuid"]]
                s["first"], s["last"] = min(s["first"], first), max(s["last"], last)
            else:
                seen[a["uuid"]] = {"asset": a, "first": first, "last": last}
        return [
            SourceAsset(source=self.name, sourceId=uid, firstSeen=s["first"], lastSeen=s["last"],
                        hostname=s["asset"]["hostname"], fqdn=s["asset"]["fqdn"],
                        ip=s["asset"]["ipv4"], mac=s["asset"]["mac_address"])
            for uid, s in sorted(seen.items())
        ]

    def transform(self, raw: list[dict], ctx: Context) -> Batch:
        out = Batch()
        vulns: dict[str, Vulnerability] = {}
        for row in raw:
            asset = ctx.assets.asset_of[f"{self.name}:{row['asset']['uuid']}"]
            first, last = parse_ts(row["first_found"]), parse_ts(row["last_found"])
            prov = {"source": self.name, "confidence": 90, "firstSeen": first, "lastSeen": last}
            fixed = row["state"] == "FIXED"
            for cve in row["plugin"]["cve"]:
                finding = Finding(
                    findingId=f"{asset}:{cve}:{row['port']['port']}",
                    status="fixed" if fixed else "open",
                    severity=row["severity"],
                    cvssScore=row["plugin"]["cvss3_base_score"],
                    port=row["port"]["port"],
                    protocol=row["port"]["protocol"],
                    pluginId=str(row["plugin"]["id"]),
                    fixedAt=parse_ts(row["last_fixed"]) if fixed else None,
                    **prov,
                )
                vulns.setdefault(cve, Vulnerability(cveId=cve, **prov))
                out.nodes.append(finding)
                out.rels.append(rel("HAS_FINDING", ("Asset", asset), finding, **prov))
                out.rels.append(rel("OF_VULN", finding, ("Vulnerability", cve), **prov))
        out.nodes += vulns.values()
        return out
