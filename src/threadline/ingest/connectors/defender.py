"""Defender for Endpoint: device inventory (EDR coverage) and logged-on users (sessions)."""

from ...model.nodes import SecurityTool, rel
from ..base import Batch, Connector, Context, SourceAsset, parse_ts
from ..resolve import short_name

TOOL = {"toolId": "mde", "name": "Microsoft Defender for Endpoint", "category": "EDR"}


class DefenderConnector(Connector):
    name = "defender"

    def extract(self, ctx: Context) -> dict:
        self.sample_or_live(ctx)
        return {"devices": ctx.estate.defender_devices, "logons": ctx.estate.defender_logons}

    def asset_records(self, raw: dict, ctx: Context) -> list[SourceAsset]:
        return [
            SourceAsset(source=self.name, sourceId=d["id"], firstSeen=parse_ts(d["firstSeen"]),
                        lastSeen=parse_ts(d["lastSeen"]), hostname=short_name(d["computerDnsName"]),
                        fqdn=d["computerDnsName"], ip=d["lastIpAddress"],
                        attrs={"os": d["osPlatform"]})
            for d in raw["devices"]
        ]

    def transform(self, raw: dict, ctx: Context) -> Batch:
        tool = SecurityTool(**TOOL, source=self.name, confidence=100, firstSeen=ctx.as_of,
                            lastSeen=ctx.as_of)
        out = Batch(nodes=[tool])
        asset_of = {d["id"]: ctx.assets.asset_of[f"{self.name}:{d['id']}"] for d in raw["devices"]}
        for d in raw["devices"]:
            last = parse_ts(d["lastSeen"])
            out.rels.append(rel(
                "COVERED_BY", ("Asset", asset_of[d["id"]]), tool,
                props={"lastCheckIn": last, "healthStatus": d["healthStatus"],
                       "onboardingStatus": d["onboardingStatus"]},
                source=self.name, confidence=100, firstSeen=parse_ts(d["firstSeen"]),
                lastSeen=last,
            ))
        for lg in raw["logons"]:
            identity = ctx.identity_by_upn.get(lg["accountName"].lower())
            if not identity:
                out.issues["defender: logon by unknown account"] += 1
                continue
            last = parse_ts(lg["lastSeen"])
            out.rels.append(rel(
                "HAS_SESSION", ("Asset", asset_of[lg["deviceId"]]), ("Identity", identity),
                props={"logonTypes": lg["logonTypes"]}, source=self.name, confidence=90,
                firstSeen=last, lastSeen=last,
            ))
        return out
