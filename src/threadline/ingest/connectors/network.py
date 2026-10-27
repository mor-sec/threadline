"""Firewall policy analysis: which assets can reach which (allowed flows), for lateral movement."""

from collections import defaultdict

from ...model.nodes import rel
from ..base import Batch, Connector, Context


class NetworkConnector(Connector):
    name = "firewall-policy"

    def extract(self, ctx: Context) -> list[dict]:
        self.sample_or_live(ctx)
        return ctx.estate.network

    def transform(self, raw: list[dict], ctx: Context) -> Batch:
        out = Batch()
        ports: dict[tuple[str, str], set[int]] = defaultdict(set)
        for f in raw:
            src, dst = ctx.assets.lookup(ip=f["src_ip"]), ctx.assets.lookup(ip=f["dst_ip"])
            if not (src and dst):
                out.issues["firewall-policy: flow endpoint not resolved to an asset"] += 1
            elif f["action"] == "allow" and src != dst:
                ports[(src, dst)].add(f["dst_port"])
        out.rels = [
            rel("CAN_REACH", ("Asset", src), ("Asset", dst), props={"ports": sorted(p)},
                source=self.name, confidence=70, firstSeen=ctx.as_of, lastSeen=ctx.as_of)
            for (src, dst), p in sorted(ports.items())
        ]
        return out
