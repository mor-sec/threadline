"""FIRST EPSS exploit-prediction scores."""

from datetime import date

from ...model.nodes import Vulnerability
from .. import feeds
from ..base import Batch, Connector, Context


class EpssConnector(Connector):
    name = "epss"

    def extract(self, ctx: Context) -> tuple[dict[str, tuple[float, float]], date]:
        if ctx.mode == "live":
            raise NotImplementedError("live EPSS feed arrives in phase 4; use --mode sample")
        return feeds.epss()

    def transform(self, raw: tuple[dict[str, tuple[float, float]], date], ctx: Context) -> Batch:
        scores, score_date = raw
        prov = {"source": "first-epss", "confidence": 100, "firstSeen": ctx.as_of,
                "lastSeen": ctx.as_of}
        return Batch(nodes=[
            Vulnerability(cveId=cve, epssScore=score, epssPercentile=pct, epssDate=score_date,
                          **prov)
            for cve, (score, pct) in sorted(scores.items())
        ])
