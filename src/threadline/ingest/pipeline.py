"""Extract -> resolve -> transform -> load -> score -> data-quality report."""

import json
from datetime import datetime

from neo4j import Driver

from ..model import risk, schema
from . import dq, loader, synthetic
from .base import Batch, Connector, Context, Mode
from .connectors.attack import AttackConnector
from .connectors.cmdb import CmdbConnector
from .connectors.defender import DefenderConnector
from .connectors.entra import EntraConnector, identity_index
from .connectors.epss import EpssConnector
from .connectors.kev import KevConnector
from .connectors.network import NetworkConnector
from .connectors.opencti import OpenCtiConnector
from .connectors.sentinel import SentinelConnector
from .connectors.tenable import TenableConnector
from .resolve import build_assets, resolve

CONNECTORS: list[Connector] = [
    AttackConnector(), KevConnector(), EpssConnector(), OpenCtiConnector(), EntraConnector(),
    CmdbConnector(), TenableConnector(), DefenderConnector(), NetworkConnector(),
    SentinelConnector(),
]


def build(mode: Mode, as_of: datetime, seed: int = 42, scale: float = 1.0) -> tuple[Batch, Context]:
    """Everything up to the database: pure and deterministic for a given input."""
    estate = synthetic.generate(as_of, seed=seed, scale=scale) if mode == "sample" else None
    ctx = Context(mode=mode, as_of=as_of, estate=estate)
    raws = {c.name: c.extract(ctx) for c in CONNECTORS}
    ctx.assets = resolve([r for c in CONNECTORS for r in c.asset_records(raws[c.name], ctx)])
    ctx.identity_by_upn = identity_index(raws["entra"])
    batch = build_assets(ctx.assets)
    for c in CONNECTORS:
        batch.extend(c.transform(raws[c.name], ctx))
    return batch, ctx


def run(driver: Driver, database: str, mode: Mode, as_of: datetime, seed: int = 42,
        scale: float = 1.0, log=print) -> dict:
    started = datetime.now(as_of.tzinfo)
    run_id = started.strftime("%Y%m%dT%H%M%S")
    log(f"building {mode} batch (as of {as_of:%Y-%m-%d}, scale {scale}, seed {seed})")
    batch, _ = build(mode, as_of, seed, scale)
    log(f"  {len(batch.nodes):,} nodes, {len(batch.rels):,} relationships")
    log(f"applying schema: {schema.apply(driver, database)} constraints/indexes")
    stats = loader.load(driver, database, batch, run_id)
    log(f"loaded: {sum(stats.nodes.values()):,} node writes, "
        f"{sum(stats.rels.values()):,} relationship writes")
    log(f"risk scores: {risk.apply(driver, database, as_of):,} assets")
    report = dq.build(driver, database, batch, stats, run_id, as_of, dq.previous())
    driver.execute_query(
        "CYPHER 25 MERGE (r:IngestRun {runId: $runId}) "
        "SET r.mode = $mode, r.asOf = $asOf, r.startedAt = $started, "
        "r.finishedAt = datetime(), r.countsJson = $counts, r.passed = $passed",
        runId=run_id, mode=mode, asOf=as_of, started=started, passed=report["passed"],
        counts=json.dumps(report["written"]), database_=database,
    )
    log(f"data-quality report: {dq.write(report)} ({'passed' if report['passed'] else 'FAILED'})")
    return report
