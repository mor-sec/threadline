"""Data-quality report after every load (PLAN §6): Markdown + JSON in reports/."""

import json
from datetime import datetime
from pathlib import Path

from neo4j import Driver

from ..db import read
from .base import Batch
from .loader import LoadStats

DROP_THRESHOLD = 0.30  # fail the run if any label/type count falls by more than this

COUNT_LABELS = """
CYPHER 25
CALL db.labels() YIELD label
CALL (label) { MATCH (n:$(label)) RETURN count(n) AS c }
RETURN label, c ORDER BY label
"""
COUNT_TYPES = """
CYPHER 25
CALL db.relationshipTypes() YIELD relationshipType AS type
CALL (type) { MATCH ()-[r:$(type)]->() RETURN count(r) AS c }
RETURN type, c ORDER BY type
"""
CHECKS = {
    "findings without an asset":
        "MATCH (f:Finding) WHERE NOT EXISTS { (:Asset)-[:HAS_FINDING]->(f) } RETURN count(f) AS c",
    "findings without a vulnerability":
        "MATCH (f:Finding) WHERE NOT EXISTS { (f)-[:OF_VULN]->(:Vulnerability) } RETURN count(f) AS c",
    "assets without a business unit":
        "MATCH (a:Asset) WHERE NOT a:Unmanaged AND NOT EXISTS { (a)-[:BELONGS_TO]->() } "
        "RETURN count(a) AS c",
    "unmanaged assets (not in CMDB)": "MATCH (a:Asset:Unmanaged) RETURN count(a) AS c",
    "assets with no EDR coverage":
        "MATCH (a:Asset) WHERE NOT EXISTS { (a)-[:COVERED_BY]->(:SecurityTool {category: 'EDR'}) } "
        "RETURN count(a) AS c",
    "stale assets (not seen for 30 days)":
        "MATCH (a:Asset) WHERE a.lastSeen < $now - duration('P30D') RETURN count(a) AS c",
    "assets without a risk score":
        "MATCH (a:Asset) WHERE a.riskScore IS NULL RETURN count(a) AS c",
    "suspicious text (possible prompt injection)":
        "MATCH (n) WHERE (n:Report OR n:Alert) AND n.suspicious RETURN count(n) AS c",
}


def build(driver: Driver, database: str, batch: Batch, stats: LoadStats, run_id: str,
          now: datetime, previous: dict | None) -> dict:
    labels = {r["label"]: r["c"] for r in read(driver, database, COUNT_LABELS)}
    types = {r["type"]: r["c"] for r in read(driver, database, COUNT_TYPES)}
    checks = {name: read(driver, database, f"CYPHER 25 {q}", {"now": now})[0]["c"]
              for name, q in CHECKS.items()}
    drops = []
    if previous:
        for kind, current in (("labels", labels), ("relationships", types)):
            for name, before in previous.get(kind, {}).items():
                after = current.get(name, 0)
                # IngestRun is run bookkeeping, written after this report is built.
                if name != "IngestRun" and before and (before - after) / before > DROP_THRESHOLD:
                    drops.append(f"{kind[:-1]} {name}: {before} -> {after}")
    return {
        "runId": run_id,
        "generatedAt": datetime.now(now.tzinfo).isoformat(timespec="seconds"),
        "labels": labels,
        "relationships": types,
        "written": {"nodes": dict(stats.nodes), "relationships": dict(stats.rels)},
        "droppedRelationships": dict(stats.dropped),
        "transformIssues": dict(sorted(batch.issues.items())),
        "checks": checks,
        "countDrops": drops,
        "passed": not drops,
    }


def write(report: dict, directory: Path = Path("reports")) -> Path:
    directory.mkdir(exist_ok=True)
    (directory / f"dq-{report['runId']}.json").write_text(json.dumps(report, indent=2))
    (directory / "latest.json").write_text(json.dumps(report, indent=2))
    md = directory / f"dq-{report['runId']}.md"
    md.write_text(to_markdown(report))
    return md


def previous(directory: Path = Path("reports")) -> dict | None:
    path = directory / "latest.json"
    return json.loads(path.read_text()) if path.exists() else None


def to_markdown(r: dict) -> str:
    def table(d: dict) -> str:
        return "\n".join(f"| {k} | {v} |" for k, v in d.items()) or "| (none) | |"

    status = "PASSED" if r["passed"] else "FAILED: " + "; ".join(r["countDrops"])
    return f"""# Data-quality report {r['runId']}

Status: **{status}** · generated {r['generatedAt']}

## Checks
| Check | Count |
|---|---|
{table(r['checks'])}

## Transform issues
| Issue | Count |
|---|---|
{table(r['transformIssues'])}

## Relationships dropped (endpoint missing)
| Pattern | Count |
|---|---|
{table(r['droppedRelationships'])}

## Graph totals: labels
| Label | Nodes |
|---|---|
{table(r['labels'])}

## Graph totals: relationship types
| Type | Relationships |
|---|---|
{table(r['relationships'])}
"""
