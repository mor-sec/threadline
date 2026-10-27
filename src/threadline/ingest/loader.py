"""Idempotent batched loader: UNWIND + MERGE on constrained keys (PLAN §6).

Labels, keys and relationship types in the Cypher text come from the model classes and
REL_SCHEMA (code), never from data; every value is a parameter.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from itertools import batched

from neo4j import Driver

from ..model.nodes import NODE_TYPES, Node, Rel
from .base import Batch

BATCH_SIZE = 1000

_PROVENANCE = """
ON CREATE SET {v}.firstSeen = row.firstSeen, {v}.sources = [row.source]
ON MATCH SET {v}.firstSeen = CASE WHEN row.firstSeen < {v}.firstSeen THEN row.firstSeen
                                  ELSE {v}.firstSeen END,
             {v}.sources = CASE WHEN row.source IN {v}.sources THEN {v}.sources
                                ELSE {v}.sources + row.source END
SET {v} += row.props,
    {v}.lastSeen = CASE WHEN {v}.lastSeen IS NULL OR row.lastSeen > {v}.lastSeen
                        THEN row.lastSeen ELSE {v}.lastSeen END,
    {v}.lastRunId = $runId
"""


def node_query(cls: type[Node]) -> str:
    q = f"CYPHER 25\nUNWIND $rows AS row\nMERGE (n:{cls.LABEL} {{{cls.KEY}: row.key}})"
    q += _PROVENANCE.format(v="n")
    if cls.EXTRA_LABELS:
        q += "SET n:$(row.addLabels)\nREMOVE n:$(row.removeLabels)\n"
    return q + "RETURN count(n) AS written"


def rel_query(start: str, typ: str, end: str) -> str:
    sk, ek = NODE_TYPES[start].KEY, NODE_TYPES[end].KEY
    return (
        f"CYPHER 25\nUNWIND $rows AS row\n"
        f"MATCH (s:{start} {{{sk}: row.start}})\nMATCH (e:{end} {{{ek}: row.end}})\n"
        f"MERGE (s)-[r:{typ}]->(e)" + _PROVENANCE.format(v="r") + "RETURN count(r) AS written"
    )


@dataclass
class LoadStats:
    nodes: Counter[str] = field(default_factory=Counter)
    rels: Counter[str] = field(default_factory=Counter)
    dropped: Counter[str] = field(default_factory=Counter)  # rels whose endpoint doesn't exist


def _node_row(n: Node) -> dict:
    return {"key": n.key, "props": n.props(), "source": n.source, "firstSeen": n.firstSeen,
            "lastSeen": n.lastSeen, "addLabels": sorted(n.labels),
            "removeLabels": sorted(n.unsetLabels)}


def _rel_row(r: Rel) -> dict:
    props = {**r.props, "source": r.source, "confidence": r.confidence}
    return {"start": r.start, "end": r.end, "props": props, "source": r.source,
            "firstSeen": r.firstSeen, "lastSeen": r.lastSeen}


def _write(driver: Driver, database: str, query: str, rows: list[dict], run_id: str) -> int:
    records, _, _ = driver.execute_query(query, rows=rows, runId=run_id, database_=database)
    return records[0]["written"]


def load(driver: Driver, database: str, batch: Batch, run_id: str) -> LoadStats:
    stats = LoadStats()
    nodes: dict[type[Node], list[Node]] = defaultdict(list)
    for n in batch.nodes:
        nodes[type(n)].append(n)
    for cls, items in nodes.items():  # all nodes first, so relationship endpoints exist
        q = node_query(cls)
        for chunk in batched(items, BATCH_SIZE, strict=False):
            stats.nodes[cls.LABEL] += _write(driver, database, q, [_node_row(n) for n in chunk],
                                             run_id)
    rels: dict[tuple[str, str, str], list[Rel]] = defaultdict(list)
    for r in batch.rels:
        rels[(r.startLabel, r.type, r.endLabel)].append(r)
    for (start, typ, end), items in sorted(rels.items()):
        q = rel_query(start, typ, end)
        for chunk in batched(items, BATCH_SIZE, strict=False):
            written = _write(driver, database, q, [_rel_row(r) for r in chunk], run_id)
            stats.rels[typ] += written
            if missing := len(chunk) - written:
                stats.dropped[f"({start})-[:{typ}]->({end})"] += missing
    return stats
