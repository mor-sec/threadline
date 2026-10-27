"""Constraints and indexes (PLAN §5.5), generated from the node model.

Individual constraints rather than GRAPH TYPE DDL: they work on every Aura version, and
relationship endpoint types are already enforced by REL_SCHEMA before anything is written.
"""

import re

from neo4j import Driver

from .nodes import NODE_TYPES

TYPE_CONSTRAINTS = [
    ("Asset", "criticality", "INTEGER"),
    ("Asset", "riskScore", "FLOAT"),
    ("Finding", "cvssScore", "FLOAT"),
    ("Finding", "firstSeen", "ZONED DATETIME"),
    ("Vulnerability", "epssScore", "FLOAT"),
    ("Alert", "createdAt", "ZONED DATETIME"),
]
RANGE_INDEXES = [
    ("Asset", "hostname"),
    ("Asset", "firstSeen"),
    ("Finding", "status"),
    ("Finding", "firstSeen"),
    ("Finding", "fixedAt"),
    ("Alert", "createdAt"),
    ("Vulnerability", "epssScore"),
    ("Identity", "upn"),
    ("Indicator", "value"),
]


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).replace(" ", "_").lower()


def statements() -> list[str]:
    out = [
        f"CREATE CONSTRAINT {_snake(label)}_{_snake(cls.KEY)}_unique IF NOT EXISTS "
        f"FOR (n:{label}) REQUIRE n.{cls.KEY} IS UNIQUE"
        for label, cls in sorted(NODE_TYPES.items())
    ]
    out.append(
        "CREATE CONSTRAINT ingest_run_run_id_unique IF NOT EXISTS "
        "FOR (n:IngestRun) REQUIRE n.runId IS UNIQUE"
    )
    out += [
        f"CREATE CONSTRAINT {_snake(label)}_{_snake(prop)}_type IF NOT EXISTS "
        f"FOR (n:{label}) REQUIRE n.{prop} IS :: {typ}"
        for label, prop, typ in TYPE_CONSTRAINTS
    ]
    out += [
        f"CREATE INDEX {_snake(label)}_{_snake(prop)}_idx IF NOT EXISTS FOR (n:{label}) ON (n.{prop})"
        for label, prop in RANGE_INDEXES
    ]
    return out


def apply(driver: Driver, database: str) -> int:
    stmts = statements()
    for stmt in stmts:
        driver.execute_query(stmt, database_=database)
    driver.execute_query("CALL db.awaitIndexes(300)", database_=database)
    return len(stmts)
