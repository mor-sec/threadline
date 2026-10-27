"""threadline command line: doctor, schema, load, query."""

import argparse
import json
import sys
from datetime import date, datetime, time

from pydantic import ValidationError

from . import db
from .config import Settings
from .graphrag.templates import TEMPLATES
from .ingest import pipeline
from .model import schema
from .model.nodes import UTC


def _settings() -> Settings:
    try:
        return Settings()
    except ValidationError as e:
        missing = ", ".join(str(err["loc"][0]).upper() for err in e.errors())
        sys.exit(f"Missing settings: {missing}. Copy .env.example to .env and fill it in.")


def _day(value: str) -> datetime:
    return datetime.combine(date.fromisoformat(value), time(), UTC)


def cmd_doctor(args: argparse.Namespace) -> int:
    s = _settings()
    print(f"uri      {s.neo4j_uri}  database {s.neo4j_database}")
    ok = True
    for role in ("write", "read"):
        try:
            with db.connect(s, role) as driver:
                driver.verify_connectivity()
                row = db.read(driver, s.neo4j_database,
                              "CALL dbms.components() YIELD name, versions, edition "
                              "WHERE name = 'Neo4j Kernel' RETURN versions[0] AS v, edition")[0]
                nodes = db.read(driver, s.neo4j_database,
                                "MATCH (n) RETURN count(n) AS c")[0]["c"]
                print(f"{role:8} ok   Neo4j {row['v']} {row['edition']}, {nodes:,} nodes")
        except Exception as e:  # report every failure, don't stop at the first
            ok = False
            print(f"{role:8} FAIL {type(e).__name__}: {e}")
    if s.neo4j_read_username == s.neo4j_write_username:
        print("note     read and write use the same account (expected on Aura Professional; "
              "read-only is enforced in code)")
    return 0 if ok else 1


def cmd_schema(args: argparse.Namespace) -> int:
    if args.action == "show":
        print(";\n".join(schema.statements()) + ";")
        return 0
    s = _settings()
    with db.connect(s, "write") as driver:
        print(f"applied {schema.apply(driver, s.neo4j_database)} constraints/indexes")
    return 0


def cmd_load(args: argparse.Namespace) -> int:
    s = _settings()
    with db.connect(s, "write") as driver:
        report = pipeline.run(driver, s.neo4j_database, args.mode, args.as_of, args.seed,
                              args.scale)
    return 0 if report["passed"] else 2


def cmd_query(args: argparse.Namespace) -> int:
    s = _settings()
    t = TEMPLATES[args.name]
    now = datetime.now(UTC)
    params = t.params(org_id=s.org_id, now=now, since=args.since)
    if not args.json:
        print(f"-- {t.question}\n{t.cypher}\n-- params: "
              f"{json.dumps(params, default=str)}\n")
    with db.connect(s, "read") as driver:
        rows = db.read(driver, s.neo4j_database, t.cypher, params)
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return 0
    for row in rows:
        print("  ".join(f"{k}={v}" for k, v in row.items()))
    print(f"\n{len(rows)} row(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="threadline", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check settings and connectivity").set_defaults(func=cmd_doctor)

    sp = sub.add_parser("schema", help="show or apply constraints and indexes")
    sp.add_argument("action", choices=["show", "apply"])
    sp.set_defaults(func=cmd_schema)

    lp = sub.add_parser("load", help="extract, resolve, load, score and report")
    lp.add_argument("--mode", choices=["sample", "live"], default="sample")
    lp.add_argument("--as-of", type=_day, default=_day(date.today().isoformat()),
                    help="anchor date for synthetic data (default: today)")
    lp.add_argument("--scale", type=float, default=1.0, help="synthetic estate size (1.0 ≈ 3k assets)")
    lp.add_argument("--seed", type=int, default=42)
    lp.set_defaults(func=cmd_load)

    qp = sub.add_parser("query", help="run a named analyst query (read-only)")
    qp.add_argument("name", choices=sorted(TEMPLATES))
    qp.add_argument("--since", type=_day, help="for q4 (default: 7 days ago)")
    qp.add_argument("--json", action="store_true")
    qp.set_defaults(func=cmd_query)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
