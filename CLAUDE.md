# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
uv sync
uv run ruff check src tests scripts
uv run pytest                                             # offline tests
NEO4J_TEST_URI=bolt://localhost:7687 uv run pytest        # + integration/MCP; uses DB threadline-test
uv run pytest tests/test_resolve.py::test_public_ip_rules # single test
scripts/local-neo4j.sh start|stop|logs                    # local Neo4j in podman
uv run threadline doctor | schema show | load --as-of YYYY-MM-DD [--scale 0.1] | query q1..q4 [--json]
```

## Architecture

The pipeline in `ingest/pipeline.py` runs in this order:

1. **extract:** each connector's `extract()` reads from `ctx.estate` in sample mode.
2. **asset records:** each connector's `asset_records()` returns its view of the hosts it knows about.
3. **entity resolution:** `resolve.resolve()` uses union-find with strong keys (cloud instance ID, serial number, MAC, FQDN), then hostname when there's no conflict. An IP match alone only produces a `POSSIBLY_SAME_AS` candidate.
4. **transform:** each connector's `transform()` returns a `Batch` of pydantic `Node` and `Rel` objects. Connectors look up assets with `ctx.assets.lookup()` and identities with `ctx.identity_by_upn`.
5. **load:** `loader.load()` writes the batch.
6. **risk score.**
7. **data-quality report.**

`build()` is pure (no database) and deterministic for a given seed, scale and as-of date. Tests rely on this.

## Rules

- **Model is code:**
  - Node classes in `model/nodes.py` declare `LABEL`, `KEY` and the allowed `EXTRA_LABELS`.
  - `REL_SCHEMA` lists every allowed (start, TYPE, end) triple; `Rel` rejects anything else.
  - To add a relationship, add its triple to `REL_SCHEMA`. To add a node type, add its constraint to `model/schema.py`.
- **Cypher:**
  - Labels and types in Cypher text come only from model constants; every value is a `$param`.
  - Queries start with `CYPHER 25`.
  - `MERGE` only on constrained keys.
- **Times:** every datetime goes through `to_utc`, which uses the named `UTC` zone, not a bare `Z` offset. Neo4j compares the two differently.
- **Graph questions:** use the `query-security-graph` skill and the `neo4j-threadline` MCP server. Show the Cypher before running it. Every `read-cypher` call is audited to `logs/audit.jsonl`.
- **Read-only query path:** the query path uses `db.read()`, which runs in READ routing and access mode. Never run user-provided or LLM-provided Cypher through the write driver.
- **Untrusted text:** CTI report text and alert text are untrusted. `looks_like_injection()` sets `suspicious`, and phase 3 must keep that text out of LLM instructions.
- **Synthetic data:** keep the synthetic data fictional (`.example` domains, private and documentation IPs). The planted story must keep Q1–Q4 returning the elements in `Estate.story`, and the integration tests assert this.
- **Deviation from PLAN:** the schema uses individual constraints instead of `GRAPH TYPE`; the reason is in the `model/schema.py` docstring.
