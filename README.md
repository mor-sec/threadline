# Threadline

![Threadline: ten sources flow through entity resolution and an idempotent loader into a Neo4j security graph that answers four analyst questions with the supporting path](docs/threadline.svg)

A security knowledge graph on Neo4j covering assets, identities, vulnerabilities, threat actors, ATT&CK techniques and controls. It is built to answer analyst questions with traceable, graph-grounded evidence. The design and phases are in [docs/PLAN.md](docs/PLAN.md).

**Status:** Phase 1 is done: data model, synthetic estate, idempotent loader, data-quality reports and the four target queries. Phase 2 (MCP and natural-language querying) is next.

## Setup

```bash
uv sync                          # Python 3.13 + deps into .venv
cp .env.example .env             # then fill in your Aura URI and credentials
uv run threadline doctor           # checks both connections
```

On Aura Professional there is no RBAC, so the read and write settings can use the same account. Read-only access is enforced in code: query-path transactions run in READ access mode, and the database rejects writes made in that mode.

### Local Neo4j (tests and offline work)

```bash
scripts/local-neo4j.sh start     # podman, Neo4j 2026.10 Enterprise (eval), 127.0.0.1 only
```

To point the CLI at it, set `NEO4J_URI=bolt://localhost:7687` with user `neo4j` and password `threadline-local-dev` in `.env`.

## Load

```bash
uv run threadline load --as-of 2026-10-27              # ~3k assets, ~48k nodes, ~104k rels
uv run threadline load --scale 0.1                      # small estate
```

Each run does the following:

1. Generates the synthetic estate ("Kestrel Bank", fictional).
2. Reads the public ATT&CK, KEV and EPSS snapshots in `src/threadline/ingest/fixtures/`.
3. Resolves assets across sources.
4. MERGEs everything in batches of 1,000.
5. Scores asset risk.
6. Writes `reports/dq-<run>.md` and `.json`.

Re-running is safe: counts stay the same. The command exits with code 2 if any label or relationship count drops by more than 30% compared with the previous run. To refresh the public fixtures, run `uv run python scripts/build_fixtures.py`.

## Ask the four questions

```bash
uv run threadline query q1   # internet-facing assets × techniques of actors targeting our sector, + mitigations
uv run threadline query q2   # attack paths from recently phished users to crown jewels
uv run threadline query q3   # KEV vulnerabilities on assets with no/stale EDR
uv run threadline query q4 --since 2026-10-20   # exposure changes since a date
```

Each query prints the exact Cypher and parameters before the results. Add `--json` for machine-readable output. The queries run read-only, use parameters for every value, and return node IDs (`assetId`, `pathNodeIds`) for provenance.

## The planted story

The synthetic data contains a story for the queries to find:

- **Q1:** FIN7 targets Financial Services and uses T1190. `vpn-gw-01` is internet-facing and has an open finding on the newest Ivanti Connect Secure KEV CVE, which is also mentioned in a FIN7 report. It is the top Q1 row.
- **Q2:** A user phished two days before `--as-of` can reach `core-banking-db01` and the other crown jewels. The path is: their workstation, a Domain Admin session left on it, the Domain Admins group, and that group's `ADMIN_TO` rights.
- **Q3:**
  - `vpn-gw-01` has no EDR;
  - `srv-rb-app01` has EDR that has been stale for more than 7 days;
  - `rogue-nas01` is unmanaged (not in the CMDB).
- **Q4:** `vm-pay-gateway01` is a new internet-facing asset, and recent KEV additions now apply to existing findings.
- **Untrusted text:** one CTI report and one alert contain prompt-injection text. They are flagged `suspicious` and counted in the data-quality report, to exercise the phase 3 guards.

## Tests

```bash
uv run pytest                                          # unit + offline pipeline tests
NEO4J_TEST_URI=bolt://localhost:7687 uv run pytest     # + integration (WIPES that database)
uv run ruff check src tests scripts
```

The integration fixture refuses any database that isn't on localhost.

## Layout

| Path | What |
|---|---|
| `src/threadline/model/` | pydantic node and relationship models, the allowed relationship schema, constraints and indexes, risk score |
| `src/threadline/ingest/` | connectors (one per source, sample mode for each), entity resolution, synthetic estate, loader, DQ report, pipeline |
| `src/threadline/graphrag/` | curated query templates; phase 3 adds the GraphRAG layer |
| `src/threadline/cli.py` | `threadline doctor / schema / load / query` |
| `docs/PLAN.md` | approved plan: model, security, phases |

## Data handling

All data is either synthetic or public (MITRE ATT&CK, CISA KEV, FIRST EPSS). Synthetic names use `.example` domains, and IPs come from the private and documentation ranges. Before ingesting any real organisational data, do the classification check described in PLAN §10.
