import os
from datetime import date, datetime, time
from urllib.parse import urlparse

import pytest
from neo4j import GraphDatabase

from threadline.ingest import pipeline
from threadline.model.nodes import UTC

AS_OF = datetime.combine(date.today(), time(), UTC)
SCALE = 0.2


@pytest.fixture(scope="session")
def sample():
    """(batch, ctx) for a small synthetic estate: no database needed."""
    return pipeline.build("sample", AS_OF, seed=42, scale=SCALE)


@pytest.fixture(scope="session")
def neo4j_test():
    """A disposable local database. Wiped before use, so it must be localhost."""
    uri = os.environ.get("NEO4J_TEST_URI")
    if not uri:
        pytest.skip("set NEO4J_TEST_URI (scripts/local-neo4j.sh) to run integration tests")
    if urlparse(uri).hostname not in ("localhost", "127.0.0.1"):
        pytest.fail(f"refusing to wipe non-local database {uri}")
    password = os.environ.get("NEO4J_TEST_PASSWORD", "threadline-local-dev")
    driver = GraphDatabase.driver(uri, auth=("neo4j", password))
    with driver.session() as s:
        s.run("MATCH (n) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS").consume()
    yield driver
    driver.close()
