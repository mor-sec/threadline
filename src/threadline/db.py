"""Driver access. Writes use the ingest credentials; every query path uses read()."""

from typing import Any, Literal

from neo4j import Driver, GraphDatabase, RoutingControl

from .config import Settings


def connect(settings: Settings, role: Literal["write", "read"]) -> Driver:
    if role == "write":
        auth = (settings.neo4j_write_username, settings.neo4j_write_password.get_secret_value())
    else:
        auth = (settings.neo4j_read_username, settings.neo4j_read_password.get_secret_value())
    return GraphDatabase.driver(settings.neo4j_uri, auth=auth)


def read(
    driver: Driver, database: str, cypher: str, params: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Run a query in READ access mode: the server rejects any write inside it."""
    records, _, _ = driver.execute_query(
        cypher, params or {}, database_=database, routing_=RoutingControl.READ
    )
    return [r.data() for r in records]
