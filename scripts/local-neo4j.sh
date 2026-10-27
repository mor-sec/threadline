#!/usr/bin/env bash
# Local Neo4j Enterprise (evaluation licence, development only) for tests and offline work.
# Usage: scripts/local-neo4j.sh [start|stop|rm|logs]
set -euo pipefail
NAME=threadline-neo4j
IMAGE=docker.io/library/neo4j:2026.10.1-enterprise
PASSWORD=${LOCAL_NEO4J_PASSWORD:-threadline-local-dev}
ENGINE=$(command -v podman || command -v docker)

case "${1:-start}" in
  start)
    if "$ENGINE" container exists "$NAME" 2>/dev/null || "$ENGINE" inspect "$NAME" >/dev/null 2>&1; then
      "$ENGINE" start "$NAME" >/dev/null
    else
      "$ENGINE" run -d --name "$NAME" \
        -p 127.0.0.1:7474:7474 -p 127.0.0.1:7687:7687 \
        -e NEO4J_AUTH="neo4j/$PASSWORD" \
        -e NEO4J_ACCEPT_LICENSE_AGREEMENT=eval \
        -e NEO4J_PLUGINS='["apoc"]' \
        -v threadline-neo4j-data:/data \
        "$IMAGE" >/dev/null
    fi
    echo "Waiting for Neo4j on bolt://localhost:7687 ..."
    for _ in $(seq 1 90); do
      if "$ENGINE" logs "$NAME" 2>&1 | grep -q "Started."; then echo "Ready (user neo4j / $PASSWORD)"; exit 0; fi
      sleep 2
    done
    echo "Neo4j did not start in time; see: $0 logs" >&2; exit 1 ;;
  stop) "$ENGINE" stop "$NAME" ;;
  rm)   "$ENGINE" rm -f "$NAME" && "$ENGINE" volume rm -f threadline-neo4j-data ;;
  logs) "$ENGINE" logs --tail 50 "$NAME" ;;
  *) echo "usage: $0 [start|stop|rm|logs]" >&2; exit 2 ;;
esac
