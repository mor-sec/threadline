"""Readers for the committed public-feed fixtures (built by scripts/build_fixtures.py)."""

import csv
import json
from datetime import date
from functools import cache
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


@cache
def attack() -> dict:
    return json.loads((FIXTURES / "attack-enterprise.json").read_text())


@cache
def kev() -> dict:
    return json.loads((FIXTURES / "kev.json").read_text())


@cache
def epss() -> tuple[dict[str, tuple[float, float]], date]:
    """{cve: (score, percentile)}, score date."""
    with (FIXTURES / "epss.csv").open() as f:
        header = f.readline()  # '#model_version:...,score_date:YYYY-MM-DDT...'
        score_date = date.fromisoformat(header.split("score_date:")[1][:10])
        scores = {r["cve"]: (float(r["epss"]), float(r["percentile"])) for r in csv.DictReader(f)}
    return scores, score_date
