"""Download public feeds and write trimmed, committed fixtures for offline `sample` mode.

    uv run python scripts/build_fixtures.py

ATT&CK Enterprise (STIX 2.1), CISA KEV and FIRST EPSS are public. Fixtures keep only the
fields the loader uses, so phases 1-3 run without network access. Phase 4 replaces them
with live connectors.
"""

import csv
import gzip
import io
import json
import random
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src/threadline/ingest/fixtures"
CACHE = ROOT / ".fixture-cache"

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

KEEP_TYPES = {"attack-pattern", "x-mitre-tactic", "intrusion-set", "malware", "tool",
              "course-of-action", "x-mitre-matrix"}
KEEP_RELS = {"uses", "mitigates", "subtechnique-of"}
NON_KEV_SAMPLE = 800  # real, non-KEV CVEs for synthetic findings
DESC_MAX = 1500


def fetch(url: str, name: str) -> bytes:
    CACHE.mkdir(exist_ok=True)
    path = CACHE / name
    if not path.exists():
        print(f"downloading {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "threadline-fixtures"})
        with urllib.request.urlopen(req, timeout=120) as r:
            path.write_bytes(r.read())
    return path.read_bytes()


def mitre_ref(obj: dict) -> dict | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return {"external_id": ref.get("external_id"), "url": ref.get("url")}
    return None


def build_attack() -> None:
    bundle = json.loads(fetch(ATTACK_URL, "enterprise-attack.json"))
    keep: dict[str, dict] = {}
    for o in bundle["objects"]:
        if o["type"] not in KEEP_TYPES or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        slim = {k: o[k] for k in ("type", "id", "name", "aliases", "x_mitre_platforms",
                                  "x_mitre_is_subtechnique", "x_mitre_shortname",
                                  "x_mitre_version", "modified", "tactic_refs") if k in o}
        if "description" in o:
            slim["description"] = o["description"][:DESC_MAX]
        if "kill_chain_phases" in o:
            slim["kill_chain_phases"] = [p["phase_name"] for p in o["kill_chain_phases"]
                                         if p["kill_chain_name"] == "mitre-attack"]
        if ref := mitre_ref(o):
            slim["external_id"], slim["url"] = ref["external_id"], ref["url"]
        keep[o["id"]] = slim
    rels = [
        {"source_ref": o["source_ref"], "target_ref": o["target_ref"],
         "relationship_type": o["relationship_type"]}
        for o in bundle["objects"]
        if o["type"] == "relationship" and o.get("relationship_type") in KEEP_RELS
        and not o.get("revoked") and not o.get("x_mitre_deprecated")
        and o["source_ref"] in keep and o["target_ref"] in keep
    ]
    version = next((o.get("x_mitre_version") for o in bundle["objects"]
                    if o["type"] == "x-mitre-collection"), None)
    out = {"attack_version": version, "objects": list(keep.values()), "relationships": rels}
    (OUT / "attack-enterprise.json").write_text(json.dumps(out, separators=(",", ":")))
    print(f"attack: {len(keep)} objects, {len(rels)} relationships (ATT&CK {version})")


def build_kev() -> set[str]:
    kev = json.loads(fetch(KEV_URL, "kev.json"))
    fields = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
              "shortDescription", "dueDate", "knownRansomwareCampaignUse", "cwes")
    vulns = [{k: v[k] for k in fields if k in v} for v in kev["vulnerabilities"]]
    out = {"catalogVersion": kev.get("catalogVersion"), "dateReleased": kev.get("dateReleased"),
           "vulnerabilities": vulns}
    (OUT / "kev.json").write_text(json.dumps(out, separators=(",", ":")))
    print(f"kev: {len(vulns)} entries (catalog {kev.get('catalogVersion')})")
    return {v["cveID"] for v in vulns}


def build_epss(kev_ids: set[str]) -> None:
    raw = gzip.decompress(fetch(EPSS_URL, "epss.csv.gz")).decode()
    lines = raw.splitlines()
    header = lines[0]  # '#model_version:...,score_date:...'
    rows = list(csv.DictReader(io.StringIO("\n".join(lines[1:]))))
    kev_rows = [r for r in rows if r["cve"] in kev_ids]
    # Recent, non-trivial non-KEV CVEs so synthetic findings look like a real scan.
    pool = [r for r in rows if r["cve"] not in kev_ids and r["cve"] >= "CVE-2022"]
    sample = random.Random(7).sample(pool, NON_KEV_SAMPLE)
    with (OUT / "epss.csv").open("w", newline="") as f:
        f.write(header + "\n")
        w = csv.DictWriter(f, fieldnames=["cve", "epss", "percentile"])
        w.writeheader()
        w.writerows(sorted(kev_rows + sample, key=lambda r: r["cve"]))
    print(f"epss: {len(kev_rows)} KEV + {len(sample)} sampled ({header})")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    build_attack()
    build_epss(build_kev())
