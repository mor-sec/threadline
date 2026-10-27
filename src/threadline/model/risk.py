"""Derived Asset.riskScore, 0-100 (PLAN §5.7). A tunable ranking heuristic, not a risk model.

    8 x criticality (1-5)                                   up to 40
    worst open finding: cvss/10 x (0.5 + epss), x1.5 if KEV  up to 30 (saturates at 1.5)
    internet-facing                                          +10
    no EDR check-in in the last 7 days                       +10
    any alert in the last 7 days                             +5
    crown jewel                                              x1.2, capped at 100
"""

from datetime import datetime

from neo4j import Driver

RISK_QUERY = """
CYPHER 25
MATCH (a:Asset)
CALL (a) {
  OPTIONAL MATCH (a)-[:HAS_FINDING]->(f:Finding {status: 'open'})-[:OF_VULN]->(v:Vulnerability)
  RETURN max(coalesce(f.cvssScore, 5.0) / 10.0 * (0.5 + coalesce(v.epssScore, 0.0))
             * CASE WHEN v:KEV THEN 1.5 ELSE 1.0 END) AS worst
}
WITH a, coalesce(worst, 0.0) AS worst,
     EXISTS {
       MATCH (a)-[c:COVERED_BY]->(:SecurityTool {category: 'EDR'})
       WHERE c.lastCheckIn >= $now - duration('P7D')
     } AS hasEdr,
     COUNT {
       MATCH (al:Alert)-[:OBSERVED_ON]->(a) WHERE al.createdAt >= $now - duration('P7D')
     } AS recentAlerts
WITH a, 8.0 * a.criticality
        + 30.0 * CASE WHEN worst > 1.5 THEN 1.0 ELSE worst / 1.5 END
        + CASE WHEN a:InternetFacing THEN 10.0 ELSE 0.0 END
        + CASE WHEN hasEdr THEN 0.0 ELSE 10.0 END
        + CASE WHEN recentAlerts > 0 THEN 5.0 ELSE 0.0 END AS base
WITH a, CASE WHEN a:CrownJewel THEN base * 1.2 ELSE base END AS score
SET a.riskScore = round(CASE WHEN score > 100.0 THEN 100.0 ELSE score END, 1)
RETURN count(a) AS scored
"""


def apply(driver: Driver, database: str, now: datetime) -> int:
    records, _, _ = driver.execute_query(RISK_QUERY, now=now, database_=database)
    return records[0]["scored"]
