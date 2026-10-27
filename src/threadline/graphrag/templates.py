"""Curated, parameterised analyst queries (PLAN §5.6). Phase 3's router selects among these
before falling back to Text2Cypher. All run read-only.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class Template:
    name: str
    question: str
    cypher: str

    def params(self, *, org_id: str, now: datetime, since: datetime | None = None) -> dict:
        p = {"orgId": org_id, "now": now, "since": since or now - timedelta(days=7),
             "phishingTechniqueIds": ["T1566", "T1566.001", "T1566.002", "T1566.003",
                                      "T1566.004"]}
        return {k: v for k, v in p.items() if f"${k}" in self.cypher}


TEMPLATES = {t.name: t for t in [
    Template(
        "q1",
        "Which internet-facing assets are exposed to techniques used by actors targeting our "
        "sector, and which controls mitigate them?",
        """CYPHER 25
MATCH (:Organization {orgId: $orgId})-[:OPERATES_IN]->(:Sector)<-[:TARGETS]-(actor:ThreatActor)
      -[:USES]->(t:Technique)
MATCH (a:Asset:InternetFacing)-[:HAS_FINDING]->(:Finding {status: 'open'})
      -[:OF_VULN]->(v:Vulnerability)-[:EXPLOITED_BY]->(t)
WITH a, t, collect(DISTINCT actor.name) AS actors, collect(DISTINCT v.cveId) AS cves
RETURN a.assetId AS assetId, a.hostname AS hostname, a.riskScore AS riskScore,
       t.techniqueId AS techniqueId, t.name AS technique, actors, cves,
       COLLECT { MATCH (m:Mitigation)-[:MITIGATES]->(t) RETURN m.mitigationId + ' ' + m.name }
         AS mitigations
ORDER BY riskScore DESC, hostname
LIMIT 25""",
    ),
    Template(
        "q2",
        "Show attack paths from a phished user to crown-jewel assets.",
        """CYPHER 25
MATCH (alert:Alert)-[:INDICATES]->(t:Technique)
WHERE t.techniqueId IN $phishingTechniqueIds
MATCH (alert)-[:INVOLVES]->(u:Identity:User)
WITH u, max(alert.createdAt) AS phishedAt
ORDER BY phishedAt DESC
LIMIT 25
// Reachability alone is not compromise: a CAN_REACH hop counts only into an exploitable asset.
MATCH p = SHORTEST 1 (u)((x)-[r:MEMBER_OF|HAS_ROLE|ADMIN_TO|CAN_ACCESS|HAS_SESSION|CAN_REACH]->(y)
            WHERE NOT r:CAN_REACH OR EXISTS {
              MATCH (y)-[:HAS_FINDING]->(:Finding {status: 'open'})-[:OF_VULN]->(:Vulnerability:KEV)
            }){1,6}(cj:Asset:CrownJewel)
WITH u, phishedAt, cj, p
ORDER BY length(p)
WITH u, phishedAt, collect(cj.hostname) AS crownJewels, collect(p)[0] AS p
RETURN u.upn AS entryUser, phishedAt, crownJewels, length(p) AS hops,
       [n IN nodes(p) | coalesce(n.hostname, n.upn, n.name, n.displayName)] AS pathNames,
       [rel IN relationships(p) | type(rel)] AS pathRelTypes,
       [n IN nodes(p) | elementId(n)] AS pathNodeIds
ORDER BY phishedAt DESC, hops
LIMIT 25""",
    ),
    Template(
        "q3",
        "Which KEV-listed vulnerabilities sit on assets with no EDR coverage?",
        """CYPHER 25
MATCH (a:Asset)-[:HAS_FINDING]->(:Finding {status: 'open'})-[:OF_VULN]->(v:Vulnerability:KEV)
WHERE NOT EXISTS {
  MATCH (a)-[c:COVERED_BY]->(:SecurityTool {category: 'EDR'})
  WHERE c.lastCheckIn >= $now - duration('P7D')
}
WITH a, collect(v.cveId) AS kevCves, max(v.epssScore) AS maxEpss
RETURN a.assetId AS assetId, a.hostname AS hostname, a.riskScore AS riskScore,
       a:InternetFacing AS internetFacing, a:Unmanaged AS unmanaged,
       CASE WHEN EXISTS { (a)-[:COVERED_BY]->(:SecurityTool {category: 'EDR'}) }
            THEN 'stale' ELSE 'none' END AS edr,
       kevCves, maxEpss
ORDER BY internetFacing DESC, riskScore DESC, hostname
LIMIT 25""",
    ),
    Template(
        "q4",
        "What changed in our exposure since last week?",
        """CYPHER 25
CALL () {
  MATCH (a:Asset)-[:HAS_FINDING]->(f:Finding)-[:OF_VULN]->(v:Vulnerability)
  WHERE f.firstSeen >= $since
  RETURN 'new finding' AS change, a.hostname AS hostname, v.cveId AS detail, f.firstSeen AS at
  UNION ALL
  MATCH (a:Asset)-[:HAS_FINDING]->(f:Finding)-[:OF_VULN]->(v:Vulnerability)
  WHERE f.fixedAt >= $since
  RETURN 'fixed' AS change, a.hostname AS hostname, v.cveId AS detail, f.fixedAt AS at
  UNION ALL
  MATCH (a:Asset)-[:HAS_FINDING]->(:Finding {status: 'open'})-[:OF_VULN]->(v:Vulnerability:KEV)
  WHERE v.kevDateAdded >= date($since)
  RETURN 'newly KEV-listed' AS change, a.hostname AS hostname, v.cveId AS detail,
         datetime({date: v.kevDateAdded, timezone: 'UTC'}) AS at
  UNION ALL
  MATCH (a:Asset:InternetFacing)
  WHERE a.firstSeen >= $since
  RETURN 'new internet-facing asset' AS change, a.hostname AS hostname, a.assetType AS detail,
         a.firstSeen AS at
}
WITH change, hostname, detail, at
ORDER BY at DESC
RETURN change, count(*) AS total, collect({hostname: hostname, detail: detail})[0..5] AS examples
ORDER BY total DESC""",
    ),
]}
