"""Graph data model: node types, relationship schema and provenance (docs/PLAN.md §5).

Field names are graph property names, so they follow Neo4j's camelCase convention.
Every node and relationship carries provenance: source, confidence, firstSeen, lastSeen.
"""

from datetime import date, datetime
from typing import Annotated, Any, ClassVar, Literal
from zoneinfo import ZoneInfo

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

UTC = ZoneInfo("UTC")


def to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("naive datetime; graph times must be timezone-aware")
    # Named 'UTC' zone, never a bare 'Z' offset: Neo4j range queries treat the two differently.
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(to_utc)]


class Node(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    LABEL: ClassVar[str]
    KEY: ClassVar[str]
    EXTRA_LABELS: ClassVar[frozenset[str]] = frozenset()

    labels: frozenset[str] = frozenset()  # extra labels to add
    unsetLabels: frozenset[str] = frozenset()  # extra labels to remove; only the owning source sets this
    source: str
    confidence: int = Field(default=80, ge=0, le=100)
    firstSeen: UtcDateTime
    lastSeen: UtcDateTime

    @model_validator(mode="after")
    def _known_labels(self):
        if bad := (self.labels | self.unsetLabels) - self.EXTRA_LABELS:
            raise ValueError(f"{self.LABEL} does not allow labels {sorted(bad)}")
        return self

    @property
    def key(self) -> str:
        return getattr(self, self.KEY)

    def props(self) -> dict[str, Any]:
        # None means "this source doesn't know", so it never clears a property another source set.
        return self.model_dump(
            exclude={"labels", "unsetLabels", "firstSeen", "lastSeen"}, exclude_none=True
        )


class Organization(Node):
    LABEL = "Organization"
    KEY = "orgId"
    orgId: str
    name: str


class Sector(Node):
    LABEL = "Sector"
    KEY = "name"
    name: str


class BusinessUnit(Node):
    LABEL = "BusinessUnit"
    KEY = "buId"
    buId: str
    name: str


class Asset(Node):
    LABEL = "Asset"
    KEY = "assetId"
    EXTRA_LABELS = frozenset({"InternetFacing", "CrownJewel", "Unmanaged"})
    assetId: str
    hostname: str
    fqdn: str | None = None
    assetType: str
    os: str | None = None
    criticality: int = Field(ge=1, le=5)
    owner: str | None = None


class AssetRecord(Node):
    """One source's view of a host, kept as evidence for entity resolution."""

    LABEL = "AssetRecord"
    KEY = "recordKey"
    recordKey: str
    hostname: str | None = None
    fqdn: str | None = None
    ip: str | None = None
    mac: str | None = None
    serial: str | None = None
    cloudInstanceId: str | None = None


class IpAddress(Node):
    LABEL = "IpAddress"
    KEY = "address"
    EXTRA_LABELS = frozenset({"Public"})
    address: str
    version: int


class Identity(Node):
    LABEL = "Identity"
    KEY = "identityId"
    EXTRA_LABELS = frozenset({"User", "ServicePrincipal", "Privileged"})
    identityId: str
    upn: str | None = None
    displayName: str
    enabled: bool = True
    mfaEnabled: bool | None = None


class Group(Node):
    LABEL = "Group"
    KEY = "groupId"
    EXTRA_LABELS = frozenset({"Privileged"})
    groupId: str
    name: str


class Role(Node):
    LABEL = "Role"
    KEY = "roleId"
    EXTRA_LABELS = frozenset({"Privileged"})
    roleId: str
    name: str


class Finding(Node):
    LABEL = "Finding"
    KEY = "findingId"
    findingId: str
    status: Literal["open", "fixed", "accepted"]
    severity: str
    cvssScore: float | None = None
    port: int | None = None
    protocol: str | None = None
    pluginId: str | None = None
    fixedAt: UtcDateTime | None = None


class Vulnerability(Node):
    LABEL = "Vulnerability"
    KEY = "cveId"
    EXTRA_LABELS = frozenset({"KEV"})
    cveId: str
    name: str | None = None
    vendorProject: str | None = None
    product: str | None = None
    epssScore: float | None = None
    epssPercentile: float | None = None
    epssDate: date | None = None
    kevDateAdded: date | None = None
    kevDueDate: date | None = None
    kevRansomware: bool | None = None


class Tactic(Node):
    LABEL = "Tactic"
    KEY = "tacticId"
    tacticId: str
    name: str
    shortName: str
    matrixOrder: int


class Technique(Node):
    LABEL = "Technique"
    KEY = "techniqueId"
    EXTRA_LABELS = frozenset({"SubTechnique"})
    techniqueId: str
    name: str
    description: str | None = None
    platforms: list[str] = Field(default_factory=list)
    stixId: str | None = None
    attackVersion: str | None = None
    url: str | None = None


class ThreatActor(Node):
    LABEL = "ThreatActor"
    KEY = "actorId"
    actorId: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    aliasText: str | None = None  # aliases joined, for full-text search
    description: str | None = None
    stixId: str | None = None


class Software(Node):
    LABEL = "Software"
    KEY = "softwareId"
    softwareId: str
    name: str
    softwareType: str
    description: str | None = None


class Mitigation(Node):
    LABEL = "Mitigation"
    KEY = "mitigationId"
    mitigationId: str
    name: str
    description: str | None = None


class SecurityTool(Node):
    LABEL = "SecurityTool"
    KEY = "toolId"
    toolId: str
    name: str
    category: str


class Alert(Node):
    LABEL = "Alert"
    KEY = "alertId"
    alertId: str
    title: str
    severity: str
    status: str
    createdAt: UtcDateTime
    description: str | None = None
    productName: str | None = None
    suspicious: bool = False  # text looks like a prompt-injection attempt (untrusted input)


class Report(Node):
    LABEL = "Report"
    KEY = "reportId"
    reportId: str
    title: str
    published: UtcDateTime
    summary: str
    tlp: str
    suspicious: bool = False


class Indicator(Node):
    LABEL = "Indicator"
    KEY = "indicatorId"
    indicatorId: str  # '<stix observable type>:<value>', e.g. 'ipv4-addr:203.0.113.7'
    indicatorType: str
    value: str
    pattern: str


NODE_TYPES: dict[str, type[Node]] = {cls.LABEL: cls for cls in Node.__subclasses__()}

# (start label, type, end label). Relationship direction follows attacker movement for
# attack-path types: control of the start node gives control of the end node (PLAN §5.2).
REL_SCHEMA: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("Organization", "OPERATES_IN", "Sector"),
        ("BusinessUnit", "PART_OF", "Organization"),
        ("ThreatActor", "TARGETS", "Sector"),
        ("ThreatActor", "USES", "Technique"),
        ("ThreatActor", "USES", "Software"),
        ("Software", "USES", "Technique"),
        ("Technique", "SUBTECHNIQUE_OF", "Technique"),
        ("Technique", "IN_TACTIC", "Tactic"),
        ("Mitigation", "MITIGATES", "Technique"),
        ("Asset", "BELONGS_TO", "BusinessUnit"),
        ("Asset", "HAS_IP", "IpAddress"),
        ("Asset", "HAS_FINDING", "Finding"),
        ("Finding", "OF_VULN", "Vulnerability"),
        ("Vulnerability", "EXPLOITED_BY", "Technique"),
        ("Asset", "COVERED_BY", "SecurityTool"),
        ("Asset", "CAN_REACH", "Asset"),
        ("Asset", "HAS_SESSION", "Identity"),
        ("AssetRecord", "RESOLVES_TO", "Asset"),
        ("AssetRecord", "POSSIBLY_SAME_AS", "Asset"),
        ("Identity", "MEMBER_OF", "Group"),
        ("Group", "MEMBER_OF", "Group"),
        ("Identity", "HAS_ROLE", "Role"),
        ("Group", "HAS_ROLE", "Role"),
        ("Identity", "ADMIN_TO", "Asset"),
        ("Group", "ADMIN_TO", "Asset"),
        ("Role", "ADMIN_TO", "Asset"),
        ("Identity", "CAN_ACCESS", "Asset"),
        ("Group", "CAN_ACCESS", "Asset"),
        ("Alert", "OBSERVED_ON", "Asset"),
        ("Alert", "INVOLVES", "Identity"),
        ("Alert", "INDICATES", "Technique"),
        ("Alert", "MATCHED", "Indicator"),
        ("Indicator", "ATTRIBUTED_TO", "ThreatActor"),
        ("Report", "MENTIONS", "ThreatActor"),
        ("Report", "MENTIONS", "Technique"),
        ("Report", "MENTIONS", "Vulnerability"),
    }
)


class Rel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: str
    startLabel: str
    start: str
    endLabel: str
    end: str
    props: dict[str, Any] = Field(default_factory=dict)
    source: str
    confidence: int = Field(default=80, ge=0, le=100)
    firstSeen: UtcDateTime
    lastSeen: UtcDateTime

    @model_validator(mode="before")
    @classmethod
    def _utc_props(cls, data: dict) -> dict:
        props = data.get("props") or {}
        data["props"] = {k: to_utc(v) if isinstance(v, datetime) else v for k, v in props.items()}
        return data

    @model_validator(mode="after")
    def _in_schema(self):
        if (self.startLabel, self.type, self.endLabel) not in REL_SCHEMA:
            raise ValueError(f"not in schema: ({self.startLabel})-[:{self.type}]->({self.endLabel})")
        return self


def rel(
    type_: str,
    start: Node | tuple[str, str],
    end: Node | tuple[str, str],
    *,
    props: dict[str, Any] | None = None,
    **provenance: Any,
) -> Rel:
    """Build a relationship from nodes or (label, key) pairs."""
    sl, sk = (start.LABEL, start.key) if isinstance(start, Node) else start
    el, ek = (end.LABEL, end.key) if isinstance(end, Node) else end
    return Rel(
        type=type_, startLabel=sl, start=sk, endLabel=el, end=ek, props=props or {}, **provenance
    )
