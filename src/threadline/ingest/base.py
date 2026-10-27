"""Connector interface shared by every source (PLAN §6).

Each connector extracts raw records (sample mode: from the synthetic estate or committed
fixtures; live mode: from the real API) and transforms them into validated graph models.
Host-bearing sources also emit SourceAssets, which entity resolution merges into Assets
before any transform runs.
"""

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from ..model.nodes import Node, Rel

if TYPE_CHECKING:
    from .resolve import Resolution
    from .synthetic import Estate

Mode = Literal["sample", "live"]

_INJECTION = re.compile(
    r"ignore (all |any )?(previous|prior|above) instructions|disregard (the |all )?"
    r"(above|previous)|you are now|system (prompt|note)|new instructions:",
    re.IGNORECASE,
)


def looks_like_injection(text: str | None) -> bool:
    """Flag untrusted text that tries to instruct a model (PLAN §10). Detection, not defence."""
    return bool(text and _INJECTION.search(text))


@dataclass
class Batch:
    nodes: list[Node] = field(default_factory=list)
    rels: list[Rel] = field(default_factory=list)
    issues: Counter[str] = field(default_factory=Counter)  # data-quality problems seen in transform

    def extend(self, other: "Batch") -> None:
        self.nodes += other.nodes
        self.rels += other.rels
        self.issues.update(other.issues)


@dataclass(frozen=True)
class SourceAsset:
    """One source's view of a host, before entity resolution. Fields map to AssetRecord."""

    source: str
    sourceId: str
    firstSeen: datetime
    lastSeen: datetime
    hostname: str | None = None
    fqdn: str | None = None
    ip: str | None = None
    mac: str | None = None
    serial: str | None = None
    cloudInstanceId: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def recordKey(self) -> str:
        return f"{self.source}:{self.sourceId}"


@dataclass
class Context:
    mode: Mode
    as_of: datetime
    estate: "Estate | None" = None
    assets: "Resolution | None" = None
    identity_by_upn: dict[str, str] = field(default_factory=dict)


class Connector:
    name: str

    def extract(self, ctx: Context) -> Any:
        raise NotImplementedError

    def asset_records(self, raw: Any, ctx: Context) -> list[SourceAsset]:
        return []

    def transform(self, raw: Any, ctx: Context) -> Batch:
        raise NotImplementedError

    def sample_or_live(self, ctx: Context) -> None:
        if ctx.mode == "live":
            raise NotImplementedError(
                f"live '{self.name}' connector is not built yet (PLAN §11); use --mode sample"
            )
        assert ctx.estate is not None, "sample mode needs the synthetic estate"


def parse_ts(value: str) -> datetime:
    """ISO-8601 or ServiceNow 'YYYY-MM-DD HH:MM:SS' (UTC) -> aware datetime."""
    from ..model.nodes import UTC

    dt = datetime.fromisoformat(value.replace(" ", "T"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
