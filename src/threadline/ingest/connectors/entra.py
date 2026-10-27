"""Entra ID (Microsoft Graph shapes): identities, groups, roles, device access rights."""

from collections import defaultdict

from ...model.nodes import Group, Identity, Role, rel
from ..base import Batch, Connector, Context

ODATA_LABEL = {"#microsoft.graph.user": "Identity", "#microsoft.graph.group": "Group",
               "#microsoft.graph.servicePrincipal": "Identity"}
PRINCIPAL_LABEL = {"User": "Identity", "ServicePrincipal": "Identity", "Group": "Group",
                   "Role": "Role"}


def identity_index(raw: dict) -> dict[str, str]:
    """UPN and on-prem account name (UPN local part, when unique) -> identityId."""
    index = {u["userPrincipalName"].lower(): u["id"] for u in raw["users"]}
    local: dict[str, list[str]] = defaultdict(list)
    for u in raw["users"]:
        local[u["userPrincipalName"].split("@")[0].lower()].append(u["id"])
    index.update({name: ids[0] for name, ids in local.items() if len(ids) == 1})
    return index


def _privileged(raw: dict) -> set[str]:
    """Principals with privileged rights: role-assignable groups (transitively) and roles."""
    groups = {g["id"]: g for g in raw["groups"]}
    priv_roles = {r["id"] for r in raw["roleDefinitions"] if r["isPrivileged"]}
    seeds = [g["id"] for g in raw["groups"] if g["isAssignableToRole"]]
    seeds += [a["principalId"] for a in raw["roleAssignments"]
              if a["roleDefinitionId"] in priv_roles]
    out: set[str] = set()
    while seeds:
        pid = seeds.pop()
        if pid not in out:
            out.add(pid)
            seeds += [m["id"] for m in groups.get(pid, {}).get("members", [])]
    return out


class EntraConnector(Connector):
    name = "entra"

    def extract(self, ctx: Context) -> dict:
        self.sample_or_live(ctx)
        return ctx.estate.entra

    def transform(self, raw: dict, ctx: Context) -> Batch:
        out = Batch()
        prov = {"source": "entra-id", "confidence": 95, "firstSeen": ctx.as_of,
                "lastSeen": ctx.as_of}
        priv = _privileged(raw)

        def labels(base: set[str], pid: str, extra: frozenset[str]) -> dict:
            got = base | ({"Privileged"} if pid in priv else set())
            return {"labels": frozenset(got), "unsetLabels": extra - got}

        for u in raw["users"]:
            out.nodes.append(Identity(
                identityId=u["id"], upn=u["userPrincipalName"], displayName=u["displayName"],
                enabled=u["accountEnabled"], **labels({"User"}, u["id"], Identity.EXTRA_LABELS),
                **prov))
        for sp in raw["servicePrincipals"]:
            out.nodes.append(Identity(
                identityId=sp["id"], displayName=sp["displayName"],
                **labels({"ServicePrincipal"}, sp["id"], Identity.EXTRA_LABELS), **prov))
        for g in raw["groups"]:
            out.nodes.append(Group(groupId=g["id"], name=g["displayName"],
                                   **labels(set(), g["id"], Group.EXTRA_LABELS), **prov))
            for m in g["members"]:
                out.rels.append(rel("MEMBER_OF", (ODATA_LABEL[m["@odata.type"]], m["id"]),
                                    ("Group", g["id"]), **prov))
        for r in raw["roleDefinitions"]:
            got = {"Privileged"} if r["isPrivileged"] else set()
            out.nodes.append(Role(roleId=r["id"], name=r["displayName"], labels=frozenset(got),
                                  unsetLabels=Role.EXTRA_LABELS - got, **prov))
        for a in raw["roleAssignments"]:
            out.rels.append(rel("HAS_ROLE", (PRINCIPAL_LABEL[a["principalType"]], a["principalId"]),
                                ("Role", a["roleDefinitionId"]), **prov))
        for a in raw["deviceAccess"]:
            asset = ctx.assets.lookup(host=a["deviceName"])
            if not asset:
                out.issues["entra: device access for unknown device"] += 1
                continue
            typ = "ADMIN_TO" if a["access"] == "admin" else "CAN_ACCESS"
            out.rels.append(rel(typ, (PRINCIPAL_LABEL[a["principalType"]], a["principalId"]),
                                ("Asset", asset), **prov))
        return out
