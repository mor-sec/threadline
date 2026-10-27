"""ServiceNow CMDB (cmdb_ci): asset identity and business context, organisation structure."""

from ...model.nodes import BusinessUnit, Organization, Sector, rel
from ..base import Batch, Connector, Context, SourceAsset, parse_ts

ASSET_TYPE = {"cmdb_ci_computer": "workstation", "cmdb_ci_server": "server",
              "cmdb_ci_vm_instance": "cloud-vm", "cmdb_ci_netgear": "network"}
CRITICALITY = {"1 - most critical": 5, "2 - somewhat critical": 4, "3 - less critical": 3,
               "4 - not critical": 2}


class CmdbConnector(Connector):
    name = "servicenow"

    def extract(self, ctx: Context) -> dict:
        self.sample_or_live(ctx)
        e = ctx.estate
        return {"company": e.org, "business_units": e.business_units, "cis": e.cmdb}

    def asset_records(self, raw: dict, ctx: Context) -> list[SourceAsset]:
        return [
            SourceAsset(
                source=self.name,
                sourceId=ci["sys_id"],
                firstSeen=parse_ts(ci["sys_created_on"]),
                lastSeen=ctx.as_of,
                hostname=ci["name"],
                fqdn=ci["fqdn"] or None,
                ip=ci["ip_address"] or None,
                mac=ci["mac_address"] or None,
                serial=ci["serial_number"] or None,
                cloudInstanceId=ci["object_id"] or None,
                attrs={
                    "assetType": ASSET_TYPE.get(ci["sys_class_name"], "unknown"),
                    "os": ci["os"] or None,
                    "criticality": CRITICALITY.get(ci["busines_criticality"], 3),
                    "owner": ci["owned_by"] or None,
                    "businessUnit": ci["u_business_unit"] or None,
                    "internetFacing": ci["u_internet_facing"] == "true",
                    "crownJewel": ci["u_crown_jewel"] == "true",
                },
            )
            for ci in raw["cis"]
        ]

    def transform(self, raw: dict, ctx: Context) -> Batch:
        prov = {"source": self.name, "confidence": 100, "firstSeen": ctx.as_of,
                "lastSeen": ctx.as_of}
        company = raw["company"]
        org = Organization(orgId=company["orgId"], name=company["name"], **prov)
        sector = Sector(name=company["sector"], **prov)
        out = Batch(nodes=[org, sector], rels=[rel("OPERATES_IN", org, sector, **prov)])
        for bu in raw["business_units"]:
            node = BusinessUnit(buId=bu["u_code"], name=bu["name"], **prov)
            out.nodes.append(node)
            out.rels.append(rel("PART_OF", node, org, **prov))
        return out
