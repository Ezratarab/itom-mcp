"""CMDB: classes, CI search, CI details, relationships, impact analysis, counts, health, duplicates."""

from typing import Annotated, Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from itom_mcp.security import QueryBuilder, SecurityError, parse_when, validate_ci_class, validate_field
from itom_mcp.tools.common import (
    CI_FIELDS,
    INSTALL_STATUS,
    OPERATIONAL_STATUS,
    Ctx,
    UserError,
    itom_tool,
    list_response,
    resolve_choices,
    resolve_ci,
)

CiClass = Annotated[str, Field(description="CMDB class table, e.g. cmdb_ci (all), cmdb_ci_server, cmdb_ci_linux_server, cmdb_ci_win_server, cmdb_ci_vm_instance, cmdb_ci_appl, cmdb_ci_db_instance, cmdb_ci_netgear, cmdb_ci_service_auto")]
Limit = Annotated[Optional[int], Field(description="Max records (capped by MAX_LIMIT)", ge=1)]
Offset = Annotated[int, Field(description="Paging offset", ge=0)]

GROUPABLE = {
    "sys_class_name", "operational_status", "install_status", "environment", "location", "support_group",
    "manufacturer", "discovery_source", "os", "model_id", "company", "department", "used_for", "business_criticality",
}


def _ci_filters(
    qb: QueryBuilder,
    *,
    name: Optional[str] = None,
    ip_address: Optional[str] = None,
    operational_status: Optional[str] = None,
    install_status: Optional[str] = None,
    environment: Optional[str] = None,
    location: Optional[str] = None,
    support_group: Optional[str] = None,
    manufacturer: Optional[str] = None,
    os: Optional[str] = None,
    discovery_source: Optional[str] = None,
    updated_after: Optional[str] = None,
    not_discovered_since: Optional[str] = None,
) -> QueryBuilder:
    qb.add_if("name", "like", name)
    qb.add_if("ip_address", "starts_with", ip_address)
    if ops := resolve_choices(OPERATIONAL_STATUS, operational_status, "operational_status"):
        qb.add("operational_status", "in", ops)
    if ins := resolve_choices(INSTALL_STATUS, install_status, "install_status"):
        qb.add("install_status", "in", ins)
    qb.add_if("environment", "like", environment)
    qb.add_if("location.name", "like", location)
    qb.add_if("support_group.name", "like", support_group)
    qb.add_if("manufacturer.name", "like", manufacturer)
    qb.add_if("os", "like", os)
    qb.add_if("discovery_source", "=", discovery_source)
    if updated_after:
        qb.add("sys_updated_on", ">=", parse_when(updated_after, "updated_after"))
    if not_discovered_since:
        qb.add_or([("last_discovered", "<", parse_when(not_discovered_since, "not_discovered_since")), ("last_discovered", "is_empty", None)])
    return qb


def register(mcp: FastMCP, ctx: Ctx) -> None:
    sn = ctx.sn

    @itom_tool(mcp, ctx, title="List CMDB CI classes")
    async def cmdb_list_classes(
        name_contains: Annotated[Optional[str], Field(description="Filter on table name or label, e.g. 'server', 'database'")] = None,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        """List CMDB CI classes (tables starting with cmdb_ci) with label and parent class. Use to find the right ci_class for other tools."""
        qb = QueryBuilder().add("name", "starts_with", "cmdb_ci")
        if name_contains:
            qb.add_or([("name", "like", name_contains), ("label", "like", name_contains)])
        qb.order_by("name", descending=False)
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query("sys_db_object", q, fields=["name", "label", "super_class"], limit=lim)
        return list_response("classes", "sys_db_object", q, res, lim, 0)

    @itom_tool(mcp, ctx, title="Search configuration items")
    async def cmdb_search_cis(
        ci_class: CiClass = "cmdb_ci",
        name: Annotated[Optional[str], Field(description="Partial name match")] = None,
        ip_address: Annotated[Optional[str], Field(description="IP or IP prefix, e.g. 10.1.2.")] = None,
        operational_status: Annotated[Optional[str], Field(description="Comma list of labels or values: Operational, Non-Operational, Repair in Progress, DR Standby, Ready, Retired")] = None,
        install_status: Annotated[Optional[str], Field(description="Comma list: Installed, On Order, In Maintenance, Pending Install, Pending Repair, In Stock, Retired, Absent")] = None,
        environment: Annotated[Optional[str], Field(description="e.g. Production, Test, Development")] = None,
        location: Annotated[Optional[str], Field(description="Partial location name")] = None,
        support_group: Annotated[Optional[str], Field(description="Partial support group name")] = None,
        manufacturer: Annotated[Optional[str], Field(description="Partial manufacturer name")] = None,
        os: Annotated[Optional[str], Field(description="Partial OS name, e.g. Linux, Windows")] = None,
        discovery_source: Annotated[Optional[str], Field(description="e.g. ServiceNow, SCCM, Manual Entry")] = None,
        updated_after: Annotated[Optional[str], Field(description="ISO date or relative (24h, 7d)")] = None,
        not_discovered_since: Annotated[Optional[str], Field(description="Stale CIs: last_discovered older than this (e.g. 30d) or never")] = None,
        order_by: Annotated[str, Field(description="name, sys_updated_on, last_discovered, sys_created_on")] = "name",
        descending: bool = False,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """Search CIs in any CMDB class with structured filters (name, IP, status, environment, location, support group, OS, discovery source, staleness)."""
        table = validate_ci_class(ci_class)
        if order_by not in {"name", "sys_updated_on", "last_discovered", "sys_created_on", "ip_address"}:
            raise UserError("order_by must be name, sys_updated_on, last_discovered, sys_created_on or ip_address")
        qb = _ci_filters(
            QueryBuilder(), name=name, ip_address=ip_address, operational_status=operational_status,
            install_status=install_status, environment=environment, location=location,
            support_group=support_group, manufacturer=manufacturer, os=os,
            discovery_source=discovery_source, updated_after=updated_after,
            not_discovered_since=not_discovered_since,
        ).order_by(order_by, descending)
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(table, q, fields=CI_FIELDS, limit=lim, offset=offset)
        return list_response("cis", table, q, res, lim, offset)

    @itom_tool(mcp, ctx, title="Get CI details")
    async def cmdb_get_ci(
        ci: Annotated[str, Field(description="CI sys_id, exact name, IP address or FQDN")],
        ci_class: CiClass = "cmdb_ci",
        all_fields: Annotated[bool, Field(description="Return every (non-sensitive) field of the CI's own class")] = False,
    ) -> dict[str, Any]:
        """Get full details of one CI, read from its most specific class table."""
        base = await resolve_ci(ctx, ci, ci_class)
        # sys_class_name comes back as a label with display_value=true; read it raw.
        raw = await sn.get("cmdb_ci", base["sys_id"], fields=["sys_class_name"], display_value="false")
        try:
            table = validate_ci_class(raw.get("sys_class_name") or ci_class)
        except SecurityError:  # class name not a cmdb_ci_* table -> fall back
            table = validate_ci_class(ci_class)
        rec = await sn.get(table, base["sys_id"], fields=None if all_fields else CI_FIELDS)
        return {"table": table, "ci": rec}

    @itom_tool(mcp, ctx, title="CI relationships")
    async def cmdb_get_relationships(
        ci: Annotated[str, Field(description="CI sys_id, exact name, IP or FQDN")],
        direction: Annotated[Literal["both", "upstream", "downstream"], Field(description="downstream = CIs this CI depends on/contains (it is parent); upstream = CIs that depend on it (it is child)")] = "both",
        relationship_type: Annotated[Optional[str], Field(description="Partial relationship type, e.g. 'Depends on', 'Runs on', 'Hosted on', 'Contains'")] = None,
        limit: Limit = 100,
    ) -> dict[str, Any]:
        """List direct relationships of a CI (cmdb_rel_ci) with type and the related CI's class."""
        target = await resolve_ci(ctx, ci)
        sid = target["sys_id"]
        lim = sn.clamp_limit(limit)
        fields = ["sys_id", "parent", "child", "type", "parent.sys_class_name", "child.sys_class_name", "parent.sys_id", "child.sys_id"]
        out: dict[str, Any] = {"ci": target}
        dirs = ["downstream", "upstream"] if direction == "both" else [direction]
        for d in dirs:
            qb = QueryBuilder().add("parent" if d == "downstream" else "child", "=", sid)
            qb.add_if("type.name", "like", relationship_type)
            q = qb.build()
            res = await sn.query("cmdb_rel_ci", q, fields=fields, limit=lim)
            out[d] = {"query_used": q, "total_count": res.total_count, "relationships": res.records}
        return out

    @itom_tool(mcp, ctx, title="CI impact / dependency analysis")
    async def cmdb_impact_analysis(
        ci: Annotated[str, Field(description="CI sys_id, exact name, IP or FQDN")],
        direction: Annotated[Literal["upstream", "downstream"], Field(description="upstream = what is impacted if this CI fails (services/apps depending on it); downstream = what this CI depends on (root-cause candidates)")] = "upstream",
        depth: Annotated[int, Field(description="Traversal depth (capped by MAX_TRAVERSAL_DEPTH)", ge=1)] = 3,
        include_open_alerts: Annotated[bool, Field(description="Also count open alerts on each impacted CI")] = False,
    ) -> dict[str, Any]:
        """Walk the CMDB relationship graph breadth-first to find impacted (upstream) or dependency (downstream) CIs, including application services. Bounded by depth and MAX_TRAVERSAL_NODES."""
        root = await resolve_ci(ctx, ci)
        max_depth = min(depth, ctx.settings.max_traversal_depth)
        max_nodes = ctx.settings.max_traversal_nodes
        here, there = ("child", "parent") if direction == "upstream" else ("parent", "child")
        seen: dict[str, dict[str, Any]] = {root["sys_id"]: {"name": root.get("name"), "class": root.get("sys_class_name"), "depth": 0}}
        edges: list[dict[str, Any]] = []
        frontier = [root["sys_id"]]
        truncated = False
        for level in range(1, max_depth + 1):
            if not frontier:
                break
            next_frontier: list[str] = []
            for i in range(0, len(frontier), 50):
                chunk = frontier[i : i + 50]
                q = QueryBuilder().add(here, "in", chunk).build()
                res = await sn.query(
                    "cmdb_rel_ci", q,
                    fields=[here, there, "type", f"{there}.name", f"{there}.sys_class_name"],
                    limit=ctx.settings.max_limit, display_value="all",
                )
                for r in res.records:
                    src = (r.get(here) or {}).get("value")
                    dst = (r.get(there) or {}).get("value")
                    if not dst:
                        continue
                    edges.append({"from": src, "to": dst, "type": (r.get("type") or {}).get("display_value")})
                    if dst not in seen:
                        if len(seen) >= max_nodes:
                            truncated = True
                            continue
                        seen[dst] = {
                            "name": (r.get(f"{there}.name") or {}).get("display_value"),
                            "class": (r.get(f"{there}.sys_class_name") or {}).get("display_value"),
                            "depth": level,
                        }
                        next_frontier.append(dst)
            frontier = next_frontier
        nodes = [{"sys_id": k, **v} for k, v in seen.items() if k != root["sys_id"]]
        if include_open_alerts and nodes:
            ids = [n["sys_id"] for n in nodes][:200]
            q = QueryBuilder().add("cmdb_ci", "in", ids).add("state", "in", ["Open", "Reopen", "Flapping"]).build()
            rows = await sn.aggregate("em_alert", q, ["cmdb_ci"])
            by_name = {r["groups"].get("cmdb_ci"): r["count"] for r in rows if "groups" in r}
            for n in nodes:
                n["open_alerts"] = by_name.get(n["name"], 0)
        services = [n for n in nodes if "service" in str(n.get("class", "")).lower()]
        return {
            "root": root,
            "direction": direction,
            "depth_used": max_depth,
            "node_count": len(nodes),
            "truncated": truncated,
            "impacted_services": services,
            "nodes": sorted(nodes, key=lambda n: (n["depth"], str(n["name"]))),
            "edges": edges[: max_nodes * 2],
        }

    @itom_tool(mcp, ctx, title="Count CIs (grouped)")
    async def cmdb_count_cis(
        ci_class: CiClass = "cmdb_ci",
        group_by: Annotated[Optional[str], Field(description="Comma list (max 2) of: " + ", ".join(sorted(GROUPABLE)))] = "sys_class_name",
        operational_status: Optional[str] = None,
        install_status: Optional[str] = None,
        environment: Optional[str] = None,
        location: Optional[str] = None,
        support_group: Optional[str] = None,
        os: Optional[str] = None,
        discovery_source: Optional[str] = None,
        not_discovered_since: Optional[str] = None,
    ) -> dict[str, Any]:
        """Count CIs, optionally grouped (by class, status, environment, location, OS, discovery source...). Answers 'how many servers per OS', 'CIs by environment', etc."""
        table = validate_ci_class(ci_class)
        groups = [g.strip() for g in (group_by or "").split(",") if g.strip()]
        if len(groups) > 2 or any(g not in GROUPABLE for g in groups):
            raise UserError(f"group_by: up to 2 of {sorted(GROUPABLE)}")
        q = _ci_filters(
            QueryBuilder(), operational_status=operational_status, install_status=install_status,
            environment=environment, location=location, support_group=support_group, os=os,
            discovery_source=discovery_source, not_discovered_since=not_discovered_since,
        ).build()
        rows = await sn.aggregate(table, q, groups or None)
        return {"table": table, "query_used": q, "group_by": groups, "total": sum(r["count"] for r in rows), "rows": rows[:500]}

    @itom_tool(mcp, ctx, title="CMDB data-quality health report")
    async def cmdb_health_report(
        ci_class: CiClass = "cmdb_ci_server",
        stale_days: Annotated[int, Field(description="A CI is stale if not discovered for this many days", ge=1, le=3650)] = 30,
    ) -> dict[str, Any]:
        """CMDB health for a class: totals, stale (not discovered), manually created, missing support group / owner / location, retired-but-operational, and duplicate names."""
        table = validate_ci_class(ci_class)
        live = QueryBuilder().add("install_status", "!=", "7")
        live_q = live.build()
        stale_when = parse_when(f"{stale_days}d")

        async def c(extra: QueryBuilder) -> int:
            return await sn.count(table, extra.build())

        report = {
            "table": table,
            "total": await sn.count(table),
            "active_not_retired": await sn.count(table, live_q),
            "stale": await c(QueryBuilder().add("install_status", "!=", "7").add_or([("last_discovered", "<", stale_when), ("last_discovered", "is_empty", None)])),
            "never_discovered_manual": await c(QueryBuilder().add("install_status", "!=", "7").add_or([("discovery_source", "is_empty", None), ("discovery_source", "=", "Manual Entry")])),
            "missing_support_group": await c(QueryBuilder().add("install_status", "!=", "7").add("support_group", "is_empty")),
            "missing_owner": await c(QueryBuilder().add("install_status", "!=", "7").add("owned_by", "is_empty").add("managed_by", "is_empty")),
            "missing_location": await c(QueryBuilder().add("install_status", "!=", "7").add("location", "is_empty")),
            "retired_but_operational": await c(QueryBuilder().add("install_status", "=", "7").add("operational_status", "=", "1")),
        }
        dup_rows = await sn.aggregate(table, live_q, ["name"])
        dups = [r for r in dup_rows if r["count"] > 1]
        report["duplicate_names"] = {"groups": len(dups), "top": dups[:25]}
        report["stale_days"] = stale_days
        return report

    @itom_tool(mcp, ctx, title="Find duplicate CIs")
    async def cmdb_find_duplicates(
        ci_class: CiClass = "cmdb_ci_server",
        field: Annotated[Literal["name", "serial_number", "ip_address", "fqdn", "mac_address", "asset_tag"], Field(description="Field that should be unique")] = "name",
        include_retired: bool = False,
        limit: Limit = 50,
    ) -> dict[str, Any]:
        """Find duplicate CIs (same name / serial / IP / FQDN / MAC) in a class."""
        table = validate_ci_class(ci_class)
        f = validate_field(field)
        qb = QueryBuilder().add(f, "is_not_empty")
        if not include_retired:
            qb.add("install_status", "!=", "7")
        q = qb.build()
        rows = await sn.aggregate(table, q, [f])
        dups = [r for r in rows if r["count"] > 1][: sn.clamp_limit(limit)]
        return {"table": table, "field": f, "query_used": q, "duplicate_groups": len(dups), "duplicates": dups}

    @itom_tool(mcp, ctx, title="Recently changed CIs")
    async def cmdb_recent_changes(
        since: Annotated[str, Field(description="ISO date or relative (24h, 7d)")] = "24h",
        ci_class: CiClass = "cmdb_ci",
        created_only: Annotated[bool, Field(description="Only CIs created (not just updated) since then")] = False,
        updated_by: Annotated[Optional[str], Field(description="User name / integration that last updated (e.g. discovery, system)")] = None,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """CIs created or updated since a time - what changed in the CMDB recently and by whom."""
        table = validate_ci_class(ci_class)
        when = parse_when(since, "since")
        qb = QueryBuilder().add("sys_created_on" if created_only else "sys_updated_on", ">=", when)
        qb.add_if("sys_updated_by", "like", updated_by)
        qb.order_by("sys_updated_on")
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(table, q, fields=CI_FIELDS + ["sys_created_on", "sys_updated_by"], limit=lim, offset=offset)
        return list_response("cis", table, q, res, lim, offset)

    @itom_tool(mcp, ctx, title="CMDB overview")
    async def cmdb_overview() -> dict[str, Any]:
        """High-level CMDB picture: CI counts per class (top 50) and per operational status."""
        by_class = await sn.aggregate("cmdb_ci", "", ["sys_class_name"])
        by_status = await sn.aggregate("cmdb_ci", "", ["operational_status"])
        return {
            "total": sum(r["count"] for r in by_class),
            "classes": len(by_class),
            "by_class_top50": by_class[:50],
            "by_operational_status": by_status,
        }
