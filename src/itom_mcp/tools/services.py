"""Service Mapping / application services and service health; CI operational context (incidents, changes, outages)."""

from typing import Annotated, Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from itom_mcp.security import QueryBuilder, parse_when, validate_ci_class
from itom_mcp.tools.common import Ctx, itom_tool, list_response, resolve_ci
from itom_mcp.tools.events import OPEN_STATES

Limit = Annotated[Optional[int], Field(description="Max records (capped by MAX_LIMIT)", ge=1)]
Offset = Annotated[int, Field(ge=0)]

SERVICE_CLASSES = {
    "application": "cmdb_ci_service_auto",
    "discovered": "cmdb_ci_service_discovered",
    "business": "cmdb_ci_service_business",
    "technical": "cmdb_ci_service_technical",
    "all": "cmdb_ci_service",
}
SERVICE_FIELDS = [
    "sys_id", "name", "sys_class_name", "operational_status", "busines_criticality", "business_criticality",
    "environment", "owned_by", "support_group", "managed_by", "version", "service_classification", "sys_updated_on",
]
OPEN_INCIDENT = ["1", "2", "3"]  # New, In Progress, On Hold


def register(mcp: FastMCP, ctx: Ctx) -> None:
    sn = ctx.sn

    async def _resolve_service(service: str) -> dict[str, Any]:
        return await resolve_ci(ctx, service, "cmdb_ci_service")

    @itom_tool(mcp, ctx, title="List services")
    async def services_list(
        kind: Annotated[Literal["application", "discovered", "business", "technical", "all"], Field(description="application = mapped application services (cmdb_ci_service_auto)")] = "application",
        name: Optional[str] = None,
        environment: Optional[str] = None,
        support_group: Optional[str] = None,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """List application / business / technical services."""
        table = validate_ci_class(SERVICE_CLASSES[kind])
        qb = QueryBuilder().add_if("name", "like", name).add_if("environment", "like", environment)
        qb.add_if("support_group.name", "like", support_group).order_by("name", descending=False)
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(table, q, fields=SERVICE_FIELDS, limit=lim, offset=offset)
        return list_response("services", table, q, res, lim, offset)

    @itom_tool(mcp, ctx, title="Service map (CIs in a service)")
    async def service_get_map(
        service: Annotated[str, Field(description="Service sys_id or exact name")],
        ci_class_contains: Annotated[Optional[str], Field(description="Only CIs whose class contains this, e.g. server, db, lb")] = None,
        limit: Limit = 200,
    ) -> dict[str, Any]:
        """CIs that make up an application service (Service Mapping svc_ci_assoc), with a breakdown by class."""
        svc = await _resolve_service(service)
        qb = QueryBuilder().add("service_id", "=", svc["sys_id"])
        qb.add_if("ci_id.sys_class_name", "like", ci_class_contains)
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(
            "svc_ci_assoc", q,
            fields=["ci_id", "ci_id.sys_id", "ci_id.sys_class_name", "ci_id.operational_status", "ci_id.ip_address"],
            limit=lim,
        )
        by_class = await sn.aggregate("svc_ci_assoc", q, ["ci_id.sys_class_name"])
        out = list_response("cis", "svc_ci_assoc", q, res, lim, 0)
        out["service"] = svc
        out["by_class"] = by_class
        if not res.records:
            out["hint"] = "Service has no svc_ci_assoc rows. It may be a manually modelled service: use cmdb_impact_analysis direction=downstream on it."
        return out

    @itom_tool(mcp, ctx, title="Service health")
    async def service_health(
        service: Annotated[str, Field(description="Service sys_id or exact name")],
    ) -> dict[str, Any]:
        """Health of a service: its operational status, open alerts on its CIs by severity, open incidents, and changes in progress."""
        svc = await _resolve_service(service)
        sid = svc["sys_id"]
        assoc = await sn.query(
            "svc_ci_assoc", QueryBuilder().add("service_id", "=", sid).build(),
            fields=["ci_id.sys_id"], limit=ctx.settings.max_limit,
        )
        ci_ids = [r.get("ci_id.sys_id") for r in assoc.records if r.get("ci_id.sys_id")]
        ci_ids = list(dict.fromkeys([sid] + ci_ids))[:100]
        alerts = await sn.aggregate(
            "em_alert", QueryBuilder().add("cmdb_ci", "in", ci_ids).add("state", "in", OPEN_STATES).build(), ["severity"]
        )
        inc_q = QueryBuilder().add_or([("cmdb_ci", "in", ci_ids), ("business_service", "=", sid)]).add("state", "in", OPEN_INCIDENT).build()
        incidents = await sn.query("incident", inc_q, fields=["number", "short_description", "priority", "state", "cmdb_ci", "opened_at"], limit=20)
        chg_q = QueryBuilder().add("cmdb_ci", "in", ci_ids).add("state", "in", ["-2", "-1", "0"]).build()  # Scheduled, Implement, Review
        changes = await sn.query("change_request", chg_q, fields=["number", "short_description", "state", "start_date", "end_date", "cmdb_ci"], limit=20)
        return {
            "service": svc,
            "cis_in_service": len(ci_ids),
            "open_alerts_by_severity": alerts,
            "open_incidents": {"total": incidents.total_count, "top": incidents.records},
            "active_changes": {"total": changes.total_count, "top": changes.records},
        }

    @itom_tool(mcp, ctx, title="CI operational summary")
    async def ci_operational_summary(
        ci: Annotated[str, Field(description="CI sys_id, exact name, IP or FQDN")],
        since: Annotated[str, Field(description="Window for changes/closed items: ISO date or relative")] = "30d",
    ) -> dict[str, Any]:
        """Everything operational about a CI: open alerts, open incidents, problems, recent and upcoming changes, outages, and the services it belongs to."""
        target = await resolve_ci(ctx, ci)
        sid = target["sys_id"]
        when = parse_when(since, "since")
        alerts = await sn.query(
            "em_alert", QueryBuilder().add("cmdb_ci", "=", sid).add("state", "in", OPEN_STATES).order_by("severity", descending=False).build(),
            fields=["number", "severity", "state", "description", "source", "sys_updated_on"], limit=20,
        )
        incidents = await sn.query(
            "incident", QueryBuilder().add("cmdb_ci", "=", sid).add("state", "in", OPEN_INCIDENT).build(),
            fields=["number", "short_description", "priority", "state", "assignment_group", "opened_at"], limit=20,
        )
        problems = await sn.query(
            "problem", QueryBuilder().add("cmdb_ci", "=", sid).add("active", "=", "true").build(),
            fields=["number", "short_description", "state", "priority", "opened_at"], limit=10,
        )
        changes = await sn.query(
            "change_request",
            QueryBuilder().add("cmdb_ci", "=", sid).add_or([("start_date", ">=", when), ("end_date", ">=", when)]).order_by("start_date").build(),
            fields=["number", "short_description", "type", "state", "risk", "start_date", "end_date"], limit=20,
        )
        affected = await sn.query(
            "task_ci", QueryBuilder().add("ci_item", "=", sid).add("sys_created_on", ">=", when).build(),
            fields=["task", "task.sys_class_name", "sys_created_on"], limit=20,
        )
        outages = await sn.query(
            "cmdb_ci_outage", QueryBuilder().add("cmdb_ci", "=", sid).add("begin", ">=", when).build(),
            fields=["number", "type", "begin", "end", "duration", "short_description", "task_number"], limit=20,
        )
        services = await sn.query(
            "svc_ci_assoc", QueryBuilder().add("ci_id", "=", sid).build(), fields=["service_id"], limit=50,
        )
        return {
            "ci": target,
            "open_alerts": {"total": alerts.total_count, "items": alerts.records},
            "open_incidents": {"total": incidents.total_count, "items": incidents.records},
            "active_problems": {"total": problems.total_count, "items": problems.records},
            "changes_in_window": {"total": changes.total_count, "items": changes.records},
            "tasks_affecting_ci": affected.records,
            "outages_in_window": outages.records,
            "member_of_services": [r.get("service_id") for r in services.records],
            "window_start_utc": when,
        }

    @itom_tool(mcp, ctx, title="List outages")
    async def outages_list(
        ci: Annotated[Optional[str], Field(description="CI sys_id / name (optional)")] = None,
        since: Annotated[str, Field(description="ISO date or relative")] = "30d",
        type: Annotated[Optional[Literal["outage", "degradation", "planned"]], Field()] = None,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """Outages / degradations / planned outages recorded against CIs."""
        qb = QueryBuilder().add("begin", ">=", parse_when(since, "since"))
        if ci:
            qb.add("cmdb_ci", "=", (await resolve_ci(ctx, ci))["sys_id"])
        qb.add_if("type", "=", type).order_by("begin")
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(
            "cmdb_ci_outage", q,
            fields=["number", "cmdb_ci", "type", "begin", "end", "duration", "short_description", "task_number"],
            limit=lim, offset=offset,
        )
        return list_response("outages", "cmdb_ci_outage", q, res, lim, offset)
