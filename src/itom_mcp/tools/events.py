"""Event Management: events, alerts, alert summaries, rules, connectors, and (opt-in) alert actions."""

from typing import Annotated, Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from itom_mcp.security import QueryBuilder, is_sys_id, parse_when, sanitize_value
from itom_mcp.tools.common import (
    ALERT_STATE,
    EVENT_STATE,
    SEVERITY,
    Ctx,
    UserError,
    itom_tool,
    list_response,
    resolve_choices,
    resolve_ci,
)

Limit = Annotated[Optional[int], Field(description="Max records (capped by MAX_LIMIT)", ge=1)]
Offset = Annotated[int, Field(ge=0)]
Severity = Annotated[Optional[str], Field(description="Comma list of labels or values: Critical(1), Major(2), Minor(3), Warning(4), Info(5), Clear(0)")]

ALERT_FIELDS = [
    "sys_id", "number", "state", "severity", "priority", "source", "node", "type", "resource", "metric_name",
    "description", "cmdb_ci", "assignment_group", "acknowledged", "maintenance", "incident", "parent",
    "group_source", "is_group", "initial_remote_time", "last_remote_time", "sys_created_on", "sys_updated_on",
    "message_key", "correlation_rule_group",
]
EVENT_FIELDS = [
    "sys_id", "time_of_event", "source", "node", "type", "resource", "metric_name", "severity", "state",
    "description", "message_key", "alert", "cmdb_ci", "processing_notes", "sys_created_on",
]
OPEN_STATES = ["Open", "Reopen", "Flapping"]
ALERT_GROUPABLE = {"severity", "state", "source", "node", "type", "cmdb_ci", "assignment_group", "metric_name", "acknowledged", "maintenance"}


def register(mcp: FastMCP, ctx: Ctx) -> None:
    sn = ctx.sn

    async def _resolve_alert(alert: str) -> dict[str, Any]:
        a = sanitize_value(alert, field="alert")
        if is_sys_id(a.lower()):
            rec = await sn.get("em_alert", a.lower(), fields=ALERT_FIELDS)
            if rec:
                return rec
        res = await sn.query("em_alert", QueryBuilder().add("number", "=", a.upper()).build(), fields=ALERT_FIELDS, limit=1)
        if not res.records:
            raise UserError(f"No alert {a!r} (use Alert0012345 number or sys_id)")
        return res.records[0]

    def _alert_query(
        *, state, severity, source, node, ci_sys_id, assignment_group, acknowledged, in_maintenance,
        description_contains, created_after, updated_after, has_incident,
    ) -> QueryBuilder:
        qb = QueryBuilder()
        states = resolve_choices(ALERT_STATE, state, "state") if state and state.lower() != "open" else (OPEN_STATES if state else [])
        if states:
            qb.add("state", "in", states)
        if sev := resolve_choices(SEVERITY, severity, "severity"):
            qb.add("severity", "in", sev)
        qb.add_if("source", "like", source).add_if("node", "like", node).add_if("cmdb_ci", "=", ci_sys_id)
        qb.add_if("assignment_group.name", "like", assignment_group).add_if("description", "like", description_contains)
        if acknowledged is not None:
            qb.add("acknowledged", "=", acknowledged)
        if in_maintenance is not None:
            qb.add("maintenance", "=", in_maintenance)
        if has_incident is not None:
            qb.add("incident", "is_not_empty" if has_incident else "is_empty")
        if created_after:
            qb.add("sys_created_on", ">=", parse_when(created_after, "created_after"))
        if updated_after:
            qb.add("sys_updated_on", ">=", parse_when(updated_after, "updated_after"))
        return qb

    @itom_tool(mcp, ctx, title="List alerts")
    async def alerts_list(
        state: Annotated[Optional[str], Field(description="'open' (= Open, Reopen, Flapping) or comma list: Open, Reopen, Flapping, Closed. Empty = all")] = "open",
        severity: Severity = None,
        source: Annotated[Optional[str], Field(description="Monitoring source, e.g. SCOM, Nagios, Dynatrace, AWS")] = None,
        node: Annotated[Optional[str], Field(description="Partial node/host name")] = None,
        ci: Annotated[Optional[str], Field(description="CI sys_id, name, IP or FQDN")] = None,
        assignment_group: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        in_maintenance: Optional[bool] = None,
        has_incident: Annotated[Optional[bool], Field(description="True = alert has an incident; False = no incident yet")] = None,
        description_contains: Optional[str] = None,
        created_after: Annotated[Optional[str], Field(description="ISO date or relative (1h, 24h, 7d)")] = None,
        updated_after: Optional[str] = None,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """List Event Management alerts (open by default), most recently updated first."""
        ci_id = (await resolve_ci(ctx, ci))["sys_id"] if ci else None
        qb = _alert_query(
            state=state, severity=severity, source=source, node=node, ci_sys_id=ci_id,
            assignment_group=assignment_group, acknowledged=acknowledged, in_maintenance=in_maintenance,
            description_contains=description_contains, created_after=created_after,
            updated_after=updated_after, has_incident=has_incident,
        )
        qb.order_by("sys_updated_on")
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query("em_alert", q, fields=ALERT_FIELDS, limit=lim, offset=offset)
        return list_response("alerts", "em_alert", q, res, lim, offset)

    @itom_tool(mcp, ctx, title="Alert details")
    async def alert_get(
        alert: Annotated[str, Field(description="Alert number (Alert0012345) or sys_id")],
        include_events: Annotated[bool, Field(description="Include the latest events that fed this alert")] = True,
        include_children: Annotated[bool, Field(description="Include correlated child alerts (if this is a group/parent)")] = True,
    ) -> dict[str, Any]:
        """One alert with its CI, related events, correlated child alerts and linked incident."""
        rec = await _resolve_alert(alert)
        out: dict[str, Any] = {"alert": rec}
        if include_events:
            q = QueryBuilder().add("alert", "=", rec["sys_id"]).order_by("sys_created_on").build()
            out["events"] = (await sn.query("em_event", q, fields=EVENT_FIELDS, limit=20)).records
        if include_children:
            q = QueryBuilder().add("parent", "=", rec["sys_id"]).build()
            out["child_alerts"] = (await sn.query("em_alert", q, fields=["number", "state", "severity", "node", "description", "cmdb_ci"], limit=50)).records
        return out

    @itom_tool(mcp, ctx, title="Alert summary / counts")
    async def alerts_summary(
        group_by: Annotated[str, Field(description="Comma list (max 2) of: " + ", ".join(sorted(ALERT_GROUPABLE)))] = "severity",
        state: Annotated[Optional[str], Field(description="'open' or comma list of states; empty = all")] = "open",
        severity: Severity = None,
        source: Optional[str] = None,
        created_after: Annotated[Optional[str], Field(description="ISO date or relative")] = None,
    ) -> dict[str, Any]:
        """Count alerts grouped by severity / state / source / node / CI / group. Answers 'how many critical alerts are open', 'noisiest nodes', etc."""
        groups = [g.strip() for g in group_by.split(",") if g.strip()]
        if not groups or len(groups) > 2 or any(g not in ALERT_GROUPABLE for g in groups):
            raise UserError(f"group_by: 1-2 of {sorted(ALERT_GROUPABLE)}")
        q = _alert_query(
            state=state, severity=severity, source=source, node=None, ci_sys_id=None, assignment_group=None,
            acknowledged=None, in_maintenance=None, description_contains=None, created_after=created_after,
            updated_after=None, has_incident=None,
        ).build()
        rows = await sn.aggregate("em_alert", q, groups)
        return {"query_used": q, "group_by": groups, "total": sum(r["count"] for r in rows), "rows": rows[:200]}

    @itom_tool(mcp, ctx, title="List events")
    async def events_list(
        state: Annotated[Optional[str], Field(description="Comma list: Ready, Processing, Processed, Error, Ignored")] = None,
        severity: Severity = None,
        source: Optional[str] = None,
        node: Optional[str] = None,
        message_key: Optional[str] = None,
        description_contains: Optional[str] = None,
        since: Annotated[str, Field(description="ISO date or relative")] = "1h",
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """List raw events (em_event), newest first. Use state=Error to find events that failed processing."""
        qb = QueryBuilder()
        if st := resolve_choices(EVENT_STATE, state, "state"):
            qb.add("state", "in", st)
        if sev := resolve_choices(SEVERITY, severity, "severity"):
            qb.add("severity", "in", sev)
        qb.add_if("source", "like", source).add_if("node", "like", node).add_if("message_key", "=", message_key)
        qb.add_if("description", "like", description_contains)
        qb.add("sys_created_on", ">=", parse_when(since, "since")).order_by("sys_created_on")
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query("em_event", q, fields=EVENT_FIELDS, limit=lim, offset=offset)
        return list_response("events", "em_event", q, res, lim, offset)

    @itom_tool(mcp, ctx, title="Event volume summary")
    async def events_summary(
        group_by: Annotated[Literal["source", "node", "state", "severity", "type", "metric_name"], Field()] = "source",
        since: Annotated[str, Field(description="ISO date or relative")] = "24h",
    ) -> dict[str, Any]:
        """Event volume grouped by source / node / state / severity / type over a time window (noise analysis)."""
        q = QueryBuilder().add("sys_created_on", ">=", parse_when(since, "since")).build()
        rows = await sn.aggregate("em_event", q, [group_by])
        return {"query_used": q, "group_by": group_by, "total": sum(r["count"] for r in rows), "rows": rows[:200]}

    @itom_tool(mcp, ctx, title="Event & alert rules")
    async def event_rules_list(
        kind: Annotated[Literal["event_rules", "alert_management_rules"], Field()] = "event_rules",
        name: Optional[str] = None,
        active: Optional[bool] = None,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """List Event Management event rules (em_match_rule) or alert management rules (em_alert_management_rule). Scripts are not returned."""
        table = "em_match_rule" if kind == "event_rules" else "em_alert_management_rule"
        qb = QueryBuilder().add_if("name", "like", name)
        if active is not None:
            qb.add("active", "=", active)
        qb.order_by("order" if kind == "event_rules" else "name", descending=False)
        q = qb.build()
        lim = sn.clamp_limit(limit)
        fields = ["sys_id", "name", "active", "order", "source", "description", "filter", "sys_updated_on", "sys_updated_by"]
        res = await sn.query(table, q, fields=fields, limit=lim, offset=offset)
        return list_response("rules", table, q, res, lim, offset)

    @itom_tool(mcp, ctx, title="Event connectors")
    async def event_connectors_list(
        active: Optional[bool] = None,
        limit: Limit = None,
    ) -> dict[str, Any]:
        """List Event Management connector instances (SCOM, SolarWinds, Zabbix...) with last run status. Credentials are never returned."""
        qb = QueryBuilder()
        if active is not None:
            qb.add("active", "=", active)
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(
            "em_connector_instance", q,
            fields=["sys_id", "name", "connector_definition", "active", "host", "mid_server", "last_run_status", "last_run_time", "last_error_message", "schedule"],
            limit=lim,
        )
        return list_response("connectors", "em_connector_instance", q, res, lim, 0)

    # ---------------------------------------------------------------- write (READ_ONLY=false only)

    def _confirm(confirm: bool) -> None:
        if confirm is not True:
            raise UserError("Write action not performed: set confirm=true after the user explicitly approved it.")

    @itom_tool(mcp, ctx, write=True, title="Acknowledge alert")
    async def alert_acknowledge(
        alert: Annotated[str, Field(description="Alert number or sys_id")],
        confirm: Annotated[bool, Field(description="Must be true; only after explicit user approval")] = False,
    ) -> dict[str, Any]:
        """[WRITE] Acknowledge an alert. Requires READ_ONLY=false and confirm=true."""
        _confirm(confirm)
        rec = await _resolve_alert(alert)
        updated = await sn.patch("em_alert", rec["sys_id"], {"acknowledged": "true"})
        return {"updated": {k: updated.get(k) for k in ("number", "state", "acknowledged")}}

    @itom_tool(mcp, ctx, write=True, title="Close alert")
    async def alert_close(
        alert: Annotated[str, Field(description="Alert number or sys_id")],
        work_note: Annotated[str, Field(description="Reason for closing (required, max 2000 chars)", max_length=2000)],
        confirm: Annotated[bool, Field(description="Must be true; only after explicit user approval")] = False,
    ) -> dict[str, Any]:
        """[WRITE] Close an alert with a work note. Requires READ_ONLY=false and confirm=true."""
        _confirm(confirm)
        note = sanitize_value(work_note, field="work_note", max_len=2000)
        rec = await _resolve_alert(alert)
        updated = await sn.patch("em_alert", rec["sys_id"], {"state": "Closed", "work_notes": note})
        return {"updated": {k: updated.get(k) for k in ("number", "state")}}

    @itom_tool(mcp, ctx, write=True, title="Add alert work note")
    async def alert_add_work_note(
        alert: Annotated[str, Field(description="Alert number or sys_id")],
        work_note: Annotated[str, Field(max_length=2000)],
        confirm: Annotated[bool, Field(description="Must be true; only after explicit user approval")] = False,
    ) -> dict[str, Any]:
        """[WRITE] Add a work note to an alert. Requires READ_ONLY=false and confirm=true."""
        _confirm(confirm)
        note = sanitize_value(work_note, field="work_note", max_len=2000)
        rec = await _resolve_alert(alert)
        await sn.patch("em_alert", rec["sys_id"], {"work_notes": note})
        return {"updated": rec.get("number")}
