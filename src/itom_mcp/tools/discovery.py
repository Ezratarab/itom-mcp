"""Discovery (schedules, runs, logs, device history, failures) and MID Servers / ECC queue."""

from typing import Annotated, Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from itom_mcp.security import QueryBuilder, is_sys_id, parse_when, sanitize_value
from itom_mcp.tools.common import (
    DISCOVERY_STATE,
    ECC_STATE,
    MID_STATUS,
    Ctx,
    UserError,
    itom_tool,
    list_response,
    resolve_choices,
)

Limit = Annotated[Optional[int], Field(description="Max records (capped by MAX_LIMIT)", ge=1)]
Offset = Annotated[int, Field(ge=0)]

STATUS_FIELDS = [
    "sys_id", "number", "name", "state", "dscl_status", "discover", "dscheduler", "mid_server",
    "started", "completed", "sys_created_on", "sys_updated_on", "description",
]
MID_FIELDS = [
    "sys_id", "name", "status", "validated", "host_name", "ip_address", "host_os_distribution",
    "version", "last_refreshed", "started", "stopped", "up_since", "cpu_count", "max_threads", "is_using_custom_cert",
]


def register(mcp: FastMCP, ctx: Ctx) -> None:
    sn = ctx.sn

    async def _resolve_status(status: str) -> dict[str, Any]:
        s = sanitize_value(status, field="discovery_status")
        if is_sys_id(s.lower()):
            rec = await sn.get("discovery_status", s.lower(), fields=STATUS_FIELDS)
            if rec:
                return rec
        res = await sn.query("discovery_status", QueryBuilder().add("number", "=", s.upper()).build(), fields=STATUS_FIELDS, limit=1)
        if not res.records:
            raise UserError(f"No discovery status {s!r} (use number DIS0012345 or sys_id)")
        return res.records[0]

    @itom_tool(mcp, ctx, title="List Discovery schedules")
    async def discovery_list_schedules(
        name: Annotated[Optional[str], Field(description="Partial schedule name")] = None,
        active: Optional[bool] = None,
        discover: Annotated[Optional[str], Field(description="Type: CIs, IPs, Networks, Cloud Resources, Serverless")] = None,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """List Discovery schedules with type, MID server, run frequency and active flag."""
        qb = QueryBuilder().add_if("name", "like", name).add_if("discover", "=", discover)
        if active is not None:
            qb.add("active", "=", active)
        qb.order_by("name", descending=False)
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(
            "discovery_schedule", q,
            fields=["sys_id", "name", "discover", "active", "mid_select_method", "mid_server", "run_type", "run_time", "run_dayofweek", "max_run", "location", "sys_updated_on"],
            limit=lim, offset=offset,
        )
        return list_response("schedules", "discovery_schedule", q, res, lim, offset)

    @itom_tool(mcp, ctx, title="List Discovery runs")
    async def discovery_list_status(
        state: Annotated[Optional[str], Field(description="Comma list: Starting, Active, Completed, Cancelled")] = None,
        schedule: Annotated[Optional[str], Field(description="Partial schedule name")] = None,
        started_after: Annotated[Optional[str], Field(description="ISO date or relative (24h, 7d)")] = "7d",
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """List Discovery runs (discovery_status), newest first: state, schedule, MID server, start/end time."""
        qb = QueryBuilder()
        if st := resolve_choices(DISCOVERY_STATE, state, "state"):
            qb.add("state", "in", st)
        qb.add_if("dscheduler.name", "like", schedule)
        if started_after:
            qb.add("sys_created_on", ">=", parse_when(started_after, "started_after"))
        qb.order_by("sys_created_on")
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query("discovery_status", q, fields=STATUS_FIELDS, limit=lim, offset=offset)
        return list_response("runs", "discovery_status", q, res, lim, offset)

    @itom_tool(mcp, ctx, title="Discovery run details")
    async def discovery_get_status(
        status: Annotated[str, Field(description="Discovery status number (DIS0012345) or sys_id")],
    ) -> dict[str, Any]:
        """One Discovery run with a summary: devices by result, error/warning log counts, and the top error messages."""
        rec = await _resolve_status(status)
        sid = rec["sys_id"]
        dev_q = QueryBuilder().add("status", "=", sid).build()
        devices = await sn.aggregate("discovery_device_history", dev_q, ["classified_as"])
        completion = await sn.aggregate("discovery_device_history", dev_q, ["last_state"])
        log_q = QueryBuilder().add("status", "=", sid).build()
        levels = await sn.aggregate("discovery_log", log_q, ["level"])
        err_q = QueryBuilder().add("status", "=", sid).add("level", "=", "2").build()
        top_errors = await sn.aggregate("discovery_log", err_q, ["short_message"])
        return {
            "run": rec,
            "devices_by_class": devices[:50],
            "devices_by_result": completion,
            "log_levels": levels,
            "top_errors": top_errors[:20],
        }

    @itom_tool(mcp, ctx, title="Discovery log messages")
    async def discovery_get_logs(
        status: Annotated[Optional[str], Field(description="Discovery status number or sys_id (optional)")] = None,
        level: Annotated[Literal["error", "warning", "info", "all"], Field()] = "error",
        ip_address: Annotated[Optional[str], Field(description="Filter by device IP (source)")] = None,
        message_contains: Optional[str] = None,
        since: Annotated[Optional[str], Field(description="ISO date or relative; default 24h when no status given")] = None,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """Discovery log entries (errors by default) for a run, an IP, or a time window."""
        qb = QueryBuilder()
        if status:
            qb.add("status", "=", (await _resolve_status(status))["sys_id"])
        level_map = {"error": "2", "warning": "1", "info": "0"}
        if level != "all":
            qb.add("level", "=", level_map[level])
        qb.add_if("source", "starts_with", ip_address)
        qb.add_if("message", "like", message_contains)
        when = since or (None if status else "24h")
        if when:
            qb.add("sys_created_on", ">=", parse_when(when, "since"))
        qb.order_by("sys_created_on")
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(
            "discovery_log", q,
            fields=["sys_created_on", "level", "source", "short_message", "message", "status", "cmdb_ci", "sensor", "pattern"],
            limit=lim, offset=offset,
        )
        return list_response("logs", "discovery_log", q, res, lim, offset)

    @itom_tool(mcp, ctx, title="Discovery device history")
    async def discovery_device_history(
        status: Annotated[Optional[str], Field(description="Discovery status number or sys_id")] = None,
        ip_address: Annotated[Optional[str], Field(description="Device IP; shows its discovery history across runs")] = None,
        only_failures: Annotated[bool, Field(description="Only devices that were not fully discovered / classified")] = False,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """Per-device Discovery results: was the IP classified, which CI was created/updated, completion state, issues."""
        if not status and not ip_address:
            raise UserError("Pass status and/or ip_address")
        qb = QueryBuilder()
        if status:
            qb.add("status", "=", (await _resolve_status(status))["sys_id"])
        qb.add_if("source", "=", ip_address)
        if only_failures:
            qb.add_or([("cmdb_ci", "is_empty", None), ("issues", ">", "0")])
        qb.order_by("sys_created_on")
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(
            "discovery_device_history", q,
            fields=["sys_created_on", "source", "status", "classified_as", "cmdb_ci", "cmdb_action", "last_state", "current_state", "issues", "issues_link"],
            limit=lim, offset=offset,
        )
        return list_response("devices", "discovery_device_history", q, res, lim, offset)

    @itom_tool(mcp, ctx, title="Top Discovery failures")
    async def discovery_failure_summary(
        since: Annotated[str, Field(description="ISO date or relative (24h, 7d)")] = "7d",
        group_by: Annotated[Literal["short_message", "source", "sensor", "pattern"], Field(description="Group errors by message, IP, sensor or pattern")] = "short_message",
    ) -> dict[str, Any]:
        """Aggregate Discovery errors over a time window: the most common error messages / failing IPs / sensors / patterns."""
        q = QueryBuilder().add("level", "=", "2").add("sys_created_on", ">=", parse_when(since, "since")).build()
        rows = await sn.aggregate("discovery_log", q, [group_by])
        return {"query_used": q, "group_by": group_by, "total_errors": sum(r["count"] for r in rows), "top": rows[:50]}

    @itom_tool(mcp, ctx, title="Discovery IP ranges")
    async def discovery_list_ranges(
        schedule: Annotated[Optional[str], Field(description="Partial schedule name")] = None,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """IP ranges / networks / single IPs configured for Discovery."""
        qb = QueryBuilder().add_if("schedule.name", "like", schedule)
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(
            "discovery_range_item", q,
            fields=["sys_id", "name", "type", "start_ip_address", "end_ip_address", "network_ip", "netmask", "schedule", "active"],
            limit=lim, offset=offset,
        )
        return list_response("ranges", "discovery_range_item", q, res, lim, offset)

    # ---------------------------------------------------------------- MID servers

    @itom_tool(mcp, ctx, title="List MID Servers")
    async def mid_server_list(
        status: Annotated[Optional[str], Field(description="Comma list: Up, Down, Upgrading, Paused")] = None,
        name: Optional[str] = None,
        validated: Optional[bool] = None,
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """List MID Servers with status, validation, host, version and last heartbeat."""
        qb = QueryBuilder()
        if st := resolve_choices(MID_STATUS, status, "status"):
            qb.add("status", "in", st)
        qb.add_if("name", "like", name)
        if validated is not None:
            qb.add("validated", "=", validated)
        qb.order_by("name", descending=False)
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query("ecc_agent", q, fields=MID_FIELDS, limit=lim, offset=offset)
        return list_response("mid_servers", "ecc_agent", q, res, lim, offset)

    @itom_tool(mcp, ctx, title="MID Server health")
    async def mid_server_health(
        heartbeat_stale_minutes: Annotated[int, Field(ge=1, le=10080, description="Flag MID servers whose last heartbeat is older than this")] = 15,
    ) -> dict[str, Any]:
        """MID Server health: down / not validated / stale heartbeat / version drift, plus ECC queue backlog and errors per MID server."""
        res = await sn.query("ecc_agent", "", fields=MID_FIELDS, limit=ctx.settings.max_limit)
        mids = res.records
        stale_before = parse_when(f"{heartbeat_stale_minutes}m")
        # Compare server-side (UTC) rather than parsing display-formatted dates.
        stale_res = await sn.query(
            "ecc_agent", QueryBuilder().add("last_refreshed", "<", stale_before).build(),
            fields=["sys_id"], limit=ctx.settings.max_limit,
        )
        stale_ids = {r.get("sys_id") for r in stale_res.records}
        versions: dict[str, int] = {}
        for m in mids:
            versions[str(m.get("version"))] = versions.get(str(m.get("version")), 0) + 1
        main_version = max(versions, key=versions.get) if versions else None
        problems = []
        for m in mids:
            issues = []
            if str(m.get("status")).lower() != "up":
                issues.append(f"status={m.get('status')}")
            if str(m.get("validated")).lower() not in ("true", "validated"):
                issues.append(f"validated={m.get('validated')}")
            if m.get("sys_id") in stale_ids:
                issues.append(f"no heartbeat for > {heartbeat_stale_minutes} min (last_refreshed {m.get('last_refreshed')})")
            if main_version and str(m.get("version")) != main_version:
                issues.append(f"version {m.get('version')} differs from majority {main_version}")
            if issues:
                problems.append({"name": m.get("name"), "host_name": m.get("host_name"), "issues": issues})
        backlog_q = QueryBuilder().add("queue", "=", "output").add("state", "=", "ready").add("agent", "starts_with", "mid.server.").build()
        backlog = await sn.aggregate("ecc_queue", backlog_q, ["agent"])
        err_q = QueryBuilder().add("state", "=", "error").add("sys_created_on", ">=", parse_when("24h")).build()
        errors = await sn.aggregate("ecc_queue", err_q, ["agent"])
        return {
            "total": len(mids),
            "up": sum(1 for m in mids if str(m.get("status")).lower() == "up"),
            "majority_version": main_version,
            "problems": problems,
            "ecc_output_backlog_by_agent": backlog[:50],
            "ecc_errors_last_24h_by_agent": errors[:50],
        }

    @itom_tool(mcp, ctx, title="ECC queue messages")
    async def ecc_queue_list(
        agent: Annotated[Optional[str], Field(description="MID Server name (without 'mid.server.' prefix) or full agent")] = None,
        state: Annotated[Optional[str], Field(description="Comma list: ready, processing, processed, error")] = "error",
        queue: Annotated[Optional[Literal["input", "output"]], Field()] = None,
        topic: Annotated[Optional[str], Field(description="e.g. Shazzam, Powershell, SSHCommand, HorizontalDiscoveryProbe")] = None,
        since: Annotated[str, Field(description="ISO date or relative")] = "24h",
        limit: Limit = None,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """ECC queue entries (MID Server probes/sensors), errors by default. Payloads are not returned."""
        qb = QueryBuilder()
        if agent:
            a = sanitize_value(agent, field="agent")
            qb.add("agent", "=", a if a.startswith("mid.server.") else f"mid.server.{a}")
        if st := resolve_choices(ECC_STATE, state, "state"):
            qb.add("state", "in", st)
        qb.add_if("queue", "=", queue).add_if("topic", "=", topic)
        qb.add("sys_created_on", ">=", parse_when(since, "since"))
        qb.order_by("sys_created_on")
        q = qb.build()
        lim = sn.clamp_limit(limit)
        res = await sn.query(
            "ecc_queue", q,
            fields=["sys_id", "sys_created_on", "agent", "queue", "topic", "name", "source", "state", "error_string", "processed", "response_to"],
            limit=lim, offset=offset,
        )
        return list_response("messages", "ecc_queue", q, res, lim, offset)
