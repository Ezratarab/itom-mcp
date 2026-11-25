"""
Generic, still-safe access for questions the dedicated tools don't cover:
structured filters only (no raw encoded queries), allowlisted tables only.
Also: check_access (connectivity / permissions self-test).
"""

from typing import Annotated, Any, Literal, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from itom_mcp.client import SnError
from itom_mcp.security import ALLOWED_TABLES, OPERATORS, QueryBuilder, parse_when, validate_field, validate_table
from itom_mcp.tools.common import Ctx, UserError, itom_tool, list_response

Limit = Annotated[Optional[int], Field(description="Max records (capped by MAX_LIMIT)", ge=1)]


class Filter(BaseModel):
    field: str = Field(description="Field name; dot-walking allowed, e.g. support_group.name")
    op: str = Field(description="One of: " + ", ".join(sorted(set(OPERATORS))) + ", or 'since' (value = 24h / 7d / ISO date, means >=)")
    value: Optional[str] = Field(default=None, description="Value (comma list for in/not_in; omit for is_empty/is_not_empty)")


def _build(filters: Optional[list[Filter]], table: str) -> QueryBuilder:
    qb = QueryBuilder(table)
    if filters and len(filters) > 20:
        raise UserError("at most 20 filters")
    for f in filters or []:
        if f.op.strip().lower() == "since":
            qb.add(f.field, ">=", parse_when(f.value or "", f.field))
        else:
            qb.add(f.field, f.op, f.value)
    return qb


def register(mcp: FastMCP, ctx: Ctx) -> None:
    sn = ctx.sn

    @itom_tool(mcp, ctx, title="List queryable ITOM tables")
    async def list_itom_tables() -> dict[str, Any]:
        """Tables the generic tools may read: the allowlist below plus every cmdb_ci_* CI class. Credential, user, script and property tables are never readable."""
        return {"tables": ALLOWED_TABLES, "plus": "any CMDB CI class table matching cmdb_ci_*"}

    @itom_tool(mcp, ctx, title="Check ServiceNow access")
    async def check_access(
        scope: Annotated[Literal["core", "all"], Field(description="core = main ITOM tables; all = every allowlisted table")] = "core",
    ) -> dict[str, Any]:
        """Self-test: connectivity, authentication and read access per ITOM table (HTTP status + visible row count). Run first when results look empty."""
        core = ["cmdb_ci", "cmdb_rel_ci", "svc_ci_assoc", "discovery_status", "discovery_log", "ecc_agent", "ecc_queue", "em_event", "em_alert", "incident", "change_request"]
        tables = core if scope == "core" else list(ALLOWED_TABLES)
        results: dict[str, Any] = {}
        for t in tables:
            try:
                res = await sn.query(t, "", fields=["sys_id"], limit=1)
                results[t] = {"readable": True, "visible_count": res.total_count}
            except SnError as e:
                results[t] = {"readable": False, "error_type": e.error_type, "status_code": e.status}
        aggregate_ok = True
        try:
            await sn.count("cmdb_ci")
        except SnError:
            aggregate_ok = False
        readable = [t for t, r in results.items() if r["readable"]]
        return {
            "success": bool(readable),
            "instance": ctx.settings.instance_host,
            "auth_type": ctx.settings.auth.type.value,
            "read_only": ctx.settings.read_only,
            "aggregate_api": aggregate_ok,
            "tables": results,
            "tools_registered": len(ctx.registered),
            "write_tools_hidden": ctx.hidden_write_tools,
        }

    if not ctx.settings.enable_generic_query:
        return

    @itom_tool(mcp, ctx, title="Query an ITOM table")
    async def itom_query(
        table: Annotated[str, Field(description="Allowlisted table (see list_itom_tables), e.g. em_alert, cmdb_ci_linux_server, discovery_status")],
        filters: Annotated[Optional[list[Filter]], Field(description="AND-ed structured filters")] = None,
        fields: Annotated[Optional[str], Field(description="Comma list of fields to return (default: all non-sensitive fields)")] = None,
        order_by: Annotated[Optional[str], Field(description="Field to sort by")] = "sys_updated_on",
        descending: bool = True,
        limit: Limit = None,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        """Generic read of any allowlisted ITOM table with structured, injection-safe filters. Use when no dedicated tool fits."""
        t = validate_table(table)
        qb = _build(filters, t)
        if order_by:
            qb.order_by(order_by, descending)
        q = qb.build()
        field_list = [validate_field(f, t) for f in (fields or "").split(",") if f.strip()] or None
        if field_list and len(field_list) > 60:
            raise UserError("at most 60 fields")
        lim = sn.clamp_limit(limit)
        res = await sn.query(t, q, fields=field_list, limit=lim, offset=offset)
        return list_response("records", t, q, res, lim, offset)

    @itom_tool(mcp, ctx, title="Count / group an ITOM table")
    async def itom_count(
        table: Annotated[str, Field(description="Allowlisted table")],
        filters: Annotated[Optional[list[Filter]], Field(description="AND-ed structured filters")] = None,
        group_by: Annotated[Optional[str], Field(description="Comma list of up to 2 fields")] = None,
    ) -> dict[str, Any]:
        """Count records in an allowlisted ITOM table, optionally grouped by up to 2 fields (Aggregate API)."""
        t = validate_table(table)
        q = _build(filters, t).build()
        groups = [validate_field(g, t) for g in (group_by or "").split(",") if g.strip()]
        if len(groups) > 2:
            raise UserError("group_by: at most 2 fields")
        rows = await sn.aggregate(t, q, groups or None)
        return {"table": t, "query_used": q, "group_by": groups, "total": sum(r["count"] for r in rows), "rows": rows[:500]}
