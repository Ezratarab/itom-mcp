"""Shared helpers for tool modules: context, the secure tool decorator, CI resolution, choices."""

from __future__ import annotations

import functools
import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from itom_mcp.client import ServiceNowClient, SnError, SnResult
from itom_mcp.config import Settings
from itom_mcp.security import (
    UNTRUSTED_NOTICE,
    QueryBuilder,
    RateLimiter,
    SecurityError,
    is_sys_id,
    sanitize_value,
    scrub,
    validate_ci_class,
)

audit = logging.getLogger("itom_mcp.audit")
logger = logging.getLogger(__name__)


class UserError(ValueError):
    """Bad input / not found / ambiguous. Message is safe to return."""


@dataclass
class Ctx:
    settings: Settings
    sn: ServiceNowClient
    limiter: RateLimiter
    registered: list[str]
    hidden_write_tools: list[str]


# --------------------------------------------------------------------------- decorator


def _summarize_args(kwargs: dict[str, Any]) -> str:
    """Audit-safe argument summary: values truncated, never more than 300 chars."""
    parts = []
    for k, v in kwargs.items():
        if v is None:
            continue
        s = json.dumps(v, default=str)
        parts.append(f"{k}={s[:60]}")
    return ", ".join(parts)[:300]


def itom_tool(
    mcp: FastMCP,
    ctx: Ctx,
    *,
    write: bool = False,
    title: Optional[str] = None,
) -> Callable[[Callable[..., Awaitable[dict[str, Any]]]], Any]:
    """
    Register an async tool with: rate limiting, audit logging, uniform error handling,
    output scrubbing and the untrusted-data notice. Write tools are only registered when
    READ_ONLY=false, and are marked destructive.
    """

    def deco(fn: Callable[..., Awaitable[dict[str, Any]]]):
        name = fn.__name__
        if write and ctx.settings.read_only:
            ctx.hidden_write_tools.append(name)
            return fn

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
            started = time.monotonic()
            outcome = "ok"
            try:
                ctx.limiter.check()
                result = await fn(*args, **kwargs)
                result = scrub(result, ctx.settings.max_field_chars)
                if isinstance(result, dict):
                    result.setdefault("success", True)
                    result["_notice"] = UNTRUSTED_NOTICE
                return result
            except (SecurityError, UserError) as e:
                outcome = "rejected"
                return {"success": False, "error_type": "invalid_input", "message": str(e)}
            except SnError as e:
                outcome = f"sn_{e.error_type}"
                return e.as_dict()
            except Exception:  # noqa: BLE001 - never leak tracebacks to the client
                ref = uuid.uuid4().hex[:12]
                outcome = f"internal:{ref}"
                logger.exception("Unhandled error in tool %s (ref %s)", name, ref)
                return {"success": False, "error_type": "internal", "message": f"Internal error (ref {ref}). See server logs."}
            finally:
                audit.info(
                    "tool=%s write=%s outcome=%s ms=%d args=[%s]",
                    name,
                    write,
                    outcome,
                    int((time.monotonic() - started) * 1000),
                    _summarize_args(kwargs),
                )

        annotations = ToolAnnotations(
            title=title,
            readOnlyHint=not write,
            destructiveHint=write,
            idempotentHint=not write,
            openWorldHint=False,
        )
        mcp.add_tool(wrapper, name=name, title=title, description=(fn.__doc__ or "").strip(), annotations=annotations)
        ctx.registered.append(name)
        return wrapper

    return deco


# --------------------------------------------------------------------------- responses


def list_response(key: str, table: str, query: str, res: SnResult, limit: int, offset: int) -> dict[str, Any]:
    out: dict[str, Any] = {
        "table": table,
        "query_used": query,
        "returned": len(res.records),
        "total_count": res.total_count,
        "limit": limit,
        "offset": offset,
        key: res.records,
    }
    if not res.records:
        out["hint"] = (
            "No records matched. If you expected results, the integration user may lack read "
            "ACLs on this table or domain; run check_access."
        )
    elif res.total_count is not None and res.total_count > offset + len(res.records):
        out["next_offset"] = offset + len(res.records)
    return out


# --------------------------------------------------------------------------- choices

OPERATIONAL_STATUS = {"1": "Operational", "2": "Non-Operational", "3": "Repair in Progress", "4": "DR Standby", "5": "Ready", "6": "Retired", "7": "Pipeline", "8": "Catalog"}
INSTALL_STATUS = {"1": "Installed", "2": "On Order", "3": "In Maintenance", "4": "Pending Install", "5": "Pending Repair", "6": "In Stock", "7": "Retired", "8": "Stolen", "100": "Absent"}
SEVERITY = {"0": "Clear", "1": "Critical", "2": "Major", "3": "Minor", "4": "Warning", "5": "Info"}
ALERT_STATE = {"Open": "Open", "Reopen": "Reopen", "Flapping": "Flapping", "Closed": "Closed"}
EVENT_STATE = {"Ready": "Ready", "Processing": "Processing", "Processed": "Processed", "Error": "Error", "Ignored": "Ignored"}
DISCOVERY_STATE = {"Starting": "Starting", "Active": "Active", "Completed": "Completed", "Cancelled": "Cancelled"}
MID_STATUS = {"Up": "Up", "Down": "Down", "Upgrading": "Upgrading", "Paused": "Paused"}
ECC_STATE = {"ready": "ready", "processing": "processing", "processed": "processed", "error": "error"}


def resolve_choice(mapping: dict[str, str], value: Optional[str], name: str) -> Optional[str]:
    """Accept a stored value or a label (case-insensitive). Unknown -> error listing valid ones."""
    if value is None or str(value).strip() == "":
        return None
    v = sanitize_value(value, field=name)
    if v in mapping:
        return v
    for key, label in mapping.items():
        if v.lower() in (label.lower(), key.lower()):
            return key
    valid = ", ".join(f"{label} ({key})" if key != label else label for key, label in mapping.items())
    raise UserError(f"{name}: unknown value {v!r}. Valid: {valid}")


def resolve_choices(mapping: dict[str, str], value: Optional[str], name: str) -> list[str]:
    """Comma-separated list of choices."""
    if not value:
        return []
    return [resolve_choice(mapping, p, name) for p in str(value).split(",") if p.strip()]  # type: ignore[misc]


# --------------------------------------------------------------------------- CIs

CI_FIELDS = [
    "sys_id", "name", "sys_class_name", "ip_address", "fqdn", "operational_status", "install_status",
    "environment", "location", "support_group", "managed_by", "owned_by", "manufacturer", "model_id",
    "serial_number", "os", "os_version", "discovery_source", "last_discovered", "first_discovered",
    "sys_updated_on", "short_description", "used_for", "business_criticality",
]


async def resolve_ci(ctx: Ctx, identifier: str, ci_class: str = "cmdb_ci") -> dict[str, Any]:
    """sys_id or exact name -> {sys_id, name, sys_class_name}. Ambiguity is an error with candidates."""
    ident = sanitize_value(identifier, field="ci")
    table = validate_ci_class(ci_class)
    fields = ["sys_id", "name", "sys_class_name", "ip_address", "operational_status"]
    if is_sys_id(ident.lower()):
        rec = await ctx.sn.get(table, ident.lower(), fields=fields)
        if not rec:
            raise UserError(f"No CI with sys_id {ident}")
        return rec
    q = QueryBuilder().add("name", "=", ident).build()
    res = await ctx.sn.query(table, q, fields=fields, limit=10)
    if len(res.records) == 1:
        return res.records[0]
    if len(res.records) > 1:
        raise UserError(
            f"{len(res.records)} CIs are named {ident!r}; pass a sys_id or a more specific ci_class. "
            f"Candidates: {json.dumps(res.records)[:1500]}"
        )
    q = QueryBuilder().add_or([("name", "like", ident), ("ip_address", "=", ident), ("fqdn", "=", ident)]).build()
    res = await ctx.sn.query(table, q, fields=fields, limit=10)
    if len(res.records) == 1:
        return res.records[0]
    if not res.records:
        raise UserError(f"No CI found matching {ident!r} in {table}")
    raise UserError(f"No exact match for {ident!r}. Similar CIs: {json.dumps(res.records)[:1500]}")
