"""
ServiceNow REST client (Table API + Aggregate API).

Hardening:
  * URLs are only ever built from the validated instance URL + a validated table name +
    a validated sys_id. Absolute/caller-supplied URLs are impossible (SSRF guard).
  * Redirects are NOT followed (a redirect to another host would leak credentials).
  * TLS verification is always on (optional private CA via CA_BUNDLE, never "off").
  * Every request has a timeout; 429/502/503/504 are retried twice with capped backoff;
    a 401 under OAuth refreshes the token once.
  * Responses larger than MAX_RESPONSE_BYTES are refused.
  * Errors are classified; ServiceNow error text is returned but bodies, headers and
    credentials are never logged.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from itom_mcp.auth import AuthError, AuthManager
from itom_mcp.config import Settings
from itom_mcp.security import validate_field, validate_sys_id, validate_table

logger = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 20 * 1024 * 1024
_RETRY_STATUS = {429, 502, 503, 504}

_HINTS = {
    "unauthorized": "ServiceNow rejected the credentials (HTTP 401).",
    "forbidden": "ServiceNow denied access (HTTP 403): the integration user lacks a role or ACL. Run check_access.",
    "not_found": "Not found (HTTP 404): unknown table, record or API (is the ITOM plugin installed?).",
    "rate_limited": "ServiceNow rate limit hit (HTTP 429). Retry later.",
    "server_error": "ServiceNow returned a server error (HTTP 5xx).",
    "http_error": "ServiceNow returned an HTTP error.",
    "redirect": "ServiceNow answered with a redirect (often SSO). Redirects are not followed for security.",
    "timeout": "The request to ServiceNow timed out.",
    "connection": "Could not connect to ServiceNow (DNS, proxy, firewall or TLS problem).",
    "invalid_response": "ServiceNow returned a non-JSON response (often an SSO/login page).",
    "too_large": "ServiceNow response exceeded the size limit; narrow the query or lower the limit.",
    "auth": "Could not authenticate to ServiceNow.",
}


class SnError(RuntimeError):
    def __init__(self, error_type: str, status: Optional[int] = None, detail: str = ""):
        self.error_type = error_type
        self.status = status
        msg = _HINTS.get(error_type, "ServiceNow request failed.")
        if detail:
            msg = f"{msg} ServiceNow said: {detail[:300]}"
        super().__init__(msg)

    def as_dict(self) -> dict[str, Any]:
        return {"success": False, "error_type": self.error_type, "status_code": self.status, "message": str(self)}


@dataclass
class SnResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    total_count: Optional[int] = None
    elapsed_ms: int = 0


def _classify(status: int) -> str:
    if status == 401:
        return "unauthorized"
    if status == 403:
        return "forbidden"
    if status == 404:
        return "not_found"
    if status == 429:
        return "rate_limited"
    if 300 <= status < 400:
        return "redirect"
    if status >= 500:
        return "server_error"
    return "http_error"


def _sn_detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return ""
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        return " - ".join(str(err[k]) for k in ("message", "detail") if err.get(k))
    return ""


class ServiceNowClient:
    def __init__(self, settings: Settings, transport: Optional[httpx.AsyncBaseTransport] = None):
        self.settings = settings
        verify: Any = settings.ca_bundle or True
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.timeout),
            verify=verify,
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": "itom-mcp/1.0"},
        )
        self.auth = AuthManager(settings.auth, self._http)

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ low level

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        json: Optional[dict[str, Any]] = None,
    ) -> httpx.Response:
        # `path` is always produced by this class from validated parts.
        url = f"{self.settings.api_base}/{path}"
        refreshed = False
        for attempt in range(3):
            try:
                headers = await self.auth.headers()
            except AuthError as e:
                raise SnError("auth", detail=str(e)) from None
            if json is not None:
                headers["Content-Type"] = "application/json"
            started = time.monotonic()
            try:
                resp = await self._http.request(method, url, params=params, json=json, headers=headers)
            except httpx.TimeoutException:
                raise SnError("timeout") from None
            except httpx.TransportError as e:
                logger.warning("%s /api/now/%s transport error: %s", method, path, type(e).__name__)
                raise SnError("connection") from None
            elapsed = int((time.monotonic() - started) * 1000)
            logger.debug("%s /api/now/%s params=%s -> %s in %d ms", method, path, params, resp.status_code, elapsed)

            if resp.status_code == 401 and self.auth.can_refresh and not refreshed:
                self.auth.invalidate()
                refreshed = True
                continue
            if resp.status_code in _RETRY_STATUS and attempt < 2:
                try:
                    wait = min(float(resp.headers.get("Retry-After", "1")), 5.0)
                except ValueError:
                    wait = 1.0
                await asyncio.sleep(max(wait, 0.2) * (attempt + 1))
                continue
            break

        if resp.status_code >= 300:
            logger.warning("%s /api/now/%s -> HTTP %s", method, path, resp.status_code)
            raise SnError(_classify(resp.status_code), resp.status_code, _sn_detail(resp))
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise SnError("too_large", resp.status_code)
        return resp

    @staticmethod
    def _json(resp: httpx.Response) -> Any:
        ctype = resp.headers.get("content-type", "")
        if "json" not in ctype:
            raise SnError("invalid_response", resp.status_code)
        try:
            return resp.json()
        except ValueError:
            raise SnError("invalid_response", resp.status_code) from None

    # ------------------------------------------------------------------ table API

    async def query(
        self,
        table: str,
        query: str = "",
        *,
        fields: Optional[list[str]] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        display_value: str = "true",
    ) -> SnResult:
        t = validate_table(table)
        lim = self.clamp_limit(limit)
        params: dict[str, Any] = {
            "sysparm_limit": lim,
            "sysparm_offset": max(int(offset or 0), 0),
            "sysparm_display_value": display_value if display_value in ("true", "false", "all") else "true",
            "sysparm_exclude_reference_link": "true",
        }
        if query:
            params["sysparm_query"] = query
        if fields:
            params["sysparm_fields"] = ",".join(validate_field(f) for f in fields)
        started = time.monotonic()
        resp = await self._request("GET", f"table/{t}", params=params)
        body = self._json(resp)
        result = body.get("result", []) if isinstance(body, dict) else []
        records = [result] if isinstance(result, dict) else (result if isinstance(result, list) else [])
        total = resp.headers.get("X-Total-Count")
        return SnResult(
            records=records,
            total_count=int(total) if total and total.isdigit() else None,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )

    async def get(self, table: str, sys_id: str, *, fields: Optional[list[str]] = None, display_value: str = "true") -> dict[str, Any]:
        t = validate_table(table)
        sid = validate_sys_id(sys_id)
        params: dict[str, Any] = {"sysparm_display_value": display_value, "sysparm_exclude_reference_link": "true"}
        if fields:
            params["sysparm_fields"] = ",".join(validate_field(f) for f in fields)
        resp = await self._request("GET", f"table/{t}/{sid}", params=params)
        body = self._json(resp)
        result = body.get("result") if isinstance(body, dict) else None
        return result if isinstance(result, dict) else {}

    async def patch(self, table: str, sys_id: str, data: dict[str, Any]) -> dict[str, Any]:
        if self.settings.read_only:
            raise SnError("http_error", detail="server is in READ_ONLY mode")
        t = validate_table(table)
        sid = validate_sys_id(sys_id)
        clean = {validate_field(k): v for k, v in data.items()}
        resp = await self._request(
            "PATCH", f"table/{t}/{sid}", params={"sysparm_display_value": "true"}, json=clean
        )
        body = self._json(resp)
        result = body.get("result") if isinstance(body, dict) else None
        return result if isinstance(result, dict) else {}

    # ------------------------------------------------------------------ aggregate API

    async def aggregate(self, table: str, query: str = "", group_by: Optional[list[str]] = None) -> list[dict[str, Any]]:
        """Count records, optionally grouped. Returns [{'count': n, 'groups': {field: display}}]."""
        t = validate_table(table)
        params: dict[str, Any] = {"sysparm_count": "true", "sysparm_display_value": "true"}
        if query:
            params["sysparm_query"] = query
        if group_by:
            params["sysparm_group_by"] = ",".join(validate_field(g) for g in group_by)
        resp = await self._request("GET", f"stats/{t}", params=params)
        body = self._json(resp)
        result = body.get("result") if isinstance(body, dict) else None
        rows = result if isinstance(result, list) else ([result] if isinstance(result, dict) else [])
        out = []
        for row in rows:
            stats = row.get("stats") or {}
            try:
                count = int(stats.get("count", 0))
            except (TypeError, ValueError):
                count = 0
            groups = {}
            for g in row.get("groupby_fields") or []:
                groups[g.get("field")] = g.get("display_value") or g.get("value") or "(empty)"
            out.append({"count": count, "groups": groups} if groups else {"count": count})
        out.sort(key=lambda r: r["count"], reverse=True)
        return out

    async def count(self, table: str, query: str = "") -> int:
        rows = await self.aggregate(table, query)
        return rows[0]["count"] if rows else 0

    # ------------------------------------------------------------------ helpers

    def clamp_limit(self, limit: Optional[int]) -> int:
        if limit is None:
            return self.settings.default_limit
        return max(1, min(int(limit), self.settings.max_limit))
