"""
ServiceNow authentication: the same three modes and the same OAuth flow as
oricohen392/mcp-snow (``auth/auth_manager.py``):

  * basic   - ``Authorization: Basic base64(user:password)``
  * oauth   - POST <token_url> with ``Authorization: Basic base64(client_id:client_secret)``,
              first ``grant_type=client_credentials``; if that fails and a username/password
              is configured, ``grant_type=password``. Result: ``Authorization: <token_type> <token>``
  * api_key - ``<SERVICENOW_API_KEY_HEADER>: <SERVICENOW_API_KEY>``

Additions: the token is cached with its ``expires_in`` and refreshed 60 s early or after
a 401, refreshes are serialised by a lock, and nothing secret is ever logged.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Optional

import httpx

from itom_mcp.config import AuthConfig, AuthType

logger = logging.getLogger(__name__)


class AuthError(RuntimeError):
    """Authentication failed. Message never contains secrets or token bodies."""


def _basic(user: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


class AuthManager:
    REFRESH_SKEW_SECONDS = 60

    def __init__(self, config: AuthConfig, http: httpx.AsyncClient):
        self.config = config
        self._http = http
        self._token: Optional[str] = None
        self._token_type: str = "Bearer"
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    async def headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        c = self.config
        if c.type is AuthType.BASIC:
            h["Authorization"] = _basic(c.username or "", c.password.get_secret_value())  # type: ignore[union-attr]
        elif c.type is AuthType.API_KEY:
            h[c.api_key_header] = c.api_key.get_secret_value()  # type: ignore[union-attr]
        else:
            await self._ensure_token()
            h["Authorization"] = f"{self._token_type} {self._token}"
        return h

    def invalidate(self) -> None:
        """Drop a cached OAuth token (called after a 401)."""
        self._token = None
        self._expires_at = 0.0

    @property
    def can_refresh(self) -> bool:
        return self.config.type is AuthType.OAUTH

    async def _ensure_token(self) -> None:
        if self._token and time.monotonic() < self._expires_at:
            return
        async with self._lock:
            if self._token and time.monotonic() < self._expires_at:
                return
            await self._fetch_token()

    async def _fetch_token(self) -> None:
        c = self.config
        if not (c.client_id and c.client_secret and c.token_url):
            raise AuthError("OAuth is not fully configured")
        headers = {
            "Authorization": _basic(c.client_id, c.client_secret.get_secret_value()),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        grants: list[dict[str, str]] = [{"grant_type": "client_credentials"}]
        if c.username and c.password:
            grants.append(
                {
                    "grant_type": "password",
                    "username": c.username,
                    "password": c.password.get_secret_value(),
                }
            )
        for data in grants:
            grant = data["grant_type"]
            try:
                resp = await self._http.post(c.token_url, headers=headers, data=data)
            except httpx.HTTPError as e:
                # Exception text may include the URL, never the body/credentials.
                logger.warning("OAuth %s grant transport error: %s", grant, type(e).__name__)
                continue
            # Never log the response body: it contains the access token.
            logger.debug("OAuth %s grant -> HTTP %s", grant, resp.status_code)
            if resp.status_code != 200:
                continue
            try:
                body = resp.json()
            except ValueError:
                continue
            token = body.get("access_token") if isinstance(body, dict) else None
            if not token:
                continue
            self._token = str(token)
            self._token_type = str(body.get("token_type") or "Bearer")
            try:
                ttl = int(body.get("expires_in") or 1800)
            except (TypeError, ValueError):
                ttl = 1800
            self._expires_at = time.monotonic() + max(ttl - self.REFRESH_SKEW_SECONDS, 30)
            logger.info("OAuth token obtained via %s grant", grant)
            return
        raise AuthError("Failed to get OAuth token using client_credentials and password grants")
