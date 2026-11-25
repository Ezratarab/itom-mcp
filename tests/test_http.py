import pytest
from starlette.testclient import TestClient

from itom_mcp.config import ConfigError
from itom_mcp.server import build_http_app, build_server
from tests.conftest import make_settings

TOKEN = "t" * 40


def app_for(**kw):
    s = make_settings(**kw)
    mcp, _ = build_server(s)
    return build_http_app(mcp, s)


def test_refuses_public_bind_without_token():
    with pytest.raises(ConfigError):
        app_for(MCP_HTTP_HOST="0.0.0.0")


def test_rejects_short_token():
    with pytest.raises(ConfigError):
        app_for(MCP_AUTH_TOKEN="short")


def test_bearer_required_and_healthz_open():
    app = app_for(MCP_HTTP_HOST="0.0.0.0", MCP_AUTH_TOKEN=TOKEN, MCP_ALLOWED_HOSTS="testserver")
    with TestClient(app) as c:
        h = c.get("/healthz")
        assert h.status_code == 200 and h.headers["x-content-type-options"] == "nosniff"
        assert c.post("/mcp", json={}).status_code == 401
        assert c.post("/mcp", json={}, headers={"Authorization": "Bearer wrong"}).status_code == 401
        init = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
        }
        r = c.post(
            "/mcp", json=init,
            headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/json, text/event-stream"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["result"]["serverInfo"]["name"] == "servicenow-itom"


def test_host_header_checked():
    app = app_for(MCP_HTTP_HOST="0.0.0.0", MCP_AUTH_TOKEN=TOKEN, MCP_ALLOWED_HOSTS="itom-mcp.apps.example.com")
    with TestClient(app) as c:
        r = c.post("/mcp", json={}, headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/json, text/event-stream"})
        assert r.status_code in (400, 403, 421)
