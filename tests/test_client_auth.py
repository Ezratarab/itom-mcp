import base64
import logging

import httpx
import pytest
import respx

from itom_mcp.client import ServiceNowClient, SnError
from tests.conftest import API, INSTANCE, make_settings

TOKEN_URL = f"{INSTANCE}/oauth_token.do"


def oauth_settings(**kw):
    return make_settings(SERVICENOW_AUTH_TYPE="oauth", SERVICENOW_CLIENT_ID="cid", SERVICENOW_CLIENT_SECRET="csecret", **kw)


@respx.mock
async def test_basic_auth_header():
    route = respx.get(f"{API}/table/em_alert").mock(return_value=httpx.Response(200, json={"result": []}, headers={"X-Total-Count": "0"}))
    sn = ServiceNowClient(make_settings())
    await sn.query("em_alert")
    sent = route.calls[0].request.headers["authorization"]
    assert sent == "Basic " + base64.b64encode(b"itom.user:S3cr3t-P@ss").decode()


@respx.mock
async def test_api_key_header():
    route = respx.get(f"{API}/table/em_alert").mock(return_value=httpx.Response(200, json={"result": []}))
    sn = ServiceNowClient(make_settings(SERVICENOW_AUTH_TYPE="api_key", SERVICENOW_API_KEY="k-123"))
    await sn.query("em_alert")
    assert route.calls[0].request.headers["x-servicenow-api-key"] == "k-123"


@respx.mock
async def test_oauth_client_credentials_then_password_fallback_and_cache(caplog):
    caplog.set_level(logging.DEBUG)
    token = respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(401, json={"error": "unauthorized_client"}),
            httpx.Response(200, json={"access_token": "TOKEN-XYZ", "token_type": "Bearer", "expires_in": 1800}),
        ]
    )
    api = respx.get(f"{API}/table/em_alert").mock(return_value=httpx.Response(200, json={"result": []}))
    sn = ServiceNowClient(oauth_settings())
    await sn.query("em_alert")
    await sn.query("em_alert")
    assert token.call_count == 2  # cc failed, password grant ok; second query reuses cache
    first, second = token.calls[0].request, token.calls[1].request
    assert b"grant_type=client_credentials" in first.content
    assert b"grant_type=password" in second.content
    assert first.headers["authorization"] == "Basic " + base64.b64encode(b"cid:csecret").decode()
    assert api.calls[0].request.headers["authorization"] == "Bearer TOKEN-XYZ"
    assert "TOKEN-XYZ" not in caplog.text and "csecret" not in caplog.text and "S3cr3t" not in caplog.text


@respx.mock
async def test_oauth_refresh_on_401():
    respx.post(TOKEN_URL).mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "OLD", "expires_in": 1800}),
            httpx.Response(200, json={"access_token": "NEW", "expires_in": 1800}),
        ]
    )
    api = respx.get(f"{API}/table/em_alert").mock(side_effect=[httpx.Response(401), httpx.Response(200, json={"result": [{"number": "A1"}]})])
    sn = ServiceNowClient(oauth_settings())
    res = await sn.query("em_alert")
    assert res.records == [{"number": "A1"}]
    assert api.calls[1].request.headers["authorization"] == "Bearer NEW"


@respx.mock
async def test_oauth_total_failure():
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(401))
    sn = ServiceNowClient(oauth_settings())
    with pytest.raises(SnError) as e:
        await sn.query("em_alert")
    assert e.value.error_type == "auth"


@respx.mock
async def test_redirect_not_followed():
    respx.get(f"{API}/table/em_alert").mock(return_value=httpx.Response(302, headers={"Location": "https://evil.example/login"}))
    evil = respx.get("https://evil.example/login").mock(return_value=httpx.Response(200))
    sn = ServiceNowClient(make_settings())
    with pytest.raises(SnError) as e:
        await sn.query("em_alert")
    assert e.value.error_type == "redirect"
    assert not evil.called


@respx.mock
async def test_retry_on_503(monkeypatch):
    monkeypatch.setattr("itom_mcp.client.asyncio.sleep", _no_sleep)
    respx.get(f"{API}/table/em_alert").mock(side_effect=[httpx.Response(503), httpx.Response(200, json={"result": []})])
    sn = ServiceNowClient(make_settings())
    await sn.query("em_alert")


async def _no_sleep(*_a, **_k):
    return None


@pytest.mark.parametrize(
    "resp,etype",
    [
        (httpx.Response(401), "unauthorized"),
        (httpx.Response(403, json={"error": {"message": "ACL"}}), "forbidden"),
        (httpx.Response(404), "not_found"),
        (httpx.Response(200, text="<html>SSO login</html>", headers={"content-type": "text/html"}), "invalid_response"),
    ],
)
@respx.mock
async def test_error_classification(resp, etype):
    respx.get(f"{API}/table/em_alert").mock(return_value=resp)
    sn = ServiceNowClient(make_settings())
    with pytest.raises(SnError) as e:
        await sn.query("em_alert")
    assert e.value.error_type == etype


@respx.mock
async def test_timeout():
    respx.get(f"{API}/table/em_alert").mock(side_effect=httpx.ReadTimeout("slow"))
    sn = ServiceNowClient(make_settings())
    with pytest.raises(SnError) as e:
        await sn.query("em_alert")
    assert e.value.error_type == "timeout"


async def test_limit_is_capped():
    sn = ServiceNowClient(make_settings(MAX_LIMIT="50"))
    assert sn.clamp_limit(10_000) == 50
    assert sn.clamp_limit(None) == 25


async def test_patch_blocked_in_read_only():
    sn = ServiceNowClient(make_settings())
    with pytest.raises(SnError):
        await sn.patch("em_alert", "a" * 32, {"acknowledged": "true"})
