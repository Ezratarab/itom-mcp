import pytest

from itom_mcp.config import AuthType, ConfigError, load_settings

BASE = {"SERVICENOW_INSTANCE_URL": "https://dev1.service-now.com", "SERVICENOW_USERNAME": "u", "SERVICENOW_PASSWORD": "p"}


def env(**kw):
    e = dict(BASE)
    e.update(kw)
    return e


def test_defaults_are_safe():
    s = load_settings(env(SERVICENOW_PASSWORD="Zq9-unique-pw"))
    assert s.read_only is True
    assert s.http_host == "127.0.0.1"
    assert s.auth.type is AuthType.BASIC
    assert "Zq9-unique-pw" not in repr(s) and "Zq9-unique-pw" not in repr(s.auth)


@pytest.mark.parametrize(
    "url",
    [
        "http://dev1.service-now.com",
        "https://evil.example.com",
        "https://dev1.service-now.com.evil.com",
        "https://user:pw@dev1.service-now.com",
        "https://dev1.service-now.com/api/now?x=1",
    ],
)
def test_instance_url_rejected(url):
    with pytest.raises(ConfigError):
        load_settings(env(SERVICENOW_INSTANCE_URL=url))


def test_custom_domain_needs_allowlist():
    s = load_settings(env(SERVICENOW_INSTANCE_URL="https://itsm.corp.example", SERVICENOW_ALLOWED_HOSTS="corp.example"))
    assert s.instance_url == "https://itsm.corp.example"


def test_oauth_same_env_vars_as_reference():
    s = load_settings(env(SERVICENOW_AUTH_TYPE="oauth", SERVICENOW_CLIENT_ID="cid", SERVICENOW_CLIENT_SECRET="cs"))
    assert s.auth.token_url == "https://dev1.service-now.com/oauth_token.do"


def test_oauth_client_credentials_only():
    e = {"SERVICENOW_INSTANCE_URL": BASE["SERVICENOW_INSTANCE_URL"], "SERVICENOW_AUTH_TYPE": "oauth", "SERVICENOW_CLIENT_ID": "c", "SERVICENOW_CLIENT_SECRET": "s"}
    assert load_settings(e).auth.username is None


def test_oauth_token_url_must_be_same_host():
    with pytest.raises(ConfigError):
        load_settings(env(SERVICENOW_AUTH_TYPE="oauth", SERVICENOW_CLIENT_ID="c", SERVICENOW_CLIENT_SECRET="s", SERVICENOW_TOKEN_URL="https://attacker.example/oauth_token.do"))


def test_api_key():
    s = load_settings({"SERVICENOW_INSTANCE_URL": BASE["SERVICENOW_INSTANCE_URL"], "SERVICENOW_AUTH_TYPE": "api_key", "SERVICENOW_API_KEY": "k"})
    assert s.auth.api_key_header == "X-ServiceNow-API-Key"


def test_secret_from_file(tmp_path):
    f = tmp_path / "pw"
    f.write_text("from-file\n")
    e = env()
    del e["SERVICENOW_PASSWORD"]
    e["SERVICENOW_PASSWORD_FILE"] = str(f)
    assert load_settings(e).auth.password.get_secret_value() == "from-file"


def test_secret_and_file_conflict(tmp_path):
    f = tmp_path / "pw"
    f.write_text("x")
    with pytest.raises(ConfigError):
        load_settings(env(SERVICENOW_PASSWORD_FILE=str(f)))


@pytest.mark.parametrize("k,v", [("READ_ONLY", "maybe"), ("MAX_LIMIT", "0"), ("LOG_LEVEL", "LOUD"), ("SERVICENOW_AUTH_TYPE", "kerberos"), ("CA_BUNDLE", "/nope.pem")])
def test_invalid_values_fail_fast(k, v):
    with pytest.raises(ConfigError):
        load_settings(env(**{k: v}))


def test_missing_credentials():
    with pytest.raises(ConfigError):
        load_settings({"SERVICENOW_INSTANCE_URL": BASE["SERVICENOW_INSTANCE_URL"]})
