import logging
import re

import pytest

from itom_mcp.security import (
    QueryBuilder,
    RateLimiter,
    RedactingFilter,
    SecurityError,
    parse_when,
    redact,
    sanitize_value,
    scrub,
    validate_ci_class,
    validate_field,
    validate_table,
)


@pytest.mark.parametrize(
    "bad",
    [
        "foo^ORnumberISNOTEMPTY",
        "x^NQsys_idISNOTEMPTY",
        "a^ORDERBYname",
        "javascript:gs.getUser().getName()",
        "abc JavaScript : gs.log(1)",
        "line\nbreak",
        "tab\there",
        "nul\x00",
        "esc\x1b",
        "del\x7f",
        "",
        "   ",
        "x" * 201,
    ],
)
def test_sanitize_rejects(bad):
    with pytest.raises(SecurityError):
        sanitize_value(bad)


def test_sanitize_accepts_normal_values():
    assert sanitize_value("  web-01.corp.local ") == "web-01.corp.local"
    assert sanitize_value(True) == "true"
    assert sanitize_value(10) == "10"


@pytest.mark.parametrize("field", ["password", "u_admin_password", "client_secret", "access_token", "api_key", "ssh_key", "support_group.u_secret", "community_string"])
def test_sensitive_fields_refused(field):
    with pytest.raises(SecurityError):
        validate_field(field)


@pytest.mark.parametrize("field", ["name; drop", "Name", "a..b", "1abc", "a.b.c.d.e", "name^OR"])
def test_invalid_field_names(field):
    with pytest.raises(SecurityError):
        validate_field(field)


def test_valid_fields():
    assert validate_field("support_group.name") == "support_group.name"
    assert validate_field("ip_address") == "ip_address"


@pytest.mark.parametrize("table", ["discovery_credentials", "sys_user", "sys_properties", "sys_script_include", "oauth_entity", "u_custom_table", "../x", "incident;", "cmdb_ci_credential_store"])
def test_tables_denied(table):
    with pytest.raises(SecurityError):
        validate_table(table)


@pytest.mark.parametrize("table", ["cmdb_ci", "cmdb_ci_linux_server", "em_alert", "ecc_agent", "discovery_status", "svc_ci_assoc"])
def test_tables_allowed(table):
    assert validate_table(table) == table


def test_ci_class_must_be_cmdb():
    with pytest.raises(SecurityError):
        validate_ci_class("em_alert")


def test_query_builder_or_group_atomic_and_order_last():
    q = (
        QueryBuilder()
        .add("state", "in", ["Open", "Reopen"])
        .add_or([("name", "like", "web"), ("ip_address", "=", "10.0.0.1")])
        .add("support_group", "is_empty")
        .order_by("sys_updated_on")
        .build()
    )
    assert q == "stateINOpen,Reopen^nameLIKEweb^ORip_address=10.0.0.1^support_groupISEMPTY^ORDERBYDESCsys_updated_on"
    terms = q.split("^")
    assert not terms[0].startswith("OR") and terms[-1].startswith("ORDERBY")


def test_query_builder_rejects_unknown_operator_and_injection():
    with pytest.raises(SecurityError):
        QueryBuilder().add("name", "CONTAINS_JS", "x")
    with pytest.raises(SecurityError):
        QueryBuilder().add("name", "=", "x^NQactive=true")
    with pytest.raises(SecurityError):
        QueryBuilder().add("name", "in", ["a", "b^ORc"])


def test_parse_when():
    assert re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$", parse_when("24h"))
    assert parse_when("2026-01-31T10:00:00+02:00") == "2026-01-31 08:00:00"
    assert parse_when("2026-01-31") == "2026-01-31 00:00:00"
    with pytest.raises(SecurityError):
        parse_when("yesterday-ish")


def test_scrub_removes_sensitive_and_truncates():
    out = scrub({"name": "a", "password": "x", "nested": [{"client_secret": "y", "d": "z" * 500}]}, 100)
    assert "password" not in out
    assert "client_secret" not in out["nested"][0]
    assert out["nested"][0]["d"].startswith("z" * 100) and "truncated" in out["nested"][0]["d"]


def test_redact():
    s = redact("Authorization: Basic dXNlcjpwYXNz access_token=abc123 password=hunter2 Bearer eyJhbGciOiJIUzI1NiJ9")
    assert "dXNlcjpwYXNz" not in s and "abc123" not in s and "hunter2" not in s and "eyJhbGci" not in s


def test_redacting_filter_on_records():
    rec = logging.LogRecord("x", logging.INFO, "f", 1, "token %s", ("access_token=SECRET1",), None)
    RedactingFilter().filter(rec)
    assert "SECRET1" not in rec.getMessage()


def test_rate_limiter():
    rl = RateLimiter(2)
    rl.check()
    rl.check()
    with pytest.raises(SecurityError):
        rl.check()
