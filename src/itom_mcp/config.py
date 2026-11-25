"""
Configuration, loaded once at startup and validated fail-fast.

ServiceNow authentication uses the same variables and the same three modes as
https://github.com/oricohen392/mcp-snow:

    SERVICENOW_INSTANCE_URL   https://<instance>.service-now.com
    SERVICENOW_AUTH_TYPE      basic | oauth | api_key        (default basic)
    SERVICENOW_USERNAME / SERVICENOW_PASSWORD                 basic, oauth password grant
    SERVICENOW_CLIENT_ID / SERVICENOW_CLIENT_SECRET           oauth
    SERVICENOW_TOKEN_URL                                      oauth (default <instance>/oauth_token.do)
    SERVICENOW_API_KEY / SERVICENOW_API_KEY_HEADER            api_key (header default X-ServiceNow-API-Key)

Hardening compared to the reference:
  * every secret can also come from ``<NAME>_FILE`` (Kubernetes/Docker secrets), and
    secrets are never accepted on the command line (they would show in ``ps``);
  * secrets are held as ``SecretStr`` so they never appear in repr/logs/tracebacks;
  * the instance URL must be https and its host must match SERVICENOW_ALLOWED_HOSTS
    (SSRF / credential-exfiltration guard); the OAuth token URL must be on the same host.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from pydantic import SecretStr

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


class ConfigError(ValueError):
    """Invalid or missing configuration. Message never contains secret values."""


class AuthType(str, Enum):
    BASIC = "basic"
    OAUTH = "oauth"
    API_KEY = "api_key"


@dataclass(frozen=True)
class AuthConfig:
    type: AuthType
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    client_id: Optional[str] = None
    client_secret: Optional[SecretStr] = None
    token_url: Optional[str] = None
    api_key: Optional[SecretStr] = None
    api_key_header: str = "X-ServiceNow-API-Key"


@dataclass(frozen=True)
class Settings:
    instance_url: str
    auth: AuthConfig
    timeout: float = 30.0
    ca_bundle: Optional[str] = None
    read_only: bool = True
    max_limit: int = 200
    default_limit: int = 25
    max_traversal_depth: int = 3
    max_traversal_nodes: int = 300
    max_field_chars: int = 4000
    rate_limit_per_minute: int = 120
    enable_generic_query: bool = True
    log_level: str = "INFO"
    # HTTP transport
    mcp_auth_token: Optional[SecretStr] = None
    http_host: str = "127.0.0.1"
    http_port: int = 8080
    mcp_allowed_hosts: tuple[str, ...] = field(default_factory=tuple)
    mcp_allowed_origins: tuple[str, ...] = field(default_factory=tuple)
    allow_unauthenticated_http: bool = False
    # Named client tokens {name: SecretStr}; MCP_AUTH_TOKEN becomes client "default".
    mcp_client_tokens: dict[str, SecretStr] = field(default_factory=dict)
    forwarded_allow_ips: str = "127.0.0.1"
    auth_max_failures: int = 10
    # Abuse / blast-radius limits
    max_concurrency: int = 8
    max_response_chars: int = 200_000
    write_rate_limit_per_minute: int = 5
    # How write tools are approved: "elicit" (human approves in the MCP client) or
    # "confirm_flag" (the model passes confirm=true; weaker, opt-in).
    write_approval: str = "elicit"

    @property
    def api_base(self) -> str:
        return f"{self.instance_url}/api/now"

    @property
    def instance_host(self) -> str:
        return urlsplit(self.instance_url).hostname or ""

    def __repr__(self) -> str:  # never dump secrets
        return f"Settings(instance_url={self.instance_url!r}, auth_type={self.auth.type.value!r}, read_only={self.read_only})"


# --------------------------------------------------------------------------- helpers


def _env(name: str, env: dict[str, str]) -> Optional[str]:
    raw = env.get(name)
    if raw is None:
        return None
    raw = raw.strip()
    return raw or None


def _secret(name: str, env: dict[str, str]) -> Optional[SecretStr]:
    """Read NAME, or the file named by NAME_FILE (mounted secret)."""
    direct = _env(name, env)
    file_path = _env(f"{name}_FILE", env)
    if direct and file_path:
        raise ConfigError(f"Set only one of {name} and {name}_FILE")
    if file_path:
        p = Path(file_path)
        if not p.is_file():
            raise ConfigError(f"{name}_FILE points to a missing file")
        value = p.read_text(encoding="utf-8").strip()
        return SecretStr(value) if value else None
    return SecretStr(direct) if direct else None


def _bool(name: str, env: dict[str, str], default: bool) -> bool:
    raw = _env(name, env)
    if raw is None:
        return default
    v = raw.lower()
    if v in _TRUTHY:
        return True
    if v in _FALSY:
        return False
    raise ConfigError(f"{name} must be true/false, got {raw!r}")


def _int(name: str, env: dict[str, str], default: int, lo: int, hi: int) -> int:
    raw = _env(name, env)
    if raw is None:
        return default
    try:
        v = int(raw)
    except ValueError as e:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from e
    if not lo <= v <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {v}")
    return v


def _csv(name: str, env: dict[str, str]) -> tuple[str, ...]:
    raw = _env(name, env)
    if not raw:
        return ()
    return tuple(p.strip().lower() for p in raw.split(",") if p.strip())


DEFAULT_ALLOWED_SN_HOSTS = ("service-now.com", "servicenowservices.com")


def host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allowed)


def validate_instance_url(url: str, allowed_hosts: tuple[str, ...]) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise ConfigError("SERVICENOW_INSTANCE_URL must use https://")
    if not parts.hostname:
        raise ConfigError("SERVICENOW_INSTANCE_URL has no host")
    if parts.username or parts.password:
        raise ConfigError("SERVICENOW_INSTANCE_URL must not embed credentials")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ConfigError("SERVICENOW_INSTANCE_URL must be the bare instance URL (no path/query)")
    if not host_allowed(parts.hostname, allowed_hosts):
        raise ConfigError(
            f"Instance host {parts.hostname!r} is not in SERVICENOW_ALLOWED_HOSTS "
            f"({', '.join(allowed_hosts)}). Add your custom domain there explicitly."
        )
    port = f":{parts.port}" if parts.port else ""
    return f"https://{parts.hostname.lower()}{port}"


# --------------------------------------------------------------------------- loader


def load_settings(env: Optional[dict[str, str]] = None) -> Settings:
    env = dict(os.environ if env is None else env)

    allowed = _csv("SERVICENOW_ALLOWED_HOSTS", env) or DEFAULT_ALLOWED_SN_HOSTS
    raw_url = _env("SERVICENOW_INSTANCE_URL", env)
    if not raw_url:
        raise ConfigError("SERVICENOW_INSTANCE_URL is required")
    instance_url = validate_instance_url(raw_url, allowed)

    raw_type = (_env("SERVICENOW_AUTH_TYPE", env) or "basic").lower()
    try:
        auth_type = AuthType(raw_type)
    except ValueError as e:
        raise ConfigError("SERVICENOW_AUTH_TYPE must be basic, oauth or api_key") from e

    username = _env("SERVICENOW_USERNAME", env)
    password = _secret("SERVICENOW_PASSWORD", env)

    if auth_type is AuthType.BASIC:
        if not username or not password:
            raise ConfigError("basic auth needs SERVICENOW_USERNAME and SERVICENOW_PASSWORD")
        auth = AuthConfig(type=auth_type, username=username, password=password)

    elif auth_type is AuthType.OAUTH:
        client_id = _env("SERVICENOW_CLIENT_ID", env)
        client_secret = _secret("SERVICENOW_CLIENT_SECRET", env)
        if not client_id or not client_secret:
            raise ConfigError("oauth needs SERVICENOW_CLIENT_ID and SERVICENOW_CLIENT_SECRET")
        if bool(username) != bool(password):
            raise ConfigError("oauth password grant needs both SERVICENOW_USERNAME and SERVICENOW_PASSWORD")
        token_url = _env("SERVICENOW_TOKEN_URL", env) or f"{instance_url}/oauth_token.do"
        tparts = urlsplit(token_url)
        if tparts.scheme != "https" or (tparts.hostname or "").lower() != urlsplit(instance_url).hostname:
            raise ConfigError("SERVICENOW_TOKEN_URL must be https and on the same host as the instance")
        auth = AuthConfig(
            type=auth_type,
            username=username,
            password=password,
            client_id=client_id,
            client_secret=client_secret,
            token_url=token_url,
        )

    else:
        api_key = _secret("SERVICENOW_API_KEY", env)
        header = _env("SERVICENOW_API_KEY_HEADER", env) or "X-ServiceNow-API-Key"
        if not api_key:
            raise ConfigError("api_key auth needs SERVICENOW_API_KEY")
        if not header.replace("-", "").isalnum() or header.lower() in {"host", "cookie", "content-length"}:
            raise ConfigError("SERVICENOW_API_KEY_HEADER is not a valid header name")
        auth = AuthConfig(type=auth_type, api_key=api_key, api_key_header=header)

    ca_bundle = _env("CA_BUNDLE", env)
    if ca_bundle and not Path(ca_bundle).is_file():
        raise ConfigError("CA_BUNDLE points to a missing file")

    log_level = (_env("LOG_LEVEL", env) or "INFO").upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigError(f"LOG_LEVEL invalid: {log_level!r}")

    default_limit = _int("DEFAULT_LIMIT", env, 25, 1, 1000)
    max_limit = _int("MAX_LIMIT", env, 200, 1, 1000)

    tokens: dict[str, SecretStr] = {}
    default_token = _secret("MCP_AUTH_TOKEN", env)
    if default_token:
        tokens["default"] = default_token
    tokens_file = _env("MCP_AUTH_TOKENS_FILE", env)
    if tokens_file:
        tp = Path(tokens_file)
        if not tp.is_file():
            raise ConfigError("MCP_AUTH_TOKENS_FILE points to a missing file")
        for n, line in enumerate(tp.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, sep, tok = line.partition(":")
            name, tok = name.strip(), tok.strip()
            if not sep or not name or not tok or not name.replace("-", "").replace("_", "").isalnum():
                raise ConfigError(f"MCP_AUTH_TOKENS_FILE line {n}: expected '<client-name>:<token>'")
            if name in tokens:
                raise ConfigError(f"MCP_AUTH_TOKENS_FILE: duplicate client name {name!r}")
            tokens[name] = SecretStr(tok)

    write_approval = (_env("WRITE_APPROVAL", env) or "elicit").lower()
    if write_approval not in ("elicit", "confirm_flag"):
        raise ConfigError("WRITE_APPROVAL must be elicit or confirm_flag")

    return Settings(
        instance_url=instance_url,
        auth=auth,
        timeout=float(_int("SERVICENOW_TIMEOUT", env, 30, 1, 300)),
        ca_bundle=ca_bundle,
        read_only=_bool("READ_ONLY", env, True),
        max_limit=max_limit,
        default_limit=min(default_limit, max_limit),
        max_traversal_depth=_int("MAX_TRAVERSAL_DEPTH", env, 3, 1, 6),
        max_traversal_nodes=_int("MAX_TRAVERSAL_NODES", env, 300, 10, 5000),
        max_field_chars=_int("MAX_FIELD_CHARS", env, 4000, 100, 100000),
        rate_limit_per_minute=_int("RATE_LIMIT_PER_MINUTE", env, 120, 1, 100000),
        enable_generic_query=_bool("ENABLE_GENERIC_QUERY", env, True),
        log_level=log_level,
        mcp_auth_token=_secret("MCP_AUTH_TOKEN", env),
        http_host=_env("MCP_HTTP_HOST", env) or "127.0.0.1",
        http_port=_int("MCP_HTTP_PORT", env, 8080, 1, 65535),
        mcp_allowed_hosts=_csv("MCP_ALLOWED_HOSTS", env),
        mcp_allowed_origins=_csv("MCP_ALLOWED_ORIGINS", env),
        allow_unauthenticated_http=_bool("MCP_ALLOW_UNAUTHENTICATED", env, False),
        mcp_client_tokens=tokens,
        forwarded_allow_ips=_env("FORWARDED_ALLOW_IPS", env) or "127.0.0.1",
        auth_max_failures=_int("AUTH_MAX_FAILURES_PER_MINUTE", env, 10, 1, 10000),
        max_concurrency=_int("MAX_CONCURRENCY", env, 8, 1, 100),
        max_response_chars=_int("MAX_RESPONSE_CHARS", env, 200_000, 10_000, 5_000_000),
        write_rate_limit_per_minute=_int("WRITE_RATE_LIMIT_PER_MINUTE", env, 5, 1, 1000),
        write_approval=write_approval,
    )
