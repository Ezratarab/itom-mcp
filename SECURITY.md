# Security model

This server gives an LLM read access to ServiceNow ITOM data through a service account.
The main risks are: the model (or a prompt injection hidden in CMDB/alert text) making
the server do something it shouldn't, credentials leaking, and the HTTP endpoint being
reachable by people who shouldn't use it. Each risk and how it is handled is listed below.
The tests in `tests/` cover each one.

| # | Risk | What the server does | Where |
|---|------|----------------------|-------|
| 1 | **Encoded-query injection** (`^OR`, `^NQ`, `^ORDERBY` inside a value rewrites the query) | Values containing `^` or control characters are rejected before any HTTP call. Queries are built only by `QueryBuilder` from validated fields, whitelisted operators and sanitized values. There is no raw `sysparm_query` input anywhere. OR groups are atomic. | `security.py` (`sanitize_value`, `QueryBuilder`) |
| 2 | **Server-side script injection** (`javascript:` in query values is executed by ServiceNow) | `javascript:` is rejected in every value, including with spaces or mixed case. | `sanitize_value` |
| 3 | **Reading tables outside ITOM** (users, credentials, scripts, properties, audit) | Explicit table allowlist plus `cmdb_ci_*`. A hard denylist (`discovery_credentials`, `sys_user`, `sys_properties`, `oauth_*`, `sys_script*`, `sys_audit`, …) wins over everything else. | `validate_table` |
| 4 | **Secret fields** (passwords, tokens, SNMP communities, keys) | Such field names are refused as filters, fields, order-by and group-by. They are also stripped from every response, recursively. | `SENSITIVE_NAME`, `scrub` |
| 5 | **Prompt injection through data** (an alert description saying "ignore previous instructions…") | Every result carries `_notice` marking it as untrusted data. The server instructions repeat this. Long strings are truncated (`MAX_FIELD_CHARS`). There are no write tools by default, so injected text cannot cause changes. | `tools/common.py` |
| 6 | **Unintended writes** | `READ_ONLY=true` by default, so write tools are not even registered. When they are enabled, each needs `confirm=true`, is annotated `destructiveHint`, and only touches `em_alert` (acknowledge, close, work note). `client.patch` refuses in read-only mode as a second check. | `itom_tool(write=True)`, `client.patch` |
| 7 | **SSRF / credential exfiltration** | The instance URL must be `https`, have no path or credentials, and its host must match `SERVICENOW_ALLOWED_HOSTS` (default `*.service-now.com`). The OAuth token URL must be on the same host. Request URLs are built only from validated parts; absolute URLs are impossible. **Redirects are not followed**, so credentials are never sent to a redirect target. | `config.py`, `client.py` |
| 8 | **TLS downgrade** | Verification cannot be turned off. Only a custom CA (`CA_BUNDLE`) is allowed. | `client.py` |
| 9 | **Secrets in logs, `ps`, tracebacks** | Secrets come only from env vars or `*_FILE` (mounted secrets), never from CLI flags. They are held as `SecretStr`, and `Settings.__repr__` hides them. The OAuth response body is never logged. A redaction filter on all logs masks `Authorization`, `Bearer`, `access_token`, `password=` and similar. httpx URL logging is silenced. | `config.py`, `auth.py`, `RedactingFilter` |
| 10 | **Unauthenticated HTTP endpoint** | HTTP mode refuses to start on a non-loopback address without `MCP_AUTH_TOKEN` (minimum 32 characters). The token is compared in constant time. Only `/healthz` is open. | `server.py` (`check_http_security`, `BearerAuthMiddleware`) |
| 11 | **DNS rebinding / Host spoofing** | MCP's transport security validates `Host` against `MCP_ALLOWED_HOSTS` (defaults to localhost on loopback binds). | `_transport_security` |
| 12 | **Error leakage** | Unexpected exceptions return `Internal error (ref xxxx)`; the traceback goes only to the server log. Starlette debug is off and the server header is removed. | `itom_tool` wrapper |
| 13 | **Resource exhaustion** | `MAX_LIMIT` caps page size. Traversal is bounded by `MAX_TRAVERSAL_DEPTH`/`NODES`. IN lists hold at most 100 items, and there are at most 20 filters. Request bodies are limited to 1 MB and responses to 20 MB. Every call has a timeout. Retries are capped. A process-wide rate limit (`RATE_LIMIT_PER_MINUTE`) applies. | various |
| 14 | **No audit trail** | Every tool call is logged on `itom_mcp.audit` with tool name, outcome, duration and a truncated argument summary. | `itom_tool` |
| 15 | **Container hardening** | UBI 9 image, non-root UID 1001, works with arbitrary UID and GID 0 (`restricted-v2` SCC), read-only root filesystem, all capabilities dropped, seccomp `RuntimeDefault`, no service account token mounted, NetworkPolicy (router ingress only; DNS + 443 egress). | `Dockerfile`, `openshift/` |

## ServiceNow side: least privilege

Create a dedicated integration user (*Web service access only*, no UI login). Give it only:

- `itil` (incidents, changes, problems), or read ACLs on those tables;
- `cmdb_read`;
- `evt_mgmt_user` (Event Management read);
- `discovery_admin` is **not** required. Read ACLs on `discovery_status`, `discovery_log`, `discovery_device_history`, `discovery_schedule`, `ecc_agent`, `ecc_queue` are enough (grant them through a custom read-only role);
- the Aggregate API (`/api/now/stats`, used for counts) uses the same table read ACLs; make sure no REST API Access Policy blocks it.

Verify role names against your release before assigning them. `check_access` shows what the account can actually read.

Do **not** give it `admin`, `credentials_admin`, or `security_admin`. If you turn on
`READ_ONLY=false`, add only `evt_mgmt_operator` for alert actions.

Prefer OAuth (`client_credentials`) with a short token lifespan over basic auth. Restrict
the integration user with a REST API Access Policy and an IP allowlist (OpenShift egress
IPs).

## Reporting

Report suspected vulnerabilities privately to the repository owner, not in public issues.
