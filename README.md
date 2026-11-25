# itom-mcp: a secure ServiceNow ITOM MCP server

An MCP server that answers ServiceNow **IT Operations Management** questions:
CMDB, Discovery, MID Servers, Event Management, Service Mapping, and the operational
context of a CI (incidents, problems, changes, outages).

- **Read-only by default.** Write tools are opt-in, and a **human** approves every write in the MCP client.
- **Same ServiceNow authentication as [oricohen392/mcp-snow](https://github.com/oricohen392/mcp-snow):** `basic`, `oauth` (client_credentials, falling back to the password grant) and `api_key`, with the same environment variables.
- **Hardened against prompt injection, query injection, data leakage and endpoint abuse.** See [SECURITY.md](SECURITY.md) for the threat model and [ARCHITECTURE.md](ARCHITECTURE.md) for how it fits together.
- **Two transports.** `stdio` for Claude Desktop / Claude Code, and stateless streamable **HTTP** (`/mcp`) for OpenShift.

---

## What it can answer

| Area | Tools | Example questions |
|------|-------|-------------------|
| CMDB | `cmdb_overview`, `cmdb_list_classes`, `cmdb_search_cis`, `cmdb_get_ci`, `cmdb_count_cis`, `cmdb_recent_changes` | "How many Linux servers per environment?" "Show the CI 10.1.4.22." "Which CIs changed in the last 24h, and who changed them?" |
| Relationships & impact | `cmdb_get_relationships`, `cmdb_impact_analysis` | "What breaks if db-prod-03 goes down?" "What does the CRM service depend on?" |
| CMDB data quality | `cmdb_health_report`, `cmdb_find_duplicates` | "How many servers are stale or have no support group?" "Find duplicate serial numbers." |
| Discovery | `discovery_list_schedules`, `discovery_list_status`, `discovery_get_status`, `discovery_get_logs`, `discovery_device_history`, `discovery_failure_summary`, `discovery_list_ranges` | "Did last night's discovery finish?" "Why wasn't 10.2.3.4 classified?" "What are the top discovery errors this week?" |
| MID Servers | `mid_server_list`, `mid_server_health`, `ecc_queue_list` | "Are any MID servers down or on the wrong version?" "Is the ECC queue backed up?" |
| Event Management | `alerts_list`, `alert_get`, `alerts_summary`, `events_list`, `events_summary`, `event_rules_list`, `event_connectors_list` | "How many critical alerts are open?" "Which nodes are noisiest today?" "Is the SCOM connector failing?" |
| Services | `services_list`, `service_get_map`, `service_health` | "Which CIs make up the Payments service, and is it healthy?" |
| Operations | `ci_operational_summary`, `outages_list` | "Give me everything about web-01: alerts, incidents, changes, outages." |
| Generic (safe) | `list_itom_tables`, `itom_query`, `itom_count` | Anything else on an allowlisted ITOM table, with structured filters only |
| Diagnostics | `check_access` | "Can the integration user read everything it needs?" |
| Write (opt-in) | `alert_acknowledge`, `alert_close`, `alert_add_work_note` | Only with `READ_ONLY=false`, **and** the human approves each call (see `WRITE_APPROVAL`) |

Every tool accepts CIs by **sys_id, exact name, IP or FQDN**. Dates can be ISO-8601 or relative (`30m`, `24h`, `7d`). List results include `query_used`, `total_count`, `returned` and `next_offset`. Every result starts with an `_notice` that the data is untrusted, and carries `_security_warnings` when hidden or injected content was neutralised.

---

## Configuration

All settings come from environment variables (or a `.env` file locally). Every secret can also be given as `<NAME>_FILE` (a path to a mounted secret). Secrets are **never** accepted as command-line flags.

| Variable | Default | Notes |
|---|---|---|
| `SERVICENOW_INSTANCE_URL` | required | `https://<instance>.service-now.com` |
| `SERVICENOW_AUTH_TYPE` | `basic` | `basic` \| `oauth` \| `api_key` |
| `SERVICENOW_USERNAME` / `SERVICENOW_PASSWORD` | | basic, or the oauth password grant |
| `SERVICENOW_CLIENT_ID` / `SERVICENOW_CLIENT_SECRET` | | oauth |
| `SERVICENOW_TOKEN_URL` | `<instance>/oauth_token.do` | must be on the instance host |
| `SERVICENOW_API_KEY` / `SERVICENOW_API_KEY_HEADER` | header `X-ServiceNow-API-Key` | api_key |
| `SERVICENOW_ALLOWED_HOSTS` | `service-now.com,servicenowservices.com` | add your custom domain here |
| `CA_BUNDLE` | | PEM file for a private CA (TLS verification is always on) |
| `SERVICENOW_TIMEOUT` | `30` | seconds |
| `READ_ONLY` | `true` | `false` registers the 3 alert write tools |
| `MAX_LIMIT` / `DEFAULT_LIMIT` | `200` / `25` | page size |
| `MAX_TRAVERSAL_DEPTH` / `MAX_TRAVERSAL_NODES` | `3` / `300` | bounds for impact analysis |
| `MAX_FIELD_CHARS` | `4000` | longer strings are truncated |
| `MAX_RESPONSE_CHARS` | `200000` | whole-response cap; trailing records are dropped with a notice |
| `RATE_LIMIT_PER_MINUTE` | `120` | per client |
| `WRITE_RATE_LIMIT_PER_MINUTE` | `5` | writes only |
| `WRITE_APPROVAL` | `elicit` | `elicit`: the human approves in the MCP client and the model's `confirm` is ignored. `confirm_flag`: the model passes `confirm=true` (weaker; needed for clients without elicitation, including stateless HTTP) |
| `MAX_CONCURRENCY` | `8` | parallel requests to ServiceNow |
| `ENABLE_GENERIC_QUERY` | `true` | `itom_query` / `itom_count` |
| `LOG_LEVEL` | `INFO` | logs go to stderr, redacted |
| `MCP_AUTH_TOKENS_FILE` | | **recommended for HTTP**: one `client-name:token` per line, for per-client audit and limits |
| `MCP_AUTH_TOKEN` | | single shared token (client name `default`) |
| `AUTH_MAX_FAILURES_PER_MINUTE` | `10` | brute-force lockout per client address |
| `MCP_HTTP_HOST` / `MCP_HTTP_PORT` | `127.0.0.1` / `8080` | HTTP refuses non-loopback binds without tokens (≥ 32 characters) |
| `MCP_ALLOWED_HOSTS` / `MCP_ALLOWED_ORIGINS` | | Host-header / browser-Origin allowlist (set to the Route host) |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | proxies trusted for `X-Forwarded-For` (OpenShift: the cluster network CIDR) |

---

## Run locally

```powershell
git clone <your-repo-url> itom-mcp
cd itom-mcp
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
copy .env.example .env      # then edit .env
.venv\Scripts\python -m pytest -q
.venv\Scripts\itom-mcp      # stdio
```

### Claude Desktop / Claude Code (stdio)

```json
{
  "mcpServers": {
    "servicenow-itom": {
      "command": "C:\\path\\to\\itom-mcp\\.venv\\Scripts\\itom-mcp.exe",
      "env": {
        "SERVICENOW_INSTANCE_URL": "https://your-instance.service-now.com",
        "SERVICENOW_AUTH_TYPE": "basic",
        "SERVICENOW_USERNAME": "itom.mcp.integration",
        "SERVICENOW_PASSWORD": "..."
      }
    }
  }
}
```

### HTTP clients (e.g. a remote client, Dify, an agent platform)

- URL: `https://<route-host>/mcp` (streamable HTTP, stateless, JSON responses)
- Header: `Authorization: Bearer <MCP_AUTH_TOKEN>`
- Health: `GET /healthz` (no authentication)

---

## Deploy on OpenShift: step by step

You need the `oc` CLI, a project you can deploy to, and outbound HTTPS from the cluster to your ServiceNow instance.

### 1. Prepare ServiceNow

1. Create an integration user (*Web service access only*) with the least-privilege roles listed in [SECURITY.md](SECURITY.md#servicenow-side-least-privilege).
2. Optional (recommended): create an OAuth API endpoint in **System OAuth → Application Registry** and use `SERVICENOW_AUTH_TYPE=oauth`.
3. Optional: add a REST API Access Policy / IP allowlist for your cluster's egress IPs.

### 2. Log in and create the project

```powershell
oc login --server=https://api.<cluster>:6443
```
```powershell
oc new-project itom-mcp
```

### 3. Build the image

**Option A: build inside OpenShift** (no local Docker needed). Run from the repo folder:

```powershell
oc apply -f openshift/buildconfig.yaml
```
```powershell
oc start-build itom-mcp --from-dir=. --follow
```

The image is then `image-registry.openshift-image-registry.svc:5000/itom-mcp/itom-mcp:latest`, which is what `openshift/deployment.yaml` already uses (change the namespace in the image path if your project is not called `itom-mcp`).

**Option B: build locally and push to your registry** (Quay, Artifactory, Nexus):

```powershell
docker build -t <registry>/itom/itom-mcp:1.0.0 .
```
```powershell
docker push <registry>/itom/itom-mcp:1.0.0
```

Then set `image:` in `openshift/deployment.yaml` to that tag.
For an air-gapped cluster, push the image to the internal mirror registry the same way.

### 4. Create the secret (never commit it)

Generate one token **per MCP client** with the OS's cryptographic random generator (do not use `Get-Random`; it is not secure):

```powershell
function New-McpToken { $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | ForEach-Object { '{0:x2}' -f $_ }) }
```
```powershell
"claude-desktop:$(New-McpToken)`ndify:$(New-McpToken)" | Set-Content -NoNewline -Encoding ascii tokens.txt
```

Create the secret, then delete the local file:

```powershell
oc create secret generic itom-mcp-secrets --from-literal=servicenow-username=itom.mcp.integration --from-literal=servicenow-password='<password>' --from-file=mcp-auth-tokens=tokens.txt
```
```powershell
Get-Content tokens.txt; Remove-Item tokens.txt
```

Give each client only its own token. The client name shows up in the audit log, and each client has its own rate limit.
For OAuth, also add `--from-literal=servicenow-client-id=... --from-literal=servicenow-client-secret=...`, then uncomment the OAuth lines in `deployment.yaml`.
If you use a vault, create the same keys with External Secrets / Sealed Secrets instead.

### 5. Edit the configuration

- `openshift/configmap.yaml`:
  - `SERVICENOW_INSTANCE_URL`, `SERVICENOW_AUTH_TYPE`
  - `MCP_ALLOWED_HOSTS`: the Route host from step 6, plus `itom-mcp,itom-mcp:8080` for in-cluster clients
  - `SERVICENOW_ALLOWED_HOSTS` if you use a custom domain
  - `FORWARDED_ALLOW_IPS`: your cluster network CIDR (`oc get network.config cluster -o jsonpath='{.spec.clusterNetwork[*].cidr}'`), so brute-force lockout sees real client IPs
- `openshift/service-route.yaml`: set `spec.host` to your Route host (for example `itom-mcp.apps.<cluster-domain>`). Delete the Route if only in-cluster clients will connect.
- Private CA for ServiceNow or an egress proxy: mount the CA and set `CA_BUNDLE`, and/or set `HTTPS_PROXY` / `NO_PROXY` in the Deployment env.

### 6. Deploy

```powershell
oc apply -k openshift/
```
```powershell
oc rollout status deployment/itom-mcp
```

### 7. Verify

```powershell
oc logs deployment/itom-mcp
```

You should see `itom-mcp 1.0.0: 36 tools registered, READ_ONLY=True ...`.

```powershell
curl.exe https://itom-mcp.apps.<cluster-domain>/healthz
```

This should return `{"status":"ok"}`. Then check that authentication is enforced; this should return **401**:

```powershell
curl.exe -i -X POST https://itom-mcp.apps.<cluster-domain>/mcp
```

Finally, connect a client with `Authorization: Bearer <its token>` and run the `check_access` tool. It reports which ITOM tables the integration user can read.

### 8. Operate

- **Scale:** `oc scale deployment/itom-mcp --replicas=3`. The HTTP transport is stateless, so no sticky sessions are needed.
- **Add, rotate or revoke a client:** edit the `mcp-auth-tokens` key of the secret, then run `oc rollout restart deployment/itom-mcp`. Rotate the ServiceNow password the same way.
- **Audit:** `oc logs deployment/itom-mcp | Select-String itom_mcp.audit`.
- **Enable alert actions:** set `READ_ONLY: "false"` in the ConfigMap and restart. With the default `WRITE_APPROVAL=elicit`, writes over the stateless HTTP transport are refused, because a human cannot be asked to approve them there. Only set `WRITE_APPROVAL=confirm_flag` if you accept that the model approves its own writes.
- **Watch for attacks:** alert on audit lines with `outcome=rejected` bursts or `outcome=ok_flagged` (neutralised prompt injection).

---

## Project layout

```
src/itom_mcp/
  config.py      settings + validation (same env vars as mcp-snow)
  auth.py        basic / oauth / api_key (mcp-snow flow + token caching)
  client.py      hardened ServiceNow REST client (Table + Aggregate API)
  security.py    sanitizing, query builder, allowlists, scrubbing, redaction, rate limit
  server.py      FastMCP assembly, logging, HTTP app + bearer auth
  tools/         cmdb, discovery (+MID/ECC), events, services (+CI ops), generic (+check_access)
tests/           136 tests: injection, prompt injection, PII, auth, redirects, redaction, HTTP abuse, approvals
openshift/       BuildConfig, ConfigMap, Secret example, Deployment, Service/Route, NetworkPolicy+PDB
requirements.lock  hash-pinned runtime deps used by the image
.github/         CI (tests, bandit, pip-audit, gitleaks, hidden-Unicode check) + Dependabot
```

## Limitations

- Verified only with unit tests and mocked HTTP, plus a real MCP client over stdio against an unreachable instance. It has **not** been run against a live ServiceNow instance yet. Run `check_access` first and report anything that differs.
- Field names follow standard ServiceNow ITOM tables. Customized instances (renamed choice values, custom number prefixes, Agent Client Collector, Health Log Analytics, Cloud Discovery specifics) may need small adjustments. `itom_query` covers allowlisted tables in the meantime.
