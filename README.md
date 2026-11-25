# itom-mcp: a secure ServiceNow ITOM MCP server

An MCP server that answers ServiceNow **IT Operations Management** questions:
CMDB, Discovery, MID Servers, Event Management, Service Mapping, and the operational
context of a CI (incidents, problems, changes, outages).

- **Read-only by default.** Write tools are opt-in and need explicit confirmation.
- **Same ServiceNow authentication as [oricohen392/mcp-snow](https://github.com/oricohen392/mcp-snow):** `basic`, `oauth` (client_credentials, falling back to the password grant) and `api_key`, with the same environment variables.
- **Hardened against the known MCP/ServiceNow security problems.** See [SECURITY.md](SECURITY.md).
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
| Write (opt-in) | `alert_acknowledge`, `alert_close`, `alert_add_work_note` | Only with `READ_ONLY=false` **and** `confirm=true` |

Every tool accepts CIs by **sys_id, exact name, IP or FQDN**. Dates can be ISO-8601 or relative (`30m`, `24h`, `7d`). List results include `query_used`, `total_count`, `returned` and `next_offset`.

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
| `RATE_LIMIT_PER_MINUTE` | `120` | per process |
| `ENABLE_GENERIC_QUERY` | `true` | `itom_query` / `itom_count` |
| `LOG_LEVEL` | `INFO` | logs go to stderr, redacted |
| `MCP_AUTH_TOKEN` | | **required** for HTTP on non-loopback; ≥ 32 characters |
| `MCP_HTTP_HOST` / `MCP_HTTP_PORT` | `127.0.0.1` / `8080` | |
| `MCP_ALLOWED_HOSTS` / `MCP_ALLOWED_ORIGINS` | | Host-header allowlist (set it to the Route host) |

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

Generate the token the clients will use:

```powershell
$token = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
```

Create the secret:

```powershell
oc create secret generic itom-mcp-secrets --from-literal=servicenow-username=itom.mcp.integration --from-literal=servicenow-password='<password>' --from-literal=mcp-auth-token=$token
```

For OAuth, also add `--from-literal=servicenow-client-id=... --from-literal=servicenow-client-secret=...`, then uncomment the OAuth lines in `deployment.yaml`.
Keep `$token`: clients need it. If you use a vault, create the same keys with External Secrets / Sealed Secrets instead.

### 5. Edit the configuration

- `openshift/configmap.yaml`:
  - `SERVICENOW_INSTANCE_URL`, `SERVICENOW_AUTH_TYPE`
  - `MCP_ALLOWED_HOSTS`: the Route host from step 6, plus `itom-mcp,itom-mcp:8080` for in-cluster clients
  - `SERVICENOW_ALLOWED_HOSTS` if you use a custom domain
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

Finally, connect a client with `Authorization: Bearer <token>` and run the `check_access` tool. It reports which ITOM tables the integration user can read.

### 8. Operate

- **Scale:** `oc scale deployment/itom-mcp --replicas=3`. The HTTP transport is stateless, so no sticky sessions are needed.
- **Rotate the MCP token or ServiceNow password:** update the secret, then run `oc rollout restart deployment/itom-mcp`.
- **Audit:** `oc logs deployment/itom-mcp | Select-String itom_mcp.audit`.
- **Enable alert actions:** set `READ_ONLY: "false"` in the ConfigMap and restart. Only do this if the integration user has the matching role and you want the model to act.

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
tests/           103 tests: injection, auth, redirects, redaction, HTTP auth, tools
openshift/       BuildConfig, ConfigMap, Secret example, Deployment, Service/Route, NetworkPolicy+PDB
```

## Limitations

- Verified only with unit tests and mocked HTTP, plus a real MCP client over stdio against an unreachable instance. It has **not** been run against a live ServiceNow instance yet. Run `check_access` first and report anything that differs.
- Field names follow standard ServiceNow ITOM tables. Customized instances (renamed choice values, custom number prefixes, Agent Client Collector, Health Log Analytics, Cloud Discovery specifics) may need small adjustments. `itom_query` covers allowlisted tables in the meantime.
