---
name: use-ip-sync
description: Operate, configure, and troubleshoot simply_ip_sync via its CANONICAL_V1 HMAC-authenticated HTTP API, curated threat-intel feed parsers, and inter-vault replication tasks.
---

# Using `simply_ip_sync`

`simply_ip_sync` is the threat-intelligence ingestion orchestrator and inter-vault delta replication daemon in the `simply_*` security ecosystem.

## Network & Security Boundary

- **`ext` network**: Outbound HTTP/HTTPS egress used to fetch external threat feeds (e.g., `https://feeds.example.org/blocklist.txt`).
- **`isolate` network**: Internal network used for authenticated reads/writes against `simply_ip_vault` instances (e.g., `https://vault-site-a.example.test`) and optional reverse-proxy access to the dashboard/API.
- **Unauthenticated probes**: `GET /health`, `GET /healthz` (liveness), `GET /ready`, `GET /readyz` (readiness: DB reachable + Master pinned).
- **Authenticated API (`/api/*`)**: Requires `X-API-Key`, `X-Timestamp`, and `X-Signature-256` headers.

## `CANONICAL_V1` Request Signing & `OriginalUri`

Every `/api/*` request is verified by `src/middleware.rs` using `OriginalUri`:
- `TARGET` is the **exact, unrewritten request path and query string** as received by the router (e.g. `/api/sync-logs?job_type=INGESTION&limit=20`). If a reverse proxy strips a subpath prefix before forwarding, `TARGET` is the post-strip path.
- Canonical string (`METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`, no trailing newline):
  ```sh
  API_KEY="<64-hex-char key>"
  SIGNING_SECRET="<64-hex-char secret>"
  METHOD="GET"
  TARGET="/api/auth/me"
  TIMESTAMP=$(date +%s)
  BODY=""

  MESSAGE="${METHOD}
  ${TARGET}
  ${TIMESTAMP}
  ${BODY}"
  SIG="sha256=$(printf '%s' "$MESSAGE" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" | awk '{print $2}')"

  curl -fsS "http://127.0.0.1:3003${TARGET}" \
    -H "X-API-Key: ${API_KEY}" \
    -H "X-Timestamp: ${TIMESTAMP}" \
    -H "X-Signature-256: ${SIG}"
  ```
- Freshness window: `±300` seconds (`MAX_TIMESTAMP_SKEW_SECS`), enforced with a single-use anti-replay cache (`src/replay.rs`).

## API Cookbook (RFC 5737 / 3849 / 2606 Examples Only)

### 1. Register a Target Vault (`POST /api/vaults`)
```json
{
  "name": "vault-site-a",
  "target_url": "https://vault-site-a.example.test",
  "api_key": "<vault-api-key>",
  "signing_secret": "<vault-signing-secret>",
  "description": "Site A vault on isolate"
}
```

### 2. Create a Destination Group (`POST /api/destination-groups`)
```json
{
  "name": "problematics-ips",
  "target_group_name": "problematics_ips",
  "cron_schedule": "0 */4 * * *",
  "mode": "upsert",
  "is_active": true,
  "skip_bogon_filtering": false,
  "target_vault_ids": ["<vault-uuid>"]
}
```

### 3. Dry-Run a Feed Before Saving (`POST /api/sources/test-fetch`)
```json
{
  "source_url": "https://feeds.example.org/threatlist.json",
  "parser_type": "JSON_PATH",
  "parser_config_json": "{\"target_address\":\"$.ipv4\",\"last_seen_at\":\"$.lastseen\",\"user_agent\":\"simply_ip_sync/1.0\"}"
}
```
Returns normalized sample records, parse counts, and any SSRF/fetch/parse errors without persisting a feed row.

### 4. Attach a Feed & Trigger Ingestion
- `POST /api/destination-groups/{group_id}/feeds` with `name`, `source_url`, `parser_type` (`REGEX_LINE` or `JSON_PATH`), optional `parser_config_json`, optional `max_age_days`, optional `skip_bogon_filtering`.
- `POST /api/destination-groups/{id}/trigger` to run all feeds in the group immediately.
- `GET /api/sync-logs?job_type=INGESTION&limit=20` to inspect execution status (`SUCCESS`, `PARTIAL`, `FAILED`), `items_processed`, and `error_message`.

### 5. Inter-Vault Delta Replication (`POST /api/sync-tasks`)
```json
{
  "name": "site-a-to-site-b",
  "source_vault_id": "<source-vault-uuid>",
  "source_group_name": "problematics_ips",
  "target_group_name": "problematics_ips",
  "cron_schedule": "*/15 * * * *",
  "is_active": true,
  "skip_bogon_filtering": false,
  "target_vault_ids": ["<target-vault-uuid>"]
}
```
- Trigger immediately with `POST /api/sync-tasks/{id}/trigger`.
- Inspect `GET /api/audit-logs` (Master-only) and `GET /api/settings` for runtime configuration.

## Curated Threat-Intel Feed Catalog (`Problematics IPS`)

| Feed Name | Parser Type | Wire Format / Notes | `parser_config_json` |
| :--- | :--- | :--- | :--- |
| `feodo_tracker` | `REGEX_LINE` | `#`-commented IPv4 blocklist | *(none)* |
| `sans_isc_block` | `REGEX_LINE` | Tab-separated `<start>\t<end>\t24\t...` netblocks | *(none)* |
| `sans_isc_shodan` | `JSON_PATH` | JSON array of objects with `ipv4` and `lastseen` (`YYYY-MM-DD` or RFC 3339); requires `user_agent` | `{"target_address":"$.ipv4","last_seen_at":"$.lastseen","user_agent":"simply_ip_sync/1.0"}` |
| `ipsum_level3` | `REGEX_LINE` | `#`-commented header + `<ip>` or `<ip>\t<score>` | *(none)* |
| `binarydefense` | `REGEX_LINE` | `#`-commented IPv4 banlist | *(none)* |
| `dataplane_sshclient` | `REGEX_LINE` | `#`-commented header + `ASN \| IP \| ts \| desc` | *(none)* |
| `dataplane_sshpwauth` | `REGEX_LINE` | `#`-commented header + `ASN \| IP \| ts \| desc` | *(none)* |
| `dataplane_dnsrd` | `REGEX_LINE` | `#`-commented header + `ASN \| IP \| ts \| desc` | *(none)* |
| `dataplane_vncrfb` | `REGEX_LINE` | `#`-commented header + `ASN \| IP \| ts \| desc` | *(none)* |

Example RFC 5737 / 3849 records handled cleanly by these parsers: `192.0.2.10`, `198.51.100.0/24`, `203.0.113.5`, `2001:db8::1`.

## SSRF & Anti-Bogon Guardrails

- **SSRF Protection (`src/jobs/external_ingestion.rs`)**: Outbound feed fetches validate the scheme (`http`/`https`), resolve DNS before connecting, reject loopback, private (RFC 1918), link-local, CGNAT, and reserved/multicast targets, and follow SSRF-validated HTTP redirects (`301`/`302`/`303`/`307`/`308`) up to 5 hops (rejecting HTTPS-to-HTTP downgrades, re-validating every hop before connecting, and stripping sensitive auth headers cross-origin; vault calls in `src/client.rs` still refuse redirects outright).
- **Anti-Bogon Sanitization (`src/bogon.rs`)**: By default (`skip_bogon_filtering = false`), `bogon::sanitize` drops any parsed IP or CIDR overlapping loopback, RFC 1918, link-local, CGNAT, RFC 5737/3849 documentation nets, or multicast/reserved ranges before pushing batches to vaults.
- **Decompression & Body Bounds (`src/jobs/decompress.rs`, `src/config.rs`)**: `MAX_DECOMPRESSED_BYTES` (default 50 MiB) is enforced mid-stream on both HTTP `Content-Encoding` and ZIP archive members.
