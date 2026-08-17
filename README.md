# simply_ip_sync

Enterprise-grade threat intelligence ingestion orchestrator and multi-site inter-vault replication
daemon. `simply_ip_sync` is the active synchronization engine in the `simply_ip_*` security
ecosystem: it pulls external threat feeds (Spamhaus, FireHOL, AbuseIPDB, pfSense exports, …),
parses and normalizes them, and pushes them in batch to one or more `simply_ip_vault` instances —
and it replicates delta changes (including tombstones) between vault instances on a schedule.

## Architecture overview

```
                    ┌─────────────────────┐
  External feed ───▶│  Extensible Parser   │
  (HTTP/HTTPS)       │  Engine (REGEX_LINE, │
                    │  JSON_PATH)          │
                    └──────────┬───────────┘
                               │ normalized IP/CIDR strings, chunked ≤5,000
                               ▼
┌──────────────┐   cron / manual trigger   ┌───────────────────────────┐
│  Scheduler   │──────────────────────────▶│  POST /api/records/batch  │──▶ simply_ip_vault #1
│ (tokio-cron- │                           │  (mode="upsert", signed   │──▶ simply_ip_vault #2
│  scheduler)  │                           │   CANONICAL_V1 HMAC)      │──▶ …
└──────┬───────┘                           └───────────────────────────┘
       │
       │ vault_sync_tasks
       ▼
┌───────────────────────────┐   GET /api/ips?since=…&include_deleted=true
│  Inter-Vault Delta Puller │◀──────────────────────────────────────── simply_ip_vault (source)
└──────────┬─────────────────┘
           │ delta records + tombstones, chunked ≤5,000
           ▼
   POST /api/records/batch (mode="upsert") ──▶ target simply_ip_vault(s)
```

Every inbound `/api/*` request and every outbound call to a vault endpoint is authenticated with
an HMAC-SHA256 signature over a `CANONICAL_V1` canonical string (`METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`),
carries a 300-second symmetric freshness window, and is protected by a single-use anti-replay
cache. Secrets at rest (per-key HMAC signing secrets, remote vault credentials) are sealed with
XChaCha20-Poly1305 when `SYNC_ENCRYPTION_KEY` is configured. Authorization follows a
Master/Parent/Daughter RBAC model — see [`RBAC_MODEL.md`](RBAC_MODEL.md) for the full
specification.

## Quick start

```sh
# Build
cargo build --release

# Run (SQLite, zero external dependencies)
DATABASE_URL="sqlite://./data/simply_ip_sync.db?mode=rwc" \
INITIAL_MASTER_KEY=$(openssl rand -hex 32) \
RUST_LOG=info \
./target/release/simply_ip_sync
```

On first boot, if no Master key exists yet, the service bootstraps one:
- If `INITIAL_MASTER_KEY` is set, it becomes the Master's plaintext API key (must be exactly 64
  hex characters). Otherwise, a random one is generated and logged **once** — copy it
  immediately, it is never shown again.
- Likewise, if `INITIAL_MASTER_SIGNING_SECRET` is set, it becomes the Master's HMAC signing
  secret; otherwise one is generated and logged once. Rotation is refused for the Master key
  through the API (see `RBAC_MODEL.md` §5), so whichever path is taken, that log line (or the
  env var you set) is the only way this secret is ever knowable. Setting both env vars
  deterministically is mainly useful for test harnesses (e.g. `scripts/test_e2e.sh`) that need to
  sign requests as Master without scraping a redirected server log.

Open `http://<host>:3003/` for the dashboard, or drive the API directly (see **Signing a request
by hand** below).

## Configuration

| Variable | Default | Notes |
| :--- | :--- | :--- |
| `BIND_HOST` / `HOST` | `0.0.0.0` | Listen address. |
| `PORT` | `3003` | Listen port. |
| `DATABASE_URL` | `sqlite://simply_ip_sync.db?mode=rwc` | SeaORM connection string. SQLite, PostgreSQL, and MySQL are supported; SQLite is pinned to a single pooled connection with WAL/NORMAL/foreign_keys pragmas. |
| `SYNC_ENCRYPTION_KEY` | *(unset)* | 64 hex character XChaCha20-Poly1305 key. When unset, secrets are stored under a self-describing plaintext envelope (`v1.plain.<hex>`) rather than failing to boot — set this in production. |
| `INITIAL_MASTER_KEY` | *(unset)* | Bootstrap Master API key. Must be exactly 64 hex characters if set; malformed values are a fatal startup error. |
| `INITIAL_MASTER_SIGNING_SECRET` | *(unset)* | Bootstrap Master HMAC signing secret. Must be exactly 64 hex characters if set; malformed values are a fatal startup error. |
| `TRUSTED_PROXIES` | *(unset — nothing trusted)* | Comma-separated CIDR ranges/addresses whose `X-Forwarded-For`/`X-Real-IP` headers are honoured. Malformed entries are a fatal startup error. |
| `MAX_BODY_SIZE_MIB` | `10` | Maximum accepted request body size. Shared by the router's body limit and the signed-body buffer in the auth middleware, so the two can never drift apart. |
| `OUTBOUND_HTTP_TIMEOUT_SECS` | `60` | Per-request timeout for outbound calls to remote vault endpoints. A hung target is aborted on this schedule rather than stalling a scheduled job indefinitely. |
| `OUTBOUND_MAX_RETRIES` | `3` | Maximum retry attempts for a transient (`429`/`502`/`503`/`504`) outbound failure, applied to vault calls and external feed fetches alike, before the job reports `FAILED`/`PARTIAL`. |
| `OUTBOUND_RETRY_BACKOFF_MS` | `500` | Base delay before the first retry; later attempts back off exponentially from this (capped at 30s) with up to 50% jitter. |
| `RUST_LOG` | *(unset)* | Standard `tracing-subscriber` env filter. |

## API endpoints

All `/api/*` routes require `X-API-Key`, `X-Timestamp`, and `X-Signature-256` headers (see
below). `/health`, `/healthz`, `/ready`, `/readyz` are unauthenticated.

| Method & Path | Description |
| :--- | :--- |
| `GET /health`, `/healthz` | Liveness probe. No database access. |
| `GET /ready`, `/readyz` | Readiness probe: database reachable and Master identity pinned. |
| `GET /api/auth/me` | Caller's own identity and rights. |
| `GET/POST /api/keys` | List / create API keys. |
| `GET/PATCH/DELETE /api/keys/{id}` | Read / update / delete a key. |
| `POST /api/keys/{id}/rotate` | Rotate a key's plaintext credential. Refused for Master. |
| `POST /api/keys/{id}/rotate-secret` | Rotate a key's HMAC signing secret. Refused for Master. |
| `GET/PUT /api/keys/{id}/permissions` | List / grant a per-resource permission row. |
| `DELETE /api/keys/{id}/permissions/{permission_id}` | Revoke a permission row. |
| `GET/POST /api/vaults` | List / register `simply_ip_vault` endpoints. |
| `GET/PATCH/DELETE /api/vaults/{id}` | Read / update / delete a vault endpoint. |
| `GET/POST /api/sources` | List / create external threat feed sources. |
| `GET/PATCH/DELETE /api/sources/{id}` | Read / update / delete a source. |
| `POST /api/sources/{id}/trigger` | Manually run an external ingestion job now. |
| `GET/POST /api/sync-tasks` | List / create inter-vault sync tasks. |
| `GET/PATCH/DELETE /api/sync-tasks/{id}` | Read / update / delete a sync task. |
| `POST /api/sync-tasks/{id}/trigger` | Manually run an inter-vault delta sync now. |
| `GET /api/sync-logs` | Execution history, filterable by `job_type`/`job_id`. |
| `GET /api/audit-logs` | Security audit trail. Master-only. |

## Signing a request by hand

```sh
API_KEY="<64-hex-char plaintext key>"
SIGNING_SECRET="<64-hex-char signing secret>"
METHOD="GET"
TARGET="/api/auth/me"   # full path + query string, exactly as sent
TIMESTAMP=$(date +%s)
BODY=""

MESSAGE="${METHOD}
${TARGET}
${TIMESTAMP}
${BODY}"
SIGNATURE="sha256=$(printf '%s' "$MESSAGE" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" | awk '{print $2}')"

curl -s "http://localhost:3003${TARGET}" \
  -H "X-API-Key: ${API_KEY}" \
  -H "X-Timestamp: ${TIMESTAMP}" \
  -H "X-Signature-256: ${SIGNATURE}"
```

For a request with a JSON body, `MESSAGE` ends with the exact raw request body bytes (no trailing
newline added after them), and `Content-Type: application/json` should be set.

## Extending the parser engine

New feed formats implement the `FeedParser` trait (`src/parsers/mod.rs`):

```rust
pub trait FeedParser {
    fn parse(&self, raw: &[u8], config: Option<&str>) -> Result<Vec<String>, ParseError>;
}
```

Built-in parsers:
- **`REGEX_LINE`** — line-oriented text feeds. Strips `#`/`;`/`//` comment lines and extracts
  IPv4/IPv6 addresses and CIDR subnets.
- **`JSON_PATH`** — structured JSON feeds. Configured via `parser_config_json`:
  `{"array_path": "data.items", "ip_field": "ipAddress"}` (`array_path` may be omitted for a bare
  top-level array).

`parser_config_json` may also carry two generic keys read by the ingestion job itself, independent
of the parser: `user_agent` and `headers` (an object of extra request headers).

## Development

```sh
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
cargo test -- --ignored     # live network feed tests, normally skipped
cargo doc --no-deps
./scripts/test_e2e.sh       # boots the real binary; see below
```

Integration tests (`tests/`) run entirely against an in-memory SQLite database and a real router
via `tower::ServiceExt::oneshot`; outbound calls to remote vaults are exercised against
`wiremock`-backed mock servers, so no network access or external services are required. A handful
of tests in `tests/live_feed_ingestion_tests.rs` are `#[ignore]`d because they hit real, public
threat-intelligence feeds over the network — run them explicitly with `cargo test -- --ignored`
when network access is available; they are not part of the default `cargo test` run.

`scripts/test_e2e.sh` is the one gate that exercises the **actual compiled binary** end-to-end
rather than the in-process router: it boots `target/debug/simply_ip_sync` against an isolated
temporary SQLite database and port, drives it with real `curl` requests carrying hand-computed
`CANONICAL_V1` HMAC signatures, spins up local Python mock `simply_ip_vault` servers to verify
real multi-vault delivery over the wire (including a partial-failure scenario), exercises live and
local-fixture feed ingestion, and confirms a clean `SIGTERM` shutdown. It requires `cargo`, `curl`,
`openssl`, `jq`, and (for the mock-vault and local-fixture sections; soft dependency, those
sections warn and skip without it) `python3`. Run it from the repository root:

```sh
./scripts/test_e2e.sh
```

## License

See [`LICENSE`](LICENSE).
