# API Reference — `simply_ip_sync`

Exhaustive, zero-knowledge catalog of every HTTP endpoint this service exposes, generated directly
from the current `src/api/*.rs` handlers, `src/lib.rs`'s route table, `src/middleware.rs`, and
`src/extract.rs`. No endpoint, alias, or parameter here is inferred — every entry below is backed
by a specific handler function and, where relevant, a payload/query struct in the current source.

See `AGENT.MD` for the architectural rules this API implements, `RBAC_MODEL.md` for the full
authorization model (R1–R7, §3–§7) referenced throughout, and `SCHEMA.MD` for the underlying table
definitions.

---

## 1. Transport & Authentication

Every route except the four public probes (§2) requires all three of the following headers,
verified by `middleware::auth_middleware` in the order listed — the order itself is a security
control, not an implementation detail (see the ordering note after the table):

| Header | Format | Purpose |
| :--- | :--- | :--- |
| `X-API-Key` | plaintext string | The key's plaintext credential. Hashed (SHA-256) and looked up against `api_keys.key_hash`. |
| `X-Timestamp` | Unix seconds, e.g. `1700000000` | Must be within ±300 seconds (`MAX_TIMESTAMP_SKEW_SECS`) of the server's clock. |
| `X-Signature-256` | `sha256=<hex>` | HMAC-SHA256 over the `CANONICAL_V1` payload (`METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`), keyed by the key's decrypted `signing_secret`. `TARGET` is the full path **and query string** the client actually sent (`OriginalUri`, not the nest-rewritten path). The `sha256=` prefix is mandatory — a bare hex digest is rejected. |

**Verification order in `auth_middleware`** (each step can fail the request before the next runs):
1. Resolve client IP (trusted-proxy-aware `X-Forwarded-For`/`X-Real-IP` walk).
2. Validate `X-Timestamp` (no DB round-trip yet).
3. Require `X-API-Key` and `X-Signature-256` present, and the latter's `sha256=` prefix.
4. Hash the key and look it up (`401 Invalid API Key` if not found).
5. Decrypt the key's `signing_secret` (`401` if the key has none — it must be rotated first).
6. Enforce the body-size limit — a declared `Content-Length` over the limit is refused immediately
   (`413`); otherwise the body is buffered up to the limit and an overflow during buffering also
   answers `413`.
7. Verify the HMAC signature over the buffered body (`401 Invalid request signature` on mismatch).
8. Anti-replay check: the `(key_id, signature digest)` pair must not have been seen before within
   the replay window (`401` — "This request signature has already been used").
9. **`bound_ips` CIDR check — deliberately last**, after authentication has fully succeeded, so a
   401-vs-403 status pair can never be used as an oracle for whether a given key exists (`403
   Client IP not allowed` if the key has a non-empty `bound_ips` list and the resolved client IP
   isn't in it).
10. `MasterPin::authenticate` runs (silently demotes an impostor `is_master=true` row that isn't
    the boot-pinned Master; never itself produces a 401).

On success, the authenticated `api_keys` row and the resolved `ClientIp` are inserted into request
extensions for the handler and `api/guards.rs` to read. **Authorization** (does this specific,
already-authenticated key have the right to do *this*) is a separate, per-endpoint concern — see
the "Authorization" column in every table below, and `RBAC_MODEL.md` for the underlying rules.

### Standard error envelope

Every failure — from `auth_middleware`, an extractor, a guard, or a handler — renders as:

```json
{ "error": "<human-readable message>" }
```

| Status | Meaning | Notes |
| :--- | :--- | :--- |
| `400 Bad Request` | Malformed input: bad JSON, an unknown field the payload's `deny_unknown_fields` rejected, an unparseable query string, invalid business input (bad `parser_type`, `mode`, `cron_schedule`, etc.) |
| `401 Unauthorized` | Authentication failed — missing/malformed header, unknown key, bad signature, stale timestamp, or replayed signature |
| `403 Forbidden` | Authenticated, but the guard for this action refused (wrong tier, missing permission verb, `bound_ips` mismatch, Master-immutability) |
| `404 Not Found` | The resource doesn't exist, **or** exists but is outside the caller's visibility scope (RBAC §4 oracle discipline — the two cases are indistinguishable by design), **or** a path segment (e.g. a UUID) didn't parse at all (`StrictPath`, same oracle-discipline reasoning) |
| `409 Conflict` | A uniqueness collision (duplicate `name`), or (for key deletion) an owned-resource inventory blocking the delete — see §3.2 |
| `413 Payload Too Large` | Request body exceeds the configured limit (`MAX_BODY_SIZE_MIB`, default 10 MiB) |
| `500 Internal Server Error` | An unexpected database or crypto failure. Never discloses the underlying error detail. |

A malformed path segment (`StrictPath`) and a well-formed-but-nonexistent/out-of-scope id
(`StrictQuery`, ordinary lookups) both answer `404` with the exact same body — this is deliberate,
not an omission (RBAC §4).

---

## 2. Public Probes (Unauthenticated)

Mounted outside the `/api` nest and outside `auth_middleware` entirely — no headers required, ever.

| Method & Path | Handler | Auth | Response |
| :--- | :--- | :--- | :--- |
| `GET /health` | `health_check` | None | `200` always. `{"status":"ok","service":"simply_ip_sync"}`. Does not touch the database — a DB outage never turns into an orchestrator restart loop. |
| `GET /healthz` | `health_check` (alias) | None | Identical to `/health`. Kubernetes-idiomatic spelling. |
| `GET /ready` | `readiness_check` | None | `200` `{"status":"ok","service":"simply_ip_sync"}` if the database answers **and** the Master identity is pinned; otherwise `503` `{"status":"not_ready","service":"simply_ip_sync"}`. |
| `GET /readyz` | `readiness_check` (alias) | None | Identical to `/ready`. |

---

## 3. API Keys — `/api/keys`

All routes in this section require `X-API-Key`/`X-Timestamp`/`X-Signature-256` (§1). Resource
model: `api_keys`. RBAC verbs relevant here: `can_manage_keys` (global, Parent-tier), Master.

### 3.1 Identity & Listing

| Method & Path | Auth / RBAC | Description | Response |
| :--- | :--- | :--- | :--- |
| `GET /api/auth/me` | Any authenticated key | Returns the caller's own identity. | `200` `ApiKeyResponse` (see §3.6) for the calling key. |
| `GET /api/keys` | Any authenticated key | Master sees every key; a Parent sees itself and its direct daughters; a Daughter sees only itself. | `200` `ApiKeyResponse[]`. |
| `GET /api/keys/{id}` | Master, self, or the key's direct parent | Otherwise `404` (not `403` — visibility scoping, RBAC §4). | `200` `ApiKeyResponse`. |

### 3.2 Lifecycle

| Method & Path | Auth / RBAC | Request Body | Response |
| :--- | :--- | :--- | :--- |
| `POST /api/keys` | `can_manage_keys` or Master. Additionally: only Master may set `can_manage_keys`/`can_manage_sources`/`can_manage_vaults` to `true` (RBAC R4 — `guard_scope_elevation`). | `CreateApiKeyPayload` (§3.7) | `201`-equivalent `200`: `{"key": ApiKeyResponse, "plaintext_key": "<string>", "plaintext_signing_secret": "<string>"}`. **The plaintext key and signing secret are returned exactly once, here** — never recoverable again except by rotation (§3.3). |
| `PATCH /api/keys/{id}` | `can_manage_keys` + administrative authority over `id` (Master, or `id`'s direct parent). If the target `is_master`, only `bound_ips` may be touched (RBAC §5, `guard_master_immutable`) — any other field in the same request is refused with `403`. Setting `can_manage_*` to `true` is R4-gated identically to creation. | `UpdateApiKeyPayload` (§3.7), all fields optional | `200` `ApiKeyResponse` (updated). |
| `DELETE /api/keys/{id}` | `can_manage_keys` + administrative authority. Refused outright for the Master key (`403`, RBAC §5 — never reaches the inventory check). | — | `204 No Content` on success. **`409 Conflict`** with `{"error": "...", "owned_resources": [{"type","id","name","owner_key_id"}, ...]}` if the key or any daughter in its subtree still owns a `vault_endpoint`/`external_source`/`sync_task` (RBAC §6 pre-flight inventory) — reassign or delete those first, then retry. Deletion cascades recursively through the entire daughter subtree once the inventory is empty. `404` if a concurrent delete already removed the row (TOCTOU-safe: checks `rows_affected`). |
| `POST /api/keys/{id}/rotate` | `can_manage_keys` + administrative authority. Refused for the Master key (`403`, RBAC §5 — rotation always mints a fresh credential, which the Master can never be issued through the API). | — | `200` `{"plaintext_key": "<string>"}`. **Returned exactly once** — the old key stops working immediately. |
| `POST /api/keys/{id}/rotate-secret` | Same as rotation above. | — | `200` `{"plaintext_signing_secret": "<string>"}`. **Returned exactly once.** |

### 3.3 Per-Resource Permission Grants — `/api/keys/{id}/permissions`

Resource model: `api_key_sync_permissions`. See `RBAC_MODEL.md` R1, R2, R6, R7 for the underlying
conjunction rules.

| Method & Path | Auth / RBAC | Request Body | Response |
| :--- | :--- | :--- | :--- |
| `GET /api/keys/{id}/permissions` | Master, self, or `id`'s direct parent (same visibility rule as `GET /api/keys/{id}`); otherwise `404`. | — | `200` — raw `api_key_sync_permissions` rows for `id` (`Vec<Model>`, unfiltered field set: `id, api_key_id, resource_type, resource_id, can_sync, can_manage, can_view_logs, created_at`). |
| `PUT /api/keys/{id}/permissions` | `can_manage_keys` (`guard_manage_keys`) **and** RBAC R2 on the target resource (global `can_manage_keys` + a `can_manage=true` row the *caller* holds on that resource) **and** R1/R7 (the caller may only grant a verb — `can_sync`/`can_manage`/`can_view_logs` — that it holds itself on that same resource). Master bypasses all three. | `GrantPermissionPayload` (§3.7) | `200` — the created or updated `api_key_sync_permissions` row (upsert: keyed on `(api_key_id, resource_type, resource_id)`). `400` if `resource_type` isn't one of `external_source`/`sync_task`/`vault_endpoint`. |
| `DELETE /api/keys/{id}/permissions/{permission_id}` | `can_manage_keys` + RBAC R2/R6 (manage rights on the resource the permission targets; the revoker need **not** hold the verb being removed). | — | `204 No Content`. `404` if the permission doesn't belong to `id`, or if a concurrent revoke already removed it (TOCTOU-safe). |

### 3.4 Query Parameters

None of the `/api/keys*` routes accept query parameters.

### 3.5 Request Body Strictness

All three payload structs below carry `#[serde(deny_unknown_fields)]` — an unrecognized field is a
`400`, not a silent drop. **`is_master` is absent from every one of them by construction** (RBAC
§5) — it cannot be set or cleared through any request body on any route, not merely rejected by a
handler check.

### 3.6 Response Schema — `ApiKeyResponse`

Every `api_keys` read returns this shape. `key_hash` and `signing_secret` are **never** included.

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | UUID | |
| `name` | string | |
| `prefix` | string | First 8 characters of the plaintext key, for display/identification only |
| `is_master` | bool | |
| `can_manage_keys` | bool | |
| `can_manage_sources` | bool | |
| `can_manage_vaults` | bool | |
| `parent_key_id` | UUID \| null | Lineage only — confers no authority (RBAC R3) |
| `bound_ips` | string \| null | Comma-separated CIDR ranges |
| `created_at` | ISO-8601 datetime | |
| `updated_at` | ISO-8601 datetime | |

### 3.7 Request Payloads

**`CreateApiKeyPayload`** (`POST /api/keys`):

| Field | Type | Required | Default | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `name` | string | yes | — | |
| `can_manage_keys` | bool | no | `false` | Setting `true` requires Master |
| `can_manage_sources` | bool | no | `false` | Setting `true` requires Master |
| `can_manage_vaults` | bool | no | `false` | Setting `true` requires Master |
| `bound_ips` | string \| null | no | `null` | Comma-separated CIDR list |

**`UpdateApiKeyPayload`** (`PATCH /api/keys/{id}`) — every field optional, only provided fields change:

| Field | Type | Notes |
| :--- | :--- | :--- |
| `name` | string \| omitted | |
| `can_manage_keys` | bool \| omitted | Setting `true` requires Master |
| `can_manage_sources` | bool \| omitted | Setting `true` requires Master |
| `can_manage_vaults` | bool \| omitted | Setting `true` requires Master |
| `bound_ips` | string \| omitted | The **only** field settable on the Master key |

**`GrantPermissionPayload`** (`PUT /api/keys/{id}/permissions`):

| Field | Type | Required | Default | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `resource_type` | string | yes | — | Must be `"external_source"`, `"sync_task"`, or `"vault_endpoint"` |
| `resource_id` | UUID | yes | — | |
| `can_sync` | bool | no | `false` | |
| `can_manage` | bool | no | `false` | |
| `can_view_logs` | bool | no | `false` | |

---

## 4. Vault Endpoints — `/api/vaults`

Resource model: `vault_endpoints`. Creation right: `can_manage_vaults`. Handler file: `src/api/vaults.rs`.

| Method & Path | Auth / RBAC | Request Body | Response |
| :--- | :--- | :--- | :--- |
| `GET /api/vaults` | Visible rows only: Master, the endpoint's owner, or any key holding a permission row on it. | — | `200` `VaultEndpointResponse[]`. |
| `GET /api/vaults/{id}` | Same visibility rule; otherwise `404`. | — | `200` `VaultEndpointResponse`. |
| `POST /api/vaults` | `can_manage_vaults` or Master (`guard_resource_creation`). | `CreateVaultEndpointPayload` | `200` `VaultEndpointResponse`. Creator is auto-granted full permissions (`can_sync`/`can_manage`/`can_view_logs`) on the new endpoint. `409` on a duplicate `name`. |
| `PATCH /api/vaults/{id}` | RBAC R2: `can_manage_keys` **and** a `can_manage=true` row on this endpoint (`guard_resource_manage`); Master bypasses. | `UpdateVaultEndpointPayload`, all fields optional | `200` `VaultEndpointResponse` (updated). |
| `DELETE /api/vaults/{id}` | RBAC §3: Master or the endpoint's `owner_key_id` only (`guard_resource_lifecycle`) — holding manage rights is **not** sufficient. | — | `204 No Content`. `404` on a lost TOCTOU race. |

### Response Schema — `VaultEndpointResponse`

Credentials (`api_key`, `signing_secret`) are **never** returned in any response, on any route.

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | UUID | |
| `name` | string | Unique |
| `target_url` | string | Base URL of the remote `simply_ip_vault` |
| `description` | string \| null | |
| `owner_key_id` | UUID \| null | Lifecycle authority holder (RBAC §3) |
| `created_at` / `updated_at` | ISO-8601 datetime | |

### Request Payloads

**`CreateVaultEndpointPayload`** (`deny_unknown_fields`):

| Field | Type | Required | Notes |
| :--- | :--- | :--- | :--- |
| `name` | string | yes | Must be unique |
| `target_url` | string | yes | |
| `api_key` | string | yes | Plaintext; this service sends it as `X-API-Key` to the remote vault |
| `signing_secret` | string | yes | Sealed at rest (XChaCha20-Poly1305) immediately on write |
| `description` | string \| null | no | |

**`UpdateVaultEndpointPayload`** (`deny_unknown_fields`) — every field optional:

| Field | Type |
| :--- | :--- |
| `name` | string \| omitted |
| `target_url` | string \| omitted |
| `api_key` | string \| omitted |
| `signing_secret` | string \| omitted (re-sealed on write) |
| `description` | string \| omitted |

---

## 5. Destination Groups & Feeds — `/api/destination-groups`

Resource model: `destination_groups` (+ `destination_group_vault_targets` junction) as the
RBAC-managed, scheduled parent; `external_sources` rows are its 1-to-N child feeds, fetched
**concurrently** and aggregated into one deduplicated, sanitized set per group execution (see
`AGENT.MD` §3.A). Creation right: `can_manage_sources`. Handler file: `src/api/sources.rs`.

| Method & Path | Auth / RBAC | Request Body | Response |
| :--- | :--- | :--- | :--- |
| `GET /api/destination-groups` | Visible rows only: Master, owner, or any key with a permission row. | — | `200` `DestinationGroupResponse[]`, each with its `feeds` nested inline. |
| `GET /api/destination-groups/{id}` | Same visibility rule; otherwise `404`. | — | `200` `DestinationGroupResponse`. |
| `POST /api/destination-groups` | `can_manage_sources` or Master. | `CreateDestinationGroupPayload` | `200` `DestinationGroupResponse` (`feeds: []` — created with none). `400` if `mode` isn't `upsert`/`full_replace`, or if `cron_schedule` fails cron validation. `409` on duplicate `name`. Auto-grants the creator full permissions on the group; registers the job with the cron scheduler if `is_active`. |
| `PATCH /api/destination-groups/{id}` | RBAC R2 (`can_manage_keys` + `can_manage=true` on this group). | `UpdateDestinationGroupPayload`, all fields optional | `200` `DestinationGroupResponse` (updated). Same `mode`/`cron_schedule` validation as creation. Re-syncs the live scheduler entry. |
| `DELETE /api/destination-groups/{id}` | RBAC §3 (Master or owner only). | — | `204 No Content`. `404` on a lost TOCTOU race. Cascades to every child feed and target-vault mapping. Removes the live scheduler entry. |
| `POST /api/destination-groups/{id}/trigger` | `can_sync` on this group, or Master (`guard_can_sync`). | — | `200` `{"status": "SUCCESS"\|"FAILED"\|"PARTIAL", "items_processed": int, "chunks_sent": int, "duration_ms": int, "error_message": string\|null}`. `409` if a run for this group (cron or manual) is already in progress (`try_start_job` concurrency guard). |
| `POST /api/destination-groups/{group_id}/feeds` | RBAC R2 on the owning group — a feed has no permission row of its own. | `CreateFeedPayload` | `200` `FeedResponse`. `400` if `parser_type` isn't `REGEX_LINE`/`JSON_PATH`, if `max_age_days` isn't positive, or — for `JSON_PATH` — if `parser_config_json`'s `target_address` selector is missing or not `$.`-prefixed (`parsers::json_path::validate_config`). `409` on duplicate feed `name` (unique across all feeds, regardless of group). |
| `PATCH /api/destination-groups/{group_id}/feeds/{feed_id}` | RBAC R2 on the owning group. | `UpdateFeedPayload`, all fields optional | `200` `FeedResponse` (updated). `404` if `feed_id` doesn't belong to `group_id` (oracle discipline — indistinguishable from a nonexistent feed). Same `JSON_PATH` config validation as creation. |
| `DELETE /api/destination-groups/{group_id}/feeds/{feed_id}` | RBAC R2 on the owning group. | — | `204 No Content`. `404` if the feed doesn't exist or doesn't belong to `group_id`. |
| `POST /api/sources/test-fetch` | `can_manage_sources` or Master (`guard_resource_creation`) — the same right creating a group requires, not a per-resource permission (there is no resource yet; unrelated to grouping, tests an arbitrary URL/parser combination directly). | `TestFetchPayload`: `{"source_url": string, "parser_type": "REGEX_LINE"\|"JSON_PATH", "parser_config_json": string\|null}` | `200` `{"status": "SUCCESS"\|"FAILED"\|"PARTIAL", "total_extracted": int, "sample": string[], "truncated": bool, "duration_ms": int, "error": string\|null}`. `400` if `parser_type` (or, for `JSON_PATH`, `parser_config_json`'s own shape) is invalid — a feed/network failure is reported as `status: "FAILED"` with `error` set, not an HTTP error. `sample` is capped at 50 entries (`truncated: true` beyond that; `total_extracted` is always the true count). Runs the same `jobs::external_ingestion::fetch_and_parse` pipeline a real scheduled run uses, but never pushes to any vault, and writes neither a `sync_logs` nor an `audit_logs` row. |

### Response Schema — `DestinationGroupResponse`

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | UUID | |
| `name` | string | Unique |
| `target_group_name` | string | Default group name in target vaults |
| `cron_schedule` | string | |
| `mode` | string | `"upsert"` or `"full_replace"` |
| `is_active` | bool | |
| `skip_bogon_filtering` | bool | `false` (default) sanitizes the aggregated feed set before push; `true` bypasses it |
| `last_run_at` | ISO-8601 datetime \| null | Across every child feed |
| `owner_key_id` | UUID \| null | Also governs every child feed |
| `targets` | `TargetSpec[]` | Resolved from `destination_group_vault_targets` |
| `feeds` | `FeedResponse[]` | Every child feed, nested inline |
| `created_at` / `updated_at` | ISO-8601 datetime | |

`TargetSpec`: `{"vault_endpoint_id": UUID, "target_group_name": string | null}` (`null` falls back
to the group's own `target_group_name`).

### Response Schema — `FeedResponse`

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | UUID | |
| `destination_group_id` | UUID | Owning group |
| `name` | string | Unique across all feeds, regardless of group |
| `source_url` | string | |
| `parser_type` | string | `"REGEX_LINE"` or `"JSON_PATH"` |
| `parser_config_json` | string \| null | See `parsers::json_path`'s `$.`-prefixed selector format for `JSON_PATH` |
| `max_age_days` | int \| null | Discards a record older than this many days; only meaningful with a `last_seen_at`/`timestamp` selector configured |
| `skip_bogon_filtering` | bool \| null | `null` inherits the owning group's setting; non-`null` overrides it for this feed's own contribution |
| `created_at` / `updated_at` | ISO-8601 datetime | |

### Request Payloads

**`CreateDestinationGroupPayload`** (`deny_unknown_fields`):

| Field | Type | Required | Default | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `name` | string | yes | — | Must be unique |
| `target_group_name` | string | yes | — | |
| `cron_schedule` | string | yes | — | Validated before any DB write |
| `mode` | string | no | `"upsert"` | `upsert` or `full_replace` |
| `is_active` | bool | no | `true` | |
| `skip_bogon_filtering` | bool | no | `false` | |
| `targets` | `TargetSpec[]` | no | `[]` | |

**`UpdateDestinationGroupPayload`** (`deny_unknown_fields`) — every field optional; `targets`, when
present, **replaces** the full set (delete-then-reinsert), not a merge:

| Field | Type |
| :--- | :--- |
| `name`, `target_group_name`, `cron_schedule`, `mode` | string \| omitted |
| `is_active`, `skip_bogon_filtering` | bool \| omitted |
| `targets` | `TargetSpec[]` \| omitted |

**`CreateFeedPayload`** (`deny_unknown_fields`):

| Field | Type | Required | Default | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `name` | string | yes | — | Must be unique across all feeds |
| `source_url` | string | yes | — | |
| `parser_type` | string | no | `"REGEX_LINE"` | Must be `REGEX_LINE` or `JSON_PATH` |
| `parser_config_json` | string \| null | no | `null` | Mandatory (and validated) for `JSON_PATH` |
| `max_age_days` | int \| null | no | `null` | Must be positive if set |
| `skip_bogon_filtering` | bool \| null | no | `null` | `null` inherits the group's setting |

**`UpdateFeedPayload`** (`deny_unknown_fields`) — every field optional:

| Field | Type |
| :--- | :--- |
| `name`, `source_url`, `parser_type`, `parser_config_json` | string \| omitted |
| `max_age_days` | int \| omitted (no way to *clear* an existing value back to `null` via update today — re-create the feed, or see `UpdateFeedPayload`'s own doc comment) |
| `skip_bogon_filtering` | bool \| omitted |

---

## 6. Vault Sync Tasks — `/api/sync-tasks`

Resource model: `vault_sync_tasks` (+ `vault_sync_task_targets` junction). Creation right:
**`can_manage_vaults`** (a sync task is a vault-to-vault topology object, not a fourth independent
right — see `RBAC_MODEL.md`'s terminology note). Handler file: `src/api/sync_tasks.rs`.

| Method & Path | Auth / RBAC | Request Body | Response |
| :--- | :--- | :--- | :--- |
| `GET /api/sync-tasks` | Visible rows only: Master, owner, or any key with a permission row. | — | `200` `VaultSyncTaskResponse[]`. |
| `GET /api/sync-tasks/{id}` | Same visibility rule; otherwise `404`. | — | `200` `VaultSyncTaskResponse`. |
| `POST /api/sync-tasks` | `can_manage_vaults` or Master. | `CreateVaultSyncTaskPayload` | `200` `VaultSyncTaskResponse`. `400` on a malformed `cron_schedule`. `409` on duplicate `name`. `mode` is always `"upsert"` server-side — not settable, deliberately (see field notes below). |
| `PATCH /api/sync-tasks/{id}` | RBAC R2 (`can_manage_keys` + `can_manage=true` on this task). | `UpdateVaultSyncTaskPayload`, all fields optional | `200` `VaultSyncTaskResponse` (updated). |
| `DELETE /api/sync-tasks/{id}` | RBAC §3 (Master or owner only). | — | `204 No Content`. `404` on a lost TOCTOU race. |
| `POST /api/sync-tasks/{id}/trigger` | `can_sync` on this task, or Master. | — | `200` — identical response shape to `POST /api/destination-groups/{id}/trigger` (§5). `409` if a run for this task is already in progress. |

### Response Schema — `VaultSyncTaskResponse`

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | UUID | |
| `name` | string | Unique |
| `source_vault_id` | UUID | |
| `source_group_name` | string | Group queried on the source vault |
| `target_group_name` | string | Default group on receiving vaults |
| `cron_schedule` | string | |
| `last_sync_at` | ISO-8601 datetime \| null | High-water mark for `since=` delta queries |
| `mode` | string | Always `"upsert"` — **not** exposed as a settable field on either payload; a delta batch is never the group's full authoritative content, so `full_replace` semantics don't apply here |
| `is_active` | bool | |
| `skip_bogon_filtering` | bool | `false` (default) sanitizes the source vault's delta records (loopback/unspecified/private-IPv4/link-local) before push; `true` bypasses it |
| `owner_key_id` | UUID \| null | |
| `targets` | `TargetSpec[]` | Same shape as §5 |
| `created_at` / `updated_at` | ISO-8601 datetime | |

### Request Payloads

**`CreateVaultSyncTaskPayload`** (`deny_unknown_fields`) — note there is **no `mode` field**; the
server always sets `"upsert"`:

| Field | Type | Required | Default |
| :--- | :--- | :--- | :--- |
| `name` | string | yes | — |
| `source_vault_id` | UUID | yes | — |
| `source_group_name` | string | yes | — |
| `target_group_name` | string | yes | — |
| `cron_schedule` | string | yes | — |
| `is_active` | bool | no | `true` |
| `skip_bogon_filtering` | bool | no | `false` |
| `targets` | `TargetSpec[]` | no | `[]` |

**`UpdateVaultSyncTaskPayload`** (`deny_unknown_fields`) — every field optional, no `mode` field here either:

| Field | Type |
| :--- | :--- |
| `name`, `source_group_name`, `target_group_name`, `cron_schedule` | string \| omitted |
| `source_vault_id` | UUID \| omitted |
| `is_active`, `skip_bogon_filtering` | bool \| omitted |
| `targets` | `TargetSpec[]` \| omitted |

---

## 7. Sync Logs — `GET /api/sync-logs`

Resource model: `sync_logs` (read-only). Handler: `src/api/sync_logs.rs::list_sync_logs`.

| Method & Path | Auth / RBAC | Response |
| :--- | :--- | :--- |
| `GET /api/sync-logs` | Master sees every row. A non-Master caller sees only rows belonging to a resource (`external_source`/`sync_task`, matched via `job_type`) it holds `can_view_logs` on (`guard_can_view_logs`), evaluated per-row after the query executes. | `200` — raw `sync_logs` rows (`Vec<Model>`). |

### Query Parameters — `SyncLogQuery` (`StrictQuery`, malformed values → `400`)

| Name | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `job_type` | string | no | none (no filter) | `"EXTERNAL_FEED"` or `"VAULT_SYNC"` |
| `job_id` | UUID | no | none (no filter) | The specific `external_sources`/`vault_sync_tasks` id |
| `limit` | integer | no | `100` | Clamped to a maximum of `1000` regardless of the value requested |
| `offset` | integer | no | `0` | |

### Response row shape (`sync_logs.Model`)

| Field | Type |
| :--- | :--- |
| `id` | UUID |
| `job_type` | string (`"EXTERNAL_FEED"` \| `"VAULT_SYNC"`) |
| `job_id` | UUID |
| `job_name` | string (denormalized name at execution time) |
| `status` | string (`"SUCCESS"` \| `"FAILED"` \| `"PARTIAL"`) |
| `items_processed` | integer |
| `chunks_sent` | integer |
| `duration_ms` | integer |
| `error_message` | string \| null |
| `timestamp` | ISO-8601 datetime |

Ordered by `timestamp` descending.

---

## 8. Audit Logs — `GET /api/audit-logs`

Resource model: `audit_logs` (read-only, Master-only). Handler: `src/api/audit.rs::list_audit_logs`.

| Method & Path | Auth / RBAC | Response |
| :--- | :--- | :--- |
| `GET /api/audit-logs` | **Master only** — `403` for every other caller, unconditionally. It is the one read surface spanning every domain, so per-caller scoping would be arbitrary. | `200` — raw `audit_logs` rows (`Vec<Model>`). |

### Query Parameters — `AuditLogQuery` (`StrictQuery`, malformed values → `400`)

| Name | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `action` | string | no | none (no filter) | Exact-match on the `action` column (e.g. `KEY_CREATE`, `VAULT_DELETE`, `GROUP_TRIGGER`, `PERMISSION_GRANT` — see §9 for the full action taxonomy) |
| `limit` | integer | no | `100` | Clamped to a maximum of `1000` |
| `offset` | integer | no | `0` | |

### Response row shape (`audit_logs.Model`)

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | UUID | |
| `api_key_id` | UUID \| null | `NULL` once the acting key is deleted (`ON DELETE SET NULL`) |
| `api_key_name` | string | **`NOT NULL`** — denormalized snapshot, survives the key's own deletion (see `m20260818_010217_audit_attribution_not_null`) |
| `api_key_prefix` | string | **`NOT NULL`**, same rationale |
| `client_ip` | string | **`NOT NULL`**, same rationale |
| `action` | string | See §9 |
| `target_resource` | string \| null | Human-readable name of the affected resource |
| `details` | string \| null | Free-text additional context |
| `timestamp` | ISO-8601 datetime | |

Ordered by `timestamp` descending.

### 9. Audit action taxonomy

Every mutating route above writes exactly one `audit_logs` row with one of these `action` values:
`KEY_CREATE`, `KEY_UPDATE`, `KEY_DELETE`, `KEY_ROTATE`, `KEY_ROTATE_SECRET`, `PERMISSION_GRANT`,
`PERMISSION_REVOKE`, `VAULT_CREATE`, `VAULT_UPDATE`, `VAULT_DELETE`, `GROUP_CREATE`,
`GROUP_UPDATE`, `GROUP_DELETE`, `GROUP_TRIGGER`, `FEED_CREATE`, `FEED_UPDATE`, `FEED_DELETE`,
`SYNC_TASK_CREATE`, `SYNC_TASK_UPDATE`, `SYNC_TASK_DELETE`, `SYNC_TASK_TRIGGER`. `GET`/list routes
and the two public probes never write an audit entry.

---

## 10. Endpoint Index (quick reference)

| Method | Path | Auth | Handler |
| :--- | :--- | :--- | :--- |
| GET | `/health` | none | `health_check` |
| GET | `/healthz` | none | `health_check` |
| GET | `/ready` | none | `readiness_check` |
| GET | `/readyz` | none | `readiness_check` |
| GET | `/api/auth/me` | any key | `get_me` |
| GET | `/api/keys` | any key (scoped) | `list_api_keys` |
| POST | `/api/keys` | `can_manage_keys`/Master + R4 | `create_api_key` |
| GET | `/api/keys/{id}` | scoped | `get_api_key` |
| PATCH | `/api/keys/{id}` | `can_manage_keys` + admin + §5 | `update_api_key` |
| DELETE | `/api/keys/{id}` | `can_manage_keys` + admin + §6 | `delete_api_key` |
| POST | `/api/keys/{id}/rotate` | `can_manage_keys` + admin + §5 | `rotate_api_key` |
| POST | `/api/keys/{id}/rotate-secret` | `can_manage_keys` + admin + §5 | `rotate_signing_secret` |
| GET | `/api/keys/{id}/permissions` | scoped | `list_key_permissions` |
| PUT | `/api/keys/{id}/permissions` | `can_manage_keys` + R1/R2/R7 | `grant_key_permission` |
| DELETE | `/api/keys/{id}/permissions/{permission_id}` | `can_manage_keys` + R2/R6 | `revoke_key_permission` |
| GET | `/api/vaults` | scoped | `list_vault_endpoints` |
| POST | `/api/vaults` | `can_manage_vaults`/Master | `create_vault_endpoint` |
| GET | `/api/vaults/{id}` | scoped | `get_vault_endpoint` |
| PATCH | `/api/vaults/{id}` | R2 | `update_vault_endpoint` |
| DELETE | `/api/vaults/{id}` | §3 | `delete_vault_endpoint` |
| GET | `/api/destination-groups` | scoped | `list_destination_groups` |
| POST | `/api/destination-groups` | `can_manage_sources`/Master | `create_destination_group` |
| POST | `/api/sources/test-fetch` | `can_manage_sources`/Master | `test_fetch_external_source` |
| GET | `/api/destination-groups/{id}` | scoped | `get_destination_group` |
| PATCH | `/api/destination-groups/{id}` | R2 | `update_destination_group` |
| DELETE | `/api/destination-groups/{id}` | §3 | `delete_destination_group` |
| POST | `/api/destination-groups/{id}/trigger` | `can_sync`/Master | `trigger_destination_group` |
| POST | `/api/destination-groups/{group_id}/feeds` | R2 on owning group | `create_feed` |
| PATCH | `/api/destination-groups/{group_id}/feeds/{feed_id}` | R2 on owning group | `update_feed` |
| DELETE | `/api/destination-groups/{group_id}/feeds/{feed_id}` | R2 on owning group | `delete_feed` |
| GET | `/api/sync-tasks` | scoped | `list_vault_sync_tasks` |
| POST | `/api/sync-tasks` | `can_manage_vaults`/Master | `create_vault_sync_task` |
| GET | `/api/sync-tasks/{id}` | scoped | `get_vault_sync_task` |
| PATCH | `/api/sync-tasks/{id}` | R2 | `update_vault_sync_task` |
| DELETE | `/api/sync-tasks/{id}` | §3 | `delete_vault_sync_task` |
| POST | `/api/sync-tasks/{id}/trigger` | `can_sync`/Master | `trigger_vault_sync_task` |
| GET | `/api/sync-logs` | scoped (`can_view_logs`) | `list_sync_logs` |
| GET | `/api/audit-logs` | Master only | `list_audit_logs` |

**34 route registrations, 32 distinct handler functions** (`health_check`/`readiness_check` each
answer two path aliases). This table and every section above it were produced by reading
`src/lib.rs`'s route table and every handler in `src/api/*.rs` directly — see `AGENT_NOTES.MD` for
the audit methodology and date.
