# Structural Convergence Report — Ecosystem-Wide (4-Way)

**Audited service (this repository):** `simply_ip_sync` @ `024ffc5` (2026-08-18)
**Compared against:**
- `example/simply_hook_executor` @ `15b8af6` (2026-08-18)
- `example/simply_ip_exporter` @ `80a3b31` (2026-08-18)
- `example/simply_ip_vault` @ `14c8fa3` (2026-08-17)

**Methodology:** Same zero-knowledge/clean-room pass as `SECURITY_COMPARISON_REPORT.md` — see that
file's header for the full statement. This report covers structure, naming, and observability
conventions rather than security properties.

---

## 1. Module & File Structure

### 1.1 Top-level `src/` shape

| Concern | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| Entry point | `main.rs` (197 lines) — env → cipher/proxies → connect → pragmas → migrate → bootstrap → pin master → state → scheduler → bind → serve | `main.rs` — migrate, bootstrap, pin, bind, serve | `main.rs` — env/DB/migration bootstrap, `bootstrap_master_key`, `verify_encryption_key` canary, `pin_at_boot`, sync worker spawn, graceful shutdown | `main.rs` (316 lines) — same shape, plus bootstrap/pin/bind/serve |
| Router assembly | `lib.rs` (96 lines) — `create_app`, `MAX_...` constants | `lib.rs` — router assembly, module registry, retention worker spawn | `lib.rs` — `MAX_REQUEST_BODY_BYTES`, `create_app` | `lib.rs` (166 lines) — `create_app`, `setup_state`, `MAX_REQUEST_BODY_BYTES` |
| App-wide state | `state.rs` (101 lines) | `state.rs` — db/config/limiter/cipher/replay_guard/master_pin | `state.rs` — db/config/cipher/replay_guard/master_pin/ip_cache/rate_limiter/vault_client | `state.rs` (208 lines) — `AppState`, `WebhookEvent`, `StartupConfigError` |
| Master-identity pin | `master.rs` (129 lines) — `MasterPin`, `OnceLock<Uuid>` | `master.rs` — `MasterPin`, `tokio::sync::OnceCell<Uuid>` | `master.rs` — `MasterPin`, `OnceLock`/`OnceCell` pattern | `master.rs` (322 lines) — `MasterPin`, `OnceLock<Uuid>` |
| Auth middleware | `middleware.rs` (160 lines) — `auth_middleware`, `ClientIp` | `middleware.rs` — `auth_middleware`, `ClientIp` | `middleware.rs` — `auth_middleware` | `middleware.rs` (328 lines) — `auth_middleware`, `ClientIp` |
| Crypto | `crypto.rs` (402 lines) — CANONICAL_V1 + `SecretCipher` + `KeyCanary` | `crypto.rs` — CANONICAL_V1 + `SecretCipher` (236–354) | `crypto.rs` — same two primitives in one file, same rationale (both protect `signing_secret`) | `crypto.rs` (839 lines) — same, plus more extensive test coverage |
| Anti-replay | `replay.rs` (129 lines) — `ReplayGuard` | `replay.rs` — `ReplayGuard` | `replay.rs` — `ReplayGuard`, `MAX_TRACKED_SIGNATURES=250_000` | `replay.rs` (440 lines) — `ReplayGuard` |
| Env/proxy config | `config.rs` (392 lines) | `config.rs` | `config.rs` — `RuntimeConfig::from_env`, `TrustedProxies`/`resolve_client_ip` | `config.rs` (1508 lines — by far the largest single file in any of the four projects; also owns webhook-dispatch tuning knobs) |
| Extractors | `extract.rs` (104 lines) — `StrictJson`, `StrictPath`, `StrictQuery` | `extract.rs` — 5 types (adds `OptionalStrictJson`, `StrictBytes`) | `extract.rs` — `StrictJson`, `StrictPath` | `extract.rs` (128 lines) — `StrictJson`, `OptionalStrictJson` |
| Errors | `error.rs` (90 lines) | `error.rs` (17–84) | `error.rs` (11–54, smallest variant set) | `error.rs` (107 lines) |
| DB pool/pragmas | `db.rs` (115 lines) — pool=1, pragmas, `has_index` | `db.rs` — pool=1, pragmas | `db.rs` — `connect`/`run_migrations`/`apply_sqlite_pragmas`, pool=1 | `db.rs` (537 lines) — pool=1, pragmas, `has_index` (fixed portability issue) |
| Guard/authorization layer | `api/guards.rs` (156 lines, 11 fns) | `api/guards.rs` (932 lines, 18 fns — largest of the four) | **No dedicated file** — inline per-module (`require_master` in `keys.rs`, `may_manage` in `endpoints.rs`) | `api/guards.rs` (457 lines, 13 fns) |
| Outbound HTTP | `client.rs` (455 lines) — signed client to `vault_endpoints` | Not applicable (no outbound-to-peer client role) | `vault_client.rs` — outbound CANONICAL_V1-signed client to `simply_ip_vault` | Not applicable (vault is the server side of this relationship) |
| Domain-specific engine | `parsers/` (3 files), `jobs/` (4 files), `scheduler.rs` — feed ingestion + inter-vault sync | `executor.rs` — script execution, `ConcurrencyLimiter` | `sync.rs`, `cache.rs`, `ipfilter.rs`, `ratelimit.rs`, `feed.rs` — hybrid sync worker + public feed endpoint | `dispatch.rs`, `retention.rs` — outbound webhook dispatch + soft-delete purge worker |

### 1.2 `api/`, `entities/`, `migration/` separation

All four projects use the identical three-way split: `src/api/*.rs` (one file per resource,
handlers only), `src/entities/*.rs` (one SeaORM entity per table, plus `mod.rs`/`prelude.rs`), and
`src/migration/*.rs` (one file per ordered migration, plus `mod.rs`). No project deviates from this
shape. `simply_ip_sync`'s `api/` directory has 8 files (`mod`, `audit`, `guards`, `health`, `keys`,
`sources`, `support`, `sync_logs`, `sync_tasks`, `vaults` — 10 total including `mod.rs`/`guards.rs`)
against 8 tables it manages; `simply_ip_exporter`'s `api/` has 6 files against its smaller 3-table
schema; `simply_hook_executor`'s has 7 against its hook/execution model; `simply_ip_vault`'s has 6
against its 7-table schema (some resource types share a file, e.g. `records.rs` covers both ban/
white entries and IP records).

**Notable outlier:** `simply_ip_exporter` is the only one of the four with no `guards.rs` file at
all — its authorization logic (`require_master`, `may_manage`, and two inline checks) is small
enough (2 named functions + 2 inline `if` blocks) that a dedicated module was apparently judged
unnecessary. This is consistent with, not a deviation from, its independently simpler two-tier
RBAC model.

### 1.3 `tests/` and `static/` directory shape

| Project | Test file count | Total test-file lines | `static/` files |
|---|---|---|---|
| `simply_ip_sync` | 14 (+`common/mod.rs`) | 4,129 (excl. `common`) | `app.js` (763 lines), `index.html` (54), `style.css` (246) |
| `simply_hook_executor` | 7 (`common/mod.rs`, `concurrency_and_contracts.rs`, `health_probes.rs`, `hook_executor_integration_tests.rs`, `rbac_model_compliance.rs`, `referential_integrity.rs`, `source_hygiene.rs`) | Not gathered | Not gathered |
| `simply_ip_exporter` | 3 (`common/mod.rs`, `integration.rs` 667 lines, `source_hygiene.rs` 466 lines) | 1,133 (excl. `common`) | Present (dashboard confirmed, sizes not gathered) |
| `simply_ip_vault` | 7 (`rbac_model_compliance.rs` 32 tests, `security_tests.rs` 82 tests, `schema_integrity_tests.rs` 29 tests, `rbac_integration_tests.rs` 109 tests, `source_hygiene.rs` 9 tests, `concurrency_and_contracts.rs` 14 tests, `frontend_syntax_test.rs` 5 tests) | Not gathered (test-*count* is, at 280 total across files) | Present |

`simply_ip_sync` has both the largest test suite by file count and by line count of the four
projects, reflecting its wider surface area (external feed ingestion, parser engine, inter-vault
sync, delta pagination, retry/backoff — none of which the other three projects have an equivalent
of). `simply_ip_vault` and `simply_hook_executor` both name a `source_hygiene.rs` file with the
identical purpose (static scans: no raw SQL/`.unwrap()` outside migrations, test-module-last
convention) — `simply_ip_sync` and `simply_ip_exporter` converge on the same filename and purpose.
`simply_ip_vault`'s `frontend_syntax_test.rs` (parses `static/app.js` with a real ECMAScript
parser) is the one test-file concept not mirrored by name in any of the other three, though
`simply_ip_exporter`'s `source_hygiene.rs` folds an equivalent `app_js_has_no_syntax_errors` check
into its general hygiene file rather than giving it a dedicated file.

---

## 2. Naming Conventions

### 2.1 Core security primitives

| Concept | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| Auth middleware fn | `auth_middleware` | `auth_middleware` | `auth_middleware` | `auth_middleware` |
| Client-IP wrapper | `ClientIp` | `ClientIp` | Not confirmed by name | `ClientIp` |
| Master-pin type | `MasterPin` | `MasterPin` | `MasterPin` | `MasterPin` |
| Replay guard type | `ReplayGuard` | `ReplayGuard` | `ReplayGuard` | `ReplayGuard` |
| Signature-id key type | Not separately named in facts gathered | `SignatureId { key_id, digest }` | `SignatureId { key_id, digest }` | `SignatureId { key_id, digest }` |
| Secrets cipher type | `SecretCipher` | `SecretCipher` | `SecretCipher` | `SecretCipher` |
| Canary type | `KeyCanary` enum (`Verified`/`NoSealedSecrets`) | Not confirmed present | `verify_encryption_key` fn, no dedicated enum | Not present |
| Canonical-string fn | `canonical_v1_payload`-equivalent (per own `crypto.rs`) | `canonical_v1_payload` | `canonical_v1_payload` | `canonical_v1_payload` |

All four projects use byte-identical names for the five most security-critical types
(`auth_middleware`, `ClientIp`, `MasterPin`, `ReplayGuard`, `SecretCipher`) despite having no
shared crate or code-generation step between them — this is convention transmission by
documentation and cross-reading (`AGENT.MD`/`AGENT_NOTES.MD` explicitly describe auditing sibling
projects), not accidental convergence.

### 2.2 Guard/authorization function naming

| Project | Prefix convention | Representative names |
|---|---|---|
| `simply_ip_sync` | `guard_*` uniformly | `guard_resource_creation`, `guard_scope_elevation`, `guard_resource_manage`, `guard_resource_lifecycle`, `guard_can_sync`, `guard_can_view_logs`, `guard_delegated_grant`, `guard_revocation`, `guard_master_immutable`, `guard_rotation_allowed`, `guard_manage_keys` |
| `simply_hook_executor` | `guard_*` for the R1–R7/§5 decision points; unprefixed verbs for supporting classifiers | `guard_execute`, `guard_manage`, `guard_visibility`, `guard_lifecycle_authority`, `guard_hook_manage_conjunction`, `guard_delegated_hook_grant` + `verb_denied`, `may_read_execution`, `refuse_master_lifecycle_action`, `is_permission_reduction`, `manages_any_hook` |
| `simply_ip_exporter` | No prefix convention (only 2 named functions) | `require_master`, `may_manage` |
| `simply_ip_vault` | `guard_*` uniformly, matching `simply_ip_sync`'s convention most closely | `guard_group_manage`, `guard_delegated_group_grant`, `guard_scope_elevation`, `guard_resource_lifecycle`, `guard_master_target`, `guard_master_immutable`, `guard_may_administer_any_group` |

`simply_ip_sync` and `simply_ip_vault` share the tightest naming convergence: both use `guard_*`
for every authorization decision with no exceptions, and both reuse the literal function names
`guard_resource_lifecycle` and `guard_master_immutable`. `simply_hook_executor` uses `guard_*` for
its primary decision points but drops the prefix for secondary classifiers/predicates
(`verb_denied`, `is_permission_reduction`) — a convention `simply_ip_sync` does not have an
equivalent second tier for, since its resource model doesn't need the extra classifiers.

### 2.3 Payload naming

| Project | Pattern | Examples |
|---|---|---|
| `simply_ip_sync` | `Create{Resource}Payload` / `Update{Resource}Payload` / `Grant{Verb}Payload` | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `GrantPermissionPayload`, `CreateExternalSourcePayload`, `CreateVaultSyncTaskPayload`, `CreateVaultEndpointPayload` |
| `simply_hook_executor` | Same `Create*Payload`/`Update*Payload` pattern, plus a `Delete*Payload` variant for the two-step §6 resolution-map flow | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `CreateHookPayload`, `UpdateHookPayload`, `UpdateParameterPayload`, `DeleteApiKeyPayload`, `EntityResolution` |
| `simply_ip_exporter` | Same pattern, drops the `Api`/entity-type infix | `CreateKeyPayload`, `UpdateKeyPayload`, `CreateEndpointPayload`, `UpdateEndpointPayload`, `ReassignOwnerPayload` (non-conforming), `AuditLogQuery` (query type, not a body payload) |
| `simply_ip_vault` | Same pattern; batch endpoint breaks it deliberately (domain-specific name, not `Create`/`Update`-prefixed) | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `CreateIpGroupPayload`, `CreateWebhookPayload`/`UpdateWebhookPayload`, `BatchRecordsPayload`, `GroupPermInput` (non-conforming) |

All four converge on `Create*Payload`/`Update*Payload` as the dominant pattern; each project has at
least one deliberately non-conforming exception for an endpoint whose shape doesn't map cleanly to
create/update (a resolution map, a batch operation, an ownership reassignment, a permission grant).

### 2.4 `AppError` naming

| Project | Variant count | Variant names |
|---|---|---|
| `simply_ip_sync` | 9 | `DbError`, `InvalidInput`, `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`, `ConflictWithDetails{message,details}`, `BodyRejected(StatusCode,String)`, `Internal` |
| `simply_hook_executor` | 10 | Same 9 + `TooManyRequests(String)` (429, for `ConcurrencyLimiter` rejections) |
| `simply_ip_exporter` | 9 | `DbError`, `InvalidInput`, `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`, `TooManyRequests`, `BodyRejected`, `Internal` — has `TooManyRequests` but **not** `ConflictWithDetails` |
| `simply_ip_vault` | 9 | Identical variant set and names to `simply_ip_sync` |

`simply_ip_sync` and `simply_ip_vault` have byte-identical `AppError` variant sets and names.
`simply_hook_executor` is the superset (adds `TooManyRequests` for its per-key concurrency
limiter, a feature `simply_ip_sync`/`simply_ip_vault` don't have); `simply_ip_exporter` has
`TooManyRequests` (for its public-feed rate limiter) but lacks `ConflictWithDetails` (it has no
cascade-inventory-refusal flow that needs structured conflict detail, consistent with its simpler
two-tier model having no subtree cascade).

---

## 3. Error Handling & Observability

### 3.1 HTTP error response format and status-code mapping

All four projects converge on the identical envelope shape — `{"error": "<message>"}`, produced by
a single `AppError::IntoResponse` impl that is the sole place status codes are decided:

| Variant meaning | Status (all 4 projects) | `simply_ip_sync` body | Notes |
|---|---|---|---|
| DB failure | 500 | `{"error":"Internal server error"}` | Real error logged server-side only, in all four |
| Invalid input | 400 | `{"error": msg}` | |
| Unauthenticated | 401 | `{"error": msg}` | |
| Authenticated, forbidden | 403 | `{"error": msg}` | |
| Not found | 404 | `{"error":"Resource not found"}` | Fixed message in all four — never echoes the requested id, part of oracle discipline |
| Conflict | 409 | `{"error": msg}` | |
| Conflict + structured detail | 409 | `{"error": message, ...details}` | `simply_ip_sync`, `simply_hook_executor`, `simply_ip_vault` only — `simply_ip_exporter` lacks this variant |
| Extractor-chosen status | passthrough (e.g. 413) | `{"error": msg}` | `BodyRejected(StatusCode, String)` — identical mechanism name and shape in all four |
| Rate-limited | 429 | N/A in `simply_ip_sync` | `simply_hook_executor` (per-key job concurrency), `simply_ip_exporter` (public feed) only |
| Unhandled internal | 500 | `{"error":"An internal server error occurred"}`/`{"error":"Internal server error"}` (wording varies slightly by project) | |

**Divergence worth flagging precisely:** oversized-body status code is **not** uniform.
`simply_ip_sync` returns **400** for an oversized body (its `auth_middleware` buffers the entire
body itself via `to_bytes(body, max_body_bytes())` before any handler or extractor runs, and maps
the overflow to `InvalidInput` rather than preserving a `413`). The other three projects all
achieve **413**: `simply_hook_executor` and `simply_ip_vault` via `DefaultBodyLimit` + `BodyRejected`
passthrough, `simply_ip_exporter` via an explicit `Content-Length` pre-check inside its own
`auth_middleware` plus a remap of `to_bytes`'s overflow path — despite also buffering the body
itself for HMAC verification, exactly as `simply_ip_sync` does. This means the *architectural*
similarity (all four buffer the body pre-handler to compute the signature) does not by itself
predict the *status code* — `simply_ip_exporter` proves an extra explicit size-check step is
sufficient to preserve 413 even in a buffering middleware, while `simply_ip_sync` does not currently
have that extra step.

**Also non-uniform:** malformed `Path`/`Query` segments. `simply_ip_sync` and `simply_hook_executor`
wrap every extractor kind their handlers use and always return the JSON envelope; `simply_ip_vault`
has a documented, deliberately-pinned open gap on exactly this point (its own test suite names it
"PINNED GAP"); `simply_ip_exporter` covers `Path` but has no confirmed `StrictQuery` equivalent.

### 3.2 Audit logging structure

| Field | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| Table/entity name | `audit_logs` | `audit_logs` | `audit_logs` | `audit_logs` |
| Writer function | `support::create_audit_log` (own `api/support.rs`) | `create_audit_log` (`api/support.rs:117-138`) | `support::create_audit_log` (`api/support.rs:51-72`) | `support::create_audit_log` (`api/support.rs:162-185`), generic over `ConnectionTrait` so it can run inside an open transaction |
| Actor id | `api_key_id: Option<Uuid>` (`ON DELETE SET NULL`) | Same | Same | Same |
| Denormalized actor snapshot | Not confirmed field-by-field this pass | `api_key_name`, `api_key_prefix` (both `NOT NULL`) | `api_key_name`/`api_key_prefix` (denormalized, survive key deletion) | `api_key_name` (`NOT NULL` since a later migration), `api_key_prefix` (`NOT NULL`) |
| Client IP captured | Yes | Yes (`String`, `NOT NULL`, via `ClientIp` extension) | Yes | Yes (`NOT NULL`) |
| Action taxonomy | Verb-per-resource strings (not enumerated in facts gathered) | `HOOK_CREATE`/`KEY_ROTATE`-style constants | `KEY_CREATE`/`KEY_UPDATE`/`KEY_DELETE`/`KEY_ROTATE`/`ENDPOINT_*` | `IP_ADD`/`IP_DELETE`/`KEY_CREATE`/`KEY_DELETE`/`batch_records_updated`-style (mixed casing across event types) |
| Target reference | Not confirmed this pass | `target_resource: Option<String>`, human-readable, never a bare UUID | `target_resource` via `describe_resource` (`kind:id (name)`) | `target_address`/`group_names` (domain-specific columns, not a generic `target_resource`) |
| Written inside the same transaction as the mutation | Not confirmed this pass | Not confirmed this pass | Not confirmed this pass | Yes, explicitly — `batch_records`' audit row is written inside the open transaction so a rollback leaves no phantom entry |
| Reader endpoint | `GET /api/audit-logs` | Master-only reader (`api/audit.rs`) | `GET /api/audit-logs`, Master-only, `action` filter + pagination | `list_audit_logs`, Master-only |

All four projects name the table and the writer function identically (`audit_logs` /
`create_audit_log`), place it in an `api/support.rs` module (three of four; `simply_hook_executor`
also uses `api/support.rs`), and gate the read side to Master only. The one structural difference
worth noting is `simply_ip_vault`'s generic-over-`ConnectionTrait` writer signature, which lets it
participate in the same DB transaction as the mutation it's recording — a stronger consistency
guarantee (no phantom audit row on rollback) than a writer that always opens its own connection.
Whether `simply_ip_sync`'s own `create_audit_log` shares this transactional property was not
re-derived in this pass and should be checked in a future session if cross-project audit-log
atomicity becomes a specific concern.

---

## Executive Verdict

**Structural convergence level: high, and increasing.** All four projects, despite having no
shared crate, build tooling, or code-generation step, have independently arrived at:

- The same five-way module split (entry point / state / security primitives / `api` handlers /
  `entities`+`migration`), with byte-identical names for the five most security-relevant types
  (`auth_middleware`, `MasterPin`, `ReplayGuard`, `SecretCipher`, `ClientIp`).
- The same `guard_*` naming convention for authorization decisions in three of four projects
  (`simply_ip_exporter` being the deliberate, documented exception, consistent with its simpler
  model).
- The same `Create*Payload`/`Update*Payload` naming pattern, each with its own documented
  exception for endpoints that don't fit the mold.
- The same `AppError` → `{"error": ...}` envelope mechanism and near-identical variant sets
  (`simply_ip_sync` and `simply_ip_vault` are byte-identical on this axis).
- The same `audit_logs`/`create_audit_log` naming and Master-only read-gating convention.

This level of convergence, given the independent development histories, is best explained by the
`AGENT.MD`/`AGENT_NOTES.MD` convention (explicitly observed in all four projects) of periodically
auditing sibling projects under `example/` and deliberately porting naming and structural patterns
— a documentation-mediated convergence process rather than shared code.

The remaining divergences are narrow and well-understood rather than symptomatic of drift:
`simply_ip_exporter`'s lack of a `guards.rs` file and `Parent` tier are consistent, deliberate
consequences of its independently-scoped, simpler RBAC model, not oversights; the 400-vs-413
oversized-body status code split and the varying `StrictQuery`/`Path`-wrapping completeness are
the only two places where projects with structurally identical intent (wrap every axum extractor,
buffer the body once for signing) arrived at genuinely different observable behavior — both are
narrow, mechanical fixes rather than architectural gaps, and both are precisely identified above
for whichever project addresses them next.
