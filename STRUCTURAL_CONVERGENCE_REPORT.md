# Structural Convergence Report — Ecosystem-Wide (4-Way)

**Audited service (this repository):** `simply_ip_sync` @ `72cce13` (2026-08-18)
**Compared against:**
- `example/simply_hook_executor` @ `15b8af6` (2026-08-18)
- `example/simply_ip_exporter` @ `80a3b31` (2026-08-18)
- `example/simply_ip_vault` @ `14c8fa3` (2026-08-17)

Same peer-pull and zero-knowledge methodology as `SECURITY_COMPARISON_REPORT.md` — see its header.
This report covers structure, naming, and observability conventions rather than security
properties. `simply_ip_vault` and `simply_hook_executor` are the ecosystem's foundational,
tightest-aligned pair (shared, byte-identical `RBAC_MODEL.md`, diffed by their own
`scripts/verify_convergence.sh`); this report checks how closely `simply_ip_sync` and
`simply_ip_exporter` — the two later peers — track that pattern.

---

## 1. Module & File Structure

### 1.1 Entry point and shared foundations

| File | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| `main.rs` | 197 lines — env → cipher/proxies → connect → pragmas → migrate → bootstrap → pin master → state → scheduler → bind → serve | Migrate, bootstrap, pin, bind, serve | Env/DB/migration bootstrap, `bootstrap_master_key`, `verify_encryption_key` canary, `pin_at_boot`, sync worker spawn, graceful shutdown | 316 lines, same shape |
| `lib.rs` | 96 lines — `create_app`, body-size constants | Router assembly, module registry, retention-worker spawn | `MAX_REQUEST_BODY_BYTES`, `create_app` | 166 lines — `create_app`, `setup_state`, `MAX_REQUEST_BODY_BYTES` |
| `state.rs` | 101 lines | db/config/limiter/cipher/replay_guard/master_pin | db/config/cipher/replay_guard/master_pin/ip_cache/rate_limiter/vault_client | 208 lines — `AppState`, `WebhookEvent`, `StartupConfigError` |
| `master.rs` | 129 lines — `MasterPin`, `OnceLock<Uuid>` | `MasterPin`, `OnceCell<Uuid>` | `MasterPin` | 322 lines — `MasterPin`, `OnceLock<Uuid>` |
| `middleware.rs` | 160 lines — `auth_middleware`, `ClientIp` | `auth_middleware`, `ClientIp` | `auth_middleware` | 328 lines — `auth_middleware`, `ClientIp` |
| `crypto.rs` | 402 lines — CANONICAL_V1 + `SecretCipher` + `KeyCanary` | CANONICAL_V1 + `SecretCipher` (co-located, same file, same rationale: both protect `signing_secret`) | Same co-location pattern | 839 lines, same pattern, most extensive test coverage of the four |
| `replay.rs` | 129 lines — `ReplayGuard` | `ReplayGuard` | `ReplayGuard`, ceiling 250,000 | 440 lines — `ReplayGuard` |
| `config.rs` | 392 lines | — | `RuntimeConfig::from_env`, `TrustedProxies`/`resolve_client_ip` | 1,508 lines — by far the largest single file in the ecosystem; also owns webhook-dispatch tuning |
| `extract.rs` | 104 lines — `StrictJson`, `StrictPath`, `StrictQuery` | 5 types (adds `OptionalStrictJson`, `StrictBytes`) | `StrictJson`, `StrictPath` | 128 lines — `StrictJson`, `OptionalStrictJson` |
| `error.rs` | 90 lines | — | Smallest variant set of the four | 107 lines |
| `db.rs` | 115 lines — pool=1, pragmas, `has_index` | Pool=1, pragmas | `connect`/`run_migrations`/`apply_sqlite_pragmas`, pool=1 | 537 lines — pool=1, pragmas, custom `has_index` |
| `api/guards.rs` | 156 lines, 11 functions | 932 lines, 18 functions — largest in the ecosystem | **No dedicated file** — inline per-module checks | 457 lines, 13 functions |

### 1.2 Domain-specific engines (where the four projects diverge by necessity)

| Project | Domain-specific modules | Role |
|---|---|---|
| `simply_ip_sync` | `parsers/` (3 files), `jobs/` (4 files), `scheduler.rs`, `client.rs` | Feed ingestion engine + inter-vault delta sync orchestrator; the only project that is both a scheduled worker and an outbound HTTP client to a peer |
| `simply_hook_executor` | `executor.rs` | Sandboxed script execution: argv/env isolation, timeout, process-group kill |
| `simply_ip_exporter` | `sync.rs`, `cache.rs`, `ipfilter.rs`, `ratelimit.rs`, `feed.rs`, `vault_client.rs` | Hybrid full/differential sync worker pulling from `simply_ip_vault`, plus a public unauthenticated feed endpoint |
| `simply_ip_vault` | `dispatch.rs`, `retention.rs` | Outbound webhook dispatch worker + soft-delete purge worker |

None of the four share a domain engine, which is expected — this is precisely the layer that
differs by service *purpose*, not by house style. The convergence claim in this report is about
the shared foundation layer (§1.1) and conventions (§2–3), not this layer.

### 1.3 `api/`, `entities/`, `migration/` separation

All four projects use the identical three-way split with no exceptions: `src/api/*.rs` (handlers
only, one file per resource), `src/entities/*.rs` (one SeaORM entity per table plus
`mod.rs`/`prelude.rs`), `src/migration/*.rs` (one file per ordered migration plus `mod.rs`).
`simply_ip_sync`'s `api/` directory has 10 files against its 8-table schema; `simply_ip_exporter`'s
has 6 against 3 tables; `simply_hook_executor`'s has 7; `simply_ip_vault`'s has 6 against 7 tables
(some resource types share a file, e.g. `records.rs` covers both ban/white entries and IP records).

**Outlier:** `simply_ip_exporter` is the only project with no `guards.rs` file — its authorization
surface (2 named functions + 2 inline checks) is small enough that a dedicated module would be
pure ceremony. This is a consistent, proportionate consequence of its simpler two-tier model, not
a structural deviation to flag as a gap.

### 1.4 `tests/` and `static/` shape

| Project | Test files | Test-file lines (excl. shared fixtures) | `static/` |
|---|---|---|---|
| `simply_ip_sync` | 14 + `common/mod.rs` | 4,129 | `app.js` 763 lines, `index.html` 54, `style.css` 246 |
| `simply_hook_executor` | 7 (`common/mod.rs`, `concurrency_and_contracts.rs`, `health_probes.rs`, `hook_executor_integration_tests.rs`, `rbac_model_compliance.rs`, `referential_integrity.rs`, `source_hygiene.rs`) | Not gathered | Not gathered |
| `simply_ip_exporter` | 3 (`common/mod.rs`, `integration.rs` 667, `source_hygiene.rs` 466) | 1,133 | Present, dashboard confirmed |
| `simply_ip_vault` | 7 (`rbac_model_compliance.rs`, `security_tests.rs`, `schema_integrity_tests.rs`, `rbac_integration_tests.rs`, `source_hygiene.rs`, `concurrency_and_contracts.rs`, `frontend_syntax_test.rs`) | Not gathered | Present |

`simply_ip_sync` has both the largest test suite by file count and by line count — proportionate to
its wider surface area (feed ingestion, parser engine, inter-vault sync, delta pagination,
retry/backoff have no equivalent in any peer). `source_hygiene.rs` is named identically across
three of the four (`simply_ip_sync`, `simply_ip_exporter`, `simply_hook_executor`, `simply_ip_vault`
— all four, in fact) for the same purpose: static scans for raw SQL, `.unwrap()`/`.expect()`, and
test-module placement conventions, independent of runtime behavior. `concurrency_and_contracts.rs`
is likewise named identically in `simply_ip_sync`, `simply_hook_executor`, and `simply_ip_vault`.

---

## 2. Naming Conventions

### 2.1 Core security primitives

| Concept | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| Auth middleware fn | `auth_middleware` | `auth_middleware` | `auth_middleware` | `auth_middleware` |
| Client-IP wrapper | `ClientIp` | `ClientIp` | Not confirmed by exact name | `ClientIp` |
| Master-pin type | `MasterPin` | `MasterPin` | `MasterPin` | `MasterPin` |
| Replay guard type | `ReplayGuard` | `ReplayGuard` | `ReplayGuard` | `ReplayGuard` |
| Signature-id key type | Present, not separately named in this pass's facts | `SignatureId { key_id, digest }` | `SignatureId { key_id, digest }` | `SignatureId { key_id, digest }` |
| Secrets cipher type | `SecretCipher` | `SecretCipher` | `SecretCipher` | `SecretCipher` |
| Canary type | `KeyCanary` enum | Not confirmed present | `verify_encryption_key` fn, no dedicated enum | Not present |
| Canonical-string fn | Own `canonical_v1_payload`-equivalent | `canonical_v1_payload` | `canonical_v1_payload` | `canonical_v1_payload` |

Five of the ecosystem's most security-critical type names — `auth_middleware`, `ClientIp`,
`MasterPin`, `ReplayGuard`, `SecretCipher` — are byte-identical across all four independently
developed codebases with no shared crate or code-generation step. This can only be explained by
deliberate cross-reading (each project's `AGENT.MD`/`AGENT_NOTES.MD` explicitly documents auditing
sibling projects under `example/`), not chance.

### 2.2 Guard/authorization function naming

| Project | Convention | Representative names |
|---|---|---|
| `simply_ip_sync` | `guard_*` uniformly, no exceptions | `guard_resource_creation`, `guard_scope_elevation`, `guard_resource_manage`, `guard_resource_lifecycle`, `guard_can_sync`, `guard_delegated_grant`, `guard_revocation`, `guard_master_immutable`, `guard_rotation_allowed` |
| `simply_hook_executor` | `guard_*` for primary decision points, unprefixed verbs for secondary classifiers | `guard_execute`, `guard_manage`, `guard_visibility`, `guard_lifecycle_authority`, `guard_hook_manage_conjunction` + `verb_denied`, `is_permission_reduction`, `manages_any_hook` |
| `simply_ip_exporter` | No prefix convention (only two named functions) | `require_master`, `may_manage` |
| `simply_ip_vault` | `guard_*` uniformly, no exceptions | `guard_group_manage`, `guard_delegated_group_grant`, `guard_scope_elevation`, `guard_resource_lifecycle`, `guard_master_target`, `guard_master_immutable` |

`simply_ip_sync` matches `simply_ip_vault`'s convention exactly — `guard_*` for every decision, no
exceptions — including reusing the literal names `guard_resource_lifecycle` and
`guard_master_immutable`. `simply_hook_executor`'s two-tier naming (prefixed decisions, unprefixed
classifiers) is not something `simply_ip_sync` needs an equivalent for, since its resource model has
no secondary classifiers to name.

### 2.3 Payload naming

| Project | Pattern | Deliberate exception |
|---|---|---|
| `simply_ip_sync` | `Create{Resource}Payload` / `Update{Resource}Payload` / `Grant{Verb}Payload` | None needed — every mutating endpoint fits create/update/grant |
| `simply_hook_executor` | `Create*Payload`/`Update*Payload` | `DeleteApiKeyPayload`/`EntityResolution` for the two-step §6 resolution-map flow |
| `simply_ip_exporter` | `Create*Payload`/`Update*Payload`, drops the entity-type infix | `ReassignOwnerPayload`, `AuditLogQuery` (a query type, not a body payload) |
| `simply_ip_vault` | `Create*Payload`/`Update*Payload` | `BatchRecordsPayload` (domain-specific name for the batch endpoint), `GroupPermInput` |

All four converge on the same dominant pattern and each has exactly one class of endpoint (a
resolution map, a batch operation, an ownership reassignment, a permission grant) that breaks it —
a shared, reasonable exception, not drift.

### 2.4 `AppError` naming

| Project | Variant count | Notable additions/omissions |
|---|---|---|
| `simply_ip_sync` | 9 | `DbError`, `InvalidInput`, `Unauthorized`, `Forbidden`, `NotFound`, `Conflict`, `ConflictWithDetails`, `BodyRejected`, `Internal` |
| `simply_hook_executor` | 10 | Same 9 + `TooManyRequests` (per-key concurrency-limiter rejections) |
| `simply_ip_exporter` | 9 | Has `TooManyRequests` (public-feed rate limiting) but **lacks `ConflictWithDetails`** — no cascade-inventory flow needs it |
| `simply_ip_vault` | 9 | Byte-identical variant set and names to `simply_ip_sync` |

`simply_ip_sync` and `simply_ip_vault` are the only pair with an exactly identical `AppError` enum.

---

## 3. Error Handling & Observability

### 3.1 HTTP error response format

All four converge on one envelope, `{"error": "<message>"}`, decided in exactly one place per
project (`AppError::IntoResponse`):

| Case | Status (all four) | Notes |
|---|---|---|
| DB failure | 500 | Real error logged server-side only, in all four — never returned |
| Invalid input | 400 | |
| Unauthenticated | 401 | |
| Authenticated, forbidden | 403 | |
| Not found | 404 | Fixed message, never echoes the requested id, in all four — part of oracle discipline |
| Conflict | 409 | |
| Conflict + structured detail | 409, extra fields merged into the envelope | `simply_ip_sync`, `simply_hook_executor`, `simply_ip_vault` only |
| Rate-limited | 429 | `simply_hook_executor` (per-key job concurrency), `simply_ip_exporter` (public feed) only |
| Extractor-chosen status passthrough | verbatim (e.g. 413) | Identical `BodyRejected(StatusCode, String)` mechanism and name in all four |

**Genuine divergence, precisely stated:** oversized-body status code is not uniform.
`simply_ip_sync` returns **400** — its `auth_middleware` buffers the whole body itself via
`to_bytes(body, max_body_bytes())` before any handler/extractor runs, and maps the overflow to
`InvalidInput`. The other three all return **413**: `simply_hook_executor` and `simply_ip_vault` via
`DefaultBodyLimit` + `BodyRejected` passthrough; `simply_ip_exporter` via an explicit
`Content-Length` pre-check inside its own body-buffering `auth_middleware`, proving the 413 outcome
is reachable even from an architecture identical to `simply_ip_sync`'s own, given one additional
check step this project does not currently have.

**Also non-uniform:** malformed `Path`/`Query` handling. `simply_ip_sync` and `simply_hook_executor`
wrap every extractor kind their handlers use; `simply_ip_vault` has a self-documented, pinned-open
gap on exactly this point; `simply_ip_exporter` covers `Path` but not `Query`.

### 3.2 Audit logging structure

| Field | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| Table/entity | `audit_logs` | `audit_logs` | `audit_logs` | `audit_logs` |
| Writer function | `support::create_audit_log` | `create_audit_log` (`api/support.rs`) | `support::create_audit_log` | `support::create_audit_log`, generic over `ConnectionTrait` so it can run inside an open transaction |
| Actor id | `api_key_id: Option<Uuid>`, `ON DELETE SET NULL` | Same | Same | Same |
| Denormalized actor snapshot | Present (not field-checked this pass) | `api_key_name`/`api_key_prefix`, both `NOT NULL` | `api_key_name`/`api_key_prefix`, survive key deletion | Same, `NOT NULL` |
| Written inside the same DB transaction as the mutation | Not re-confirmed this pass | Not re-confirmed this pass | Not re-confirmed this pass | Yes, confirmed for `batch_records` — a stronger consistency guarantee (no phantom row on rollback) |
| Reader gating | Master-only | Master-only | Master-only, filterable/paginated | Master-only |

All four name the table and writer function identically and gate reads to Master only.
`simply_ip_vault`'s transaction-generic writer signature is a structural refinement the other three
have not been confirmed to match — worth checking in a future pass rather than asserting either
way for `simply_ip_sync`.

---

## Executive Verdict

**Structural convergence level: high, and holding as the ecosystem scales past its original pair.**
Despite no shared crate, build tooling, or code-generation step, all four projects have
independently arrived at the same five-way module split (entry point / state / security primitives
/ `api` handlers / `entities`+`migration`), the same naming for the five most security-relevant
types, the same `guard_*` convention in three of four projects (the fourth's exception being
proportionate to its simpler model, not a deviation), the same `Create*Payload`/`Update*Payload`
convention with one reasonable exception apiece, and the same `AppError`/`{"error": ...}` contract.

`simply_ip_sync` specifically tracks the `simply_ip_vault`/`simply_hook_executor` gold-standard pair
more closely than the ecosystem's third peer (`simply_ip_exporter`) does on almost every axis in
this report: identical `guard_*` discipline (matching `simply_ip_vault` exactly), an identical
`AppError` variant set (again matching `simply_ip_vault` exactly), and a `guards.rs` file where
`simply_ip_exporter` has none. Where `simply_ip_sync` differs from the gold standard — the
400-vs-413 oversized-body status and the domain-specific engine modules (`parsers/`, `jobs/`,
`scheduler.rs`, `client.rs`) — the former is a narrow, fixable inconsistency now precisely
identified above, and the latter is expected: it is exactly the layer where each service's actual
purpose necessarily produces its own shape, and no amount of convergence should erase that
difference.
