# FILE_MAP.MD — what lives where in `src/`, and why

An index of every `.rs` file in `src/`, written for someone (or something) arriving cold and
needing to know where a change belongs before making it.

> Companion documents: `AGENT.MD` (architectural and security ruleset), `SCHEMA.MD` (database
> schema), `RBAC_MODEL.md` (normative authorization specification), `API_REFERENCE.md` (exhaustive
> per-endpoint HTTP API catalog — method/path/aliases, RBAC guard, query parameters, request/
> response payload shapes, generated directly from `src/api/*.rs` and `src/lib.rs`'s route table),
> `AGENT_NOTES.MD` (session worklog).

---

## Top level

### `src/main.rs` — process entry point *only*

Startup sequence, in order, and nothing else: env → connect → pragmas → migrate → bootstrap
Master (`bootstrap_master_key`, the only writer of `is_master = true` in the service) → build
state (`setup_state`) → `master_pin.pin_at_boot()` → `scheduler.boot()` → bind → serve → graceful
shutdown. Moving the pin later than it is now would reopen the tampering window it exists to
close (see `master.rs`).

### `src/lib.rs` — router assembly and the crate's public surface

`create_app` (full route table, middleware layering, static fallback) and `setup_state`.
`#![warn(missing_docs)]` at the top of the file. No handler bodies — a route line here should read
as a mapping from path to handler and nothing more. The body-size limit
(`config::max_body_bytes`) is applied both by the router's `DefaultBodyLimit` and by
`middleware::auth_middleware`'s signed-body buffer, from the same function, so the two can never
drift into a band of sizes one accepts and the other refuses.

### `src/db.rs` — connection setup, session pragmas, migrations

`connect` (pool construction, `max_connections=1` for SQLite, the four mandatory pragmas set on
`SqliteConnectOptions`), `apply_sqlite_pragmas`, `run_migrations`, `has_index` (a custom
per-backend catalog query, not `SchemaManager::has_index` — see the module doc comment for why).
The only place outside `migration/` permitted to issue raw SQL, and then only `PRAGMA`/catalog
inspection, never DML.

### `src/state.rs` — shared application state

`AppState`: `db`, `cipher`, `replay`, `master_pin`, `trusted_proxies`, `http` (outbound client),
`scheduler`. Every field is behind an `Arc` (or its own internal `Arc`/`OnceLock`), so `#[derive(Clone)]`
can never silently hand a request its own private copy of a security primitive. `for_tests`
constructs state with a pre-pinned Master and a `Plaintext` cipher for the integration suites.

### `src/master.rs` — the Master identity pin

`MasterPin`: `pin_at_boot`, `resolve`, `authenticate`. Answers exactly one question — "is this key
the Master this process pinned?" — and demotes (never 401s) an impostor `is_master=true` row at
the single point a key enters request extensions. The generated `master_marker` unique index
defends *cardinality* (at most one Master row); this module defends *identity* (which one).
Neither substitutes for the other — see the module doc comment.

### `src/middleware.rs` — inbound authentication

`auth_middleware`: resolves client IP → validates `X-Timestamp` (no DB round-trip) → looks up the
key by `SHA-256(X-API-Key)` → checks a declared `Content-Length` against `max_body_bytes()` and
rejects with `413` before reading a byte if it's over → buffers the body (remapping `to_bytes`'s
own overflow fallback to `413` too, for a body without a declared length) and verifies the
`CANONICAL_V1` signature → checks the anti-replay guard (only after verification succeeds) →
checks `bound_ips` (last, so a 401-vs-403 pair can't be used as a key-existence oracle) → calls
`MasterPin::authenticate`. Also
`ClientIp`. No per-resource authorization — that is `api/guards.rs`.

### `src/crypto.rs` — at-rest encryption and request signing

`SecretCipher` (XChaCha20-Poly1305, `v1.plain.`/`v1.xchacha20poly1305.` envelopes, strictly
fail-closed on an unrecognised prefix), `canonical_v1_payload`, `compute_signature`,
`verify_signature` (constant-time via `Mac::verify_slice`, returns the raw digest for the replay
guard), `generate_signing_secret`. `ENCRYPTION_KEY_ENV = "SYNC_ENCRYPTION_KEY"`.
`check_key_canary`/`KeyCanary` (`NoSealedSecrets`/`Verified`): pure, DB-free boot canary — opens one
already-stored sealed secret with the *configured* cipher to prove `SYNC_ENCRYPTION_KEY` is the key
the data at rest was actually sealed under, called from `main.rs::verify_encryption_key` right
after Master bootstrap and before the process binds a listener. Without this, a syntactically valid
but *wrong* key boots cleanly, reports ready, and only fails later — inside outbound syncs, as an
authentication error against the *vault* rather than a local misconfiguration.

### `src/config.rs` — environment parsing and client-address resolution

`resolve_client_ip` (right-to-left `X-Forwarded-For` walk, trusted-peer gated), `normalize_ip`,
`parse_trusted_proxies`, `resolve_bind_addr`, `validate_initial_master_key`, `max_body_bytes`,
`outbound_http_timeout`, `max_decompressed_bytes` (decompression-bomb ceiling, shared by
`jobs::decompress`'s two independent expansion points). `TRUSTED_PROXIES` and `INITIAL_MASTER_KEY`
are security boundaries and fail hard on a malformed value; tuning variables (`MAX_BODY_SIZE_MIB`,
`MAX_DECOMPRESSED_BYTES`, `OUTBOUND_HTTP_TIMEOUT_SECS`) fail soft to a default with a logged
warning. `outbound_max_retries`/`outbound_retry_backoff` (`retry.rs`'s two tunables) are
deliberately **not** `OnceLock`-cached the way the others are — they read `env::var` fresh on every
call, specifically so a test can set one and see it take effect immediately rather than being stuck
with whatever the first caller in the process observed.

### `src/replay.rs` — anti-replay guard

`ReplayGuard`: single-use signature cache keyed on `(key_id, raw digest bytes)`, monotonic
`tokio::time::Instant` expiry (never wall-clock), amortized sweep plus a capacity-triggered sweep.
Never flushed wholesale on saturation — that would let every currently valid signature replay at
once. Backed by a plain `std::sync::Mutex<HashMap<...>>` — never held across an `.await` — whose
check-then-insert happens under a single lock acquisition, which is exactly what makes it safe
under real concurrent contention (see `tests/concurrency_and_contracts.rs`'s `Barrier`-based test).

### `src/retention.rs` — historic-log purge worker

`run_retention_worker` (spawned detached from `main.rs`, not drained on shutdown — a purge sweep is
a bounded, idempotent `DELETE ... WHERE timestamp < threshold`, unlike the in-flight HTTP requests
graceful shutdown actually needs to wait for): purges `sync_logs` and `audit_logs` rows older than
independently-configured retention windows (`SYNC_LOG_RETENTION_DAYS_ENV` default 92,
`AUDIT_LOG_RETENTION_DAYS_ENV` default 365 — a security/compliance trail reasonably wants a longer
horizon than operational job-run noise). `0` disables purging for that table. This project has no
soft-deleted *resource* rows to purge the way `simply_ip_vault`'s equivalent module does — RBAC
§6 uses hard-delete-with-cascade-inventory instead — so retention here is scoped to the two
unbounded history tables rather than a resource's own lifecycle.

### `src/retry.rs` — transient-failure retry policy

`is_transient_status` (`429`/`502`/`503`/`504`, deliberately excluding `500` and `413`) and
`backoff_with_jitter` (exponential off `config::outbound_retry_backoff()`, capped at 30s, up to 50%
jitter). Shared by `client.rs`'s outbound calls to remote vaults and
`jobs::external_ingestion`'s feed fetches — one retry policy, not two independently-tuned ones.

### `src/extract.rs` — strict request extractors

Three extractor wrappers, one per axum extractor any handler uses — handlers use nothing else:
- `StrictJson<T>`: `Json<T>` whose rejection renders as `AppError` (`400`/`413` as appropriate)
  rather than axum's default plain-text body. Combined with `#[serde(deny_unknown_fields)]` on
  payload types, this is how §5's "`is_master` must never be settable" rule is enforced at the type
  level rather than in a handler.
- `StrictPath<T>`: a malformed path segment (e.g. a non-UUID id) renders as `AppError::NotFound`,
  not axum's plain-text `PathRejection` — deliberately `NotFound`, not `InvalidInput`, so a
  syntactically invalid id stays indistinguishable from a well-formed id for a resource that
  doesn't exist (RBAC §4 oracle discipline; see `tests/concurrency_and_contracts.rs`'s
  `a_malformed_id_and_a_nonexistent_id_are_indistinguishable`).
- `StrictQuery<T>`: an unparseable query string renders as `AppError::InvalidInput` rather than
  axum's plain-text `QueryRejection`.

All three exist for the same reason: axum's built-in `Path`/`Query`/`Json` rejections are plain
text, and every other refusal this service emits is `{"error": "..."}` — a caller that parses the
envelope to decide whether to retry would otherwise hit a parse failure instead of a status it can
act on for exactly these three cases.

### `src/client.rs` — outbound signed HTTP client

`post_batch` (`POST {vault}/api/records/batch`), `get_ips_delta` (`GET {vault}/api/ips`, paginated
internally). Both sign with `CANONICAL_V1` using the target `vault_endpoints` row's decrypted
`signing_secret`. `build_http_client` refuses redirects. No SSRF private-IP blocklist —
`vault_endpoints` are admin-configured, `can_manage_vaults`-gated internal services, not
arbitrary user-supplied URLs; see the module doc comment for the full reasoning.

### `src/scheduler.rs` — in-process cron scheduler

`SchedulerHandle` wraps `tokio_cron_scheduler::JobScheduler` plus a `Uuid → Uuid` map from this
service's resource ids to the scheduler's own job ids, so `upsert_source`/`upsert_task`/
`remove_source`/`remove_task` can keep the live job set in sync with CRUD mutations without a
restart. `normalize_cron` upgrades a conventional 5-field cron expression (as used in `SCHEMA.MD`'s
own examples) to the 6-field `sec min hour dom month dow` form the underlying crate requires.

### `src/error.rs` — the error type and its HTTP rendering

`AppError` and `IntoResponse`. Variants: `DbError`, `InvalidInput`, `Unauthorized`, `Forbidden`,
`NotFound`, `Conflict`, `ConflictWithDetails` (carries §6's pre-flight inventory), `BodyRejected`
(carries an extractor's own status so normalizing the response *shape* doesn't also normalize its
*meaning*), `Internal`.

---

## `src/parsers/` — the extensible parsing engine

`mod.rs`: the `FeedParser` trait, `normalize_ip_or_cidr`, `for_type` (parser_type string →
implementation). `regex_line.rs`: `REGEX_LINE` (comment-stripping, IPv4/IPv6/CIDR token
extraction). `json_path.rs`: `JSON_PATH` (dotted `array_path` traversal, per-element `ip_field`
pull; also a `"jsonl": true` mode for newline-delimited JSON feeds — Spamhaus DROP's actual wire
format, one object per line with no enclosing array, verified against the real download). Both
re-validate every extracted token through `normalize_ip_or_cidr` rather than trusting the
extraction pattern alone.

## `src/jobs/` — execution pipelines

`mod.rs`: `chunk_records` (`MAX_BATCH_SIZE = 5_000`), `JobSummary`, `write_sync_log`, and the
concurrency guard — `RunningJobs`, `JobGuard`, `try_start_job`. The guard is a
`HashSet<Uuid>` behind a `std::sync::Mutex` (never held across `.await`), claimed via
`try_start_job` and released by `JobGuard::drop` on every exit path including an early `?` —
refuses a second concurrent execution of the same source/task rather than letting two overlapping
runs push interleaved batches to the same target group. Wired into both manual-trigger HTTP
handlers (`api/sources.rs`, `api/sync_tasks.rs` — a second concurrent trigger gets `409`) and the
scheduler's cron closures (a slow prior tick causes the next one to skip with a logged warning).
`decompress.rs`: `decompress_if_zip`/`is_zip` — transparent ZIP-archive decompression inserted
into `external_ingestion.rs` before any parser runs, so ZIP-distributed feeds (e.g. StopForumSpam)
work with every parser type without the parser layer knowing archives exist; a pure passthrough
for the (overwhelmingly common) non-ZIP case. Both `decompress_if_zip` and the sibling
`read_capped_body` (which streams the HTTP response body itself, before decompression is even
decided) take an explicit `max_decompressed_bytes` ceiling and abort mid-stream the instant the
running total crosses it — the decompression-bomb defense for the two independent points a fetched
body can expand: `Content-Encoding` (handled transparently by `reqwest`, so a naive `bytes()` read
would already have fully buffered an oversized payload before anything could check its size) and a
ZIP archive's own internal members.
`external_ingestion.rs`: fetch → decompress-if-zip → parse → dedupe → chunk → push to every
configured target vault, one `sync_logs` row per execution, `last_run_at` always updated (it means
"last execution", not "last successful execution"). A fetch+parse that completes but yields
**zero** items is deliberately reported as `PARTIAL`, not `SUCCESS` — this pipeline re-fetches a
feed's full content every run (not an incremental diff), so genuinely zero entries is anomalous
and is exactly what an HTML error/captive-portal page served with `200 OK` looks like to
`REGEX_LINE`. `vault_sync.rs`: delta fetch (including tombstones) → chunk → push, `last_sync_at`
only advances when **every** target succeeds — zero *new* delta records is routine here (it is an
incremental diff), so that same zero-items flag does not apply. Both are plain
`(&AppState, Uuid) -> Result<JobSummary, AppError>` functions, callable identically from
`scheduler.rs` and from the manual-trigger HTTP handlers (both of which claim the concurrency
guard above before calling in).

`scheduler.rs` additionally exposes `validate_cron_expression` — called from the `POST`/`PATCH`
handlers in `api/sources.rs` and `api/sync_tasks.rs` *before* any database write, via the same
normalize-then-parse path the scheduler itself uses, so anything it accepts is guaranteed
schedulable and a malformed `cron_schedule` never reaches persistence.

---

## `src/api/` — HTTP handlers, split by domain

Flat re-exports from `mod.rs`: `api::create_api_key` resolves the same regardless of which file it
lives in. `guards.rs` is `pub(crate)`; four credential primitives (`generate_random_key`,
`hash_key`, `key_prefix`) are `pub` because `main.rs`'s Master bootstrap and the integration test
suites mint keys directly against the database.

- **`mod.rs`** — module wiring and the flat re-export surface only.
- **`support.rs`** — shared plumbing three-or-more domains need: `generate_random_key`,
  `hash_key`, `key_prefix`, `find_permission`, `grant_full_permission`, `create_audit_log`, the
  `RESOURCE_*` constants. Decides nothing — no function here inspects *who* is calling.
- **`guards.rs`** — every authorization decision, one function per `RBAC_MODEL.md` rule:
  `guard_resource_creation`, `guard_scope_elevation` (R4), `guard_resource_manage` (R2),
  `guard_resource_lifecycle` (§3), `guard_can_sync`, `guard_can_view_logs`,
  `guard_delegated_grant` (R1/R7), `guard_revocation` (R6), `guard_master_immutable`/
  `guard_rotation_allowed` (§5), `guard_manage_keys`.
- **`health.rs`** — `health_check`/`readiness_check`. Mounted outside `/api` and outside
  `auth_middleware` in `lib.rs`. `readiness_check` deliberately proves the database is live with an
  ordinary typed query (`ApiKey::find().count()`), not a raw `SELECT 1` — this is the one
  unauthenticated route in the service, so it is the one place a raw-SQL exemption would be least
  defensible, and `tests/source_hygiene.rs`'s raw-SQL scanner would flag it if it ever regressed.
- **`keys.rs`** — identity (`get_me`), key CRUD, rotation, cascade deletion with §6 pre-flight
  inventory, permission grant/revoke. The largest module, deliberately not split further — R1–R7
  are all about how keys delegate to other keys.
- **`vaults.rs`** — `vault_endpoints` CRUD. Credentials are never returned in any response.
- **`sources.rs`** — `external_sources` CRUD, target-vault mapping, `trigger_external_source`.
- **`sync_tasks.rs`** — `vault_sync_tasks` CRUD, target-vault mapping, `trigger_vault_sync_task`.
  Re-uses `sources::TargetSpec`, the one type genuinely shared between the two junction-table
  shapes.
- **`sync_logs.rs`** — `list_sync_logs`, scoped per-resource by `can_view_logs` for non-Master
  callers.
- **`audit.rs`** — `list_audit_logs`. Master-only.

---

## `src/entities/` — SeaORM models

One file per table, plus `mod.rs` (declarations) and `prelude.rs` (the flat `Entity` re-export
set). No business logic, no defaults that encode policy.

**The one rule that is not obvious.** `api_key::Model` deliberately omits `master_marker`. The
column exists in the database (see the migration below) and SeaORM builds explicit column lists
from the entity, so leaving the field out of the struct is what guarantees no query ever names it
— every engine rejects a write to a generated column. Do not add it back.

## `src/migration/` — schema migrations

Named `m<YYYYMMDD>_<NNNNNN>_<name>.rs` — an 8-digit authoring date, a 6-digit zero-padded sequence
number (disambiguates same-day migrations; not a literal time-of-day), and a short description.
`src/migration/mod.rs`'s registration order must match filename order — see `AGENT.MD`'s "SeaORM
Migration Standards" section for the full rule and the audit-attribution-`NOT NULL` pattern below.

`m20260101_013240_initial_schema` — all 9 `SCHEMA.MD` tables, including the `target_group_name`
override columns on both junction tables, FKs with the specified `CASCADE`/`SET NULL` behavior,
and the six mandatory indexes. `m20260101_013241_derive_master_marker` — adds the generated
`master_marker` column and its unique index; aborts before any DDL if the database already holds
two or more Master rows. `m20260818_010217_audit_attribution_not_null` — tightens
`audit_logs.api_key_name`/`.api_key_prefix`/`.client_ip` to `NOT NULL` (every `create_audit_log`
call site already supplies all three; the columns were nullable only because the initial schema
declared them so). Backfills any pre-existing `NULL` to the unmistakable sentinel `"(unknown)"`
before constraining, and rebuilds the table on SQLite (no `ALTER COLUMN` there) via a single
`table_definition(attribution_not_null: bool)` shared by both the rebuild and `down`, so the two
paths cannot describe different tables.

## `tests/` — what each suite owns

| File | Owns |
| :--- | :--- |
| `common/mod.rs` | Shared harness: in-memory DB + pinned Master, `insert_key` (mints credentials directly against the database), `sign`/`signed_request` (real `CANONICAL_V1` signing), and `MockVault` — a **stateful** stand-in for a remote `simply_ip_vault` that actually stores records behind `GET /api/ips` + `POST /api/records/batch`, so a test can assert what the target *converged on* (distinct counts, canonical dedup, tombstone flags) rather than only what the engine asked for. Mirrors two real contract details the tests turn on: `since` is an OR across `last_seen_at` and (when `include_deleted`) a tombstone's `deleted_at`, and a soft delete never touches `last_seen_at` |
| `security_tests.rs` | Inbound HMAC verification, replay, `bound_ips`, outbound signature generation against a `wiremock`-mocked vault, and trusted-proxy `X-Forwarded-For` handling (permitted when forwarded through a trusted peer, never a `bound_ips` bypass from an untrusted one) |
| `parser_tests.rs` | `REGEX_LINE`/`JSON_PATH` black-box behavior through the public `parsers` API, local fixtures reproducing StopForumSpam's ZIP and Spamhaus's JSONL feed shapes (both inspected against the real downloads) via `tempfile::tempdir()` for automatic cleanup, and HTML-masquerading-as-a-feed fixtures (block page, captive portal, a large synthetic body) |
| `chunking_tests.rs` | Batch chunking never exceeds `MAX_BATCH_SIZE` at any boundary |
| `api_validation_tests.rs` | Malformed `cron_schedule` on `POST`/`PATCH` for both `/api/sources` and `/api/sync-tasks` is rejected with `400` before any database write |
| `external_ingestion_tests.rs` | Per-target `target_group_name` override; HTML-masquerade-as-200 via both parser types; gzip-compressed response decompression; a slow/hung target aborted by the client's own timeout rather than hanging; the `try_start_job` concurrency guard exercised directly |
| `vault_sync_tests.rs` | Tombstone propagation through a full fetch→push cycle; `last_sync_at` only advances on total success; multi-vault fan-out and partial-failure resilience; per-target `target_group_name` override; a slow/hung target vault aborted on the push path specifically; multi-page delta paging (15,001 records / 4 pages). Plus the high-volume two-vault convergence scenario (`test_inter_vault_sync_high_volume_partial_overlap`): 1,000-record groups with a 500-record partial overlap converging to 1,500 distinct rows against a stateful `MockVault`, then a differential second pass delivering exactly 200 tombstones + 100 additions |
| `live_feed_ingestion_tests.rs` | `#[ignore]`d — real network calls to the four feeds named in `AGENT_NOTES.MD`, both via the parser directly and through the full `jobs::external_ingestion::run` pipeline. Run explicitly with `cargo test -- --ignored` |
| `rbac_model_compliance.rs` | One test per `RBAC_MODEL.md` rule/section, named `r1_`…`r7_`/`s3_`…`s7_` so `scripts/verify_convergence.sh` can mechanically confirm every rule has coverage; `s5_`/`s7_` additionally carry an `ADVERSARIAL(§N)` raw-SQL test proving the guarantee holds against a writer that bypasses the application, not only a cooperative one. Plus `can_sync` manual-trigger allow/403, a 2-way concurrent-delete regression test, and the unauthenticated-request-never-reaches-a-handler check |
| `schema_integrity_tests.rs` | Migrations apply cleanly; `ADVERSARIAL(§5)` — a raw-SQL insert with the marker column absent is rejected by the database itself; FK cascade on a junction table |
| `referential_integrity.rs` | FK enforcement via `db::connect` (not `common::setup`'s bare `Database::connect`, which never enables `PRAGMA foreign_keys`): bidirectional cascade correctness (a doomed and a survivor source sharing one target vault), write-time rejection of a dangling FK, and a test proving `owner_key_id` deliberately carries **no** FK constraint at all |
| `health_probes.rs` | `/health` never touches the database even when it's closed; `/ready` independently depends on both a live database and the boot-time Master pin (including a startup-ordering test — an unpinned `MasterPin` swapped into `AppState` post-setup — that a steady-state-only suite can't produce); the liveness body has exactly the two documented fields; neither probe leaks internal error text |
| `concurrency_and_contracts.rs` | Real multi-task/thread contention the router's single-connection SQLite pool can't otherwise expose: 16 OS threads hammering `ReplayGuard::check_and_record` directly via a `Barrier` (exactly one admitted; distinct signatures never block each other), 16 concurrent `tokio::spawn`ed deletes of the same resource (exactly one `204`), and the `StrictPath`/`StrictQuery` JSON-envelope-totality contract (malformed path/query, and the oracle-discipline pairing between a malformed id and a nonexistent one) |
| `client_resilience_tests.rs` | Outbound retry/backoff on transient vault failures, adaptive batch splitting on `413`, `full_replace`'s chunk-0-only rule surviving a `413` split, and per-page retry on the delta-fetch side |
| `source_hygiene.rs` | `static/app.js` parses as valid ECMAScript (`oxc_parser`, self-tested against a known-broken fixture); every literal `document.getElementById()` reference resolves against `index.html` or an id `app.js` injects itself; the one dynamic id-construction pattern is verified against its actual invariant (every nav button's `data-tab` has a matching panel id) |

`scripts/test_e2e.sh` (repository root, not under `tests/`) is the complementary black-box gate:
it boots the real compiled binary and drives it with `curl` over a real socket, which none of the
above can do. See its own header comment and `AGENT_NOTES.MD` session 2 for what it covers.

`scripts/verify_convergence.sh` (repository root) is a fourth kind of gate: mechanical drift
detection between this project and `example/simply_ip_vault`, not a test of this project's own
behavior in isolation. It pulls the peer, diffs security-critical functions after normalizing away
expected vocabulary differences (crate names, env var names), asserts structural invariants
(ordering, index presence, absence of raw SQL/wall-clock replay expiry/bare-hex signature
fallbacks), and cross-checks `tests/rbac_model_compliance.rs` for full rule and adversarial
coverage. Unlike `simply_ip_vault`/`simply_hook_executor`'s own copy of this script, this one does
not diff `RBAC_MODEL.md` for byte-identity — this project's copy is a deliberate restatement, not a
shared file — so Pillar 0 instead checks structural section coverage plus rule-test coverage. See
the script's own header comment for the full rationale and its `--verbose` flag.

---

## `static/` — the dashboard

Vanilla HTML5/CSS3/JS with no build step and no external dependency, served by `lib.rs`'s
`ServeDir` fallback. Structure and styling follow the ecosystem's shared conventions, verified
against all three peers under `example/*/static/` (see `AGENT_NOTES.MD` Session 15 for the audit).

| File | Responsibility |
| :--- | :--- |
| `index.html` | The page shell only — it contains no data-bearing markup. A `.login-screen` > `.login-card` sign-in view, then `#dashboard-container` holding a `.top-bar` (`.header` with `.logo`, the RBAC tier chip, Refresh/Logout) and a `nav.tab-nav[role=tablist]` of `.tab-btn[data-tab]`. Each `data-tab="X"` pairs with an empty `<main id="tab-X" class="tab-panel">` that `app.js` fills; `tests/source_hygiene.rs` enforces that pairing. `#toast-container` is the single mount point for notifications. |
| `style.css` | The design system. Its `:root` block is **byte-identical** to `simply_ip_vault`/`simply_hook_executor`/`simply_ip_exporter` — a token meaning something different here than one service over is worse than no token, because everything built on it drifts silently. Below that, the shared component set (`.card`, `.data-table` in a `.table-container`, `.tab-nav`/`.tab-btn`, `.btn` family, `.form-group`/`.input-field`, `.badge` family, `.toast`, utilities). Components the peers have but this UI has no markup for (modals, pagination, batch selection) are deliberately absent rather than carried as dead rules. |
| `app.js` | Everything dynamic: a pure-JS SHA-256/HMAC fallback for non-secure contexts (`crypto.subtle` is unavailable over plain-HTTP LAN), the `SyncClient` that signs every request with `CANONICAL_V1` and unwraps the `{"error": …}` envelope, `activateTab()` reactive menu switching, and one `render*`/`*Row`/`show*Form` trio per resource. One-time credentials render into a `.key-reveal` block rather than a `window.alert()`, since the value has to be selectable and re-readable. |
