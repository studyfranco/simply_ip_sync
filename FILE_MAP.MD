# FILE_MAP.MD — what lives where in `src/`, and why

An index of every `.rs` file in `src/`, written for someone (or something) arriving cold and
needing to know where a change belongs before making it.

> Companion documents: `AGENT.MD` (architectural and security ruleset), `SCHEMA.MD` (database
> schema), `RBAC_MODEL.md` (normative authorization specification), `AGENT_NOTES.MD` (session
> worklog).

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
key by `SHA-256(X-API-Key)` → buffers the body and verifies the `CANONICAL_V1` signature → checks
the anti-replay guard (only after verification succeeds) → checks `bound_ips` (last, so a
401-vs-403 pair can't be used as a key-existence oracle) → calls `MasterPin::authenticate`. Also
`ClientIp`. No per-resource authorization — that is `api/guards.rs`.

### `src/crypto.rs` — at-rest encryption and request signing

`SecretCipher` (XChaCha20-Poly1305, `v1.plain.`/`v1.xchacha20poly1305.` envelopes, strictly
fail-closed on an unrecognised prefix), `canonical_v1_payload`, `compute_signature`,
`verify_signature` (constant-time via `Mac::verify_slice`, returns the raw digest for the replay
guard), `generate_signing_secret`. `ENCRYPTION_KEY_ENV = "SYNC_ENCRYPTION_KEY"`.

### `src/config.rs` — environment parsing and client-address resolution

`resolve_client_ip` (right-to-left `X-Forwarded-For` walk, trusted-peer gated), `normalize_ip`,
`parse_trusted_proxies`, `resolve_bind_addr`, `validate_initial_master_key`, `max_body_bytes`.
`TRUSTED_PROXIES` and `INITIAL_MASTER_KEY` are security boundaries and fail hard on a malformed
value; tuning variables (`MAX_BODY_SIZE_MIB`) fail soft to a default with a logged warning.

### `src/replay.rs` — anti-replay guard

`ReplayGuard`: single-use signature cache keyed on `(key_id, raw digest bytes)`, monotonic
`tokio::time::Instant` expiry (never wall-clock), amortized sweep plus a capacity-triggered sweep.
Never flushed wholesale on saturation — that would let every currently valid signature replay at
once.

### `src/extract.rs` — strict request extractors

`StrictJson<T>`: `Json<T>` whose rejection renders as `AppError` (`400`/`413` as appropriate)
rather than axum's default body. Combined with `#[serde(deny_unknown_fields)]` on payload types,
this is how §5's "`is_master` must never be settable" rule is enforced at the type level rather
than in a handler.

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
for the (overwhelmingly common) non-ZIP case.
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
  `auth_middleware` in `lib.rs`.
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

`m20260101_000001_initial_schema` — all 9 `SCHEMA.MD` tables, including the `target_group_name`
override columns on both junction tables, FKs with the specified `CASCADE`/`SET NULL` behavior,
and the six mandatory indexes. `m20260101_000002_derive_master_marker` — adds the generated
`master_marker` column and its unique index; aborts before any DDL if the database already holds
two or more Master rows.

## `tests/` — what each suite owns

| File | Owns |
| :--- | :--- |
| `common/mod.rs` | Shared harness: in-memory DB + pinned Master, `insert_key` (mints credentials directly against the database), `sign`/`signed_request` (real `CANONICAL_V1` signing) |
| `security_tests.rs` | Inbound HMAC verification, replay, `bound_ips`, outbound signature generation against a `wiremock`-mocked vault, and trusted-proxy `X-Forwarded-For` handling (permitted when forwarded through a trusted peer, never a `bound_ips` bypass from an untrusted one) |
| `parser_tests.rs` | `REGEX_LINE`/`JSON_PATH` black-box behavior through the public `parsers` API, local fixtures reproducing StopForumSpam's ZIP and Spamhaus's JSONL feed shapes (both inspected against the real downloads) via `tempfile::tempdir()` for automatic cleanup, and HTML-masquerading-as-a-feed fixtures (block page, captive portal, a large synthetic body) |
| `chunking_tests.rs` | Batch chunking never exceeds `MAX_BATCH_SIZE` at any boundary |
| `api_validation_tests.rs` | Malformed `cron_schedule` on `POST`/`PATCH` for both `/api/sources` and `/api/sync-tasks` is rejected with `400` before any database write |
| `external_ingestion_tests.rs` | Per-target `target_group_name` override; HTML-masquerade-as-200 via both parser types; gzip-compressed response decompression; a slow/hung target aborted by the client's own timeout rather than hanging; the `try_start_job` concurrency guard exercised directly |
| `vault_sync_tests.rs` | Tombstone propagation through a full fetch→push cycle; `last_sync_at` only advances on total success; multi-vault fan-out and partial-failure resilience; per-target `target_group_name` override; a slow/hung target vault aborted on the push path specifically |
| `live_feed_ingestion_tests.rs` | `#[ignore]`d — real network calls to the four feeds named in `AGENT_NOTES.MD`, both via the parser directly and through the full `jobs::external_ingestion::run` pipeline. Run explicitly with `cargo test -- --ignored` |
| `rbac_tests.rs` | `can_sync` manual-trigger allow/403, R4 scope elevation, §5 Master immutability/rotation refusal, §3 owner-only lifecycle |
| `schema_integrity_tests.rs` | Migrations apply cleanly; `ADVERSARIAL(§5)` — a raw-SQL insert with the marker column absent is rejected by the database itself; FK cascade on a junction table |
| `source_hygiene.rs` | `static/app.js` parses as valid ECMAScript (`oxc_parser`, self-tested against a known-broken fixture); every literal `document.getElementById()` reference resolves against `index.html` or an id `app.js` injects itself; the one dynamic id-construction pattern is verified against its actual invariant (every nav button's `data-tab` has a matching panel id) |

`scripts/test_e2e.sh` (repository root, not under `tests/`) is the complementary black-box gate:
it boots the real compiled binary and drives it with `curl` over a real socket, which none of the
above can do. See its own header comment and `AGENT_NOTES.MD` session 2 for what it covers.
