# AGENT_NOTES.MD — session worklog

## Session 1 (2026-08-11/12): initial implementation

Built the service from scratch — nothing under `src/` existed at the start of this session.
Converged against `example/simply_ip_vault` (primary reference) and `example/simply_hook_executor`
(secondary) for the shared security primitives (`CANONICAL_V1` HMAC scheme, XChaCha20-Poly1305
secrets-at-rest, SQLite pragma/pool discipline, Master identity pinning), while building the
domain-specific pieces (parsers, ingestion/replication jobs, scheduler, RBAC over this service's
own resource set) fresh.

**Decisions made without an explicit spec answer, recorded here for the next session:**

1. **`vault_sync_tasks` creation is gated by `can_manage_vaults`, not a new global flag.**
   `SCHEMA.MD`'s `api_keys` table defines exactly three Master-grantable rights
   (`can_manage_keys`, `can_manage_sources`, `can_manage_vaults`); there is no fourth. A sync task
   is a vault-to-vault topology object (`source_vault_id` + `vault_sync_task_targets`, both FKs
   into `vault_endpoints`), so it shares the vault-management right rather than the
   feed-ingestion one. Documented in `RBAC_MODEL.md`'s terminology section.
2. **`RBAC_MODEL.md` here is a new document, not a byte-identical copy of the peers'.** Their copy
   is explicitly scoped to `simply_ip_vault` + `simply_hook_executor` and diffed by their own
   `scripts/verify_convergence.sh`. This service's copy follows the identical normative structure
   (Tiers, R1–R7, §3–§7) restated with its own terminology. No three-way convergence script was
   built — out of scope for the initial implementation.
3. **`client.rs` has no SSRF private-IP blocklist**, unlike `simply_ip_vault::dispatch.rs`'s
   webhook sender. That defends against a *lower-privileged* caller pointing a webhook at an
   internal address; here, creating a `vault_endpoint` is already a `can_manage_vaults`-gated
   (effectively Parent/Master-tier) action, so the threat model is different. Redirect-refusal is
   kept since it's cheap and directly relevant regardless of who configured the target.
4. **`TRUSTED_PROXIES` supports CIDR/bare-IP entries only, not hostnames.** The peers'
   `TrustedProxies` does async DNS resolution with TTLs and a boot grace period; this service's
   `AGENT.MD` only asks for "right-to-left `TRUSTED_PROXIES` header parsing", and the CIDR-only
   subset covers the realistic case (internal network ranges) without the DNS-resolution
   machinery. If a hostname-based trusted proxy is ever needed, port the peers'
   `config.rs::TrustedProxies` resolution logic wholesale rather than reinventing it.
5. **Master's HMAC signing secret is logged once at bootstrap, unconditionally** — not only in the
   generated-key branch. `RBAC_MODEL.md` §5 forbids rotating the Master key through the API
   (rotation always returns a fresh credential, and the Master's is never reachable that way), so
   without this log line the Master would be bootstrapped with a `signing_secret` no operator
   could ever obtain, permanently unable to sign a request. Caught by an end-to-end smoke test
   (booted the real binary, signed a real `GET /api/auth/me` with the initial credentials) before
   this was fixed — the earlier version only logged the secret when `INITIAL_MASTER_KEY` was
   *unset*, which is backwards: that branch's plaintext key is already knowable to the operator
   either way.
6. **§6 cascade deletion is a simplified pre-flight-inventory-and-refuse, not the peers' full
   resolution-map resubmission protocol.** Deleting a key walks its daughter subtree, refuses with
   a structured `409` inventory if any key in the subtree still owns a resource, and otherwise
   deletes the whole subtree in one pass. There is no per-entity "delete or reassign" resolution
   map to resubmit — the caller reassigns/deletes the listed resources individually via the
   existing CRUD endpoints and retries the key deletion. Simpler, still upholds "data is never
   destroyed implicitly."
7. **`parent_key_id` has no database-level foreign key.** Matches the peers' own precedent for
   FK-shaped relationships SQLite can't express portably; the safety property (no dangling
   `parent_key_id` after a cascade delete) is covered by `api/keys.rs::collect_subtree` always
   deleting a resolved subtree as one unit, and pinned by
   `tests/rbac_tests.rs::resource_lifecycle_delete_requires_owner_or_master`.

**A test-harness gotcha worth remembering for anyone adding a new `tests/*.rs` request built by
hand (not via `common::signed_request`):** `auth_middleware` extracts `ConnectInfo<SocketAddr>`.
In production this is always populated by `into_make_service_with_connect_info` before a request
reaches any middleware; a manually-built `axum::http::Request` in a test that skips
`.extensions_mut().insert(ConnectInfo(...))` gets a `500` from axum's own extractor rejection
machinery, not the `401` the *auth* logic would otherwise produce for e.g. a missing signature
header. Two tests hit this early in the session (`security_tests::missing_signature_header_is_rejected`,
`rbac_tests::unauthenticated_request_never_reaches_a_handler`) — both fixed by inserting the
extension. Not a production bug: `main.rs` always uses `into_make_service_with_connect_info`.

**Also caught by the test suite, not by review:** the first draft of `tests/vault_sync_tests.rs`
seeded mock `GET /api/ips` responses with RFC3339 timestamps (`"...Z"` suffix). `client::IpRecordResponse`'s
timestamp fields are `Option<chrono::NaiveDateTime>` (matching `simply_ip_vault`'s own wire format,
which is naive/timezone-less), and chrono's default `NaiveDateTime` deserializer rejects a
trailing `Z` as unexpected trailing input — every mocked delta record failed to deserialize,
manifesting as the whole sync job reporting `FAILED`. Fixed by dropping the `Z` in the test
fixtures; left as a note here because the failure mode (a client-side `reqwest::Error` wrapped in
`ClientError::Request`) doesn't obviously point at "wrong timestamp format" from the job's
`FAILED` status and generic error string alone.

**Not yet done, flagged for a future session (session 1 items still open after session 2):**
- No live Docker build was performed — `docker` was not available in either session's environment.
  The `Dockerfile`/`docker-compose.yml` are believed correct (binary name, port 3003) but the image
  itself remains unverified. Build and smoke-test it before first deployment.
- Hostname-based `TRUSTED_PROXIES` entries (see session 1 decision 4).

---

## Session 2 (2026-08-16): resilience hardening, ZIP/JSONL feed support, and `scripts/test_e2e.sh`

Two rounds of follow-up work landed in this session, in order: (a) source hygiene / cron
validation / multi-vault resilience / live+fixture feed tests (new `tests/*.rs` files plus two
production-code additions), then (b) `scripts/test_e2e.sh`, a full end-to-end suite driving the
real compiled binary over real HTTP — requested mid-session and folded into the same pass since it
exercises largely the same surface (cron validation, multi-vault sync, feed ingestion) from the
outside instead of through `tower::ServiceExt::oneshot`.

**Production code changes (not just tests):**

1. **ZIP archive support in the ingestion pipeline** (`src/jobs/decompress.rs`, new module).
   StopForumSpam's downloads are `.zip` archives; `decompress_if_zip` is a transparent
   pre-parsing step in `jobs::external_ingestion::execute` — detected by magic bytes
   (`PK\x03\x04` / the empty-archive `PK\x05\x06` form), decompresses every non-directory member
   and concatenates them newline-separated, and is a pure passthrough for the overwhelmingly
   common case of an already-plain feed body. Lives in the ingestion layer, not the parser layer,
   so every parser type gains ZIP support without knowing archives exist.
2. **JSONL mode for `JSON_PATH`** (`src/parsers/json_path.rs`). Spamhaus's `drop_v6.json` was
   fetched and inspected directly (not assumed from the name) — it is **not** a JSON array, it is
   newline-delimited JSON (one `{"cidr":...}` object per line) with a trailing
   `{"type":"metadata",...}` footer line carrying no `cidr` field. Added a `"jsonl": true`
   `parser_config_json` flag: each line is parsed independently and a line that fails to parse, or
   parses but lacks `ip_field`, is skipped rather than aborting the whole feed — which is what
   lets the metadata footer pass through harmlessly.
3. **Cron expression validation before persistence**
   (`scheduler::validate_cron_expression`, using the `croner` crate directly — added as an
   explicit dependency; it was already present transitively via `tokio-cron-scheduler`). Wired
   into `POST`/`PATCH` on both `/api/sources` and `/api/sync-tasks`, called *before* any database
   write (before `state.db.begin()` on the update paths, specifically, so an invalid cron never
   even opens a transaction). Validates via the exact same normalize-then-parse path the scheduler
   itself will later use, so anything accepted here is guaranteed schedulable.
4. **Deterministic Master signing-secret bootstrap**
   (`INITIAL_MASTER_SIGNING_SECRET` env var, `config::validate_initial_master_signing_secret`).
   Added specifically so `scripts/test_e2e.sh` never needs to scrape the Master's signing secret
   out of a buffered/redirected server log — mirrors the peers' documented preference for
   deterministic bootstrap over log-scraping. Generation + one-time logging remains the default
   when unset, matching session 1's fix.

**New test files:**

- `tests/source_hygiene.rs` — `oxc_parser` (pinned `=0.143.0`, matching the peers' exact pinned
  version) confirms `static/app.js` has zero syntax errors, plus a self-test that feeds it a known
  broken fixture (a backtick inside a template literal) to prove the check can actually fail, not
  just always pass. Also cross-checks every literal `document.getElementById("...")` call against
  `index.html` — which immediately found a **real gap in the check's own first draft**, not in
  `app.js`: 16 ids (`source-form`, `new-vault-btn`, etc.) are injected by `app.js` itself via
  `innerHTML` templates and queried in the same function, so checking against `index.html` alone
  produced 16 false positives. Fixed by unioning ids declared in `index.html` with ids `app.js`
  injects itself, plus a second, narrower test that only same-function id round-trips (declared
  and queried with identical spelling) count as satisfied. The one genuinely dynamic id
  (`"tab-" + btn.dataset.tab`) is verified by a dedicated test asserting every nav button's
  `data-tab` value has a matching `id="tab-<value>"` panel, rather than by string-matching the
  concatenation itself. Resolves session 1's "no headless-browser verification" gap for syntax and
  reference-integrity purposes — actual visual/interaction behavior in a browser is still
  unverified, and remains a real gap since no browser is available in this environment.
- `tests/api_validation_tests.rs` — invalid `cron_schedule` → `400` on both `POST /api/sources` and
  `POST /api/sync-tasks`, confirms nothing was persisted, and confirms `PATCH` with a bad cron
  leaves the existing valid value untouched.
- `tests/vault_sync_tests.rs` (extended) — two new tests: successful 2-target fan-out (both mocks
  receive the batch, signature header present and well-formed, tombstone/group-name correctness,
  `last_sync_at` advances to ≥ the job's own start time) and partial failure (healthy target still
  receives its batch even though its sibling returns `413`; job reports `PARTIAL`; `sync_logs`
  records `PARTIAL`; `last_sync_at` withheld).
- `tests/live_feed_ingestion_tests.rs` — `#[ignore]`d, hits the four real feeds named in the task
  brief plus one full-pipeline test (through `jobs::external_ingestion::run`, not just the parser).
  Run and confirmed passing against the live network during this session
  (`cargo test -- --ignored`): mass_scanner 19,229 entries, doh-ipv4 1,901, vpn-ipv4 12,362,
  doh-ipv6 1,305 (1,305 of which parse as genuine `Ipv6Addr`, asserted specifically so a parser
  that silently extracted zero v6 addresses from a v6-only feed couldn't slip through a
  non-empty-only check).
- `tests/parser_tests.rs` (extended) — local fixtures reproducing the *real* inspected shapes of
  StopForumSpam's `listed_ip_30_ipv6.zip` (fetched once to confirm: single member
  `listed_ip_30_ipv6.txt`, bare IPv6 addresses, one per line) and Spamhaus's `drop_v6.json`
  (fetched once to confirm the JSONL shape above), built with `tempfile::tempdir()` for automatic
  cleanup on drop even if an assertion panics partway through.

**`scripts/test_e2e.sh`** — structured after `example/simply_ip_vault/scripts/test_e2e.sh` and
`example/simply_hook_executor/scripts/test_e2e.sh` (extracted their conventions via a research
pass rather than reading both ~3,000-line files in full: `set -uo pipefail` not `-e` since checks
expect non-2xx on purpose, working-directory + marker-file guard, `hmac_sign`/`api_call`/`check*`
helper shape, `mktemp -d` work directory, background daemon + `trap cleanup EXIT INT TERM`,
Python `http.server`-based mock downstream servers). Scoped to ~11 sections against the peers'
~29-35 (proportionate to a narrower domain, per the research pass's own recommendation) — probes,
boot identity, HMAC signing & anti-replay (missing/wrong/tampered/expired/future/malformed
timestamp, deliberate replay-of-identical-request), cron validation, multi-vault mock servers,
successful fan-out, partial failure, live feed ingestion (network-gated — skips with a warning
rather than failing if `raw.githubusercontent.com` is unreachable), local ZIP/JSONL fixtures
(same fixture shapes as the two new Rust tests above, generated fresh each run and served via a
local `python3 -m http.server`), additional hardening/edge cases (malformed JSON, unexpected
field, unknown route, RBAC privilege-escalation attempts, Master immutability/rotation refusal),
and graceful `SIGTERM` shutdown. **104/104 checks passing**, run 4 times consecutively to confirm
no flakiness, with an explicit post-run check for lingering processes/temp files after each run.

Two real bugs found by writing and running this script (both fixed, neither previously caught by
the Rust test suite since nothing there drives the real compiled binary over a real socket):

- **Non-hex characters in the hand-typed deterministic Master key/secret.** The first draft used
  readable literals like `"e2e5ip5sync5aaa...a"` — `i`, `p`, `s`, `y`, `n`, `c` are not hex digits,
  so `validate_initial_master_key` correctly refused it and the server exited during boot before
  the readiness probe ever succeeded. Fixed by building the 64-char strings with `printf`
  (`"e2e5$(printf '1%.0s' $(seq 1 60))"`) instead of hand-counting a literal — exactly the kind of
  mistake a hand-typed hex string invites, which is now impossible to repeat the same way.
- **A timestamp collision between two unrelated `GET /api/auth/me` calls in different sections**
  (§2's boot-identity check and §3's deliberate-replay check) intermittently produced the *exact*
  same `CANONICAL_V1` signature, because both happened to land in the same wall-clock second and
  the script's original `next_timestamp` tracked "last used" *per request identity* rather than
  globally — two different identities can still coincidentally sign an identical
  (method, target, timestamp, body) tuple. The server correctly rejected the second occurrence as
  a replay, which surfaced as `§3`'s "first use of a fresh signature is accepted" check failing
  with `401` on some runs and not others. Fixed by making `next_timestamp` a single script-wide
  monotonic counter, so every signed request across the entire run gets a timestamp guaranteed
  unique against every other request the script has ever sent — the one deliberate replay test is
  now the only place a repeat is possible, by construction.
- **(Process-leak, not a check failure) the local fixture file server leaked across runs.** It was
  launched as `(cd "$FIXTURE_DIR" && python3 -m http.server ...) &`; `$!` in that form captures the
  *subshell's* pid, not necessarily python3's (bash does not guarantee `exec`-in-place for a
  subshell), so `kill "$FIXTURE_SERVER_PID"` in `cleanup()` sometimes killed an already-exited
  subshell wrapper while python3 kept running as an orphan. Three leaked `http.server` processes
  (ports 18800/18801/18802, one per affected run) were found still listening after the fact,
  confirmed by `ps aux`, and killed manually. Fixed by using `python3 -m http.server PORT
  --directory DIR` directly (no subshell), which makes `$!` unambiguously python3's own pid. Two
  further clean runs afterward confirmed zero lingering processes and zero lingering temp files.

**Explicit gap versus the requested validation gates:** the task asked for
`./scripts/verify_convergence.sh` as a validation gate. This repository does not have one and,
per session 1 decision 2, deliberately does not — the peers' `verify_convergence.sh` diffs
specific shared files (`RBAC_MODEL.md`, `config.rs::resolve_client_ip`, etc.) between exactly
`simply_ip_vault` and `simply_hook_executor`, a two-party comparison this service was never a
party to, and building a three-way (or `simply_ip_sync`-specific two-way) equivalent is a
separate, non-trivial piece of tooling that wasn't part of either session's task list. Flagged
here rather than silently skipped or fabricated.

**Test metrics after this session:**
- `cargo test` (default, offline): **93 tests**, 0 failed (47 lib unit + 4 api_validation + 2
  chunking + 6 parser + 7 rbac + 5 schema_integrity + 7 security + 6 source_hygiene + 4 vault_sync,
  across `src/` unit tests and 8 integration-test binaries under `tests/`).
- `cargo test -- --ignored`: **5 tests**, 0 failed (live network feed tests).
- `./scripts/test_e2e.sh`: **104 checks**, 0 failed, 0 skipped (python3 and network were both
  available in this session's environment; the script degrades to warn-and-skip for the
  mock-vault/fixture sections without python3, and for the live-feed section without network).
- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`, `cargo doc --no-deps`:
  all clean, zero warnings.

---

## Session 3 (2026-08-16): resilience hardening — timeouts, concurrency, compression, group overrides

Requested as a hardening pass over the session-2 suite: network delays, proxy spoofing, target
group overrides, secrets rotation, HTML-masquerading-as-200, concurrent job execution. Landed four
production-code changes (not just tests) plus new coverage across `tests/` and
`scripts/test_e2e.sh`.

**Production code changes, each driven by a task that turned out to expose a real gap:**

1. **`OUTBOUND_HTTP_TIMEOUT_SECS` config** (`config::outbound_http_timeout`,
   `client::build_http_client`). The 60s timeout already existed (session 1) but was hardcoded;
   made configurable the same way `MAX_BODY_SIZE_MIB` already is (fail-soft, `OnceLock`-cached).
   **Tests deliberately do not rely on this env var/cache to control timing** — a
   process-wide `OnceLock` set by one test would leak into every other test sharing the binary.
   Instead, timeout tests override `AppState.http` directly with a purpose-built short-timeout
   `Client` (both `AppState` and `reqwest::Client` are already plain, publicly-fielded/cloneable
   types, so this needed no new test-only constructor). Documented directly in
   `build_http_client`'s doc comment so the next person reaching for
   `OUTBOUND_HTTP_TIMEOUT_SECS` in a test doesn't rediscover the hazard the hard way.
2. **Response decompression enabled on the outbound `reqwest` client** (`gzip`, `deflate`,
   `brotli`, `zstd` Cargo features). This was a **real latent bug**, not a defensive
   just-in-case: `reqwest`'s compression support is opt-in per feature flag, and none were enabled
   — a feed host or CDN compressing its response (common) would have handed a `FeedParser`
   opaque compressed bytes. For `REGEX_LINE` this fails *silently*: compressed bytes essentially
   never contain an ASCII IP-shaped substring, so the job would report `SUCCESS` with 0 items
   pushed, indistinguishable from a genuinely empty feed. For `JSON_PATH` it would report `FAILED`
   with a confusing "invalid JSON" error that gives no hint the real problem is Content-Encoding.
   Found while working the autonomy directive's "unexpected payload compression formats" item, not
   by an explicit task — confirmed as a real gap before fixing (checked `Cargo.toml`, found no
   compression feature enabled on `reqwest`), not assumed.
3. **Job-concurrency guard** (`jobs::{RunningJobs, JobGuard, try_start_job}`,
   `AppState.running_jobs`). Task 6 asked for concurrent-trigger safety; rather than only proving
   SQLite's `busy_timeout` absorbs contention (true, but only tests robustness against a problem,
   not a real product decision), added an explicit per-resource "one execution at a time" guard:
   a `HashSet<Uuid>` behind a `std::sync::Mutex` (never held across an `.await`, so no deadlock
   risk), claimed via a `try_start_job` returning an RAII `JobGuard` that releases the slot on
   drop — safe against every early-return path including `?`. Wired into both manual-trigger HTTP
   handlers (a second concurrent trigger gets `409 Conflict`, not a queued duplicate run) and the
   scheduler's cron closures (a slow-running prior tick causes the next one to skip with a logged
   warning, not stack up). This also happens to be the *correct* fix for the literal race the task
   describes — two overlapping executions of the same source/task pushing interleaved,
   possibly-conflicting batches to the same target group — rather than merely tolerating it.
4. **`external_ingestion`: a zero-item successful fetch+parse is now `PARTIAL`, not `SUCCESS`**
   (`jobs/external_ingestion.rs`). This is a genuine product-behavior change, made deliberately and
   documented in-line: unlike `vault_sync` (an incremental delta puller, where "zero new records
   since last time" is routine and expected), `external_ingestion` re-fetches a feed's *entire*
   current content on every run — a real, previously non-trivial threat list dropping to
   genuinely zero entries between runs is itself anomalous, and is exactly what an HTML
   error/captive-portal/WAF-block page served with `200 OK` looks like to `REGEX_LINE` (valid
   UTF-8 text, no parse error, just no IP-shaped tokens). `JSON_PATH` already got this right for
   free (HTML isn't valid JSON, so it hits the existing hard-`FAILED` parse-error path) — this
   change only affects `REGEX_LINE`'s silent-empty-success case. **Broke one existing test**
   (`rbac_tests.rs::trigger_with_granted_can_sync_succeeds`, which used a comment-only fixture body
   that now correctly reports `PARTIAL`) — fixed by giving that fixture a real IP, since the
   test's actual subject is the RBAC gate, not ingestion content semantics; recorded here rather
   than silently patched, since "a test broke and I changed the fixture" is exactly the kind of
   edit that deserves a one-line trail.

**New test files / major additions:**

- `tests/external_ingestion_tests.rs` (new file, 6 tests): per-target `target_group_name`
  override independent of the source's default; HTML-masquerade-as-200 via `REGEX_LINE` (zero
  items, `PARTIAL`, no panic) and via `JSON_PATH` (hard `FAILED`, confirming the two parsers fail
  the way each one's contract predicts); gzip-compressed response transparently decompressed;
  slow/hung target aborted by the client's own timeout in `<2s` wall-clock despite a 5s mock delay
  (proves no worker-thread hang, not just that an error eventually surfaces); the job-guard
  primitive exercised directly (second claim on a live id refused, unrelated id unaffected,
  released on drop).
- `tests/vault_sync_tests.rs` (+2 tests): the same per-target `target_group_name` override for
  `vault_sync_task_targets` specifically (session 2 only covered the "both targets get the same
  group" case); the same slow/hung-target timeout scenario for the inter-vault push path
  specifically, since Task 3 named `vault_sync_tests.rs` explicitly and the two pipelines, while
  sharing `client::post_batch`, have independent `sync_logs`/`last_sync_at` bookkeeping worth
  pinning separately.
- `tests/security_tests.rs` (+2 tests): a forwarded client IP from a *trusted* proxy is checked
  against `bound_ips` (and permitted when inside range); the zero-trust counterpart — an identical
  forged `X-Forwarded-For` from an *untrusted* peer must not bypass `bound_ips` at all, falling
  back to the peer's own (disallowed) address. Together these are the actual security property
  worth pinning: not just "bound_ips works", but "a header alone, without a trusted network path,
  can never widen what a header alone should never be able to widen."
- `tests/parser_tests.rs` (+4 tests): a realistic Cloudflare-block-page fixture through
  `REGEX_LINE` (zero matches) and `JSON_PATH` (hard failure); a captive-portal page whose redirect
  URL happens to *contain* a private IP literal, confirming the line-oriented scanner still
  extracts it correctly rather than getting confused by surrounding markup (documented as
  intentional — `normalize_ip_or_cidr` re-validates every candidate regardless); a 50,000-line
  synthetic HTML body as a bounded-time/no-blowup proxy for "no unbounded memory growth on
  adversarial input" (an actual memory profiler is out of reach for a unit test, so wall-clock
  time under a generous 5s ceiling is what's checked).
- `scripts/test_e2e.sh` (+4 sections, black-box/real-socket versions of the above): §7a target
  group override observed on the wire (mock vault's received batch body); §7b live credential
  rotation — `PATCH /api/vaults/{id}` while the daemon keeps running, re-trigger without restart,
  confirm the *new* `X-API-Key` value on the next outbound request the mock actually receives;
  §7c five genuinely concurrent trigger requests fired via backgrounded `curl` (signed
  sequentially beforehand so each gets its own monotonic timestamp, then launched in parallel) —
  observed 2×`200` + 3×`409` on every run, proving both real concurrency occurred and the guard
  correctly serialized it, never a `500`; §7d truncated (`sha256=ab`), non-hex, and empty
  `X-Signature-256` values all cleanly `401` rather than panicking a hex-decode; the HTML-masquerade
  fixture added alongside the existing ZIP/JSONL ones in §9.

**Test metrics after this session:**
- `cargo test` (default, offline): **102 tests**, 0 failed (up from 93: +6 `external_ingestion_tests.rs`
  (new file), +2 `vault_sync_tests.rs`, +2 `security_tests.rs`, +4 `parser_tests.rs` minus the one
  `rbac_tests.rs` fixture fix which is a same-count edit).
- `cargo test -- --ignored`: **5 tests**, 0 failed (unchanged — no new live-network tests this
  session; everything above uses local fixtures/mocks, consistent with session 2's rate-limit
  avoidance rationale).
- `./scripts/test_e2e.sh`: **126 checks** (up from 104), 0 failed, 0 skipped, run **3 times
  consecutively** with an explicit post-run check for lingering processes/temp files after each —
  clean every time, including the concurrency section (which is the one section whose result
  legitimately varies run-to-run: the 200-vs-409 split depends on real scheduling, but the
  *invariants* checked — no unexpected status, at least one success, every response accounted for
  as either 200 or 409 — held on all three runs).
- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`, `cargo doc --no-deps`:
  all clean, zero warnings.

**Not done / flagged rather than assumed out of scope:**
- Genuine "network partition recovery" (a target vault becoming unreachable mid-run, then
  recovering on a *later* run and the delta catching up correctly) is not covered. The
  partial-failure tests (session 2 + this session) cover "a target fails this run", and the
  `last_sync_at`-withholding behavior already guarantees a subsequent successful run replays the
  full since-last-success delta — so the recovery *mechanism* is exercised, but not end-to-end as
  its own named scenario. Left for a future session rather than simulated with a fragile
  process-pause/resume in bash.
- `./scripts/verify_convergence.sh` still does not exist (see sessions 1–2's decision) and was not
  requested as a gate this session.

## Session 4 (2026-08-17): delta pagination, outbound retry/backoff, adaptive 413 splitting, safe multi-chunk `full_replace`

Requested as four production features plus tests: (1) paginate `GET /api/ips` delta fetches
instead of assuming one page is the whole result; (2) retry transient outbound failures
(`429`/`502`/`503`/`504`) with exponential backoff+jitter; (3) adaptively split a batch in half on
`413 Payload Too Large` and resend the halves; (4) make multi-chunk `full_replace` ingestion safe —
only the first chunk of a run may carry `full_replace`, every later chunk must downgrade to
`upsert` or it erases what the previous chunk just delivered.

**Production code changes:**

1. **`config::outbound_max_retries` / `config::outbound_retry_backoff`** (new, `OUTBOUND_MAX_RETRIES`
   default `3`, `OUTBOUND_RETRY_BACKOFF_MS` default `500`). Unlike every other tunable in this
   module (`outbound_http_timeout` included), these two are **deliberately not `OnceLock`-cached** —
   they read `std::env::var` fresh on every call. A cached value set by one test would leak into
   every other test sharing the binary (the exact hazard session 3 flagged for
   `OUTBOUND_HTTP_TIMEOUT_SECS`, which is why timeout tests override `AppState.http` directly
   instead). Retry tests can't use that workaround as cleanly — the retry loop lives inside
   `client::post_batch`/`get_ips_delta`, not behind a swappable `Client` — so instead the config
   reads live, and any test that needs a non-default value sets/removes the env var around just its
   own call, under a shared `tokio::sync::Mutex` (`tests/client_resilience_tests.rs::env_lock`) so
   two such tests never run concurrently and stomp each other's value mid-flight.
2. **`retry` module** (new file, `src/retry.rs`): `is_transient_status(u16) -> bool` — exactly
   `429 | 502 | 503 | 504`, deliberately excluding both `500` (a generic server error retrying won't
   fix) and `413` (handled by splitting, not retrying — retrying an oversized payload unchanged
   would just get `413` again). `backoff_with_jitter(attempt) -> Duration` — exponential off
   `outbound_retry_backoff()`, capped at 30s, up to 50% jitter so a fleet of vaults hitting the same
   flaky target don't all retry in lockstep.
3. **`client.rs`**: `post_batch` and `get_ips_delta` each split into three layers — a single-attempt
   fn (`post_batch_once` / `get_ips_page`), a retry wrapper around it
   (`post_batch_with_retry` / `get_ips_page_with_retry`, looping on `is_transient_status` up to
   `outbound_max_retries()`, always re-signing with a fresh timestamp since CANONICAL_V1 covers the
   timestamp and a request signed before a multi-second backoff sleep could land outside the
   receiving side's freshness window), and the public entry point. `post_batch`'s public layer adds
   413-adaptive splitting on top: a `VecDeque<(Vec<BatchRecordInput>, BatchMode)>` work queue rather
   than recursion (an async fn can't recurse without boxing the future) — on `413` with more than
   one record, splits at the midpoint and pushes both halves back to the front, first-half-first,
   aggregating successful responses via a new `BatchRecordsResponse::merge`. `get_ips_delta`'s
   public layer adds the pagination loop (unchanged `DELTA_PAGE_SIZE = 5_000`, breaks on a
   short/final page), now with each page independently retried — a `503` on page 3 of 4 no longer
   requires re-fetching pages 1–2.
4. **`BatchMode` gained `FullReplace`** plus `BatchMode::parse(&str) -> Option<Self>`
   (`"upsert"`/`"full_replace"`, `None` for anything else — a typo must be caught at the API
   boundary, not silently reinterpreted). The safety rule — only the *first* delivered piece of a
   run may carry `full_replace`, everything after downgrades to `upsert` — is applied at **two
   layers that must agree**: `jobs::mode_for_chunk_index(base_mode, chunk_index)` at the job-chunking
   layer (`external_ingestion.rs`, chunk 0 keeps `base_mode`, every later chunk is `Upsert`), and
   again *inside* `post_batch`'s own 413-split queue (the second half of any split is always forced
   to `Upsert`, regardless of how many times a chunk has already been re-split) — because a chunk
   that starts as chunk 0's `full_replace` and then gets 413-split into two wire requests must still
   only have the *first* of those two carry `full_replace`, or the split itself would recreate the
   exact bug the job-layer rule exists to prevent.
5. **`jobs/vault_sync.rs` deliberately NOT modified.** `full_replace` was not extended to
   `vault_sync_tasks`: a vault-sync delta batch (`since=`-filtered) is a small incremental slice, not
   a group's full content, so `full_replace` there would read as "delete everything this run's tiny
   delta didn't mention" — nearly the entire target group, on every single run. `vault_sync.rs`
   still hardcodes `BatchMode::Upsert` for every chunk and inherited the pagination+retry behavior
   automatically, with zero code changes of its own, purely from the `client.rs` rewrite underneath
   it. Documented in `AGENT.MD` §3.B and `SCHEMA.MD`'s `vault_sync_tasks.mode` column description so
   a future session doesn't "fix" this as a missing feature.
6. **`api/sources.rs`**: `mode` accepted on create (defaults to `"upsert"`) and update, validated
   with `BatchMode::parse` before the transaction — an invalid value is `400` and never persisted,
   same pattern already established for `cron_schedule` validation.

**Unrelated pre-existing build break, found and fixed (blocking, not part of the four features):**
`Cargo.toml` already had `croner` bumped `"2"` → `"3"` and `tokio-cron-scheduler` `"0.13"` →
`"0.15"` as an uncommitted change from before this session, but `scheduler.rs::validate_cron_expression`
still called croner 2.x's removed builder API (`croner::Cron::new(&expr).with_seconds_required().with_dom_and_dow().parse()`).
This isn't a lint — it's `E0599`, so it failed `cargo check`/`test`/`build` outright, not just
`clippy`. Fixed by switching to croner 3's actual API: `croner::parser::CronParser::builder().seconds(Seconds::Required).dom_and_dow(true).build().parse(&normalized)`.
Confirmed no other `croner::` call sites existed to update. This had to be fixed before any of this
session's own validation gates could even compile — flagged here explicitly since it's out of scope
for the four requested features but was silently blocking all of them.

**New test files / major additions:**

- `tests/client_resilience_tests.rs` (new file, 7 tests): retry recovery after two transient
  failures then success on the third attempt (`post_batch` directly, asserting the aggregated
  response and exactly 3 requests reaching the mock); retry exhaustion (`OUTBOUND_MAX_RETRIES=2` ⇒
  3 total attempts, then a clean error, no infinite retry); a non-transient `400` is never retried
  (exactly 1 request); adaptive 413 splitting completing delivery of 5,000 records (asserts the
  *delivered* — i.e. `≤2000`-record — sub-batches sum to exactly 5,000, since `received_requests()`
  also captures the oversized attempts that provoked each `413`); the same splitting preserving
  `full_replace` on only the first of two delivered sub-chunks after one split; a `413` on a
  single record failing outright rather than looping forever (nothing left to split); the same
  per-page retry behavior for `get_ips_delta`. All env-var-mutating tests share
  `env_lock()` (a `tokio::sync::Mutex`, not `std::sync::Mutex` — clippy's `await_holding_lock` lint
  correctly flags a sync mutex guard held across an `.await`).
- `tests/external_ingestion_tests.rs` (+1 test): 12,000 synthetic records through a `full_replace`
  source (`MAX_BATCH_SIZE=5,000` ⇒ 3 chunks of 5000/5000/2000) — asserts all 12,000 land, exactly 3
  POSTs are sent, and the wire-level `mode` field is `full_replace,upsert,upsert` in delivery order,
  never more than the first.
- `tests/vault_sync_tests.rs` (+1 test): 15,001 synthetic delta records across 4 pages
  (`DELTA_PAGE_SIZE=5,000` ⇒ 5000/5000/5000/1) — a closure-based `wiremock` responder reads
  `offset`/`limit` query params to serve the correct page; asserts exactly 4 GET requests, exactly 4
  push chunks whose combined records sum to 15,001, and `last_sync_at` still advances.
- `tests/api_validation_tests.rs` (+3 tests): an invalid `mode` on source creation is `400` and
  nothing persists; both valid values are accepted and omitting `mode` defaults to `"upsert"`; an
  invalid `mode` on update is `400` without mutating the existing row — mirrors the file's existing
  `cron_schedule` validation tests exactly.
- Lib unit tests (+6): `config.rs` (`outbound_max_retries`/`outbound_retry_backoff` default-when-unset,
  ×2), `retry.rs` (`is_transient_status`'s exact set, backoff growth+cap, ×2), `jobs/mod.rs`
  (`mode_for_chunk_index`: only chunk 0 keeps `full_replace`; `upsert` stays `upsert` for every
  chunk, ×2).
- `scripts/test_e2e.sh`: `mock_vault.py` extended in place — `GET /api/ips` now actually honors
  `offset`/`limit` (previously always returned the whole delta file regardless of query params, a
  gap this session's pagination scenario needed real support for, not just a mode string); a new
  `GET /feed.txt` branch lets a mock vault instance double as an external-feed HTTP source; the POST
  mode dispatch gained `retry:<status>:<n>` (fail with `<status>` for the first `<n>` POSTs *while
  that exact mode string is active* — the hit counter resets whenever the mode file's content
  changes, so re-arming the same mode string later in the same long-lived process counts from zero
  again) and `split413:<threshold>` (413 iff the POSTed `records` array exceeds `<threshold>`,
  otherwise success), alongside the existing `ok`/`fail500`/`fail413`. Two new long-lived mock
  instances launched alongside the existing source/target1/target2 (`EXTRA_MOCK` — large delta +
  feed-file serving; `RESILIENCE_MOCK` — the POST target whose mode file drives retry/413/full_replace
  scenarios), both added to the process-cleanup trap. Four new subsections: **7e** (15,001-record
  delta across 4 pages, checked end-to-end through a real sync-task trigger); **7f** (a target
  failing twice with `503` before succeeding on the 3rd attempt, verified against the mock's own
  request log, not just the job's reported status); **7g** (the same 15,001-record delta re-pushed
  against a 2,000-record 413 ceiling — asserts the exact attempt/delivery cascade: 3 job-level
  chunks of 5,000 each split into 4 delivered sub-batches apiece plus the trailing 1-record chunk
  needing no split, 22 total wire attempts, 13 delivered, all summing back to 15,001); **7h**
  (12,000-record `full_replace` feed via `EXTRA_MOCK`'s `/feed.txt`, asserting the wire-level `mode`
  sequence `full_replace,upsert,upsert` exactly as the unit test does, but over a real socket against
  the actual compiled binary).

**Test metrics after this session:**
- `cargo test` (default, offline): **120 tests**, 0 failed (up from 102: +6 lib unit tests, +1
  `vault_sync_tests.rs`, +7 `client_resilience_tests.rs` (new file), +1 `external_ingestion_tests.rs`,
  +3 `api_validation_tests.rs`).
- `cargo test -- --ignored`: **5 tests**, 0 failed (unchanged — no new live-network tests this
  session).
- `./scripts/test_e2e.sh`: **162 checks** (up from 126), 0 failed, 0 skipped, run **twice
  consecutively** with an explicit post-run check for lingering `mock_vault.py`/`http.server`
  processes — clean both times, zero leaks.
- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`: both clean, zero
  warnings (after the croner fix above — before it, neither could even compile).

**Not done / flagged rather than assumed out of scope:**
- `full_replace` support was scoped to `external_sources` only, by design (see the vault_sync
  decision above) — this is not a gap, it's the considered safety boundary this session's own Task 4
  exists to enforce.
- `./scripts/verify_convergence.sh` still does not exist (see sessions 1–2's decision) and was not
  requested as a gate this session.
