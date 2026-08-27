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

## Session 5 (2026-08-17): decompression-bomb byte limits, partial multi-chunk failure verification, non-UTF-8 feed resilience

Requested as three production-hardening edge cases plus tests: (1) a hard ceiling on decompressed
feed body size, to stop a ZIP/gzip decompression bomb from exhausting memory; (2) verification that
a fatal error partway through a multi-chunk push sequence — not just a target down from the first
request — correctly reports `PARTIAL`/`FAILED` and withholds the incremental-sync cursor; (3) lossy
UTF-8 decoding so a non-UTF-8/Latin-1/raw-binary feed body degrades gracefully instead of hard-
failing or panicking. Landed one new config knob, two new streaming byte-cap functions, two lossy-
decoding call-site changes, and a large new-tests-only surface (Task 2 turned out to already be
correctly implemented — see below).

**Production code changes:**

1. **`config::max_decompressed_bytes`** (new, `MAX_DECOMPRESSED_BYTES`, default 50 MiB =
   `52_428_800` bytes). `OnceLock`-cached like `max_body_bytes`/`outbound_http_timeout` (a stable
   tuning knob, not something a test needs to override mid-run via env var the way the retry
   backoff vars deliberately aren't cached) — `jobs::decompress`'s functions take the limit as an
   explicit parameter instead of reading the config themselves, so every test that needs a specific
   limit just passes one directly, with zero env-var-mutation/hermeticity concerns at all.
2. **`jobs::decompress::read_capped_body`** (new): replaces `external_ingestion.rs`'s old
   `response.bytes().await` single-shot read. This is the change that actually matters for the
   `Content-Encoding` (gzip/deflate/brotli/zstd) case: `reqwest`'s decompression happens
   transparently inside the response body stream (`tower_http::decompression::Decompression`
   wrapping the underlying hyper service — confirmed by reading `reqwest` 0.13's source, since it
   has no standalone `decoder.rs` the way older versions did), so by the time a single `bytes()`
   call returns, an arbitrarily large decompressed payload would *already* be fully buffered in
   memory — checking its length afterward is not a defense, it's a post-mortem. `read_capped_body`
   instead polls `Response::chunk()` (available without the `stream` Cargo feature, unlike
   `bytes_stream()` — no new dependency needed) in a loop, accumulating a running byte count and
   erroring out the instant it crosses `max_bytes`, so the oversized remainder past that point is
   never actually read off the stream, let alone buffered.
3. **`jobs::decompress::decompress_if_zip`** (signature changed: now takes `max_decompressed_bytes:
   u64`). Guards the *second*, independent expansion point: even a body that passed
   `read_capped_body`'s wire-level cap (ZIP archives are rarely re-gzipped, so their compressed
   size on the wire is usually already small) can still be a ZIP bomb internally. Each member is
   read through `Read::take(remaining_budget + 1)` rather than the old unbounded `read_to_end` — the
   budget is the *combined* ceiling minus what's already been decompressed from earlier members in
   the same archive (not a fresh per-member allowance), since an archive with many small-looking
   members could otherwise smuggle an arbitrarily large aggregate past a naive per-member check.
   Reading `budget + 1` bytes rather than exactly `budget` is what lets a single `read_to_end` call
   detect the overflow (`contents.len() > budget`) without a second read.
4. **`parsers::regex_line::RegexLineParser::parse`** and **`parsers::json_path::parse_jsonl`**:
   `std::str::from_utf8(raw).map_err(...)?` (hard failure on any invalid byte) replaced with
   `String::from_utf8_lossy(raw)` (invalid sequences become `U+FFFD`, which can never form an
   IP-shaped token, so the practical effect is "that stretch of text extracts nothing" rather than
   "the whole feed fails"). **This is a deliberate behavior change, not a bug fix** — the prior
   behavior was intentional and had its own test (`rejects_non_utf8_body`) asserting the `Err`; that
   test is now `non_utf8_body_degrades_to_zero_entries_instead_of_erroring`, asserting the opposite,
   per this session's explicit Task 3 requirement. `JSON_PATH`'s non-`jsonl` path
   (`serde_json::from_slice`) needed no change: JSON syntax already requires valid UTF-8, so
   `serde_json` itself returns a clean `Err` (never a panic) on invalid bytes — lossy pre-decoding
   there would only risk corrupting a genuinely valid multi-byte UTF-8 string value at a chunk
   boundary for no benefit, since there's no boundary here (the raw bytes are the *whole* fetched
   body, never a partial read).
5. **Unrelated fix along the way**: `zip::write::FileOptions` is `Copy`, and clippy's
   `clone_on_copy` (part of `-D warnings`) caught a stray `.clone()` in one of this session's own
   new test helpers (`decompress.rs`'s aggregate-cap test, looping `start_file` across 5 members) —
   fixed immediately, not deferred; mentioned here only because it's the one clippy finding this
   session's own new code produced.

**Task 2 — verified, not implemented; no production code changed.** Read `vault_sync.rs`'s and
`external_ingestion.rs`'s per-target chunk loops closely before writing any test: both already
`break` out of a target's own chunk sequence on the first `client::post_batch` error (so a later
chunk is never attempted once an earlier one in the same sequence fails), already track
`target_ok`/`all_succeeded` correctly across that break, and `vault_sync::run` already only writes
`last_sync_at` when `all_succeeded` is true. This already fully satisfies "a mid-run chunk failure
must report `PARTIAL`/`FAILED` and withhold the sync cursor" — it just wasn't exercised by an
existing test at *chunk* granularity specifically (existing tests covered "one whole target is down
from its first request", not "chunk 1 of 3 succeeds, chunk 2 fails, chunk 3 must never even be
sent"). Two new tests close that gap directly rather than assuming the property held:
`mid_run_chunk_failure_stops_further_chunks_and_withholds_last_sync_at` (`vault_sync_tests.rs`,
upsert mode — the only mode `vault_sync_tasks` ever uses) and
`full_replace_mid_run_chunk_failure_stops_further_chunks_and_reports_partial`
(`external_ingestion_tests.rs`, `full_replace` mode — the literal shape this session's task
described, since `full_replace` was never extended to `vault_sync` in session 4 and that decision
stands unchanged). **The task's premise ("Chunk #1 executes full_replace... clearing target
entries... target Vault remains in a partially populated state") only applies to
`external_ingestion`**, not `vault_sync` — `vault_sync_tasks.mode` is still strictly `upsert`
(`SCHEMA.MD`, `AGENT.MD` §3.B), so its own version of this test uses `upsert`'s equivalent risk
(chunk 1 landing, chunk 2 failing, and the next run needing to redo the whole delta rather than
skip what chunk 1 already delivered) instead. Also worth being explicit about, since it's easy to
mistake for a gap: `external_ingestion.rs` has **no `last_sync_at`-style cursor to withhold** at
all — it re-fetches a feed's *entire* current content on every run regardless of the previous run's
outcome, so "the next scheduled run performs a complete re-sync" (the safety property Task 2 asks
for) already holds structurally there, with nothing to protect. `last_run_at` is still recorded
unconditionally on every run, same as before this session — it has only ever meant "the job
executed", never "the job succeeded".

**New test files / major additions:**

- `src/jobs/decompress.rs` (+6 unit tests): `single_member_exceeding_the_limit_is_rejected_without_fully_decompressing`
  and `combined_output_across_multiple_members_is_capped_in_aggregate` (the latter proving the
  ceiling is enforced on the *combined* total across members, not reset per member) for the ZIP
  path; `read_capped_body_passes_through_a_body_under_the_limit` and
  `read_capped_body_aborts_once_the_stream_exceeds_the_limit` against a real streamed
  `wiremock`/`reqwest::Response` (available here since `wiremock` is already a dev-dependency
  reachable from `src/`-level `#[cfg(test)]` modules, not just `tests/`); the three pre-existing
  ZIP tests updated for the new `max_decompressed_bytes` parameter.
- `src/parsers/regex_line.rs` (+2 tests, 1 renamed): `mixed_encoding_body_still_extracts_the_valid_utf8_portions`
  and `latin1_byte_in_a_comment_does_not_prevent_extraction` — a single bad byte sequence must stay
  local to the line/stretch it corrupted, not poison extraction from the rest of the body.
- `src/parsers/json_path.rs` (+2 tests): `raw_binary_body_is_a_clean_parse_error_not_a_panic` (the
  non-`jsonl` path) and `jsonl_mode_skips_a_non_utf8_line_without_failing_the_whole_body`.
- `tests/parser_tests.rs` (+3 tests): the same three properties above, black-box through
  `parsers::for_type`, plus a 10,000-byte deterministic (not `rand`-seeded, so reproducible)
  pseudo-random binary buffer fed to both parser types to confirm neither panics.
- `tests/external_ingestion_tests.rs` (+4 tests): `oversized_gzip_response_is_rejected_as_a_decompression_bomb_without_buffering_it_fully`
  (a real gzip-encoded ~50MiB+1KiB-of-repeated-bytes body — compresses to ~51KB on the wire at
  roughly 1000:1, *not* the "under 1KB" this session first assumed and had to correct after the
  test's own sanity-check assertion failed against the real ratio DEFLATE achieves on run-length
  data) through the full fetch pipeline; `oversized_zip_member_is_rejected_as_a_decompression_bomb`,
  the same shape via a `.zip`; `full_replace_mid_run_chunk_failure_stops_further_chunks_and_reports_partial`
  and `non_utf8_feed_body_does_not_crash_the_job_and_extracts_the_valid_ips` (Task 2/3 above).
- `tests/vault_sync_tests.rs` (+1 test): `mid_run_chunk_failure_stops_further_chunks_and_withholds_last_sync_at`.
- `scripts/test_e2e.sh`: `mock_vault.py` gained `failafter:<status>:<n>` (the mirror of the existing
  `retry:<status>:<n>` — succeeds the first `<n>` POSTs while this mode string is active, fails
  every one after that — for modeling a target that goes down mid-run rather than one recovering).
  Three new subsections inserted before section 7h's existing cleanup (reusing `EXTRA_MOCK` and
  `RESILIENCE_MOCK` from session 4 rather than spawning new processes): **7i** (a ~50MiB+1KiB ZIP
  bomb, tiny on disk, rejected `FAILED` with an explanatory message, no crash); **7j** (a two-target
  sync task where the "good" target completes all 4 push chunks of a 15,001-record delta and the
  "bad" target — `failafter:500:1` — accepts chunk 1 then fails every chunk after, reporting
  `PARTIAL` with the task's `last_sync_at` confirmed still `null` afterward, and the bad target's
  request log confirming chunks 3–4 were never attempted); **7k** (a Latin-1/raw-binary feed body
  extracting exactly its two valid IPs, `SUCCESS`, none of the encoding noise pushed).

**Test metrics after this session:**
- `cargo test` (default, offline): **136 tests**, 0 failed (up from 120: +8 lib unit tests
  (`decompress.rs` +4, `regex_line.rs` +2, `json_path.rs` +2), +8 integration tests
  (`vault_sync_tests.rs` +1, `external_ingestion_tests.rs` +4, `parser_tests.rs` +3)).
- `cargo test -- --ignored`: **5 tests**, 0 failed (unchanged).
- `./scripts/test_e2e.sh`: **192 checks** (up from 162), 0 failed, 0 skipped, run **twice
  consecutively** with an explicit post-run check for lingering `mock_vault.py`/`http.server`
  processes — clean both times, zero leaks.
- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`: both clean, zero
  warnings.

**Not done / flagged rather than assumed out of scope:**
- No `MAX_DECOMPRESSED_BYTES` protection was added for a *non-ZIP, non-`Content-Encoding`*
  expansion point, because there isn't one in this pipeline — the only two places bytes can expand
  are the two this session covers. If a future parser format introduces its own internal
  decompression (e.g. a `.tar.gz` or nested-archive feed), that format's own implementation would
  need to thread the same `max_decompressed_bytes` parameter through, following
  `decompress_if_zip`'s pattern.
- Task numbering note for future readers: doc comments in `tests/external_ingestion_tests.rs`
  reference "Task 1"/"Task 2"/"Task 3" from *this* session's own task list, which reuses the same
  numbers as pre-existing "Task 1"–"Task 4" comments left by earlier sessions' *different* task
  lists in the same file (e.g. line 86's "Task 1" is session 3's target-group-name-override task;
  line 399's "Task 1" is this session's decompression-bomb task). This ambiguity already existed
  before this session (session 4 added "Task 4" comments that likewise collide with an
  already-present "Task 4" from an earlier session) — flagged here rather than silently
  perpetuated, but not retroactively fixed across the whole suite, since every "Task N" label is
  already only ever meaningful relative to the task list active in its own originating session, not
  a global identifier.
- `./scripts/verify_convergence.sh` still does not exist (see sessions 1–2's decision) and was not
  requested as a gate this session.

## Session 6 (2026-08-17): cross-project test-pattern audit

Requested as an audit, not a features session: read every peer project's test suite in `example/`
(pulling each first, per `AGENT.MD`'s peer-sync rule), extract testing techniques not yet present
here, and adapt the genuinely applicable ones. **Read-only against `example/`** — every peer repo
was only `git pull --ff-only`d and read; all edits landed exclusively in `simply_ip_sync`'s own
tree.

**Projects audited** (all three under `example/`, each freshly pulled first):
- `simply_hook_executor` (`ee9209a`, already up to date) — `tests/health_probes.rs`,
  `referential_integrity.rs`, `rbac_model_compliance.rs`, `source_hygiene.rs`, `scripts/test_e2e.sh`.
- `simply_ip_exporter` (`bd90b7c` → `f23e17c`, fresh pull today) — `tests/integration.rs`,
  `source_hygiene.rs`, `scripts/test_e2e.sh`, and its new `src/extract.rs`/`error.rs` additions.
- `simply_ip_vault` (`e8f9c14` → `ff18806`, fresh pull today) — `tests/security_tests.rs`,
  `rbac_integration_tests.rs` (brand new — added the same day, alongside a real
  `since`-filtering/tombstone-visibility bug fix in `src/api/records.rs`), `rbac_model_compliance.rs`.

Audited via three parallel read-only research agents (one per peer), each briefed on this
project's existing coverage so findings were filtered against what's already here rather than
re-suggesting it. Every finding was then independently re-verified against `simply_ip_sync`'s
actual code (grep the real handler, read the real guard, run the test before trusting it) before
acting on it — two findings turned out to need correction after that step (see below).

**Patterns adapted, by source:**

- **`simply_hook_executor`**: a dedicated `tests/health_probes.rs` (new) proving liveness survives
  a severed database (`state.db.close_by_ref()`, not a mock) and readiness independently depends on
  *both* the database and the boot-time Master-pin invariant — including a startup-ordering test
  (an unpinned `MasterPin::new()` swapped into `AppState` post-`common::setup()`) that a
  steady-state-only suite structurally cannot produce, since every other test's harness has already
  pinned the master by the time it runs. Also a dedicated `tests/referential_integrity.rs` (new):
  cascade correctness proven *bidirectionally* (a doomed and a survivor source sharing one target
  vault — deleting the doomed one must not touch the survivor's junction row, which a single-row
  cascade test can't distinguish from "cascaded too broadly"), write-time FK rejection (not just
  delete-time), and — the most interesting port — a test proving `owner_key_id` on
  `external_sources`/`vault_endpoints`/`vault_sync_tasks` carries **no FK constraint at all**
  (confirmed against the migration: no `ForeignKey::create()` targets it), which is deliberate: a
  raw-SQL insert with a dangling `owner_key_id` succeeds where any other dangling FK in this schema
  is rejected. That absence is exactly why `keys.rs::delete_api_key` enforces ownership cleanup at
  the *application* layer (409 + resource inventory) instead — a property that turned out to have
  **zero existing test coverage** before this session (`tests/rbac_tests.rs` gained
  `deleting_a_key_that_still_owns_resources_is_blocked_with_inventory` and
  `deleting_a_key_with_no_owned_resources_succeeds`).
- **`simply_ip_exporter`**: `two_concurrent_identical_signed_requests_only_one_succeeds` → ported as
  `security_tests.rs::two_concurrent_replays_of_the_same_signature_only_one_succeeds` (fires two
  identically-signed requests through `tokio::join!` against the same shared-state `Router`,
  proving `ReplayGuard::check_and_record`'s check-then-insert is atomic under *real* concurrency,
  not just the sequential reuse the existing replay test already covered) — and the same technique
  applied to a resource delete (`rbac_tests.rs::concurrent_deletes_of_the_same_resource_do_not_both_succeed`),
  which **caught a genuine bug**: see "Production code changes" below. The exporter's
  `an_oversized_body_is_413_not_400` and its malformed-JSON-envelope-shape test were also ported —
  see the correction note below for why the first one's expected status changed on the way in.
- **`simply_ip_vault`**: `attack_single_bit_signature_mutations_never_verify` → ported as two
  `crypto.rs` unit tests, `every_single_bit_flip_of_a_valid_tag_fails_verification` (all 256 bit
  positions of a valid HMAC-SHA256 tag, individually) and `every_wrong_tag_length_fails_verification`
  (every length 0–63 except the correct 32) — strictly stronger than the existing single
  fixed-tamper test, which only samples 4 of a nibble's 16 possible hex values and can't isolate a
  short-circuit/word-boundary comparison bug. `s4_oracle_discipline_out_of_scope_is_indistinguishable_from_nonexistent`
  → ported as `rbac_tests.rs::out_of_scope_and_nonexistent_vaults_are_indistinguishable` (also
  present in `test_e2e.sh` §10a) — `simply_ip_sync` had per-owner visibility scoping on
  `GET /api/vaults/{id}` (out-of-scope → `404`, same as nonexistent) but no test pinning that the
  two cases are byte-identical, which is the actual enumeration-resistance property that matters.
  The vault's fresh `rbac_integration_tests.rs::batch_enforces_address_validation_and_rejects_duplicates`
  test (rejecting a whole batch containing `203.0.113.60` and `203.0.113.60/32` as the same address
  in two notations) prompted `external_ingestion_tests.rs::mixed_notation_duplicate_addresses_canonicalize_and_dedupe_to_one_record`
  — this one turned out to already be correctly handled here (see the correction note below), so the
  new test is a regression guard proving that, not a bug fix.

**Two findings that needed correction after verifying against real behavior, not just reading code:**

1. **Oversized-body status code.** The exporter's peer test expects `413`. Tracing
   `simply_ip_sync`'s actual request path (`middleware.rs::auth_middleware`) shows it reads the
   *entire* body itself via `axum::body::to_bytes(body, max_body_bytes())` — needed regardless,
   since `CANONICAL_V1` covers the body — and this happens *before* any handler or `StrictJson`
   extractor ever runs, with an oversized read mapped to `AppError::InvalidInput` → **`400`**, not
   `413`. `StrictJson`'s own `BodyRejected` → `413` path is consequently unreachable from any
   `/api/*` route under the current wiring (every route sits behind `auth_middleware`, which always
   consumes the body first). The ported test
   (`api_validation_tests.rs::oversized_inbound_body_is_rejected_cleanly_before_signature_verification`,
   plus `test_e2e.sh` §10a) asserts the real `400` and documents why, rather than asserting a status
   this codebase's architecture doesn't produce. (Two smaller mistakes surfaced while getting this
   test right and are worth naming so the next person doesn't repeat them: a `X-Timestamp` of
   `"1700000000"` fails the 300-second skew check *before* the API key is ever looked up, producing
   a misleading `401`; and passing an 11 MiB string as a `curl --data-binary` shell argument hits
   the OS's `ARG_MAX` ("Argument list too long") in `test_e2e.sh`, fixed by writing the body to
   `$WORK_DIR/oversized_body` and using `--data-binary @file` instead.)
2. **Canonicalization dedup — already correct, not a gap.** The vault's duplicate-rejection bug
   looked at first read like it might apply symmetrically to `simply_ip_sync`'s own outbound dedup
   (`external_ingestion.rs`'s `seen.insert(r.clone())`, which operates on raw strings). It doesn't:
   every `FeedParser` already runs each candidate through `parsers::normalize_ip_or_cidr` — which
   canonicalizes via `IpAddr`/`IpNetwork`'s own `Display` impl, not string manipulation — *before*
   the job layer ever sees it, so `/32`↔bare and unabbreviated↔abbreviated IPv6 spellings already
   collapse to one string ahead of the dedup step. Confirmed by writing the test before assuming
   either way; it passed on the first run.

**Production code changes (both found by writing the ported tests, not planned in advance):**

1. **Concurrent-delete race, fixed in four handlers.** The concurrent-delete test above initially
   *failed* — `[204, 204]`, not `[204, 404]` — against `delete_external_source`. Its
   find-then-delete sequence (`find_by_id` → `guard_resource_lifecycle` → `delete_by_id`) never
   checked whether the `DELETE` actually removed a row; SQLite's single-connection pool
   (`db::SQLITE_MAX_CONNECTIONS = 1`) serializes the four underlying queries from two concurrent
   requests, but not at request granularity, so both requests' `find_by_id` calls could observe the
   row before either's `delete_by_id` ran, and a `DELETE ... WHERE id = ?` matching zero rows is not
   a SQL error — the handler returned `204` regardless. Fixed identically in all four handlers with
   the same shape (`external_source`, `vault_endpoint`, `vault_sync_task`,
   `api_key_sync_permission` revoke): check `DeleteResult.rows_affected == 0` and return
   `AppError::NotFound` instead of an empty `204`. `delete_api_key` (subtree deletion via
   `delete_many`) was deliberately left alone — no test exercises its concurrency, and it's a
   different-shaped operation (bulk delete over a computed subtree, not a single lookup-then-delete)
   not obviously fixable with the same one-line pattern.

**A note on working conditions this session:** the repository's working tree was modified by
something outside this session twice while this work was in progress — first a `git reset` back to
`HEAD` (confirmed via `git reflog`: `HEAD@{0}: reset: moving to HEAD`, no stash created) that wiped
every tracked-file change in flight, including a separate, apparently concurrent effort that had
independently added a raw-SQL/unwrap-expect scanner to `tests/source_hygiene.rs` and several
related `src/` hardening fixes; then, later, a `git clean`-shaped removal of this session's two new
untracked files specifically. Neither event is this session's doing, and neither the other
concurrent effort's changes nor its author are known — flagged here as a fact about how this
session's numbers came together (redone twice from scratch) rather than a claim about what caused
it. Nothing from that other effort survived to be included in this session's final diff or its test
counts below.

**New test files / major additions:**

- `tests/health_probes.rs` (new, 6 tests): see "Patterns adapted" above.
- `tests/referential_integrity.rs` (new, 3 tests): see "Patterns adapted" above.
- `tests/rbac_tests.rs` (+6 tests): R1 non-amplification
  (`cannot_grant_can_sync_without_holding_it_yourself_r1`), R6 revocation-without-the-verb
  (`revocation_requires_only_manage_not_the_verb_itself_r6`), the two key-deletion-ownership tests,
  the oracle-discipline test, and the concurrent-delete test that caught the bug above.
- `tests/security_tests.rs` (+3 tests): `outbound_get_ips_delta_signs_correctly_with_since_and_include_deleted`
  (pins the exact query parameters — `group_name`, `since`, `include_deleted=true`, `limit`,
  `offset` — and that the signed target includes the query string, not just the path), the
  mid-body tamper test, and the concurrent-replay test.
- `src/crypto.rs` (+2 unit tests): the bit-flip and wrong-length sweeps.
- `tests/api_validation_tests.rs` (+2 tests): the oversized-body and malformed-JSON-envelope tests.
- `tests/external_ingestion_tests.rs` (+1 test): the canonicalization-dedup regression guard.
- `scripts/test_e2e.sh`: new §10a ("RBAC delegation (R1/R6) & enumeration resistance") — the R1/R6
  grant/revoke pair, the out-of-scope-vs-nonexistent oracle-discipline check (reusing the
  already-registered `SCRATCH_VAULT_ID` and `DAUGHTER_KEY` rather than provisioning new fixtures),
  and the oversized-body check (file-based `--data-binary @path`, not a shell argument).

**Test metrics after this session:**
- `cargo test` (default, offline): **159 tests**, 0 failed (up from 136: +6 `health_probes.rs`
  (new file), +3 `referential_integrity.rs` (new file), +6 `rbac_tests.rs`, +3 `security_tests.rs`,
  +2 `crypto.rs` unit tests, +2 `api_validation_tests.rs`, +1 `external_ingestion_tests.rs`).
- `cargo test -- --ignored`: **5 tests**, 0 failed (unchanged).
- `./scripts/test_e2e.sh`: **202 checks** (up from 192), 0 failed, 0 skipped, run **three times**
  across this session (once mid-session after §10a landed, twice more after the concurrent-delete
  fix) with an explicit post-run check for lingering `mock_vault.py`/`http.server` processes — clean
  every time.
- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`: both clean, zero
  warnings.

**Not done / flagged rather than assumed out of scope:**
- `simply_ip_exporter`'s canary-decrypt-at-boot pattern (detecting a syntactically valid but
  *wrong* `SYNC_ENCRYPTION_KEY` at startup by decrypting one known-sealed value as a canary, rather
  than only discovering the mismatch on the first real request) is a genuinely applicable gap —
  `simply_ip_sync` seals vault/key signing secrets under `SYNC_ENCRYPTION_KEY` the same way and has
  no equivalent check — but it is a new production startup behavior, not a test, and this session's
  scope was test-pattern audit and adaptation. Flagged for a future features session rather than
  implemented here.
- `delete_api_key`'s subtree-delete path was not given the same `rows_affected` check as the other
  four handlers (see "Production code changes" above) — no test currently exercises its
  concurrency, and its bulk-delete shape doesn't take the same one-line fix.
- `simply_hook_executor`'s `rbac_model_compliance.rs`-style "hot-flip" test (drop the
  `master_marker` unique index at runtime, insert a second `is_master=true` row via raw SQL, prove
  every mutating handler still refuses both) was not ported: `master.rs::MasterPin::authenticate`
  already demotes an impostor `is_master=true` row per-request regardless of the DB constraint
  (documented in its own doc comment: "an attacker with database write access does not need two
  Masters, only to demote the real one and promote itself"), and pinning that specific property
  with its own adversarial test is reasonable follow-up work rather than something this session had
  time to add on top of everything above.
- `./scripts/verify_convergence.sh` still does not exist (see sessions 1–2's decision) and was not
  requested as a gate this session.

## Session 7 (2026-08-17): closing the anomalies flagged in Session 6

Requested as a direct follow-up to Session 6's own "Not done / flagged" list: fix the readiness
probe's raw SQL, the delete-handler TOCTOU race, residual `unwrap`/`expect` in `main.rs`/`state.rs`,
and the missing encryption-key startup canary; close the `Path`/`Query` JSON-error-envelope gap;
add high-contention (`std::sync::Barrier`/many-way concurrent) tests reaching past the
single-connection SQLite pool; harden the E2E harness (`check_not_contains` with an empty-needle
guard); update `AGENT_NOTES.MD`/`FILE_MAP.MD`.

**Starting state was not a blank slate.** By the time this session began investigating, most of the
four anomalies were *already* fixed in the working tree — by a change this session did not make and
whose origin this session cannot identify (the repository has, over several recent sessions, shown
edits landing between turns that no session in this log claims; see Session 6's own note on the
same phenomenon). Rather than assume that work was either trustworthy or complete, everything below
was independently re-verified against the actual current source before being relied on, and new
tests were added specifically where verification showed a real gap remained. What follows is
organized by what was **verified as already correct**, and what this session **actually added**.

**Verified already correct (not this session's authorship, confirmed by reading and testing):**
- `api/health.rs::readiness_check` — already uses `ApiKey::find().count(&state.db)`, a typed SeaORM
  query, not `Statement::from_string(..., "SELECT 1")`. No raw SQL remains on the one unauthenticated
  route in the service.
- `keys.rs::revoke_key_permission`, `sources.rs::delete_external_source`,
  `vaults.rs::delete_vault_endpoint`, `sync_tasks.rs::delete_vault_sync_task` — all four already
  check `DeleteResult.rows_affected == 0` and return `AppError::NotFound` instead of an unconditional
  `204`, closing the concurrent-delete TOCTOU Session 6 found and fixed. Re-verified by re-running
  `tests/rbac_tests.rs::concurrent_deletes_of_the_same_resource_do_not_both_succeed` (still passing)
  and by writing a stronger 16-way version this session (see below).
- `main.rs::verify_encryption_key` + `crypto::check_key_canary`/`KeyCanary` — the startup canary
  Session 6 flagged as "not done" now exists: it opens one already-stored sealed secret with the
  configured cipher right after Master bootstrap, and refuses to start (logging operator-facing
  guidance) if it doesn't open. `NoSealedSecrets` handles the fresh-database case (nothing to check
  against yet) without falsely failing. This closes Session 6's one production-behavior gap.
- `main.rs::shutdown_signal` — no `.unwrap()`/`.expect()`; a signal handler that fails to install
  degrades to `pending()` for that arm rather than panicking the shutdown future.
- `extract.rs::StrictPath<T>`/`StrictQuery<T>` — both already exist alongside `StrictJson<T>`,
  fully adopted across every handler in `src/api/` (confirmed via `grep` — no bare `Path<_>`/
  `Query<_>` extractor remains anywhere in `src/api/*.rs`). `StrictPath`'s rejection is deliberately
  `AppError::NotFound`, not `InvalidInput` — a malformed id must stay indistinguishable from a
  well-formed id for a resource that doesn't exist (§4 oracle discipline), not merely get the same
  *envelope shape* as a validation error.
- `tests/concurrency_and_contracts.rs` (new file, already present) — a 16-OS-thread
  `std::sync::Barrier` test proving `ReplayGuard::check_and_record`'s check-then-insert admits
  exactly one winner under genuine contention (plus a companion test that distinct signatures never
  block each other), and four tests pinning the `StrictPath`/`StrictQuery` JSON-envelope contract
  (malformed path segment, malformed query string, the oracle-discipline pairing between a malformed
  id and a nonexistent one, and the unauthenticated probes answering inside the envelope too).
- `scripts/test_e2e.sh::pick_port` — already walks a range to avoid collisions (used for the main
  server port and every mock vault port); starts at the service's actual default port (3003) rather
  than an arbitrary 3000, which is more correct than the task's own illustrative example, not a gap.

**What this session actually added:**

1. **`crypto.rs` (+4 unit tests):** `check_key_canary` had zero direct test coverage despite being
   new security-critical code. Added `canary_reports_no_sealed_secrets_on_an_empty_database`,
   `canary_verifies_a_secret_sealed_under_the_same_key`,
   `canary_fails_closed_when_the_configured_key_does_not_match_the_sealed_secret` (the property the
   canary exists for), and `canary_passes_trivially_in_plaintext_mode` (no key configured means
   nothing to mismatch, so the canary must not spuriously fail).
2. **`tests/concurrency_and_contracts.rs` (+1 test):**
   `sixteen_concurrent_deletes_of_the_same_resource_admit_exactly_one_success` — the existing
   2-way `tokio::join!` concurrent-delete test (`rbac_tests.rs`, from Session 6) is what originally
   caught the TOCTOU race, but it doesn't match the 16-way contention scale this session's own
   replay-guard test uses. There is no in-process data structure to reach past with OS threads for
   *deletion* the way there is for the replay guard — the atomicity guarantee is the database's own
   per-statement atomicity plus checking `rows_affected`, not a hand-rolled lock — so `tokio::spawn`
   (real concurrent tasks against the single-connection pool) is the correct tool here, not
   `std::thread`. 16 concurrent deletes of one resource; exactly one `204`, the rest `404`. Stable
   across 8 consecutive runs before being trusted.
3. **`scripts/test_e2e.sh`:** added `check_not_contains` (ported verbatim in spirit from
   `example/simply_hook_executor`/`example/simply_ip_exporter`'s identical helper — refuses an empty
   needle rather than reporting a vacuous `PASS`, since `[[ "$x" == *""* ]]` is true for every
   string). Used it immediately in a new credential-leak canary: create a vault endpoint with
   distinctive, greppable `api_key`/`signing_secret` values, then assert neither ever appears in the
   create response, `GET /api/vaults/{id}`, or `GET /api/vaults` (list) — the property
   `FILE_MAP.MD` has claimed since it was written ("Credentials are never returned in any response")
   but that had no E2E assertion pinning it against the real compiled binary until now.
4. **`FILE_MAP.MD` refresh** — the file had drifted materially behind the actual `src/` tree:
   `src/retry.rs` was entirely absent; `extract.rs`'s entry didn't mention `StrictPath`/`StrictQuery`;
   `crypto.rs`'s entry didn't mention the canary; `config.rs`'s entry didn't mention
   `max_decompressed_bytes` or the retry tunables; `health.rs`'s entry didn't note the raw-SQL-to-
   typed-query change; `decompress.rs`'s entry didn't mention the byte-cap parameter; and the
   `tests/` table was missing `health_probes.rs`, `referential_integrity.rs`,
   `concurrency_and_contracts.rs`, and `client_resilience_tests.rs` outright. All fixed.

**Deliberately not changed, with reasoning:**
- `state.rs::AppState::for_tests` still uses `.expect("scheduler starts in tests")` and
  `.expect("http client builds")`. This is not a production code path — it is only ever called from
  `tests/common/mod.rs`; `main.rs::run()` calls `AppState::new()` (which is already `Result`-based)
  instead. AGENT.MD's rule is "zero `.unwrap()`/`.expect()` in production **or HTTP handlers** —
  `for_tests` is neither, and a test harness that panics loudly when its own setup is broken is the
  correct behavior, not a gap. Converting it to return `Result` and pushing `.expect()` out to every
  call site in `tests/common/mod.rs` would be pure churn for identical behavior.
- `keys.rs::delete_api_key`'s subtree bulk-delete (`delete_many().filter(...).exec(...)`) was **not**
  given the same `rows_affected` check as the other four handlers — flagged already in Session 6 and
  still true: no test exercises its concurrency, and it's a different-shaped operation (a computed
  subtree walk, not a single lookup-then-delete) that the one-line pattern doesn't transfer to
  cleanly. Left as a known, explicitly-tracked gap rather than a rushed, untested fix.
- `./scripts/verify_convergence.sh` still does not exist and was not run as a gate — `simply_ip_sync`
  is deliberately outside the `simply_ip_vault`/`simply_hook_executor` pair's convergence-diffing
  scope (see sessions 1–2, and `RBAC_MODEL.md`'s own status line). Building one was not one of this
  session's five tasks; only running it as a gate was mentioned, and there is nothing to run.

**Test metrics after this session:**
- `cargo test` (default, offline): **170 tests**, 0 failed (up from 165 at the start of this
  session's investigation, itself already up from Session 6's 159 via the unattributed prior work
  described above: +6 lib unit tests overall this session's investigation window, +1
  `concurrency_and_contracts.rs`; this session's own additions are +4 lib unit tests
  (`crypto.rs`'s canary tests) and +1 integration test (the 16-way delete)).
- `cargo test -- --ignored`: **5 tests**, 0 failed (unchanged).
- `./scripts/test_e2e.sh`: **212 checks** (up from 202), 0 failed, 0 skipped, run twice consecutively
  with an explicit post-run check for lingering `mock_vault.py`/`http.server` processes — clean both
  times.
- `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`: both clean, zero
  warnings.
- `./scripts/verify_convergence.sh`: does not exist for this service; not run (see above).

## Session 8 (2026-08-18): independent security and structural convergence reports (4-way)

Requested as a read-only, zero-knowledge/clean-room comparative audit against every peer in
`example/`, not a single named one — the task text gave two disjoint example peers
(`simply_hook_executor` or `simply_ip_vault`), but `example/` actually holds three
(`simply_hook_executor`, `simply_ip_exporter`, `simply_ip_vault`); asked the user which to use,
and the answer was explicit: compare against **all** of them. Both target reports
(`SECURITY_COMPARISON_REPORT.md`, `STRUCTURAL_CONVERGENCE_REPORT.md`) did not previously exist in
this repository and were created fresh, not overwritten.

**Task 0 — peer sync.** Ran `git pull` in each of the three peer checkouts under `example/`
(read-only elsewhere in those trees, per standing policy — see Session 2's clarification):
- `simply_hook_executor`: fast-forwarded to `15b8af6` (2026-08-18) — that project's own version of
  this exact task, "docs: finalize independent security and structural convergence reports",
  comparing itself against `simply_ip_vault`.
- `simply_ip_exporter`: fast-forwarded to `80a3b31` (2026-08-18) — same commit message, first time
  that project created its own two convergence-report files.
- `simply_ip_vault`: already up to date at `14c8fa3` (2026-08-17); no new commits.

**Methodology — zero-knowledge audit.** By the same logic that this session must not read its own
prior `SECURITY_COMPARISON_REPORT.md`/`STRUCTURAL_CONVERGENCE_REPORT.md` (neither existed yet, so
this was moot for `simply_ip_sync` itself), each peer's *own* two report files were explicitly
excluded from every research pass, since all three had just written or already had their own
self-comparison conclusions and reading them first would bias a fresh read of the actual code.
Facts for each peer were gathered by an independent `Explore`-type research pass per project (three
in total, run in parallel), each instructed to report only structured facts — file:line references,
exact names, exact status codes — not conclusions, and each explicitly told to skip that project's
own comparison-report files while reading everything else (`RBAC_MODEL.md`/`AGENT.MD`/`SCHEMA.MD`/
`FILE_MAP.MD`/`AGENT_NOTES.MD`/`src/**/*.rs`/`tests/**/*.rs`). Every fact used in the two final
reports was then re-derived against this project's own current source directly (not taken from
agent claims alone) before being included — e.g. the `deny_unknown_fields` 9/9 coverage count, the
`rows_affected` TOCTOU-check call sites, the `AppError` variant table, and the `guards.rs` function
list were all re-grepped/re-read fresh in this session rather than carried over from memory of
earlier sessions.

**Key findings surfaced by the comparison (full detail in the two report files):**
- `simply_ip_sync` has 100% `deny_unknown_fields` coverage (9/9 payload structs) — the only one of
  the four projects with universal coverage; `simply_ip_exporter` has zero occurrences anywhere
  (a gap that project's own notes already document), and the other two apply it only to key-admin
  payloads.
- A peer's own audit notes (`simply_ip_exporter`'s `AGENT_NOTES.MD`, dated 2026-08-17) recorded the
  concurrent-delete TOCTOU race as **present and unfixed** in `simply_ip_sync` across four delete
  handlers, at the commit it inspected. That finding is now stale — Session 7's work (`024ffc5`)
  closed all four of those plus a fifth (`revoke_key_permission`), independently of that peer's
  observation. Documented as a stale-finding correction in `SECURITY_COMPARISON_REPORT.md` §1.2
  rather than silently dropped.
- The oversized-body status code (400 in this project vs. 413 in all three peers) is confirmed,
  again, as a genuine architectural divergence rather than a bug — `simply_ip_exporter` proves the
  413 outcome is reachable even from a body-buffering middleware like this project's own, via one
  additional explicit `Content-Length` pre-check step this project does not have. Left as a
  precisely-described, not-yet-acted-on finding; fixing it was not in scope for this read-only task.
- Structural naming convergence is high across all four projects on no shared code path:
  `auth_middleware`, `MasterPin`, `ReplayGuard`, `SecretCipher`, `ClientIp` are named identically in
  all four; `simply_ip_sync` and `simply_ip_vault` have byte-identical `AppError` variant sets.
- `AGENT.MD`'s own text (line ~82) still says API keys are matched via "Argon2/SHA-256" when
  `support::hash_key` uses plain SHA-256 only — a stale-documentation observation, not a
  vulnerability (SHA-256 is the correct choice for a high-entropy random token). Noted in the
  security report; `AGENT.MD` itself was not edited (not the explicitly protected document for this
  task — that's `RBAC_MODEL.md`, read-only and untouched throughout — but also not asked to be
  corrected here).

**Explicitly not done:** no application code in `src/`/`tests/` was read for the purpose of
changing it, and none was changed, in either this repository or any peer under `example/` — this
was a strictly read-only pass except for the two new report files and this note.

**Final action:** `git add .`, commit
`docs: finalize independent security and structural convergence reports`, then `git push` — this is
the one task in this session's history that explicitly authorizes and requires pushing to the
remote.

## Session 9 (2026-08-18): repeat 4-way convergence pass + `AGENT.MD` philosophy section

A follow-up request, structurally identical to Session 8 (same 4-way zero-knowledge audit, same
two target report files, same mandatory-document list) but adding one new task: document, inside
`AGENT.MD` itself, *why* `example/` exists — not just the pull-before-analyze mechanics Session 2
already added there, but the philosophy (security posture parity, architectural alignment, testing
strategy comparison) and the historical origin (`simply_ip_vault` + `simply_hook_executor` as the
founding, tightest-converged pair; `simply_ip_exporter` and this project as later peers the
ecosystem scaled to).

**Task 0 — peer sync, re-run.** `git -C example/<peer> pull --ff-only` against all three peers:
- `simply_hook_executor`: **already up to date** at `15b8af6` (2026-08-18) — no new commits since
  Session 8.
- `simply_ip_exporter`: **already up to date** at `80a3b31` (2026-08-18) — same.
- `simply_ip_vault`: **already up to date** at `14c8fa3` (2026-08-17) — same.

No peer had moved since the last audit, and this repository's own `HEAD` (`72cce13`) was likewise
unchanged going into this session (`git status` clean, no drift since Session 8's push) — so the
factual substance of both reports is expected to be, and is, materially the same as Session 8's.
Both reports were nonetheless rewritten from scratch this session (not diffed against or copied
from the previous version) to genuinely satisfy the zero-knowledge instruction — the previous
version of neither file was opened or read before writing the new one.

**Task 3 — `AGENT.MD` philosophy section.** Added a new "Why `example/` Exists" subsection inside
the existing "🔄 Peer Repository Synchronization" section (which already covered the *mechanics* of
pulling before analyzing, added in an earlier session), covering the three purposes named in the
task brief and the founding-pair/scaling history. `RBAC_MODEL.md` was not touched — it remains the
one document under an explicit read-only constraint.

**Findings:** unchanged in substance from Session 8 — see that session's entry for the full list
(100% `deny_unknown_fields` coverage in this project vs. partial/zero in the three peers; the
400-vs-413 oversized-body divergence; the stale "Argon2/SHA-256" line in `AGENT.MD`, now doubly
confirmed still present at the time of this session and still not corrected, since correcting it
was not part of either session's task list). No new vulnerability or structural finding surfaced by
re-running the pass against an unchanged ecosystem.

**Final action:** `git add .`, commit
`docs: finalize independent security/structural reports and update AGENT.MD`, then `git push`.

## Session 10 (2026-08-19): harmonization with `simply_ip_vault` — retention, migration standards, RBAC test rename, `verify_convergence.sh`

Requested as a five-task harmonization pass against `simply_ip_vault` specifically (not the
4-way comparison Sessions 8-9 ran): core-module parity, `retention.rs`, frontend design tokens,
an RBAC test-suite rename/alignment, SeaORM migration-naming standards plus an audit-attribution
`NOT NULL` migration, and a new `scripts/verify_convergence.sh`. The task as first delivered named
`simply_hook_executor` as the target service while this repository's own mandatory documents and
task body described `simply_ip_sync`'s own modules (`external_sources`, `vault_sync_tasks`) — asked
the user via `AskUserQuestion` rather than guessing which repository was meant, since acting on the
wrong one would have meant writing to a read-only peer checkout; the user confirmed the task was
meant for `simply_ip_sync` and resent it with the corrected framing.

**Core module harmonization (`error.rs`, `extract.rs`, `crypto.rs`, `middleware.rs`) — verified
already at parity, not re-written.** Read both this project's and `simply_ip_vault`'s current
implementations side by side before touching anything: identical `AppError` variant set and
`{"error": ...}` envelope mechanics (`ConflictWithDetails`'s merge-at-top-level logic is
byte-for-byte the same shape), identical `StrictJson` remap-only-content-errors design, identical
XChaCha20-Poly1305/`CANONICAL_V1`/`verify_slice` crypto primitives, identical
timestamp→lookup→body/signature→replay→`bound_ips`-last middleware ordering. This project's
`extract.rs` additionally has `StrictPath`/`StrictQuery` (the peer has neither), and `crypto.rs`
already has the boot-time `check_key_canary` the peer lacks — so on the two axes where the two
differ, this project is ahead, not behind. No code changes were made to any of these four files;
making changes to already-converged code would have been churn, not harmonization.

**`src/retention.rs` — new file.** This project has no soft-deleted *resource* rows anywhere in its
schema (confirmed via `grep -rn is_deleted src/entities/` — nothing) — RBAC §6 uses
hard-delete-with-cascade-inventory instead, so the peer's "purge soft-deleted IP records" pattern
doesn't transfer directly. Adapted the same shape (env-configurable retention window, `0` disables,
malformed value warns-and-falls-back, `MissedTickBehavior::Delay` on the sweep ticker) to what this
project actually has unbounded growth in: `sync_logs` and `audit_logs`. Gave the two independent
env vars (`SYNC_LOG_RETENTION_DAYS_ENV` default 92, `AUDIT_LOG_RETENTION_DAYS_ENV` default 365)
rather than one shared window, since operational job-run noise and the security/compliance audit
trail reasonably want different horizons — a design decision made explicitly, not left implicit.
Spawned detached (`tokio::spawn`, not threaded through graceful shutdown) since a purge sweep is a
bounded, idempotent `DELETE ... WHERE timestamp < threshold`, unlike the in-flight HTTP requests
graceful shutdown actually needs to drain. 4 new unit tests (window boundary for each table
independently, `0` disables both, malformed env falls back to default).

**Migration standards + `audit_attribution_not_null` migration.** Audited both existing migrations
against a strict `m<YYYYMMDD>_<NNNNNN>_<name>.rs` reading — both already conform
(`m20260101_000001_initial_schema`, `m20260101_000002_derive_master_marker`; the `NNNNNN` segment
was already a zero-padded sequence number, matching the convention `simply_ip_vault`'s own
migrations use, e.g. `m20260811_000010_...`) — so no renaming was needed, only documenting the rule
that was already being followed. Added `AGENT.MD`'s new "SeaORM Migration Standards" section
codifying the naming rule and the audit-attribution pattern. Then applied that second rule for
real: confirmed `create_audit_log`'s signature takes `key: &api_key::Model` and `client_ip: IpAddr`
by value (not `Option`), so all 18 call sites across `keys.rs`/`sources.rs`/`sync_tasks.rs`/
`vaults.rs` already always supply real values — the `Option<String>` on `api_key_name`/
`api_key_prefix`/`client_ip` was schema-only nullability nothing in the application ever actually
used. Added `m20260818_000003_audit_attribution_not_null`, ported from `simply_ip_vault`'s own
migration of the same name/purpose (backfill pre-existing `NULL`s to the sentinel `"(unknown)"`,
then constrain; SQLite rebuild via a shared `table_definition(attribution_not_null: bool)` so `up`
and `down` cannot describe different tables — its own `#[cfg(test)]` module asserts exactly that).
Updated `audit_log::Model`'s three fields from `Option<String>` to `String` and
`support::create_audit_log`'s `ActiveModel` construction to match; updated `SCHEMA.MD`'s
`audit_logs` table. 2 new unit tests ship with the migration itself.

**`tests/rbac_tests.rs` → `tests/rbac_model_compliance.rs`.** Renamed and restructured so every
test is named after the exact `RBAC_MODEL.md` rule/section it proves (`r1_`…`r7_`, `s3_`…`s7_`),
matching the indexing convention `simply_ip_vault`'s own compliance suite uses. 8 of the 13
pre-existing tests already mapped cleanly to a rule (renamed in place); 5 rules had no dedicated
test before this session (R2, R3, R5, R7, §7) and got new ones, written directly from
`api/guards.rs`'s actual logic rather than from the spec text alone — every one passed on the first
run, which is itself a fact worth recording: it means the mental model of `guard_resource_manage`/
`guard_delegated_grant`'s conjunction logic used to write the tests matched the code exactly, not
approximately. The `ADVERSARIAL(§5)` raw-SQL test that already existed in
`schema_integrity_tests.rs` was moved (not duplicated) into the compliance file, since rule-tagged
and adversarial tests belong indexed together per the peer's own convention; a new
`ADVERSARIAL(§7)` test (duplicate `key_hash` rejected by the DB's own `UNIQUE` constraint) and a
non-adversarial `s7_mandatory_indexes_exist` (checks all 10 named indexes via `db::has_index`
against the live catalog, not the migration source) were added since §7 previously had no test at
all. Fixed four stale `tests/rbac_tests.rs` cross-references in `RBAC_MODEL.md` §7,
`concurrency_and_contracts.rs`, and `referential_integrity.rs`. Suite grew from 13 tests to 20.

**`scripts/verify_convergence.sh` — new file.** Did not exist for this project before this session
(Sessions 1-9 all noted it as "not run, doesn't exist for this service, deliberately outside
`simply_ip_vault`/`simply_hook_executor`'s convergence scope"). Adapted from `simply_ip_vault`'s own
script (peer-sync-then-warn-not-fail, `extract_fn`/`normalize`/`compare_fn` structure, per-pillar
assertions) with one structural change Pillar 0 required: this project's `RBAC_MODEL.md` is a
deliberate *restatement*, not the peer's byte-identical shared file, so byte-diffing it would fail
by design — replaced with a check that every normative section heading (R1-R7, §3-§7) is present,
plus the same rule-coverage and adversarial-coverage checks the peer's script runs against its own
compliance suite, retargeted at `tests/rbac_model_compliance.rs`. Two real false positives surfaced
and were fixed while getting the script to a clean run: (1) the raw-SQL scanner initially flagged
`db.rs::has_index`'s three backend-specific catalog queries (`sqlite_master`/`pg_indexes`/
`information_schema.statistics`) as smuggled DML — fixed by widening the `db.rs` exemption window to
recognize catalog-table names, the same class of exemption `PRAGMA` already got; (2) the
`extract_fn`/`normalize` pipeline reported `resolve_client_ip`/`is_trusted` as drifted purely
because rustfmt wrapped the peer's parameter list one-per-line where this project's stayed on one
line — fixed by joining the whole normalized function body into a single line before diffing
(collapses any line-break-only difference) and stripping a leading `pub` from `fn`/`async fn`
(visibility is not the behavior being compared). After both fixes: `52 matching, 2 documented
divergences (the peer's split `resolve_bind_addr`/`parse_bind_addr` vs. this project's fused
single function; each side's own from-scratch-tuned pragma set), 0 unexplained` — clean pass, run
twice (once with `SKIP_PEER_SYNC=1`, once for real against the network).

**Frontend (`static/`).** `app.js` was already fully aligned on the substantive axes the task asked
about — it already sends all three `CANONICAL_V1` headers and already parses the `{"error": ...}`
envelope with a fallback (`(data && data.error) || \`HTTP ${resp.status}\``) — confirmed by reading
before assuming a gap existed. `style.css` genuinely lacked several token *categories* the peer's
design system has (a two-step radius scale, shadow tokens, a dedicated monospace font stack, named
transition speeds) even though this project's own color palette is deliberately kept rather than
swapped for the peer's Breeze theme — added the missing categories to `:root` and wired them into
representative existing rules (button/nav transitions, toast/panel shadow, monospace elements) as a
bounded, verifiable pass rather than a full visual rewrite unjustified for a ~4x-smaller,
different-domain dashboard.

**Quality gates, all clean at session end:** `cargo check --all-targets`, `cargo clippy
--all-targets -- -D warnings` — zero warnings. `cargo test` — **182 passed, 0 failed, 5 ignored**
(up from 170 at Session 7's end: +4 `retention.rs`, +2 the new migration's own tests, +7 net on the
renamed/expanded RBAC suite (20 vs. 13, minus the 1 adversarial test moved out of
`schema_integrity_tests.rs`)). `./scripts/test_e2e.sh` — **212/212 checks passed**, unchanged from
Session 7 (no new HTTP-surface behavior this session, so no new E2E coverage was owed).
`./scripts/verify_convergence.sh` — **PASSED**, run for the first time ever against a real peer
(52 matching / 2 documented / 0 unexplained). `src/` grew from 42 to 47 files (`retention.rs`, the
new migration, plus no other new modules); `tests/` stayed at 14 files (one renamed, none added or
removed net).

**Not done, with reasoning:** did not rename `m20260101_000001_initial_schema.rs`/
`m20260101_000002_derive_master_marker.rs` — both already conform to the naming rule this session
formalized in `AGENT.MD`, and renaming a migration that has already been applied against any
existing database would break that database's migration-history table, which is a materially
different (and far riskier) action than documenting a rule the files already satisfy. Did not
rewrite `static/app.js`'s reactive table/modal state machine or attempt visual parity with the
peer's ~3x-larger dashboard — the task's own substantive asks about it (JSON errors, HMAC headers)
were already met, and a wider rewrite would be scope creep against a functionally different,
smaller product. No commit/push instruction was given in this task's `validation_and_quality`
block (unlike Sessions 8-9's explicit authorization) — changes are staged for review, not
committed, pending explicit instruction.

### Session 10 addendum (same day): closing the two gaps `SECURITY_COMPARISON_REPORT.md` named

A follow-up task arrived mid-session, referencing this project's own security/structural reports
and asking to close the two specific gaps they had documented as accepted-but-real divergences: the
nullable audit-attribution columns, and the 400-vs-413 oversized-body status code.

**Audit attribution `NOT NULL` — already done earlier this same session.** The task's Task 1 asked
for exactly `m20260818_000003_audit_attribution_not_null.rs`, which this session had already
written a few hours earlier (see above) — confirmed still present and unmodified rather than
redone. One deliberate deviation from the task's suggested backfill values, kept and recorded here
rather than silently applied: the task suggested `"UNKNOWN"` for the two name/prefix columns and
`"0.0.0.0"` for `client_ip`. `"0.0.0.0"` is a real, meaningful address (conventionally "any
interface" / "unspecified address") — using it as a sentinel would make a genuinely-unattributed
historical row indistinguishable from one legitimately recorded against that address, which is
exactly the failure mode the migration's own doc comment (and `simply_ip_vault`'s original, which
this was ported from) explicitly warns against: "a backfill that wrote... `"127.0.0.1"` would be
indistinguishable from a genuine record, which is a worse outcome than the NULL it replaces." Kept
the existing `"(unknown)"` sentinel for all three columns uniformly instead — unmistakable, and
already shipped with its own unit test (`the_backfill_value_cannot_be_confused_with_a_real_one`)
proving it can't parse as an IP address or read as a plausible name.

**400 → 413 for oversized inbound bodies — genuinely new work this addendum did.** `auth_middleware`
(`src/middleware.rs`) buffers the whole request body itself, before any handler or `StrictJson`
extractor runs, because it needs the raw bytes to verify the `CANONICAL_V1` signature — that's why
an overflow there had been surfacing as `AppError::InvalidInput` (`400`) instead of the
`AppError::BodyRejected` (`413`) path every other body-size rejection in the ecosystem uses. Fixed
with the same two-part approach `simply_ip_exporter`'s own `auth_middleware` uses (per the earlier
zero-knowledge audit): (1) an explicit `Content-Length` pre-check — reject with `413` before a
single byte is read, when the client honestly declares a length over `max_body_bytes()`; (2) remap
the `to_bytes` call's own overflow fallback (the case with no declared `Content-Length`, or a
chunked body) to `413` as well, instead of `400`. Both paths return the standard
`{"error": "Request body exceeds the maximum allowed size"}` envelope via `BodyRejected`, so the
JSON contract stays uniform regardless of which of the two catches a given oversized request.
Updated the one Rust test that pinned the old `400` behavior
(`oversized_inbound_body_is_rejected_cleanly_before_signature_verification`) to expect `413`, and
added a new one exercising the `Content-Length` pre-check specifically
(`a_declared_content_length_over_the_limit_is_rejected_without_reading_the_body` — a mismatched
`Content-Length`/actual-body-length request that must be rejected without axum ever attempting to
read the (much smaller) body, proving the fast path is real and not merely coincidentally correct
because the slow path also happens to catch it). Updated `scripts/test_e2e.sh`'s equivalent
real-socket check to expect `413` and added a `check_jq` assertion on the envelope's `error`
message. `SECURITY_COMPARISON_REPORT.md`/`STRUCTURAL_CONVERGENCE_REPORT.md` were left as the dated
snapshots they are (their own headers name the commit audited) rather than edited in place — this
note is the living record that the finding they both describe is now closed as of this commit.

**Metrics after this addendum:** `cargo test` — **183 passed, 0 failed, 5 ignored** (up from 182:
+1, the new `Content-Length` pre-check test). `./scripts/test_e2e.sh` — **213/213 passed** (up from
212: +1, the new `check_jq` envelope assertion on the same check block).
`./scripts/verify_convergence.sh` — still **PASSED**, 52 matching / 2 documented / 0 unexplained
(unaffected by this change — no pillar in that script currently asserts the body-size status code).
`cargo check --all-targets`/`cargo clippy --all-targets -- -D warnings` — clean.

**Commit:** both this addendum's changes and the earlier harmonization work in this same session
are staged together under the addendum's own message,
`fix(sync): enforce NOT NULL on audit attribution columns and return 413 for oversized bodies` —
no push instruction was given, so the commit was made locally only.

## Session 11 (2026-08-19): migrations renamed to literal `mYYYYMMDD_HHMMSS_*` timestamps

Session 10's own addendum had explicitly declined to rename `m20260101_000001_initial_schema.rs`/
`m20260101_000002_derive_master_marker.rs`, reasoning that the `NNNNNN` segment was already a valid
zero-padded sequence number matching the convention documented in `AGENT.MD`, and that renaming an
already-applied migration is a breaking change against any database with real history (the
filename is the identifier `seaql_migrations` tracks). The user overrode that caution directly this
session: confirmed the project has no production deployment yet, and asked for the literal
`HHMMSS` (not sequence-number) format explicitly. With that confirmation, renaming stopped being
unsafe and became just a normal edit.

**What changed.** All three migrations renamed via `git mv` (preserves history) to a literal
authored-time format, using each file's real first-commit timestamp as the `HHMMSS` (git blame,
not invented): `m20260101_000001_initial_schema.rs` → `m20260101_013240_initial_schema.rs` and
`m20260101_000002_derive_master_marker.rs` → `m20260101_013241_derive_master_marker.rs` (both
authored in the same commit, `f891b44`, at `01:32:40+02:00`; the second bumped by one second since
two files cannot share an identical timestamp under this convention and still express which came
first). `m20260818_000003_audit_attribution_not_null.rs` → `m20260818_010217_audit_attribution_not_null.rs`
(real commit time `01:02:17+02:00`, on the `a48e919` commit from Session 10's addendum; the
`20260818` date segment was kept as originally chosen — the session's own "today" — even though the
literal commit timestamp technically landed just past midnight into the 19th).

**Everything downstream of the file names updated in the same pass:** `src/migration/mod.rs`'s
`mod` declarations and `Box::new(...)` registrations (module names are derived from file names, so
these are not optional); cross-reference doc comments in `src/master.rs`, `src/entities/api_key.rs`,
`src/entities/audit_log.rs`, `src/migration/m20260101_013240_initial_schema.rs` (referenced its
sibling by old name); `RBAC_MODEL.md` §5's citation; `scripts/verify_convergence.sh`'s two
`assert_present` file-path arguments; `FILE_MAP.MD`'s migration-section prose; `SCHEMA.MD`'s
`audit_logs` table's three `NOT NULL` footnotes; `AGENT.MD`'s "SeaORM Migration Standards" section
itself — rewrote rule 1 to describe the naming segment as a literal time-of-day rather than a
sequence counter (the rule text and the files it describes must agree, or the section becomes
exactly the kind of stale documentation this project's own audits keep flagging in `AGENT.MD`), and
added an explicit note that renaming an *already-applied* migration is unsafe against a database
with real history and was only done here because the project confirmed it has none yet.
`tests/referential_integrity.rs`'s one comment citing the initial-schema file by name. Left
`AGENT_NOTES.MD`'s own historical Sessions 8-10 entries untouched — they are a dated log of what was
decided and why at the time (including the earlier, now-superseded decision not to rename), not a
living reference; correcting them in place would erase the record of that reasoning rather than
supersede it, which is what this entry does instead.

**Verification.** `cargo check --all-targets`/`cargo clippy --all-targets -- -D warnings` clean.
`cargo test`: unchanged at 183 passed / 0 failed / 5 ignored — renaming a migration file changes
nothing SeaORM's `Migrator` sees at the *value* level (the migration name it records comes from the
module, which was renamed consistently), so no test assertions needed to change, only the
`mod.rs`/cross-reference wiring. `./scripts/test_e2e.sh`: 213/213, unchanged.
`./scripts/verify_convergence.sh`: still PASSED, 52 matching / 2 documented / 0 unexplained — its
two `assert_present` checks against the master-marker migration's file path were updated to the new
name and still find what they're looking for.

**Not done:** did not touch `example/` in any way (read-only per standing policy, and irrelevant to
a purely local file-naming decision). Did not add a fourth migration or otherwise touch schema
content — this was a rename-and-propagate-references pass only.

## Session 12 (2026-08-19): `API_REFERENCE.md` — exhaustive endpoint catalog

Requested as a fresh, zero-knowledge documentation audit: catalog every HTTP endpoint this service
exposes, with no reliance on any prior summary of the API (there wasn't one — `API_REFERENCE.md`
did not exist before this session).

**Methodology.** Read `src/lib.rs`'s `create_app` route table directly (the single place every
route is registered, including the `/healthz`/`/readyz` aliases), then every handler function in
all seven files under `src/api/` (`health.rs`, `keys.rs`, `vaults.rs`, `sources.rs`,
`sync_tasks.rs`, `sync_logs.rs`, `audit.rs` — confirmed exhaustive via `api/mod.rs`'s `mod`
declarations, which name exactly these seven plus `guards`/`support`, neither of which registers a
route), `src/middleware.rs` (header requirements and verification order), and `src/extract.rs`
(`StrictJson`/`StrictPath`/`StrictQuery`'s exact rejection→status mapping). Every payload struct's
field list, `#[serde(deny_unknown_fields)]` presence, and every guard function call site was read
from the handler bodies directly, not inferred from names.

**What the audit found:** 34 route registrations (method+path pairs) resolving to 32 distinct
handler functions — `health_check` and `readiness_check` each answer two path spellings
(`/health`+`/healthz`, `/ready`+`/readyz`). No handler was found unreachable from the route table
and no route was found pointing at a function absent from `api/mod.rs`'s re-export surface — the
route table and the handler set agree exactly.

**Structure of `API_REFERENCE.md`:** an opening transport/authentication section (the exact header
list and `auth_middleware` verification order, numbered 1–10, matching the real `if`/`?`
sequence in the source — including the deliberate `bound_ips`-checked-last ordering and the
`Content-Length`-precheck-then-`to_bytes`-cap two-step for the `413` path) and the standard error
envelope/status table (from `error.rs`'s `AppError` match arms), then one section per resource
(`/api/keys` split into 3.1 identity/listing, 3.2 lifecycle, 3.3 permission grants, since the file
covers all three; `/api/vaults`, `/api/sources`, `/api/sync-tasks`, `/api/sync-logs`,
`/api/audit-logs`), each with a per-route table (method/path/auth/body/response), the full response
schema, and every request payload's field table with required/default/notes columns pulled from the
`#[serde(default = "...")]` functions and doc comments actually attached to each field. Closes with
an audit-action taxonomy (all 18 `action` string literals actually passed to `create_audit_log`,
grep-confirmed) and a flat 34-row quick-reference index.

**Cross-linked into the existing document hierarchy** (Task 3): `AGENT.MD`'s "Document & Context
Hierarchy" list was stale before this edit — it said "responsibilities are split across three
files" while already listing five (a drift from an earlier, unrelated addition); fixed the count
wording to "these files" while adding `API_REFERENCE.md` and `RBAC_MODEL.md` as explicit entries
(the latter was previously described only in its own file, never listed in `AGENT.MD`'s hierarchy
at all — a second, separate staleness this pass also closed). `FILE_MAP.MD`'s "Companion documents"
header line, which already named `AGENT.MD`/`SCHEMA.MD`/`RBAC_MODEL.md`/`AGENT_NOTES.MD`, now also
names `API_REFERENCE.md`.

**Verification:** `cargo check --all-targets`/`cargo clippy --all-targets -- -D warnings` clean
(no source code was touched — this was a documentation-only session, `src/`/`tests/` diff is
empty). `cargo test`: unchanged at 183 passed / 0 failed / 5 ignored. `./scripts/verify_convergence.sh`:
still PASSED, 52 matching / 2 documented / 0 unexplained.

`./scripts/test_e2e.sh` reported **211/213**, two failures, both in the same live-network
subsection (`live-mass-scanner`, `https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt`).
Confirmed via a direct `curl` that the upstream file now answers `404` — it has been moved,
renamed, or removed in the `stamparm/maltrail` repository since this fixture was last verified
against the live source, unrelated to anything changed this session (`scripts/test_e2e.sh` itself
has zero diff and was last touched two sessions ago, commit `a48e919`). Not fixed here: swapping or
hardening a live external URL is a test-fixture maintenance task outside this session's scope
(documentation only), and the same class of flakiness is exactly why `tests/live_feed_ingestion_tests.rs`
is separately `#[ignore]`d from the default `cargo test` run. Left as a known, external, dated
finding for whichever session next touches `scripts/test_e2e.sh`'s live-network fixture list.

**Not done:** no changes to `RBAC_MODEL.md`'s own content (only referenced, not edited) or to any
file under `example/`.
