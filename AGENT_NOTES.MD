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
