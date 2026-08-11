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

**Not yet done, flagged for a future session:**
- No `scripts/verify_convergence.sh` equivalent for this service (see decision 2 above).
- No live Docker build was performed — `docker` was not available in the environment this session
  ran in. The `Dockerfile`/`docker-compose.yml` were inherited as a copy-paste from
  `simply_ip_exporter` (wrong binary name, wrong port) and corrected to match this service, but the
  image itself is unverified. Build and smoke-test it before first deployment.
- No headless-browser verification of `static/app.js` — reviewed by hand (balanced
  backticks/braces including the one legitimately-nested template literal in `showKeyForm`;
  `node`/`deno`/any JS engine was unavailable in-session to parse-check it). Confirmed the server
  serves `index.html`/`app.js`/`style.css` correctly via `curl`; the dashboard's actual runtime
  behavior in a browser has not been exercised end-to-end.
- Hostname-based `TRUSTED_PROXIES` entries (see decision 4).
