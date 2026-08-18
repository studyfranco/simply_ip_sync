# Security Comparison Report — Ecosystem-Wide (4-Way)

**Audited service (this repository):** `simply_ip_sync` @ `024ffc5` (2026-08-18)
**Compared against:**
- `example/simply_hook_executor` @ `15b8af6` (2026-08-18)
- `example/simply_ip_exporter` @ `80a3b31` (2026-08-18)
- `example/simply_ip_vault` @ `14c8fa3` (2026-08-17)

**Methodology:** Zero-knowledge / clean-room audit. This report was produced by reading each
project's current `.rs` source, `RBAC_MODEL.md` (or, for `simply_ip_exporter`, its own
`AGENT.MD`), `SCHEMA.MD`, `FILE_MAP.MD`, and `AGENT_NOTES.MD` directly — it does **not** read or
rely on any project's own prior `SECURITY_COMPARISON_REPORT.md` or
`STRUCTURAL_CONVERGENCE_REPORT.md`, including `simply_ip_sync`'s own (this file, overwritten
wholesale). Facts for the three peers were gathered by independent research passes explicitly
instructed to skip those files, then re-verified by hand against exact source before being
included below. See `AGENT_NOTES.MD` Session 8 for the pull log and methodology note.

---

## 1. Zero-Knowledge Security Assessment

This section evaluates each project independently against its own stated model, then flags
cross-project gaps.

### 1.1 Findings by project

| # | Finding | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|---|
| F1 | `update_*` handler exempts Master from an immutability rule its own RBAC/AGENT doc states | Not found — `guards::guard_master_immutable` gates every field except `bound_ips` on every Master-touching write path | Not found — `guard_master_self_edit_is_bound_ips_only` enforced | **Found**: `update_api_key` has no `existing.is_master` special case at all — a Master caller can change the Master row's own `name`/`can_manage_keys` through the ordinary update endpoint, not just `bound_ips`. Not a violation of *this project's own* AGENT.MD (which never states the bound-ips-only restriction), but a real divergence from what RBAC_MODEL.md's language would require if this project were bound by it — it explicitly is not. | Not found — `guard_master_immutable` enforced |
| F2 | Startup encryption-key canary present (proves key is *correct*, not just well-formed) | **Present** — `crypto::check_key_canary` / `KeyCanary` enum, called from `main.rs::verify_encryption_key` | Not confirmed by this pass (not in the peer's own `main.rs` facts gathered) — treat as unverified rather than absent | **Present** — `main::verify_encryption_key`, canary-decrypts the Master row's sealed `signing_secret` at boot | **Absent** — `SecretCipher::from_env` validates only 64-hex-char *format*; a wrong-but-well-formed key surfaces only later, per-request, as a 500 |
| F3 | `deny_unknown_fields` coverage on mutating payload structs | **9/9 (100%)** — every `Create*`/`Update*`/`Grant*` payload | Applied only to key-admin payloads (`CreateApiKeyPayload`, `UpdateApiKeyPayload`, `EntityResolution`, `DeleteApiKeyPayload`); **absent** on `CreateHookPayload`/`UpdateHookPayload`/`UpdateParameterPayload` | **0 occurrences anywhere in `src/`** — a self-documented gap in the project's own `AGENT_NOTES.MD` | Applied to key-admin + batch payloads (`CreateApiKeyPayload`, `UpdateApiKeyPayload`, `BatchRecordsPayload`/`BatchRecordInput`); **absent** on `CreateIpGroupPayload`, `BanWhitePayload`, `CreateWebhookPayload`/`UpdateWebhookPayload`, `GroupPermInput` |
| F4 | TOCTOU race on concurrent delete-by-id (`rows_affected` unchecked) | **Fixed** — all 5 delete/revoke call sites (`vaults.rs`, `keys.rs` ×2, `sources.rs`, `sync_tasks.rs`) check `rows_affected == 0 → 404`; a peer's own audit notes (see §1.2) had flagged this as unfixed in an earlier commit of this project — it has since been closed | **Fixed** (soft-delete variant) — was a real bug (two concurrent deletes both returned `204`, producing duplicate audit rows), fixed by conditioning the soft-delete write on the row still being live | **Fixed** — `delete_api_key`/`delete_endpoint` both check `rows_affected == 0 → 404` | **Deliberately not a strict single-winner guard** — `delete_ip_record` re-reads and checks `is_deleted` (idempotency-by-read); documented and tested contract that two concurrent deletes may both report success, with no torn state. This is an accepted design choice, not an oversight, but it is a materially different guarantee than the other three projects' single-winner semantics. |
| F5 | Oversized-body status code | **400** — `auth_middleware` buffers the whole body itself via `to_bytes(body, max_body_bytes())` before any handler/extractor runs; overflow maps to `AppError::InvalidInput` | **413** — `StrictBytes`/`DefaultBodyLimit` path preserves the extractor's own status | **413** — explicit `Content-Length` pre-check inside `auth_middleware`, plus remapping `to_bytes`'s own overflow to 413 | **413** — `DefaultBodyLimit::max` kept specifically so the JSON envelope survives via `AppError::BodyRejected` |
| F6 | Body-size ceiling configurability | Env-configurable, `MAX_BODY_SIZE_MIB` (default 10 MiB) | Hardcoded `MAX_REQUEST_BODY_BYTES = 3 MiB`, not env-configurable — documented as a deliberate, tracked divergence in the peer's own notes | Hardcoded 3 MiB, same divergence | Env-configurable, `MAX_BODY_SIZE_MIB` (default 10 MiB) — raised from a hardcoded 3 MiB specifically so a 10,000-record batch fits |
| F7 | Malformed `Path`/`Query` segment returns the `{"error": ...}` envelope (not axum's bare-text default) | **Yes** — `StrictJson`/`StrictPath`/`StrictQuery`, all three axum extractor kinds wrapped | **Yes** — `StrictJson`, `OptionalStrictJson`, `StrictPath`, `StrictQuery`, `StrictBytes` (all four+ extractor kinds wrapped; this was itself a bug-fix, see §1.2) | Partial — `StrictJson`+`StrictPath` only; no confirmed `StrictQuery` equivalent | Partial — `StrictJson`+`OptionalStrictJson` confirmed; `Path`/`Query` rejection is a documented, deliberately-**pinned open gap** ("PINNED GAP … invert when closed") — axum's own plain-text rejection still leaks through for `Path<Uuid>`/`Query<T>` |
| F8 | AGENT.MD/doc-vs-code drift found | `AGENT.MD` states keys are matched via "Argon2/SHA-256" — actual `support::hash_key` uses plain SHA-256 only. Not a vulnerability (plain SHA-256 is the *correct* choice for a high-entropy random token; Argon2 is for low-entropy secrets), but the documentation is stale. | None found in this pass | None found in this pass | None found in this pass |
| F9 | `bound_ips` enforced against Master too (not exempted) | **Yes** | **Yes** | Not explicitly re-confirmed this pass; `RBAC_MODEL.md` does not scope this project, so no normative claim applies | **Yes** |
| F10 | `is_master` reachable from any request payload type | **No** — absent from every payload struct | **No** — absent from `CreateApiKeyPayload`/`UpdateApiKeyPayload`; only appears in read-response structs | **No** — absent from `CreateKeyPayload`/`UpdateKeyPayload` | **No** — absent from `CreateApiKeyPayload`/`UpdateApiKeyPayload` |

### 1.2 Cross-project bug-class convergence (independently discovered, not shared code)

All four projects have, within the last few days, independently found and fixed instances of the
**same three bug classes** through structurally identical review processes (each auditing its own
code and its `example/` peers). This is a genuine convergence signal, not coincidence — the
projects share enough architecture (single-connection SQLite pool, HMAC middleware pipeline, RBAC
guard layer) that the same defect shapes recur:

1. **TOCTOU on concurrent delete-by-id.** Found and fixed in `simply_ip_sync` (this project, 5
   call sites), `simply_hook_executor` (1 soft-delete path), and `simply_ip_exporter` (2 delete
   handlers). `simply_ip_vault` made a deliberate, tested design choice *not* to use a
   single-winner guard on its whole-record delete path (idempotency-by-read instead) — this is the
   one place the convergence is a genuine design divergence rather than an unfixed gap.
   `simply_ip_exporter`'s own `AGENT_NOTES.MD` (Session dated 2026-08-17, "session 2") explicitly
   recorded this bug class as **present and unfixed in `simply_ip_sync`** across four delete
   handlers at the time of that peer's audit — that finding is now stale: this project's Session 7
   (commit `024ffc5`) closed all of them, and a fifth call site (`revoke_key_permission` in
   `keys.rs`) is also covered.
2. **Framework extractor rejections bypassing the JSON error envelope.** `axum`'s built-in
   `Json`/`Path`/`Query` extractors reject malformed input as plain text *before* any handler runs,
   which is invisible to handler-level tests. All four projects found this independently and built
   a `Strict*` extractor family to close it; `simply_ip_vault` is the only one of the four with a
   still-open, explicitly pinned gap on this exact class (see F7).
3. **Missing boot-time verification that a security invariant (not just its syntactic shape) is
   satisfied.** `simply_ip_sync` and `simply_ip_exporter` both added an encryption-key *canary*
   (decrypt a real stored secret to prove the configured key is correct); `simply_ip_vault`'s own
   notes (referenced by the exporter's audit of it) confirm it lacked this at the time the exporter
   added its own.

### 1.3 RBAC scope note

`simply_ip_sync`'s own `RBAC_MODEL.md` restates the Master/Parent/Daughter model in this
project's own terminology and explicitly notes it is *not* in the scope of the peers' shared,
byte-identical `RBAC_MODEL.md` (which covers only `simply_ip_vault` and `simply_hook_executor`,
enforced by their own `scripts/verify_convergence.sh`). `simply_ip_exporter` is likewise excluded
from that shared document by its own header, and independently documents a simpler two-tier
Master/Daughter model (no Parent tier) in its own `AGENT.MD`. No inconsistency was found between
any project's implementation and its own governing document, except F1 above.

---

## 2. Security Parity

### 2.1 RBAC conjunction / governance-rule enforcement

| Rule | `simply_ip_sync` (own model) | `simply_hook_executor` | `simply_ip_exporter` (own model) | `simply_ip_vault` |
|---|---|---|---|---|
| Tiers | Master / Parent / Daughter | Master / Parent / Daughter | Master / Daughter (no Parent) | Master / Parent / Daughter |
| R1 Non-amplification | `guard_delegated_grant` | `guard_delegated_hook_grant` | N/A (no delegation tier below Master) | `guard_delegated_group_grant` |
| R2 Manage-is-a-conjunction | `guard_resource_manage` | `guard_hook_manage_conjunction` | N/A — only `require_master`/`may_manage` (owner-or-master), no separate global+per-resource conjunction | `guard_group_manage` |
| R3 Parentage confers no authority | Implicit (no code path derives rights from `parent_key_id`) | Implicit | N/A | Implicit |
| R4 Only-Master-creates-parents | `guard_resource_creation` / `guard_scope_elevation` | `guard_master_to_grant_scopes` | Implicit — only Master (`require_master`) can create any key, parent tier doesn't exist | `guard_scope_elevation` |
| R5 Manage may propagate sideways | Covered by `guard_resource_manage` + `guard_delegated_grant` | Covered by `guard_hook_manage_conjunction` + `guard_delegated_hook_grant` | N/A | Covered by `guard_group_manage` + `guard_delegated_group_grant` |
| R6 Revocation is never escalation | `guard_revocation` | `is_permission_reduction` | N/A | (equivalent logic, not named in facts gathered) |
| R7 Granting bounded by R1+R2 | Composed at call sites of `guard_delegated_grant` | `guard_delegated_hook_grant` (explicit R1+R7 combination) | N/A | `guard_delegated_group_grant` |
| §5 Master uniqueness enforcement | Guard function count: **11** (`guards.rs`, 156 lines) | Guard function count: **18** (`guards.rs`, 932 lines) | Guard function count: **2 named** (`require_master`, `may_manage`) + inline checks, no `guards.rs` file | Guard function count: **13** (`guards.rs`, 457 lines) |

The guard-layer size difference (`simply_ip_sync` 156 lines / `simply_hook_executor` 932 lines /
`simply_ip_exporter` no dedicated file / `simply_ip_vault` 457 lines) tracks each project's
resource-model complexity, not its rigor: `simply_hook_executor` has the most distinct visibility
scopes (shared resource + creator-private execution records + privilege-escalation fields on
hooks), `simply_ip_sync` has the fewest (no creator-private entity), and `simply_ip_exporter`'s
flat two-tier model needs no conjunction logic at all.

### 2.2 Master-key DB constraint & uniqueness mechanism

| Property | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| Uniqueness marker | `master_marker`, `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` under unique index | Same pattern (`idx_api_keys_master_marker`) | Same pattern, added via raw `ALTER TABLE` in initial migration | Same pattern |
| Marker on entity `Model`? | **No** (deliberately, documented) | **No** | **No** | **No** |
| `is_master` on entity `Model`? | Yes (read-only field) | Yes | Yes | Yes |
| `is_master` in any payload type? | No | No | No | No |
| Boot-time identity pin | `MasterPin` (`OnceLock<Uuid>`), `pin_at_boot`, `authenticate` demotes impostor | `MasterPin` (`tokio::sync::OnceCell<Uuid>`), same demotion pattern | `MasterPin`, same pattern (`OnceLock`/`OnceCell`) | `MasterPin` (`OnceLock<Uuid>`), same pattern |
| Rotation refused for Master | Yes, unconditionally | Yes (`refuse_master_lifecycle_action`) | Yes (`delete_api_key`/`rotate_api_key` check `existing.is_master`) | Yes |
| Master deletable via API | No — regenerate via direct DB row removal | No | No | No |
| Index-presence verified live at boot | `crate::db::has_index` | `SchemaManager::has_index` (a documented portability trap on non-SQLite backends per `simply_ip_exporter`'s own audit of this project) | Not confirmed this pass | `crate::db::has_index` (custom, specifically because `SchemaManager::has_index` broke Postgres startup — a defect the project's own `FILE_MAP.MD` documents fixing) |

`simply_ip_sync` and `simply_ip_vault` converge on the same `has_index`-portability fix;
`simply_hook_executor` still uses `SchemaManager::has_index`, which is currently safe only because
that project is SQLite-only — the same class of latent Postgres-portability defect `simply_ip_vault`
already hit and fixed.

### 2.3 Privilege isolation (lifecycle, ownership, cascade)

| Property | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| `owner_key_id`-scoped lifecycle | Yes — `guard_resource_lifecycle` (Master + owner only) | Yes — `guard_lifecycle_authority` | Yes — `may_manage` (`is_master || owner_key_id == caller.id`) | Yes — `guard_resource_lifecycle` |
| Cascade pre-flight inventory on key delete | Yes — `collect_subtree`/`owned_resource_inventory`, 409 with structured detail | Yes (§6-compliant, per `rbac_model_compliance.rs`) | Not applicable — flat two-tier model, no subtree cascade described | Yes — full §6 pre-flight walk |
| Oracle discipline (out-of-scope = 404, identical to nonexistent) | Yes, stated in own `RBAC_MODEL.md` §4 and tested (`concurrency_and_contracts.rs`) | Yes, §4-compliant | Not RBAC_MODEL.md-scoped; own model doesn't define a visibility-scoping oracle requirement beyond `require_master`/`may_manage`'s binary gate | Yes, §4-compliant |
| `parent_key_id` DB-level FK | **No** — deliberately, per this project's own `RBAC_MODEL.md` §7 text | Not confirmed this pass | Not applicable (no parent tier) | Not confirmed this pass (RBAC_MODEL.md §7 requires an index, not necessarily a FK) |

### 2.4 Cryptography

| Property | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| Secrets-at-rest cipher | XChaCha20-Poly1305 | XChaCha20-Poly1305 | XChaCha20-Poly1305 | XChaCha20-Poly1305 |
| Key length | 32 bytes / 64 hex chars | 32 bytes / 64 hex chars | 32 bytes / 64 hex chars | 32 bytes / 64 hex chars |
| Envelope prefixes | `v1.plain.<hex>` / `v1.xchacha20poly1305.<nonce>.<ct>` | Same | Same | Same (a retired `aesgcm256:` bridge was removed 2026-08-02; unrecognized shapes now hard-reject) |
| Encryption key env var | `SYNC_ENCRYPTION_KEY` | `SIGNING_SECRET_KEY` (alias `VAULT_ENCRYPTION_KEY`) | `EXPORTER_ENCRYPTION_KEY` | `VAULT_ENCRYPTION_KEY` (alias `SIGNING_SECRET_KEY`) |
| Missing/malformed key behavior | Not re-confirmed this pass for the fail path specifically; format validated at `SecretCipher` construction | No key set → falls back to `Plaintext` mode with a startup warning (zero-config-friendly, but permissive); malformed key aborts | Not confirmed this pass | Malformed/missing key is a hard boot error, no silent plaintext fallback — the strictest of the four |
| Request-signing HMAC | HMAC-SHA256, `Mac::verify_slice` constant-time | HMAC-SHA256, `Mac::verify_slice` | HMAC-SHA256, `Mac::verify_slice` | HMAC-SHA256, `Mac::verify_slice`; convergence script additionally forbids `==` on any signature/digest anywhere in `src/` |
| Canonical string | `CANONICAL_V1`: `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY` | `CANONICAL_V1` (default) + optional `BODY_ONLY` mode per-key | `CANONICAL_V1`, identical format | `CANONICAL_V1`, identical format |
| Signature header | `X-Signature-256: sha256=<hex>` | Same, plus `X-Hub-Signature-256` accepted only in `BODY_ONLY` mode | Same | Same |
| Timestamp skew window | 300s (`MAX_TIMESTAMP_SKEW_SECS`) | 300s default, env-overridable (`SIGNATURE_MAX_AGE_SECONDS`) | 300s default, env-overridable | 300s (`MAX_TIMESTAMP_SKEW_SECS`) |
| Anti-replay ceiling | `MAX_TRACKED_SIGNATURES = 100,000` | `250,000` | `250,000` | `100,000` |
| Anti-replay keying | `(key_id, raw digest bytes)`, `std::sync::Mutex<HashMap<..,Instant>>`, monotonic clock, never wholesale-cleared | Same shape | Same shape | Same shape |
| Auth-pipeline ordering (timestamp → key lookup → body/signature → replay → `bound_ips` last) | Yes | Yes, explicitly documented as load-bearing | Yes | Yes |

`simply_ip_sync` diverges from all three peers on one point worth flagging precisely: it does not
appear to document (in the facts gathered) an explicit "missing key = hard error, no plaintext
fallback" policy the way `simply_ip_vault` does. This is a documentation-completeness gap to close
in a future pass, not a demonstrated behavioral flaw — `SecretCipher`'s actual fail path was not
re-derived from scratch in this session.

---

## 3. Payload & Input Strictness

### 3.1 `deny_unknown_fields` coverage

| Project | Payloads with `deny_unknown_fields` | Payloads without it | Coverage |
|---|---|---|---|
| `simply_ip_sync` | All 9: `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `GrantPermissionPayload`, `CreateExternalSourcePayload`, `UpdateExternalSourcePayload`, `CreateVaultSyncTaskPayload`, `UpdateVaultSyncTaskPayload`, `CreateVaultEndpointPayload`, `UpdateVaultEndpointPayload` | None | **100%** |
| `simply_hook_executor` | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `EntityResolution`, `DeleteApiKeyPayload` | `CreateHookPayload`, `UpdateHookPayload`, `UpdateParameterPayload` | Partial — key-admin only |
| `simply_ip_exporter` | None | `CreateKeyPayload`, `UpdateKeyPayload`, `CreateEndpointPayload`, `UpdateEndpointPayload`, `ReassignOwnerPayload`, `AuditLogQuery` | **0%** (self-documented gap) |
| `simply_ip_vault` | `CreateApiKeyPayload`, `UpdateApiKeyPayload`, `BatchRecordsPayload`, `BatchRecordInput` | `CreateIpGroupPayload`, `BanWhitePayload`, `CreateWebhookPayload`, `UpdateWebhookPayload`, `GroupPermInput` | Partial — key-admin + batch only |

`simply_ip_sync` is the only one of the four projects with universal `deny_unknown_fields`
coverage. The other three converge on a shared rationale for their partial coverage — the
attribute is treated as specifically defending the Master-immutability boundary (rejecting a
stray `is_master` field), not as a general payload-hygiene control — which is a materially weaker
policy than blanket coverage: an unrecognized field on a *non*-key-admin payload (a hook parameter,
an IP group, a webhook config, a vault endpoint) is silently ignored rather than rejected on those
three projects, whereas on `simply_ip_sync` it always produces a 400.

### 3.2 Strict-extractor family

| Project | Extractor types | `Path`/`Query` rejections in JSON envelope? |
|---|---|---|
| `simply_ip_sync` | `StrictJson<T>`, `StrictPath<T>`, `StrictQuery<T>` | Yes, all three |
| `simply_hook_executor` | `StrictJson<T>`, `OptionalStrictJson<T>`, `StrictPath<T>`, `StrictQuery<T>`, `StrictBytes` | Yes, all — the widest extractor family of the four, closing this gap for every input kind the service accepts (including raw bytes) |
| `simply_ip_exporter` | `StrictJson<T>`, `StrictPath` | Path yes; no confirmed `StrictQuery` — a query-string type-mismatch (e.g. `AuditLogQuery`'s `limit`) may still leak axum's bare-text rejection |
| `simply_ip_vault` | `StrictJson<T>`, `OptionalStrictJson<T>` | **No** — `Path<Uuid>`/`Query<T>` rejections are a documented, deliberately-pinned open gap in this project's own test suite |

### 3.3 Validation parity summary

`simply_ip_sync` and `simply_hook_executor` both wrap every extractor kind their service actually
uses (three and five respectively) in a Strict* type; `simply_ip_exporter` and `simply_ip_vault`
each have one confirmed, load-bearing gap on this axis (missing `StrictQuery` and missing
`Path`/`Query` wrapping respectively). Combined with the `deny_unknown_fields` picture above,
`simply_ip_sync` has the strictest payload/input posture of the four services as measured by these
two controls; `simply_ip_exporter` has the weakest.

---

## Executive Verdict

**Maturity ranking on the security axes examined (strictest/most complete first):**
`simply_ip_sync` ≈ `simply_hook_executor` > `simply_ip_vault` > `simply_ip_exporter`.

The ecosystem is **substantially converged** on its core security architecture: all four services
share an identical CANONICAL_V1 HMAC scheme, an identical XChaCha20-Poly1305 secrets-at-rest
envelope format, an identical DB-generated Master-uniqueness marker pattern, an identical
boot-time `MasterPin` demotion mechanism, and an identical replay-guard data structure and sweep
policy — none of this is copy-pasted in the literal sense (each has its own file layout and
naming), but the design decisions are the same to the level of exact constant semantics
(`window/4` routine sweep, `window/16` capacity backoff, monotonic-clock keying). This is strong
evidence of a coordinated, well-understood shared threat model rather than four independently
converging designs by chance.

Where the four diverge, the divergences fall into two categories:

1. **Accepted, documented divergences** that do not represent a security gap: the 3 MiB
   hardcoded vs. 10 MiB env-configurable body-size ceiling (`simply_hook_executor`/
   `simply_ip_exporter` vs. `simply_ip_sync`/`simply_ip_vault`); `simply_ip_vault`'s deliberate
   idempotency-by-read delete semantics vs. the other three's strict single-winner
   `rows_affected` check; `simply_ip_exporter`'s independent, simpler two-tier RBAC model (a
   scoping decision stated up front in `RBAC_MODEL.md` itself, not a gap against a model it never
   claimed to implement).
2. **Real, load-bearing gaps that should be closed:** `simply_ip_exporter`'s complete absence of
   `deny_unknown_fields` (self-documented, the most significant single finding in this report);
   `simply_ip_vault`'s pinned-open `Path`/`Query` JSON-envelope gap; `simply_ip_vault`'s absent
   encryption-key correctness canary; `simply_hook_executor`'s continued use of
   `SchemaManager::has_index` (a latent, currently-dormant Postgres-portability defect of exactly
   the kind `simply_ip_vault` already hit in production and fixed); and `simply_ip_exporter`'s
   `update_api_key` handler, which does not enforce the "Master immutable except `bound_ips`"
   guarantee at all (F1) — the weakest single Master-protection finding across all four projects,
   though not a violation of that project's own, narrower governing document.

`simply_ip_sync` itself has no vulnerability findings in this pass beyond the cosmetic
`AGENT.MD` documentation drift (F8) and the not-yet-independently-re-derived encryption-key
fail-fast policy noted in §2.4. Its TOCTOU-race and error-envelope gaps — the two bug classes every
peer independently found in itself — were already closed in this project's own prior session
(commit `024ffc5`) before this audit began. On the two hardest-to-fake strictness metrics measured
here (`deny_unknown_fields` coverage and extractor-family completeness), `simply_ip_sync` is at or
tied for the ecosystem maximum.
