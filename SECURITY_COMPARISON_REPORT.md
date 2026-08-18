# Security Comparison Report — Ecosystem-Wide (4-Way)

**Audited service (this repository):** `simply_ip_sync` @ `72cce13` (2026-08-18)
**Compared against:**
- `example/simply_hook_executor` @ `15b8af6` (2026-08-18)
- `example/simply_ip_exporter` @ `80a3b31` (2026-08-18)
- `example/simply_ip_vault` @ `14c8fa3` (2026-08-17)

All three peers were pulled fresh at the start of this pass (`git -C example/<peer> pull --ff-only`)
and reported no new commits — each was already at the SHA above. See `AGENT_NOTES.MD`'s latest
session entry for the pull log.

**Methodology:** Zero-knowledge / clean-room audit. This report is written directly from the
current `.rs` source and `RBAC_MODEL.md` of all four projects. No prior version of this file, and
no peer's own `SECURITY_COMPARISON_REPORT.md`/`STRUCTURAL_CONVERGENCE_REPORT.md`, was read or
relied on to produce it. `simply_ip_vault` and `simply_hook_executor` are treated as the
ecosystem's gold standard, per their shared, byte-identical `RBAC_MODEL.md` and
`scripts/verify_convergence.sh` — deviations from their pattern are flagged as such, but a
deviation is only a finding when it is actually weaker, not merely different.

---

## 1. Zero-Knowledge Security Assessment

### 1.1 RBAC scope — who is actually bound by `RBAC_MODEL.md`

| Project | Bound by the shared `RBAC_MODEL.md`? | Actual tier model implemented |
|---|---|---|
| `simply_hook_executor` | Yes — named in the document's own scope line, byte-identical copy, diffed by `verify_convergence.sh` | Master / Parent / Daughter |
| `simply_ip_vault` | Yes — same as above | Master / Parent / Daughter |
| `simply_ip_exporter` | **No** — excluded by the shared document's own header; has an independent, simpler spec in its own `AGENT.MD` | Master / Daughter only (no Parent tier) |
| `simply_ip_sync` | **No** — this project's own `RBAC_MODEL.md` explicitly states it restates the shared model in local terminology and is outside that document's stated scope / not diffed by `verify_convergence.sh` | Master / Parent / Daughter |

No project misrepresents its own scope: `simply_ip_exporter`'s and `simply_ip_sync`'s RBAC
documents each say plainly, in their own text, that they are not the shared gold-standard
document. This is a documentation-honesty check that all four pass.

### 1.2 Per-project vulnerability findings

| # | Finding | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|---|
| F1 | Master-immutability rule ("immutable except own `bound_ips`") actually enforced on the general update path, not just delete/rotate | **Enforced** — `guards::guard_master_immutable` runs on every Master-touching field write | **Enforced** — `guard_master_self_edit_is_bound_ips_only` | **NOT enforced** — `update_api_key` has no `existing.is_master` special case at all; a Master caller can change the Master row's `name`/`can_manage_keys` through the ordinary update endpoint. Consistent with this project's own (narrower) AGENT.MD, which never states the bound-ips-only restriction — but a real gap against the stricter posture the other three projects hold themselves to. | **Enforced** — `guard_master_immutable` |
| F2 | Startup canary proves the configured encryption key is *correct*, not merely well-formed | **Present** — `crypto::check_key_canary` / `KeyCanary` enum, invoked from `main.rs::verify_encryption_key` | Not confirmed present in the facts available for this pass | **Present** — `main::verify_encryption_key` canary-decrypts the Master row's sealed `signing_secret` at boot | **Absent** — `SecretCipher::from_env` validates only 64-hex-char format; a wrong-but-well-formed key surfaces only later as an opaque per-request `500` |
| F3 | `deny_unknown_fields` on every mutating payload struct | **9/9 — 100%** | Key-admin payloads only (4/7 spot-checked); `CreateHookPayload`/`UpdateHookPayload`/`UpdateParameterPayload` lack it | **0/6 — none anywhere in `src/`**, a gap the project's own notes already record | Key-admin + batch payloads only; `CreateIpGroupPayload`/`BanWhitePayload`/`CreateWebhookPayload`/`UpdateWebhookPayload`/`GroupPermInput` lack it |
| F4 | Concurrent-delete TOCTOU (`rows_affected` unchecked) | **Closed** — all 5 delete/revoke call sites check `rows_affected == 0 → 404` | **Closed** (soft-delete variant; a race previously produced duplicate audit rows) | **Closed** — both delete handlers check `rows_affected` | **Deliberate idempotency-by-read instead** — two concurrent whole-record deletes may both report success; a documented and tested design choice, not an unguarded race |
| F5 | `bound_ips` enforced against the Master key too, never exempted | **Yes** | **Yes** | Not re-confirmed this pass; project is outside `RBAC_MODEL.md`'s scope so no normative claim applies | **Yes** |
| F6 | `is_master` reachable from any request payload type | **No** | **No** | **No** | **No** |
| F7 | `master_marker` field present on the entity `Model` (would let SeaORM attempt to write it) | **Absent, by design** — documented in the entity's own doc comment | **Absent** | **Absent** | **Absent** |

### 1.3 Convergent bug classes (independently discovered, not shared code)

The following defect shapes were found and fixed independently, in the last few days, in more than
one of these four projects — evidence of a shared architecture producing the same failure modes
rather than a shared codebase:

1. **TOCTOU on concurrent delete-by-id.** Fixed in `simply_ip_sync` (5 call sites),
   `simply_hook_executor` (1 soft-delete path), and `simply_ip_exporter` (2 handlers).
   `simply_ip_vault`'s whole-record delete path deliberately keeps idempotency-by-read semantics
   instead of a single-winner guard — the one place this convergence is a genuine, tested design
   choice rather than a fix. Note for the record: an earlier external audit of `simply_ip_sync`
   (performed by the `simply_ip_exporter` project against an older commit of this repository) had
   flagged this bug class as present and unfixed here; that observation is now stale — the current
   commit (`72cce13`, and the fix itself landed at `024ffc5`) closes it.
2. **Framework extractor rejections bypassing the JSON error envelope.** Axum's built-in
   `Json`/`Path`/`Query` extractors reject malformed input as plain text before any handler runs.
   All four projects built a `Strict*` extractor family to close this independently;
   `simply_ip_vault` still has one open, explicitly self-documented ("PINNED GAP") instance of it on
   `Path`/`Query`.
3. **Missing boot-time verification that a security invariant holds, not just its syntactic shape.**
   `simply_ip_sync` and `simply_ip_exporter` both added an encryption-key canary; `simply_ip_vault`
   has not yet.

No finding in this pass rises to a live, exploitable vulnerability in `simply_ip_sync` itself.

---

## 2. Security Parity

### 2.1 RBAC governance-rule enforcement (R1–R7)

| Rule | `simply_ip_sync` | `simply_hook_executor` (gold standard) | `simply_ip_exporter` | `simply_ip_vault` (gold standard) |
|---|---|---|---|---|
| R1 Non-amplification | `guard_delegated_grant` | `guard_delegated_hook_grant` | N/A — no delegation tier below Master exists | `guard_delegated_group_grant` |
| R2 Manage-is-a-conjunction | `guard_resource_manage` | `guard_hook_manage_conjunction` | N/A — only `require_master`/`may_manage` (owner-or-master), no global+per-resource conjunction | `guard_group_manage` |
| R3 Parentage confers no authority | Implicit (no path derives rights from `parent_key_id`) | Implicit | N/A | Implicit |
| R4 Only-Master-creates-parents | `guard_resource_creation` / `guard_scope_elevation` | `guard_master_to_grant_scopes` | Implicit — only Master can create any key at all | `guard_scope_elevation` |
| R5 Manage may propagate sideways | `guard_resource_manage` + `guard_delegated_grant` | `guard_hook_manage_conjunction` + `guard_delegated_hook_grant` | N/A | `guard_group_manage` + `guard_delegated_group_grant` |
| R6 Revocation is never escalation | `guard_revocation` | `is_permission_reduction` | N/A | Equivalent logic present, not separately named in this pass's facts |
| R7 Granting bounded by R1+R2 | Composed at `guard_delegated_grant` call sites | `guard_delegated_hook_grant` (explicit R1+R7 combination) | N/A | `guard_delegated_group_grant` |
| Guard-layer size | 11 functions, 156 lines | 18 functions, 932 lines | 2 named functions, no dedicated file | 13 functions, 457 lines |

Guard-layer size tracks resource-model complexity, not rigor: `simply_hook_executor` has the most
distinct visibility scopes (shared resources + creator-private execution records + a
privilege-escalation field), `simply_ip_sync` has the fewest (no creator-private entity), and
`simply_ip_exporter`'s flat model needs no conjunction logic at all.

### 2.2 Master-key uniqueness & immutability mechanism

| Property | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| Uniqueness marker | Generated column `master_marker` under a unique index | Same pattern | Same pattern | Same pattern |
| Marker on entity `Model`? | No (deliberate) | No | No | No |
| Boot-time identity pin | `MasterPin` (`OnceLock<Uuid>`) | `MasterPin` (`OnceCell<Uuid>`) | `MasterPin` | `MasterPin` (`OnceLock<Uuid>`) |
| Index presence verified live at boot | `crate::db::has_index` (custom) | `SchemaManager::has_index` — a documented Postgres-portability trap, currently dormant since this project is SQLite-only | Not confirmed this pass | `crate::db::has_index` (custom, added specifically after `SchemaManager::has_index` broke Postgres startup in production) |
| Rotation refused for Master | Yes, unconditionally | Yes | Yes | Yes |
| Master deletable via API | No | No | No | No |

`simply_ip_sync` and `simply_ip_vault` converge on the same portability fix that
`simply_hook_executor` has not yet needed to make (and currently doesn't need to, being
SQLite-only) — worth flagging to `simply_hook_executor` as a latent defect matching one
`simply_ip_vault` already hit.

### 2.3 Privilege isolation

| Property | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| `owner_key_id`-scoped lifecycle | `guard_resource_lifecycle` | `guard_lifecycle_authority` | `may_manage` inline check | `guard_resource_lifecycle` |
| Cascade pre-flight inventory | Yes, structured 409 | Yes | N/A — flat model, no subtree cascade | Yes |
| Oracle discipline (out-of-scope ≡ nonexistent) | Yes, stated and tested | Yes | Not scoped by `RBAC_MODEL.md`; own model has a simpler binary gate | Yes |
| `parent_key_id` as a DB-level FK | No, deliberately (own `RBAC_MODEL.md` §7) | Not re-confirmed | N/A | Not re-confirmed |

### 2.4 Cryptography

| Property | `simply_ip_sync` | `simply_hook_executor` | `simply_ip_exporter` | `simply_ip_vault` |
|---|---|---|---|---|
| Secrets-at-rest cipher | XChaCha20-Poly1305 | XChaCha20-Poly1305 | XChaCha20-Poly1305 | XChaCha20-Poly1305 |
| Key length | 32 bytes / 64 hex chars | Same | Same | Same |
| Envelope prefixes | `v1.plain.<hex>` / `v1.xchacha20poly1305.<nonce>.<ct>` | Same | Same | Same (a retired `aesgcm256:` bridge was removed and now hard-rejects) |
| Encryption-key env var | `SYNC_ENCRYPTION_KEY` | `SIGNING_SECRET_KEY` (alias `VAULT_ENCRYPTION_KEY`) | `EXPORTER_ENCRYPTION_KEY` | `VAULT_ENCRYPTION_KEY` (alias `SIGNING_SECRET_KEY`) |
| Request-signing HMAC | HMAC-SHA256, constant-time verify | Same | Same | Same, plus a convergence-script rule forbidding `==` on any signature/digest anywhere in `src/` |
| Canonical string | `CANONICAL_V1`: `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY` | Same, plus an optional `BODY_ONLY` per-key mode | Same | Same |
| Timestamp skew window | 300s | 300s, env-overridable | 300s, env-overridable | 300s |
| Anti-replay ceiling | 100,000 tracked signatures | 250,000 | 250,000 | 100,000 |
| Anti-replay keying/sweep policy | `(key_id, raw digest)`, monotonic clock, `window/4` routine / `window/16` capacity-backoff sweep, never wholesale-cleared | Identical shape | Identical shape | Identical shape |
| Auth pipeline ordering (timestamp → key lookup → body/signature → replay → `bound_ips` last) | Yes | Yes, explicitly documented as load-bearing | Yes | Yes |

The replay-guard sweep constants (`÷4` routine, `÷16` capacity-backoff) matching exactly across all
four independently-developed codebases is the single strongest piece of evidence in this report
that convergence here is deliberate cross-reading, not four teams coincidentally choosing the same
numbers.

---

## 3. Payload & Input Strictness

### 3.1 `deny_unknown_fields` coverage

| Project | Coverage | Payloads missing it |
|---|---|---|
| `simply_ip_sync` | **100% (9/9)** | None |
| `simply_hook_executor` | Partial | `CreateHookPayload`, `UpdateHookPayload`, `UpdateParameterPayload` |
| `simply_ip_exporter` | **0%** | `CreateKeyPayload`, `UpdateKeyPayload`, `CreateEndpointPayload`, `UpdateEndpointPayload`, `ReassignOwnerPayload`, `AuditLogQuery` |
| `simply_ip_vault` | Partial | `CreateIpGroupPayload`, `BanWhitePayload`, `CreateWebhookPayload`, `UpdateWebhookPayload`, `GroupPermInput` |

`simply_ip_sync` is the only one of the four with universal coverage. The other three share the
same rationale for partial coverage — treating the attribute as an `is_master`-exclusion control
specifically, not a general payload-hygiene rule — which means an unrecognized field on a
non-key-admin payload is silently ignored on those three services and rejected on this one.

### 3.2 Strict-extractor family and framework-rejection coverage

| Project | Extractor types | `Path`/`Query` rejections land in the JSON envelope? |
|---|---|---|
| `simply_ip_sync` | `StrictJson`, `StrictPath`, `StrictQuery` | Yes, all three used |
| `simply_hook_executor` | `StrictJson`, `OptionalStrictJson`, `StrictPath`, `StrictQuery`, `StrictBytes` | Yes, the widest family of the four |
| `simply_ip_exporter` | `StrictJson`, `StrictPath` | `Path` yes; no confirmed `StrictQuery` |
| `simply_ip_vault` | `StrictJson`, `OptionalStrictJson` | **No** — a documented, deliberately pinned open gap in the project's own tests |

### 3.3 Validation parity verdict

Measured strictly on these two axes, `simply_ip_sync` and `simply_hook_executor` (one of the two
gold-standard projects) are tied for the strongest input-validation posture in the ecosystem;
`simply_ip_exporter` is the weakest on both axes simultaneously.

---

## Executive Verdict

**Maturity ranking on the security axes examined:** `simply_ip_sync` ≈ `simply_hook_executor` >
`simply_ip_vault` > `simply_ip_exporter`.

The ecosystem's core security architecture is **highly converged**, and the convergence is
evidently deliberate rather than coincidental: identical HMAC scheme, identical AEAD envelope
format, identical Master-uniqueness mechanism, identical `MasterPin` boot-time demotion pattern,
and — most tellingly — identical replay-guard sweep-interval divisors across four independent
codebases. `simply_ip_sync`, though outside the original `simply_ip_vault`/`simply_hook_executor`
convergence pair by its own `RBAC_MODEL.md`'s explicit scope statement, matches or exceeds the gold
standard on every security control examined in this report, with no unresolved vulnerability
findings against it. Its remaining rough edges are a single stale-documentation item (`AGENT.MD`
still describing key hashing as "Argon2/SHA-256" when the code uses plain SHA-256 — the correct
choice for a high-entropy token, so cosmetic rather than a security defect) and an
encryption-key-failure-mode fact not independently re-derived in this pass.

Of the two projects with real findings against them: `simply_ip_exporter` carries the most material
gap in the ecosystem — zero `deny_unknown_fields` coverage combined with a Master-immutability rule
that is not enforced on its general update path — both self-consistent with that project's simpler,
narrower governing document, but genuinely weaker than the rest of the ecosystem holds itself to.
`simply_ip_vault`, despite being a gold-standard project, has two open, self-documented gaps (the
pinned `Path`/`Query` envelope gap and the absent encryption-key canary) that the newer projects in
this ecosystem (`simply_ip_sync`, `simply_ip_exporter`) have already closed — a reminder that
"gold standard" describes the origin of the convergence, not a guarantee that the original pair
remains ahead of every derivative on every axis.
