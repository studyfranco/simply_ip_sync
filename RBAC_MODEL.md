# Canonical RBAC & Authorization Model — `simply_ip_sync`

**Status:** Normative specification for this service. Structurally convergent with
`simply_ip_vault`/`simply_hook_executor`'s shared `RBAC_MODEL.md` (same tier structure, same R1–R7
governance rules, same §3–§7 guarantees), restated here with this service's own terminology since
`simply_ip_sync` is not in that document's stated scope and is not diffed by its
`scripts/verify_convergence.sh`.

## Terminology

| Generic term | `simply_ip_sync` |
| :--- | :--- |
| **Managed resource** (shared, permission rows) | External Source, Inter-Vault Sync Task, Vault Endpoint |
| **Resource-creation rights** | `can_manage_sources` (External Source), `can_manage_vaults` (Vault Endpoint **and** Sync Task) |
| **Per-resource permission table** | `api_key_sync_permissions` |
| **Operational verb** | `can_sync` — permission to invoke a resource's `/trigger` endpoint |
| **Per-resource management verb** | `can_manage` — the R2 conjunction's per-resource half |
| **Visibility verb** | `can_view_logs` — permission to read a resource's `sync_logs` rows |

**Why Sync Tasks are gated by `can_manage_vaults`, not a fourth flag.** `SCHEMA.MD`'s `api_keys`
table defines exactly three Master-grantable global rights (`can_manage_keys`,
`can_manage_sources`, `can_manage_vaults`) — there is no independent right for creating inter-vault
sync tasks. A sync task is fundamentally a vault-to-vault topology object (`source_vault_id` plus
`vault_sync_task_targets`, both foreign keys into `vault_endpoints`), so it is gated by the same
right that gates registering the vault endpoints it connects.

There is no separate "creator-private entity" category in this service — every managed resource
(`external_sources`, `vault_sync_tasks`, `vault_endpoints`) carries `owner_key_id` directly and is
governed uniformly by §3 below.

---

## 1. Permission Tiers

| Tier | Granted by | May manage resources | Notes |
| :--- | :--- | :--- | :--- |
| **Master** (unique) | Bootstrap only | Yes, everywhere | Full system control; bypasses scoping; sees all entities |
| **Parent** (`can_manage_keys`) | Master only | Yes, where a `can_manage` row is held | May create daughter keys and delegate rights to them |
| **Daughter** (no `can_manage_keys`) | Master or any parent | Never | Rights ⊆ its creator's rights; cannot create keys |

Resource-creation rights (`can_manage_sources`, `can_manage_vaults`) sit at the same tier as
`can_manage_keys`, are granted strictly by Master, and are never implied by `can_manage_keys` or by
resource management rights. Managing keys and being able to create a new external source or vault
endpoint are separate powers.

---

## 2. Core Governance Rules

- **R1 — Non-amplification.** A caller may only grant a permission verb (`can_sync`,
  `can_manage`, `can_view_logs`) on a resource that it currently holds itself on that same
  resource. Applies at every tier below Master.
- **R2 — Manage is a conjunction.** Managing a specific resource (editing its configuration, or
  delegating permissions on it) requires holding both global `can_manage_keys` **and** a
  `can_manage = true` row for that specific resource. Neither alone is sufficient.
  `can_manage_keys` is never a global bypass of per-resource RBAC.
- **R3 — Parentage confers no authority.** `parent_key_id` exists solely for cascading deletion
  and key visibility scoping. Rights are never derived from key lineage.
- **R4 — Only Master creates parents.** Only the Master key may grant `can_manage_keys`,
  `can_manage_sources`, or `can_manage_vaults`. A parent key can never mint another parent key or a
  resource-creation right.
- **R5 — Manage may propagate sideways.** A parent holding manage rights on a resource may grant
  manage rights on that resource to another existing parent key (bounded by R1 and R2), but this
  can never elevate a daughter key to parent status.
- **R6 — Revocation is never escalation.** Removing a permission requires manage rights on the
  resource only; the revoker need not hold the verb being removed, and may revoke its own
  permissions.
- **R7 — Granting is bounded by R1 and R2 together**, simultaneously and without exception.

---

## 3. Resource Lifecycle & Ownership

- Every `external_sources`, `vault_sync_tasks`, and `vault_endpoints` row carries `owner_key_id`.
- Resource lifecycle actions — deleting or renaming the entity itself — are restricted exclusively
  to Master and the designated `owner_key_id`. Holding `can_manage` (R2) confers no lifecycle
  authority: a parent that merely manages a resource's configuration must not be able to delete it.
- Master may reassign ownership at any time (via a direct update; there is no dedicated
  reassignment endpoint in this service's initial surface).

---

## 4. Visibility & Oracle Discipline

- **Master:** full visibility over all keys, resources, and configuration.
- **Own subtree:** a parent sees itself and its direct daughter keys.
- **Shared resources:** a key sees a resource (in `GET /api/sources`, `/api/vaults`,
  `/api/sync-tasks`) if it is Master, the resource's owner, or holds any permission row on it.
- **Oracle discipline.** A resource outside the caller's visibility scope returns `404`, identical
  to a genuinely nonexistent id.

---

## 5. Master Key Guarantees

- Exactly one Master key exists, enforced by a database constraint: `api_keys.master_marker`,
  `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` under a plain unique index
  (`Postgres: STORED`, `SQLite/MySQL: VIRTUAL`) — see
  `migration::m20260101_013241_derive_master_marker`.
- The marker is never a field on the `api_key` entity `Model` (see `entities/api_key.rs`), so no
  query can ever write to it.
- `is_master` is not present in any create/update payload type (`CreateApiKeyPayload`,
  `UpdateApiKeyPayload`) — removed from the type, not merely rejected in a handler.
- The Master key is immutable through the API except for its own `bound_ips`
  (`guards::guard_master_immutable`). Rotation is refused for every caller including the Master
  itself (`guards::guard_rotation_allowed`), since rotation returns a fresh plaintext credential
  that would otherwise be unrecoverable-by-design for the one key that can never re-mint itself.
- The Master key cannot be deleted through the API. Regeneration is: delete the row directly in
  the database; the service re-mints one at next boot (`main.rs::bootstrap_master_key`).
- `master.rs::MasterPin` additionally pins the Master's *identity* (not just cardinality) at boot,
  and demotes (rather than 401s) an impostor `is_master=true` row on every request — see that
  module's doc comment for the full rationale.

---

## 6. Cascade Deletion & Pre-flight Inventory

- Deleting a key cascades recursively through its entire daughter subtree
  (`api/keys.rs::collect_subtree`).
- **Data is never destroyed implicitly.** Before any key deletion, the service walks the full
  subtree being deleted and collects every `vault_endpoint`/`external_source`/`vault_sync_task`
  owned by any key in it (`api/keys.rs::owned_resource_inventory`).
- If that inventory is non-empty, deletion is refused with a `409` carrying the structured
  inventory (type/id/name/owner). The caller must reassign or delete each listed resource first,
  then resubmit the deletion.
- The Master key can never appear in a deletable subtree (its `parent_key_id` is always `NULL`,
  and deletion is refused outright for a Master target regardless).

---

## 7. Database Constraints & Indexing

- The Master-uniqueness constraint per §5.
- Indexes on `api_keys.parent_key_id`, `*.owner_key_id` (on all three resource tables),
  `api_keys.prefix`, `api_keys.key_hash` (via its `UNIQUE` constraint), and the composite unique
  index on `api_key_sync_permissions (api_key_id, resource_type, resource_id)`.
- `parent_key_id` is **not** a database-level foreign key (SQLite has no
  `ALTER TABLE … ADD CONSTRAINT`, and a self-referential FK on the same table SeaORM's migration
  builder is creating is awkward across all three supported backends); the application-level
  equivalent (cascade-safe deletion via subtree walking) is covered by
  `tests/rbac_model_compliance.rs::s3_resource_lifecycle_delete_requires_owner_or_master` and the key CRUD
  handlers themselves.
