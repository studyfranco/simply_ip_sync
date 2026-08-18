# Simply IP Sync - AI Agent Context & Directives

Hello AI Agent! You are assisting with the development of `simply_ip_sync`. Read and strictly adhere to these guidelines before inspecting or writing any code.

---

## 📄 Document & Context Hierarchy

To keep this context clean and modular, responsibilities are split across three files:
1. **`AGENT.MD`** *(This file)*: Core architectural rules, security constraints, documentation standards, and testing directives.
2. **`SCHEMA.MD`**: Official Database Schema, SeaORM Entity relations, M:N RBAC definitions, and Enum specifications.
3. **`AGENT_NOTES.MD`**: Agent worklog. You MUST update this file with architectural decisions, progress notes, or pending tasks after completing significant modifications.
4. **`example/`**: You can find the code of other similar/linked project inside. **Read [Peer Repository Synchronization](#-peer-repository-synchronization) before reading anything in here.**

---

## 🔄 Peer Repository Synchronization

`example/` holds **live git clones** of the peer services, not flat snapshots.
They are what `scripts/verify_convergence.sh` compares against and what every convergence or security report describes.

### Why `example/` Exists

This ecosystem's security and architectural convergence did not start with `simply_ip_sync`. It
originated with two foundational sibling projects — **`simply_ip_vault`** and
**`simply_hook_executor`** — which independently arrived at, and then deliberately converged on, the
same RBAC tier model, the same CANONICAL_V1 HMAC signing scheme, the same XChaCha20-Poly1305
secrets-at-rest envelope, and the same DB-generated Master-uniqueness pattern. Their shared
`RBAC_MODEL.md` (byte-identical across both repositories, diffed by their own
`scripts/verify_convergence.sh`) is the tightest point of alignment in the ecosystem and the closest
thing it has to a gold standard.

The ecosystem is designed to **scale beyond that original pair**. `simply_ip_exporter` joined as a
third peer with its own, deliberately simpler two-tier RBAC model (no Parent tier — a documented,
intentional divergence, not a gap), and `simply_ip_sync` (this project) joined as a fourth,
positioned as the active ingestion/replication orchestrator that talks to `simply_ip_vault` over the
network rather than sharing its database. Every peer checked out under `example/` — whatever their
number grows to — exists for three concrete purposes:

1. **Security posture parity** — checking that authentication, replay protection, secrets handling,
   and RBAC enforcement in this project are at least as strict as the ecosystem's gold standard, and
   flagging any gap (in either direction) precisely rather than assuming convergence.
2. **Architectural alignment** — confirming that module layout, naming conventions, and error-handling
   contracts read as the same "house style" across independently-developed codebases, so an engineer
   who knows one service is not starting from zero on another.
3. **Testing strategy comparison** — borrowing test patterns (adversarial RBAC tests, high-contention
   concurrency tests, source-hygiene static scans) that a sibling project discovered were necessary,
   before this project has to rediscover the same bug class the hard way.

`example/` is **not** a template to copy wholesale, and a peer's choice is not automatically the
right one for this project — see `RBAC_MODEL.md`'s own scope note and the divergences documented in
`SECURITY_COMPARISON_REPORT.md`/`STRUCTURAL_CONVERGENCE_REPORT.md` for cases where this project's
own design was judged correct and the peer's was not (or vice versa).

### Mandatory: pull before you analyse

**Before reading any file under `example/`, and before generating a convergence, parity, or security report, you MUST run:**

```sh
git -C example/<peer_repo> pull
```

for every peer repo you are about to consult. Skipping this and analyzing a stale checkout risks
comparing against code the peer project has already changed, producing a "convergence" report that
is convergent with the past rather than the present. This does not apply to routine work that
merely *uses* `example/` as a pattern reference during normal feature implementation (as opposed to
producing a comparison/audit artifact) — use judgment, but default to pulling first when in doubt.

`scripts/verify_convergence.sh` automates this at the start of every run for any `example/*`
directory that contains a `.git` — see that script for the graceful offline-mode fallback.

### Rules

- **Pull first, read second.** Not "pull if it looks stale" — staleness is invisible from inside the tree.
- **State the revision.** A report that does not name the peer commit it audited cannot be reproduced or re-checked. Both reports in this repository carry the peer's short SHA in their header.
- **A failed pull is reportable, not ignorable.** If the remote is unreachable, say so in the report and name the local `HEAD` being analysed instead. Silent analysis of an unknown revision is the thing this section exists to prevent.
- **Never commit the peer.** `example/` is `.gitignore`d. Reports about the peer belong in this repository; the peer's own code does not.
- **Read-only.** Never modify, stage, or commit inside a peer checkout. `git pull --ff-only` is the only write this repository's tooling performs there.

---

## 🎯 Project Overview

`simply_ip_sync` is an enterprise-grade threat intelligence ingestion orchestrator and multi-site inter-vault replication daemon written in Rust. It serves as the active synchronization engine in the ecosystem:
- **External Feeds Ingestion:** Periodically downloads, parses, and cleans threat lists from external HTTP/HTTPS sources (e.g., Spamhaus, FireHOL, AbuseIPDB JSON) and pushes them in batch to one or multiple target `simply_ip_vault` instances.
- **Inter-Vault Replication:** Orchestrates delta-based replication between pairs of `simply_ip_vault` instances using temporal filtering (`since`) and tombstone handling (`is_deleted`, `deleted_at`).
- **Control & Audit:** Exposes a Vanilla JS dashboard and a REST API protected by full HMAC-SHA256 authentication and granular RBAC, allowing manual triggers of sync jobs on demand by authorized keys.

---

## 🛠️ Tech Stack & Constraints

- **Backend:** Rust + Axum (0.8+) + Tokio (1.x).
- **Default Port:** `3003` (`BIND_HOST` / `PORT`).
- **Encryption Key:** `SYNC_ENCRYPTION_KEY` (XChaCha20-Poly1305, 64 hex characters).
- **ORM (SQL-Agnostic):** SeaORM (2.0+). Defaults to **SQLite** for zero-config local development/testing, but MUST remain strictly **SQL-agnostic** (PostgreSQL-ready). **Never write vendor-specific raw SQL queries.**
  - **Zero raw SQL for DML in `src/`.** Use typed entity methods (`Entity::find()`, `ActiveModel`) or SeaQuery builders.
  - Exceptions: `src/migration/` for DDL generated columns, and SQLite `PRAGMA` setup in `src/db.rs`.
- **Database Setup (`src/db.rs`):** SQLite connection pool pinned to `max_connections = 1` with 4 WAL session pragmas (`foreign_keys=ON`, `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`).
- **Frontend:** STRICTLY Vanilla JS, HTML5, and CSS3. **NO external dependencies** (No React, Vue, Tailwind, Bootstrap, CDN links, or Axios). Native `fetch()` only.
- **Quality & Safety:**
  - Zero compiler warnings, zero `clippy` warnings.
  - **Zero `.unwrap()` or `.expect()`** in production or HTTP handlers. Use structured `AppError` and Axum's `IntoResponse`.
  - **Mandatory `rustdoc`**: Document all public items with `///`. Enforce `#![warn(missing_docs)]` in `lib.rs`.

---

## 🏛️ Core Architectural Rules

### 1. Security & Network (Zero-Trust)

#### Inbound Requests (To `simply_ip_sync`)
- **Middleware Protection:** All `/api/*` routes pass through custom authentication middleware (`src/middleware.rs`).
- **Authentication (HMAC-SHA256):** Every inbound request MUST carry **three** headers:
  - `X-API-Key`: Plaintext API Key (matched via Argon2/SHA-256 hash).
  - `X-Timestamp`: UTC Unix time in seconds.
  - `X-Signature-256`: `sha256=<hex>` HMAC over `CANONICAL_V1` string (`METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`).
- **Anti-Replay Guard:** Monotonic 300-second symmetric freshness window + raw digest single-use cache (`replay::ReplayGuard`).
- **Secrets at Rest (`SYNC_ENCRYPTION_KEY`):** Encrypt stored API key signing secrets AND remote Vault credentials (`signing_secret` of `vault_endpoints`) using **XChaCha20-Poly1305** (`v1.xchacha20poly1305.<nonce>.<ct>`). Requires 64 hex character key.
- **CIDR Restriction & IP Extraction:** Standard `bound_ips` verification and right-to-left `TRUSTED_PROXIES` header parsing.

#### Outbound Requests (From `simply_ip_sync` to remote `ip_vault` endpoints)
- When communicating with remote `ip_vault` instances, `simply_ip_sync` acts as a client and MUST generate valid `CANONICAL_V1` HMAC signatures (`X-API-Key`, `X-Timestamp`, `X-Signature-256`) using the stored `api_key` and decrypted `signing_secret` of the target `vault_endpoint`.

#### IP Extraction & Trusted Proxies
- Respect `X-Forwarded-For` / `X-Real-IP` **only** when TCP peer is in `TRUSTED_PROXIES`.
- Walk `X-Forwarded-For` right-to-left, skipping trusted proxy hops.
- Invalid syntax in `TRUSTED_PROXIES` is fatal at startup.

---

### 2. Extensible Parsing Engine (External Sources)

`simply_ip_sync` supports fetching external threat intelligence over HTTP/HTTPS with modular parsers:

1. **`REGEX_LINE` (Text / Line-by-Line):**
   - Strips comments (lines starting with `#`, `;`, `//`).
   - Extracts valid IPv4/IPv6 addresses and CIDR subnets using strict IP regex patterns line by line.
   - Decoded with `String::from_utf8_lossy`, not a hard UTF-8 validation: a body containing
     ISO-8859-1/Windows-1252 bytes or transit corruption degrades those bytes to `U+FFFD`
     (extracting nothing from that stretch) rather than failing the entire feed.
2. **`JSON_PATH` (Structured JSON):**
   - Parses JSON payloads (e.g., AbuseIPDB API response, pfSense JSON exports).
   - Configured via `parser_config_json` containing the JSON path/pointer to the array of items and target key field (e.g., `{"array_path": "data", "ip_field": "ipAddress"}`).
   - `jsonl` mode (newline-delimited JSON, one object per line) decodes each line with the same
     lossy UTF-8 conversion as `REGEX_LINE`, so one non-UTF-8 line among well-formed ones only
     fails that line (skipped, same as any other malformed JSONL line) rather than the whole feed.
     The non-`jsonl` path needs no separate handling: `serde_json::from_slice` already validates
     UTF-8 as ordinary JSON syntax and returns a clean `Err`, never a panic, on invalid bytes.
3. **Extensible Trait (`FeedParser`):**
   - Modular architecture allowing simple addition of future parsers (e.g., CSV, XML, STIX/TAXII).

---

### 3. Synchronization & Ingestion Pipeline

#### A. External Ingestion Pipeline
1. **Fetch:** HTTP GET to `external_sources.source_url` with optional custom headers/user-agent. Transient upstream failures (`429`/`502`/`503`/`504`) are retried with exponential backoff and jitter (`OUTBOUND_MAX_RETRIES`, `OUTBOUND_RETRY_BACKOFF_MS`) before the job is marked `FAILED`. The response body is read via `jobs::decompress::read_capped_body` — a streaming read with a running byte count, not a single-shot `Response::bytes()` — so a `Content-Encoding` (gzip/deflate/brotli/zstd) decompression bomb aborts mid-stream with `FAILED` at `MAX_DECOMPRESSED_BYTES` (default 50 MiB) instead of buffering an arbitrarily large decompressed payload in memory first.
2. **Parse:** Execute configured `FeedParser` to extract normalized IP/CIDR strings. A `.zip`-archived body (`jobs::decompress::decompress_if_zip`) is decompressed first, member by member, under the same `MAX_DECOMPRESSED_BYTES` ceiling applied independently to the combined member output — a small archive whose member(s) decompress far past that ceiling aborts the same way, never after fully decompressing the bomb.
3. **Chunking & Batching:** Split extracted records into chunks of **5,000 items maximum** to comply with `ip_vault`'s `MAX_REQUEST_BODY_BYTES` (3 MiB limit).
4. **Push:** Send each chunk via `POST /api/records/batch` to all associated target `vault_endpoints` (defined in `external_source_vault_targets`). `external_sources.mode` is `"upsert"` (default — never implicitly deletes) or `"full_replace"` (this run's fetched content becomes the group's full authoritative set). **`full_replace` semantics apply to chunk 0 of each target's own chunk sequence only** — every later chunk of the same run automatically downgrades to `"upsert"` (`jobs::mode_for_chunk_index`), since a second `full_replace` write would read as "delete everything not in this chunk" and erase the previous chunk's just-delivered records. A `413 Payload Too Large` response from a target additionally triggers adaptive splitting: the offending chunk is halved and each half resent (recursively, if still too large), with the same first-piece-only-keeps-the-original-mode rule applied to the halves.
5. **Log:** Write detailed outcome to `sync_logs`.

#### B. Inter-Vault Sync Pipeline (Vault-to-Vault Delta)
1. **Fetch Delta:** Query source Vault via `GET /api/ips?group_name=X&since=<last_sync_at>&include_deleted=true`, transparently paginating (`limit`/`offset`) through the full delta result set and retrying transient per-page failures independently. `since` and `include_deleted=true` are what make this an *incremental* fetch — see point 3 below for why that rules out `full_replace` for this pipeline.
2. **Chunking & Batching:** Group incoming delta records (including soft-deleted tombstones) into lots of 5,000 records.
3. **Replicate:** Post chunked payload to `POST /api/records/batch` in mode `"upsert"` on all target Vaults (defined in `vault_sync_task_targets`). Unlike external ingestion, `vault_sync_tasks.mode` is **strictly `"upsert"`, deliberately not extended to `full_replace`**: a delta batch is a small incremental slice, not a group's full content, so a `full_replace` write here would read as "delete everything in the target group this run's delta didn't happen to touch" — which is nearly everything, on every run. The `413`-adaptive-splitting behavior still applies (it's a property of `client::post_batch`, independent of mode).
4. **Timestamp Update:** On success across all targets, update `vault_sync_tasks.last_sync_at` to the job start timestamp.

---

### 4. Scheduler & Manual Execution

- **Background Cron Scheduler:** Uses an in-process async scheduler (`tokio-cron-scheduler`) reading active `external_sources` and `vault_sync_tasks` schedules.
- **Manual Trigger Endpoints:**
  - `POST /api/sources/{id}/trigger`
  - `POST /api/sync-tasks/{id}/trigger`
- **Execution Rights:** Non-master keys holding `can_sync = true` permission on a specific source or sync task can manually trigger immediate execution outside the cron schedule.

---

### 5. Granular Multi-Tenant RBAC (M:N)

Implements `RBAC_MODEL.md` (Master / Parent / Daughter):
- **Master (`is_master`):** Full administrative rights. Identity pinned at boot. Single master enforced via database-generated `master_marker`.
- **Parent (`can_manage_keys`):** Can manage Daughter keys and assign resource permissions up to its own scope.
- **Daughter:** Cannot create keys. Can hold operational rights (`can_sync`, `can_manage`, `can_view_logs`) on specific sources, sync tasks, or vault endpoints via `api_key_sync_permissions`.
- **Conjunction (R2):** Managing a resource's permissions requires global `can_manage_keys` **AND** `can_manage = true` on that resource's permission row.

---

### 6. Audit Trail

Every mutating action (Key CRUD, Vault Endpoint CRUD, External Source CRUD, Sync Task CRUD, Permission updates) writes an entry to `audit_logs` storing denormalized actor details (`api_key_id`, `api_key_name`, `api_key_prefix`, `client_ip`), `action`, `target_resource`, and timestamp. `api_key_name`, `api_key_prefix`, and `client_ip` are **`NOT NULL`** (since `m20260818_000003_audit_attribution_not_null`): `api_key_id` is nullable and `ON DELETE SET NULL` specifically so deleting a key cannot erase the record of what it did, which means the denormalized snapshot columns are the *only* attribution that survives the key — an audit row with no name/prefix/IP recorded would be an action with no representable actor at all. See the migration's own module doc for the full rationale and the pre-`NOT NULL` backfill it performs.

---

### 7. SeaORM Migration Standards

Every migration in `src/migration/` follows two mandatory rules, checked as part of every schema
change and audited whenever a new migration is added:

1. **Naming convention.** Every migration file is named `m<YYYYMMDD>_<NNNNNN>_<migration_name>.rs`
   — an 8-digit date the migration was authored, an underscore, a 6-digit zero-padded sequence
   number (not a literal time-of-day; it exists to make ordering unambiguous when two migrations
   share a date), an underscore, and a short `snake_case` description. `SeaORM`'s `Migrator` applies
   migrations in the order they are listed in `src/migration/mod.rs`, and that list's order **must**
   match the filename order — the filename is not decorative, it is the mechanism a human (or an
   agent) uses to verify the applied order matches the intended one at a glance. Current migrations:
   `m20260101_000001_initial_schema.rs`, `m20260101_000002_derive_master_marker.rs`,
   `m20260818_000003_audit_attribution_not_null.rs`.
2. **Audit attribution integrity.** Any column that denormalizes actor/attribution data for the
   audit trail (see §6) must be `NOT NULL` once every write path that populates it is verified to
   always supply a value — nullability on such a column is either a temporary state during a
   backfill migration, or a bug. A migration that tightens such a column to `NOT NULL` must:
   - **Backfill first, constrain second.** Pre-existing rows may legitimately hold `NULL` (they
     predate the column's existence, or predate the migration itself); update them to an
     unambiguous, unmistakable-for-real-data sentinel (e.g. `"(unknown)"`, never a plausible-looking
     value like `"system"` or `"127.0.0.1"`) before applying the constraint, or the migration fails
     against any database with existing history.
   - **Never let this conflict with `ON DELETE SET NULL` on the owning FK.** A denormalized
     attribution column existing specifically *because* the FK it accompanies is nullable
     (`api_key_id: ON DELETE SET NULL`, so a key's own deletion doesn't erase its audit trail) must
     itself become `NOT NULL` once every write path is verified never to omit it — the FK's
     nullability and the denormalized column's non-nullability are not in tension; they are the
     same design decision seen from two different columns.
   - **SQLite needs a table rebuild, not `ALTER COLUMN`.** SQLite has no
     `ALTER TABLE … ALTER COLUMN`; tightening nullability there means: create a replacement table
     with the tightened definition (built via SeaORM's schema builder, not hand-written DDL, so
     column types match the original byte-for-byte), copy every row across with an explicit column
     list on both sides of `INSERT … SELECT` (never `SELECT *` — positional copying silently
     corrupts data on a future column reorder), drop the original, rename the replacement into
     place, and recreate every index the original table had. PostgreSQL and MySQL take
     `ALTER COLUMN … SET NOT NULL`/`MODIFY` directly; branch on `manager.get_database_backend()`.
   - See `m20260818_000003_audit_attribution_not_null.rs` for the reference implementation of all
     of the above, including its own `#[cfg(test)]` assertions that the strict/loose table
     definitions differ in exactly the intended columns and that the backfill sentinel cannot be
     mistaken for real data.

---

## 🌐 Public Probes

- `GET /health` or `/healthz`: Liveness probe (HTTP 200 `{"status":"ok","service":"simply_ip_sync"}`). No DB query.
- `GET /ready` or `/readyz`: Readiness probe (HTTP 200 if DB is up and master key pinned, HTTP 503 otherwise).

---

## 🧪 Testing & Validation Standards

- **Integration Tests:** Located in `tests/`. SQLite in-memory (`sqlite::memory:`).
- **Required Coverage:**
  1. Inbound HMAC validation & anti-replay tests.
  2. Outbound HMAC signature generation correctness against mock `ip_vault` endpoints.
  3. External feed parsing correctness (`REGEX_LINE` and `JSON_PATH`, including ZIP-archived and
     newline-delimited-JSON feed shapes via local fixtures — never against the live rate-limited
     source), including non-UTF-8/raw-binary bodies (lossy degradation, never a panic, valid IPs
     extracted where possible) and decompression-bomb rejection (a small ZIP member or
     `Content-Encoding`-compressed body that expands past `MAX_DECOMPRESSED_BYTES` must abort
     `FAILED`, not OOM).
  4. Batch chunking (verifying payloads never exceed 5,000 records).
  5. Inter-vault delta replication and tombstone propagation, including multi-vault fan-out and
     partial-failure resilience — including a failure partway through a single target's own
     multi-chunk push sequence (a later chunk failing after an earlier one already succeeded), not
     just a target that is down from the first request — must report `PARTIAL`/`FAILED`, must not
     advance `last_sync_at`, and must never attempt the chunk(s) after the one that failed.
  6. Manual trigger permissions (`can_sync` vs unauthorized 403).
  7. Adversarial infrastructure tests (`ADVERSARIAL(§N)` for master uniqueness).
  8. Cron expression validation: `POST /api/sources` and `POST /api/sync-tasks` must reject a
     malformed `cron_schedule` with `400` before any database write.
  9. `static/app.js` source hygiene: zero JavaScript syntax errors, and every
     `document.getElementById()` reference resolvable against `static/index.html` (statically or
     dynamically injected).
- **Live network tests** (`tests/live_feed_ingestion_tests.rs`) are `#[ignore]`d and excluded from
  the default `cargo test` run; they must still pass when run explicitly via
  `cargo test -- --ignored` before merging a change that touches the parser or ingestion pipeline.
- **`./scripts/test_e2e.sh`** is a mandatory quality gate alongside `cargo check`/`clippy`/`test`.
  It boots the real compiled binary (not the in-process router) against an isolated temp database
  and port, drives it with hand-signed `curl` requests, and is the only gate that proves actual
  multi-vault delivery over a real socket and a clean process shutdown on `SIGTERM`.

*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*