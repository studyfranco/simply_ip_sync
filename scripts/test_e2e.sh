#!/usr/bin/env bash
# End-to-end test suite for simply_ip_sync.
#
# Boots the real compiled binary against an isolated temporary SQLite database and port, drives it
# with real HMAC-signed HTTP requests via curl (never through the Rust test harness), and spins up
# local Python mock `simply_ip_vault` HTTP servers to verify actual multi-vault delivery over the
# wire — the one thing `tests/*.rs` cannot prove, since those exercise the router in-process via
# `tower::ServiceExt::oneshot` and never open a real socket.
#
# Structured and worded after example/simply_ip_vault/scripts/test_e2e.sh and
# example/simply_hook_executor/scripts/test_e2e.sh (this ecosystem's established E2E convention),
# scoped down to simply_ip_sync's own domain (threat feed ingestion + inter-vault sync) rather than
# their IP-ban/webhook domains.
#
# Not using `set -e`: assertions on purpose expect non-2xx responses (400/401/403/404/409), so a
# non-zero curl/jq exit inside a check must not abort the whole run.
set -uo pipefail

# ── Working-directory guard ──────────────────────────────────────────────────
# Fails loudly rather than silently running against the wrong tree (or, worse, deleting a
# temp dir under an unrelated `simply_ip_sync`-named directory that happens to exist elsewhere).
if [[ "$(basename "$PWD")" != "simply_ip_sync" ]]; then
    echo "ERROR: Script must be executed from the simply_ip_sync repository root." >&2
    echo "       Current directory: $PWD" >&2
    exit 1
fi
for marker in Cargo.toml AGENT.MD SCHEMA.MD src/main.rs scripts/test_e2e.sh; do
    if [[ ! -e "$marker" ]]; then
        echo "ERROR: '$PWD' is named simply_ip_sync but is not this repository." >&2
        echo "       Expected to find '$marker' and did not." >&2
        exit 1
    fi
done
PROJECT_ROOT="$PWD"
# Ensure local cargo-installed binaries (e.g. cargo-audit in ~/.cargo/bin) are on PATH
export PATH="$HOME/.cargo/bin:$PATH"

# ── Output helpers ───────────────────────────────────────────────────────────
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

ts() { date +"%H:%M:%S.%3N"; }
log() { echo -e "$(ts) ${CYAN}[INFO]${RESET} $*" >&2; }
warn() { echo -e "$(ts) ${YELLOW}[WARN]${RESET} $*" >&2; }
err() { echo -e "$(ts) ${RED}[ERROR]${RESET} $*" >&2; }
log_section() {
    echo "" >&2
    echo -e "$(ts) ${BOLD}${MAGENTA}=== $* ===${RESET}" >&2
}

status_color() {
    case "$1" in
        2??) echo -n "$GREEN" ;;
        400|401|403|404|409|413|422) echo -n "$YELLOW" ;;
        4??) echo -n "$YELLOW" ;;
        5??) echo -n "$RED" ;;
        *) echo -n "$RESET" ;;
    esac
}

# Every diagnostic function above writes to stderr, never stdout: helpers below return values to
# callers via `$(...)` command substitution (vault ids, key ids, plaintext credentials), which
# only captures stdout. Any log/print pollution of stdout would silently corrupt captured values.

# ── Preflight ─────────────────────────────────────────────────────────────────
log_section "Preflight"
for tool in cargo curl openssl jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        err "Required tool '$tool' not found on PATH."
        exit 1
    fi
done
if ! command -v cargo-audit >/dev/null 2>&1 && ! cargo audit --version >/dev/null 2>&1; then
    log "cargo-audit not found on PATH; attempting to install via 'cargo install cargo-audit'..."
    if ! cargo install cargo-audit; then
        err "cargo-audit is required for dependency security audits but is missing and could not be installed."
        exit 1
    fi
fi
log "Found cargo-audit: $(command -v cargo-audit 2>/dev/null || echo "cargo audit subcommand")"

PYTHON3_AVAILABLE=0
if command -v python3 >/dev/null 2>&1; then
    PYTHON3_AVAILABLE=1
else
    warn "python3 not found — multi-vault mock-server and local-fixture sections will be skipped."
fi
log "All required tools present."

# ── Build ─────────────────────────────────────────────────────────────────────
mkdir -p "$PROJECT_ROOT/target"
WORK_DIR="$(mktemp -d "${TMPDIR:-$PROJECT_ROOT/target}/simply_ip_sync_e2e.XXXXXX")"
DB_PATH="$WORK_DIR/e2e.db"
SERVER_LOG="$WORK_DIR/server.log"
RESP_BODY_FILE="$WORK_DIR/resp_body"

# ── Dependencies & Security Audit ─────────────────────────────────────────────
log_section "Dependencies & Security Audit"

log "Running cargo audit --deny warnings in $PROJECT_ROOT ..."
if ! (cd "$PROJECT_ROOT" && cargo audit --deny warnings >"$WORK_DIR/cargo_audit.log" 2>&1); then
    err "cargo audit detected vulnerabilities or failed:"
    cat "$WORK_DIR/cargo_audit.log" >&2
    rm -rf "$WORK_DIR"
    exit 1
fi
log "cargo audit passed cleanly."

log_section "Build"
log "Running cargo build in $PROJECT_ROOT ..."
if ! (cd "$PROJECT_ROOT" && cargo build --locked --quiet 2>"$WORK_DIR/build.log"); then
    err "Build failed:"
    cat "$WORK_DIR/build.log" >&2
    rm -rf "$WORK_DIR"
    exit 1
fi
log "Build succeeded."
BINARY="$PROJECT_ROOT/target/debug/simply_ip_sync"
if [[ ! -x "$BINARY" ]]; then
    err "Expected binary not found at $BINARY"
    rm -rf "$WORK_DIR"
    exit 1
fi

# ── Port selection ───────────────────────────────────────────────────────────
BIND_HOST="127.0.0.1"
REQUESTED_PORT="${PORT:-}"
SERVER_PORT=""

port_in_use() {
    local port="$1"
    (exec 3<>"/dev/tcp/$BIND_HOST/$port") 2>/dev/null
}

pick_port() {
    local start="$1" end="$2" label="$3"
    if [[ -n "${4:-}" ]]; then
        if port_in_use "$4"; then
            err "$label: port $4 was requested but something is already listening on it."
            exit 1
        fi
        echo "$4"
        return
    fi
    local candidate offset width=$((end - start + 1))
    local first=$((RANDOM % width))
    for ((offset = 0; offset < width; offset++)); do
        candidate=$((start + (first + offset) % width))
        if ! port_in_use "$candidate"; then
            echo "$candidate"
            return
        fi
    done
    err "$label: no free port found in range $start-$end."
    exit 1
}

SERVER_PORT="$(pick_port 20000 24999 "simply_ip_sync" "$REQUESTED_PORT")" || {
    rm -rf "$WORK_DIR"
    exit 1
}
BASE_URL="http://$BIND_HOST:$SERVER_PORT"
log "simply_ip_sync will listen on $BASE_URL"

# ── Deterministic Master credentials ────────────────────────────────────────
# Both set as env vars before boot so this script never needs to scrape them back out of the
# (buffered, redirected) server log — see src/config.rs::INITIAL_MASTER_KEY_ENV and
# ::INITIAL_MASTER_SIGNING_SECRET_ENV, and src/main.rs::bootstrap_master_key.
# Must be exactly 64 hex characters (validate_initial_master_key / ..._signing_secret enforce
# this strictly) — built with printf rather than hand-counted literals, since a hand-typed 64-char
# hex string is exactly the kind of thing that silently grows a stray non-hex character.
MASTER_KEY="e2e5$(printf '1%.0s' $(seq 1 60))"
MASTER_SIGNING_SECRET="e2e6$(printf '2%.0s' $(seq 1 60))"

declare -A SIGNING_SECRETS=()
SIGNING_SECRETS["$MASTER_KEY"]="$MASTER_SIGNING_SECRET"

register_key_secret() {
    local key="$1" secret="$2"
    if [[ -z "$key" || "$key" == "null" || -z "$secret" || "$secret" == "null" ]]; then
        err "register_key_secret called with an empty key/secret — the API response was malformed"
        return 1
    fi
    SIGNING_SECRETS["$key"]="$secret"
}

# ── Daemon lifecycle ─────────────────────────────────────────────────────────
SERVER_PID=""
SSRF_SERVER_PID=""
MOCK_SOURCE_PID=""
MOCK_TARGET1_PID=""
MOCK_TARGET2_PID=""
FIXTURE_SERVER_PID=""
EXTRA_MOCK_PID=""
RESILIENCE_MOCK_PID=""

if ! command -v sqlite3 >/dev/null 2>&1; then
    sqlite3() {
        python3 - "$@" <<'PY'
import sqlite3, sys
db_path = sys.argv[1]
query = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read()
conn = sqlite3.connect(db_path, timeout=10.0)
try:
    cur = conn.cursor()
    if query.strip().lower() == ".dump":
        for line in conn.iterdump():
            print(line)
    else:
        for stmt in [s.strip() for s in query.split(";") if s.strip()]:
            cur.execute(stmt)
            for row in cur.fetchall():
                print("|".join("" if v is None else str(v) for v in row))
        conn.commit()
finally:
    conn.close()
PY
    }
fi

cleanup() {
    local pid_var pid
    for pid_var in SERVER_PID SSRF_SERVER_PID MOCK_SOURCE_PID MOCK_TARGET1_PID MOCK_TARGET2_PID FIXTURE_SERVER_PID EXTRA_MOCK_PID RESILIENCE_MOCK_PID; do
        pid="${!pid_var}"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "Stopping $pid_var (pid $pid)..."
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

E2E_ENCRYPTION_KEY="0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

log_section "Boot"
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" \
    RUST_LOG=info \
    INITIAL_MASTER_KEY="$MASTER_KEY" \
    INITIAL_MASTER_SIGNING_SECRET="$MASTER_SIGNING_SECRET" \
    SYNC_ENCRYPTION_KEY="$E2E_ENCRYPTION_KEY" \
    ALLOW_PRIVATE_INGEST_URLS_FOR_TEST=true \
    BIND_HOST="$BIND_HOST" \
    PORT="$SERVER_PORT" \
    TRUSTED_PROXIES="127.0.0.1/32" \
    "$BINARY" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
log "Started simply_ip_sync (pid $SERVER_PID), logging to $SERVER_LOG"

log "Waiting for the server to become ready..."
READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        err "Server process exited during startup. Log:"
        cat "$SERVER_LOG" >&2
        exit 1
    fi
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/ready" 2>/dev/null)
    if [[ "$STATUS_CODE" == "200" ]]; then
        READY=1
        break
    fi
    sleep 0.5
done
if [[ "$READY" -ne 1 ]]; then
    err "Server did not become ready in time. Log:"
    cat "$SERVER_LOG" >&2
    exit 1
fi
log "Server is up and /ready reports 200."

# ── CANONICAL_V1 signing ─────────────────────────────────────────────────────

# Computes the full X-Signature-256 header value the server expects — `sha256=<hex>` over the
# CANONICAL_V1 string METHOD\nTARGET\nTIMESTAMP\nRAW_BODY (four fields joined by single LFs, no
# trailing newline). TARGET is the full request target including query string — CANONICAL_V1 signs
# the query string too, so a script that stripped it here would make every check below pass
# vacuously against query-string tampering.
#
# `printf '%s\n%s\n%s\n%s'` (not `echo -e`, not string interpolation) is what makes the delimiters
# real newlines and keeps the message byte-exact, with no trailing newline after the body.
# Usage: hmac_sign SECRET METHOD TARGET TIMESTAMP BODY
hmac_sign() {
    local secret="$1" method="$2" target="$3" timestamp="$4" body="${5:-}"
    printf 'sha256=%s' "$(printf '%s\n%s\n%s\n%s' "$method" "$target" "$timestamp" "$body" \
        | openssl dgst -sha256 -hmac "$secret" -r | cut -d' ' -f1)"
}

# Guarantees a fresh X-Timestamp for every signed request the script issues, script-wide. The
# suite fires many calls per second; repeating an identical (method, target, timestamp, body)
# tuple within the same wall-clock second reproduces an identical signature, which the server
# correctly rejects as a replay. A per-request-identity counter (this function's first cut) is not
# enough: two *unrelated* checks hitting the same method+path+body (e.g. two separate
# `GET /api/auth/me` calls in different sections) can still coincidentally land in the same
# wall-clock second and collide, since the server's replay guard has no notion of this script's
# bookkeeping keys — only a single script-wide monotonic counter can guarantee every timestamp
# this script ever signs with is unique, which is what makes the deliberate replay test below (the
# one section that intentionally reuses a timestamp) meaningful rather than accidental.
LAST_TS=0
next_timestamp() {
    local now; now=$(date -u +%s)
    if [[ "$now" -le "$LAST_TS" ]]; then
        now=$((LAST_TS + 1))
    fi
    LAST_TS=$now
    SIGNED_TS=$now
}

print_response_body() {
    if [[ -z "$RESP_BODY" ]]; then
        echo -e "$(ts)          ${DIM}(empty body)${RESET}" >&2
        return
    fi
    local formatted
    if formatted=$(echo "$RESP_BODY" | jq . 2>/dev/null); then
        while IFS= read -r line; do
            echo -e "$(ts)          ${DIM}${line}${RESET}" >&2
        done <<< "$formatted"
    else
        echo -e "$(ts)          ${DIM}${RESP_BODY}${RESET}" >&2
    fi
}

# Signed request through the real client path: looks up the caller's registered signing secret,
# computes CANONICAL_V1, and issues the request. Sets $RESP_STATUS / $RESP_BODY.
# Usage: api_call METHOD PATH [API_KEY] [JSON_BODY]
api_call() {
    local method="$1" path="$2" api_key="${3:-}" data="${4:-}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method")
    if [[ -n "$api_key" ]]; then
        local secret="${SIGNING_SECRETS[$api_key]:-unregistered-key-has-no-signing-secret}"
        next_timestamp
        local sig; sig=$(hmac_sign "$secret" "$method" "$path" "$SIGNED_TS" "$data")
        args+=(-H "X-API-Key: $api_key" -H "X-Timestamp: $SIGNED_TS" -H "X-Signature-256: $sig")
    fi
    if [[ -n "$data" ]]; then
        args+=(-H "Content-Type: application/json" --data-binary "$data")
    fi
    RESP_STATUS=$(curl "${args[@]}" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" >&2
    print_response_body
}

# Lower-level escape hatch for checks that deliberately need malformed/missing/tampered headers —
# takes arbitrary curl args instead of computing a valid signature automatically.
# Usage: raw_call METHOD PATH [curl-args...]
raw_call() {
    local method="$1" path="$2"; shift 2
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" "$@" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" >&2
    print_response_body
}

# ── Assertions ────────────────────────────────────────────────────────────────

check() {
    local expected="$1" description="$2"
    if [[ "$RESP_STATUS" == "$expected" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    fi
}

check_jq() {
    local filter="$1" expected="$2" description="$3"
    local actual
    actual=$(echo "$RESP_BODY" | jq -r "$filter" 2>/dev/null)
    if [[ "$actual" == "$expected" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (got '$actual')" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

check_true() {
    local expr="$1" description="$2"
    local actual
    actual=$(echo "$RESP_BODY" | jq -e "$expr" 2>/dev/null)
    if [[ "$actual" == "true" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (jq expr '$expr' was not true)" >&2
    fi
}

check_local() {
    local actual="$1" expected="$2" description="$3"
    if [[ "$actual" == "$expected" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

# Usage: check_matches ACTUAL BASH_REGEX "description" — for assertions against a shape
# (e.g. "sha256=<64 hex chars>") rather than an exact expected value.
check_matches() {
    local actual="$1" pattern="$2" description="$3"
    if [[ "$actual" =~ $pattern ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (got '$actual')" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (got '$actual', expected to match /$pattern/)" >&2
    fi
}

skip() {
    SKIP_COUNT=$((SKIP_COUNT + 1))
    echo -e "$(ts)   ${YELLOW}⊘ SKIP${RESET} $*" >&2
}

# Usage: check_not_contains "literal substring" "description" — asserts $RESP_BODY does NOT
# contain `needle`. Refuses an empty needle rather than silently passing: `[[ "$x" == *""* ]]` is
# true for every string, so an empty needle here would report PASS unconditionally regardless of
# what leaked — exactly the false-positive shape this helper exists to prevent (adopted from
# example/simply_hook_executor and example/simply_ip_exporter's identical helper).
check_not_contains() {
    local needle="$1" description="$2"
    if [ -z "$needle" ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (empty needle — the assertion is vacuous)" >&2
        return
    fi
    if [[ "$RESP_BODY" == *"$needle"* ]]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (the body contains it)" >&2
    else
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    fi
}

# ── 1. Public probes ─────────────────────────────────────────────────────────
log_section "1. Public probes"

raw_call GET "/health"
check "200" "GET /health is 200 with no credentials"
check_jq ".status" "ok" "/health reports status=ok"
check_jq ".service" "simply_ip_sync" "/health reports service=simply_ip_sync"

raw_call GET "/healthz"
check "200" "GET /healthz (k8s-idiomatic alias) is 200"

raw_call GET "/ready"
check "200" "GET /ready is 200 once boot has completed"
check_jq ".status" "ok" "/ready reports status=ok"

raw_call GET "/readyz"
check "200" "GET /readyz (k8s-idiomatic alias) is 200"

# ── 2. Boot identity verification ────────────────────────────────────────────
log_section "2. Boot identity verification"

api_call GET "/api/auth/me" "$MASTER_KEY"
check "200" "the deterministic INITIAL_MASTER_KEY authenticates"
check_jq ".is_master" "true" "it reports is_master=true"
check_jq ".can_manage_keys" "true" "Master reports can_manage_keys=true"
check_jq ".can_manage_sources" "true" "Master reports can_manage_sources=true"
check_jq ".can_manage_vaults" "true" "Master reports can_manage_vaults=true"
MASTER_ID=$(echo "$RESP_BODY" | jq -r '.id')

# ── 3. HMAC signing & anti-replay ────────────────────────────────────────────
log_section "3. HMAC signing & anti-replay"

raw_call GET "/api/keys"
check "401" "unauthenticated request to a protected route is 401, not 500 or a route-not-found 404"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $(date +%s)"
check "401" "request missing X-Signature-256 entirely is 401"

TS_NOW=$(date +%s)
BAD_SIG="sha256=$(printf '0%.0s' {1..64})"
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $TS_NOW" -H "X-Signature-256: $BAD_SIG"
check "401" "a well-formed but wrong signature is 401"

# Deliberate replay: sign one request, send it twice with byte-identical headers.
next_timestamp
REPLAY_TS="$SIGNED_TS"
REPLAY_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$REPLAY_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $REPLAY_TS" -H "X-Signature-256: $REPLAY_SIG"
check "200" "first use of a fresh signature is accepted"
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $REPLAY_TS" -H "X-Signature-256: $REPLAY_SIG"
check "401" "replaying the exact same signed request is rejected"

# A signature computed over one body must not verify a request carrying a different (tampered)
# body — proves the signature actually covers the body, not just the headers.
next_timestamp
TAMPER_TS="$SIGNED_TS"
TAMPER_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "POST" "/api/vaults" "$TAMPER_TS" '{"name":"original"}')
raw_call POST "/api/vaults" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $TAMPER_TS" \
    -H "X-Signature-256: $TAMPER_SIG" -H "Content-Type: application/json" \
    --data-binary '{"name":"tampered-after-signing","target_url":"http://127.0.0.1:1","api_key":"k","signing_secret":"s"}'
check "401" "a signature computed over a different body than the one actually sent is rejected"

# Expired timestamp: outside the 300s symmetric freshness window.
STALE_TS=$(( $(date +%s) - 3600 ))
STALE_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$STALE_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $STALE_TS" -H "X-Signature-256: $STALE_SIG"
check "401" "a timestamp 1 hour in the past (outside the 300s window) is rejected"

FUTURE_TS=$(( $(date +%s) + 3600 ))
FUTURE_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$FUTURE_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $FUTURE_TS" -H "X-Signature-256: $FUTURE_SIG"
check "401" "a timestamp 1 hour in the future is rejected (the window is symmetric)"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: not-a-number" -H "X-Signature-256: sha256=deadbeef"
check "401" "a malformed (non-numeric) X-Timestamp is rejected, not a 500"

# ── 4. Cron expression validation ────────────────────────────────────────────
log_section "4. Cron expression validation"

for bad_cron in "invalid_cron" "* * *" "99 99 99 * *"; do
    api_call POST "/api/destination-groups" "$MASTER_KEY" \
        "{\"name\":\"bad-cron-group-$RANDOM\",\"cron_schedule\":\"$bad_cron\",\"target_group_name\":\"g\"}"
    check "400" "POST /api/destination-groups with cron_schedule '$bad_cron' is rejected with 400"
done

api_call GET "/api/destination-groups" "$MASTER_KEY"
check "200" "listing destination groups still works after the rejected attempts"
check_jq "length" "0" "none of the invalid-cron destination groups were persisted"

# A vault endpoint is needed as source_vault_id before sync-task cron validation can be checked in
# isolation from a foreign-key failure.
api_call POST "/api/vaults" "$MASTER_KEY" \
    '{"name":"cron-validation-scratch-vault","target_url":"http://127.0.0.1:1","api_key":"k","signing_secret":"s"}'
check "200" "create a scratch vault endpoint for the cron-validation-only checks"
SCRATCH_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

for bad_cron in "invalid_cron" "* * *" "not-a-cron-at-all"; do
    api_call POST "/api/sync-tasks" "$MASTER_KEY" \
        "{\"name\":\"bad-cron-task-$RANDOM\",\"source_vault_id\":\"$SCRATCH_VAULT_ID\",\"source_group_name\":\"sg\",\"target_group_name\":\"tg\",\"cron_schedule\":\"$bad_cron\"}"
    check "400" "POST /api/sync-tasks with cron_schedule '$bad_cron' is rejected with 400"
done

api_call GET "/api/sync-tasks" "$MASTER_KEY"
check_jq "length" "0" "none of the invalid-cron sync tasks were persisted"

api_call POST "/api/destination-groups" "$MASTER_KEY" \
    '{"name":"valid-cron-group","cron_schedule":"0 0 * * *","target_group_name":"g"}'
check "200" "a syntactically valid 5-field cron_schedule is accepted"
api_call DELETE "/api/destination-groups/$(echo "$RESP_BODY" | jq -r '.id')" "$MASTER_KEY"
check "204" "clean up the valid-cron scratch group"

# ── 5. Multi-vault sync: mock ip_vault servers ──────────────────────────────
log_section "5. Multi-vault sync — mock ip_vault servers"

MULTI_VAULT_AVAILABLE=0
if [[ "$PYTHON3_AVAILABLE" -eq 1 ]]; then
    cat > "$WORK_DIR/mock_vault.py" <<'PYEOF'
# Minimal mock simply_ip_vault: serves a paginated GET /api/ips delta, an optional static
# GET /feed.txt (for doubling as an external-feed HTTP source), and logs every
# POST /api/records/batch (headers + body) as one JSON line per request. Behavior for POST and the
# contents served by GET are controlled by re-reading small files on every request — mode_path,
# delta_path, feed_path — so the test script can flip a target's behavior, swap its delta content,
# or make a feed appear, all without restarting the process or losing its port.
#
# mode values:
#   ok                    - normal success response.
#   fail500               - every POST fails with 500.
#   fail413               - every POST fails with 413 (payload can never be split small enough).
#   retry:<status>:<n>    - the first <n> POSTs while this exact mode string is active fail with
#                           <status> (429/502/503/504), every POST after that succeeds. The hit
#                           counter resets whenever the mode file's content changes, so re-arming a
#                           fresh "retry:503:2" later in the same process starts counting from zero
#                           again.
#   split413:<threshold>  - a POST is rejected with 413 iff its `records` array has more than
#                           <threshold> entries; otherwise it succeeds. Models a target vault with a
#                           real payload-size ceiling, for exercising client-side adaptive splitting.
#   failafter:<status>:<n> - the mirror of retry: the first <n> POSTs while this exact mode string
#                           is active succeed, every POST after that fails with <status>. Models a
#                           target that accepts the first chunk or two of a multi-chunk run (e.g.
#                           the full_replace chunk that just cleared-and-set its content) and then
#                           goes down mid-stream — the same hit-counter-reset-on-mode-change rule
#                           as retry: applies.
import http.server
import json
import sys
import urllib.parse

port = int(sys.argv[1])
log_path = sys.argv[2]
mode_path = sys.argv[3]
delta_path = sys.argv[4]
feed_path = sys.argv[5] if len(sys.argv) > 5 else None

_mode_state = {"last": None, "hits": 0}


class Handler(http.server.BaseHTTPRequestHandler):
    def _mode(self):
        try:
            with open(mode_path) as f:
                return f.read().strip() or "ok"
        except FileNotFoundError:
            return "ok"

    def _write_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/ips"):
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            with open(delta_path, "rb") as f:
                all_records = json.loads(f.read())
            offset = int(qs.get("offset", ["0"])[0])
            limit = int(qs.get("limit", [str(len(all_records))])[0])
            self._write_json(200, all_records[offset:offset + limit])
        elif feed_path and self.path.startswith("/feed.txt"):
            try:
                with open(feed_path, "rb") as f:
                    body = f.read()
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        entry = {
            "path": self.path,
            "signature": self.headers.get("X-Signature-256"),
            "timestamp": self.headers.get("X-Timestamp"),
            "api_key": self.headers.get("X-API-Key"),
            "body": raw.decode("utf-8", "replace"),
        }
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        mode = self._mode()
        if mode != _mode_state["last"]:
            _mode_state["last"] = mode
            _mode_state["hits"] = 0

        forced_status = None
        if mode == "fail500":
            forced_status = 500
        elif mode == "fail413":
            forced_status = 413
        elif mode.startswith("retry:"):
            _, status_str, n_str = mode.split(":")
            _mode_state["hits"] += 1
            if _mode_state["hits"] <= int(n_str):
                forced_status = int(status_str)
        elif mode.startswith("split413:"):
            threshold = int(mode.split(":")[1])
            try:
                record_count = len(json.loads(raw).get("records", []))
            except (json.JSONDecodeError, AttributeError):
                record_count = 0
            if record_count > threshold:
                forced_status = 413
        elif mode.startswith("failafter:"):
            _, status_str, n_str = mode.split(":")
            _mode_state["hits"] += 1
            if _mode_state["hits"] > int(n_str):
                forced_status = int(status_str)

        if forced_status is not None:
            self.send_response(forced_status)
            self.end_headers()
            return

        self._write_json(
            200,
            {"created": 1, "updated": 0, "restored": 0, "locked_skipped": 0, "soft_deleted": 0, "linked": 1},
        )

    def log_message(self, format, *args):
        pass


http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PYEOF

    SOURCE_PORT="$(pick_port 18700 18720 "mock source vault")"
    TARGET1_PORT="$(pick_port 18721 18740 "mock target1 vault")"
    TARGET2_PORT="$(pick_port 18741 18760 "mock target2 vault")"

    SOURCE_LOG="$WORK_DIR/source_hits.log"; : > "$SOURCE_LOG"
    TARGET1_LOG="$WORK_DIR/target1_hits.log"; : > "$TARGET1_LOG"
    TARGET2_LOG="$WORK_DIR/target2_hits.log"; : > "$TARGET2_LOG"
    TARGET1_MODE="$WORK_DIR/target1_mode"; echo "ok" > "$TARGET1_MODE"
    TARGET2_MODE="$WORK_DIR/target2_mode"; echo "ok" > "$TARGET2_MODE"
    UNUSED_MODE="$WORK_DIR/unused_mode"; echo "ok" > "$UNUSED_MODE"

    SOURCE_DELTA="$WORK_DIR/source_delta.json"
    cat > "$SOURCE_DELTA" <<'JSONEOF'
[
  {"id":"11111111-1111-1111-1111-111111111111","target_address":"198.51.100.10","group_name":"src-group","is_deleted":false,"created_at":"2026-01-01T00:00:00","updated_at":"2026-01-01T00:00:00","last_seen_at":"2026-01-01T00:00:00"},
  {"id":"22222222-2222-2222-2222-222222222222","target_address":"198.51.100.11","group_name":"src-group","is_deleted":true,"deleted_at":"2026-01-02T00:00:00","created_at":"2026-01-01T00:00:00","updated_at":"2026-01-02T00:00:00","last_seen_at":"2026-01-01T00:00:00"}
]
JSONEOF

    # EXTRA_MOCK doubles as: (a) a large-delta source for the pagination test (its delta file is
    # overwritten in place, per subsection, since the mock re-reads it fresh on every GET), and
    # (b) a static /feed.txt server for the full_replace multi-chunk test (its feed file starts out
    # absent — a 404 — until 7h writes it). RESILIENCE_MOCK is a POST target whose mode file drives
    # the retry/413 scenarios; SOURCE_DELTA is passed as its (unused by those tests) delta arg.
    EXTRA_PORT="$(pick_port 18761 18780 "extra mock vault (pagination/feed)")"
    RESILIENCE_PORT="$(pick_port 18781 18800 "resilience mock vault (retry/413)")"
    EXTRA_LOG="$WORK_DIR/extra_hits.log"; : > "$EXTRA_LOG"
    RESILIENCE_LOG="$WORK_DIR/resilience_hits.log"; : > "$RESILIENCE_LOG"
    EXTRA_DELTA="$WORK_DIR/extra_delta.json"; echo "[]" > "$EXTRA_DELTA"
    EXTRA_FEED="$WORK_DIR/extra_feed.txt"  # deliberately not created yet — see 7h
    RESILIENCE_MODE="$WORK_DIR/resilience_mode"; echo "ok" > "$RESILIENCE_MODE"

    python3 "$WORK_DIR/mock_vault.py" "$SOURCE_PORT" "$SOURCE_LOG" "$UNUSED_MODE" "$SOURCE_DELTA" &
    MOCK_SOURCE_PID=$!
    python3 "$WORK_DIR/mock_vault.py" "$TARGET1_PORT" "$TARGET1_LOG" "$TARGET1_MODE" "$SOURCE_DELTA" &
    MOCK_TARGET1_PID=$!
    python3 "$WORK_DIR/mock_vault.py" "$TARGET2_PORT" "$TARGET2_LOG" "$TARGET2_MODE" "$SOURCE_DELTA" &
    MOCK_TARGET2_PID=$!
    python3 "$WORK_DIR/mock_vault.py" "$EXTRA_PORT" "$EXTRA_LOG" "$UNUSED_MODE" "$EXTRA_DELTA" "$EXTRA_FEED" &
    EXTRA_MOCK_PID=$!
    python3 "$WORK_DIR/mock_vault.py" "$RESILIENCE_PORT" "$RESILIENCE_LOG" "$RESILIENCE_MODE" "$SOURCE_DELTA" &
    RESILIENCE_MOCK_PID=$!
    sleep 0.3

    if kill -0 "$MOCK_SOURCE_PID" 2>/dev/null && kill -0 "$MOCK_TARGET1_PID" 2>/dev/null \
        && kill -0 "$MOCK_TARGET2_PID" 2>/dev/null && kill -0 "$EXTRA_MOCK_PID" 2>/dev/null \
        && kill -0 "$RESILIENCE_MOCK_PID" 2>/dev/null; then
        MULTI_VAULT_AVAILABLE=1
        log "Mock vaults up: source=:$SOURCE_PORT target1=:$TARGET1_PORT target2=:$TARGET2_PORT extra=:$EXTRA_PORT resilience=:$RESILIENCE_PORT"
    else
        warn "One or more mock vault servers failed to start; skipping multi-vault sections."
    fi
else
    skip "multi-vault sync sections (python3 unavailable)"
fi

if [[ "$MULTI_VAULT_AVAILABLE" -eq 1 ]]; then
    api_call POST "/api/vaults" "$MASTER_KEY" \
        "{\"name\":\"mock-source-vault\",\"target_url\":\"http://127.0.0.1:$SOURCE_PORT\",\"api_key\":\"mock-key\",\"signing_secret\":\"mock-secret\"}"
    check "200" "register the mock source vault endpoint"
    SOURCE_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/vaults" "$MASTER_KEY" \
        "{\"name\":\"mock-target1-vault\",\"target_url\":\"http://127.0.0.1:$TARGET1_PORT\",\"api_key\":\"mock-key\",\"signing_secret\":\"mock-secret\"}"
    check "200" "register mock target vault 1"
    TARGET1_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/vaults" "$MASTER_KEY" \
        "{\"name\":\"mock-target2-vault\",\"target_url\":\"http://127.0.0.1:$TARGET2_PORT\",\"api_key\":\"mock-key\",\"signing_secret\":\"mock-secret\"}"
    check "200" "register mock target vault 2"
    TARGET2_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

    # skip_bogon_filtering:true -- the mock source's fixture delta uses TEST-NET-2 (198.51.100.0/24)
    # addresses (RFC 5737 documentation range), which the new pre-push bogon sanitizer would
    # otherwise strip entirely; this section is testing multi-vault fan-out, not bogon filtering.
    api_call POST "/api/sync-tasks" "$MASTER_KEY" \
        "{\"name\":\"multi-vault-e2e-task\",\"source_vault_id\":\"$SOURCE_VAULT_ID\",\"source_group_name\":\"src-group\",\"target_group_name\":\"dst-group\",\"cron_schedule\":\"0 0 * * *\",\"is_active\":false,\"skip_bogon_filtering\":true,\"targets\":[{\"vault_endpoint_id\":\"$TARGET1_VAULT_ID\"},{\"vault_endpoint_id\":\"$TARGET2_VAULT_ID\"}]}"
    check "200" "create a sync task fanning out to both target vaults"
    SYNC_TASK_ID=$(echo "$RESP_BODY" | jq -r '.id')
    check_jq ".targets | length" "2" "the created task carries both configured targets"
    check_jq ".last_sync_at" "null" "a freshly created task has no last_sync_at yet"

    log_section "6. Multi-vault sync — successful fan-out"

    api_call POST "/api/sync-tasks/$SYNC_TASK_ID/trigger" "$MASTER_KEY"
    check "200" "manually trigger the multi-vault sync task"
    check_jq ".status" "SUCCESS" "the job reports SUCCESS when every target accepts the batch"
    check_jq ".items_processed" "2" "both delta records (including the tombstone) were processed"

    T1_HITS=$(wc -l < "$TARGET1_LOG" | tr -d ' ')
    T2_HITS=$(wc -l < "$TARGET2_LOG" | tr -d ' ')
    check_local "$T1_HITS" "1" "target vault 1 received exactly one POST /api/records/batch"
    check_local "$T2_HITS" "1" "target vault 2 received exactly one POST /api/records/batch"

    T1_SIG=$(head -n1 "$TARGET1_LOG" | jq -r '.signature')
    T2_SIG=$(head -n1 "$TARGET2_LOG" | jq -r '.signature')
    check_matches "$T1_SIG" '^sha256=[0-9a-f]{64}$' "target 1's received request carries a CANONICAL_V1-shaped X-Signature-256"
    check_matches "$T2_SIG" '^sha256=[0-9a-f]{64}$' "target 2's received request carries a CANONICAL_V1-shaped X-Signature-256"

    T1_BODY_GROUP=$(head -n1 "$TARGET1_LOG" | jq -r '.body | fromjson | .group_name')
    check_local "$T1_BODY_GROUP" "dst-group" "the batch pushed to target 1 carries the configured target_group_name"
    T1_TOMBSTONE=$(head -n1 "$TARGET1_LOG" | jq -r '.body | fromjson | .records[] | select(.target_address=="198.51.100.11") | .is_deleted')
    check_local "$T1_TOMBSTONE" "true" "the soft-deleted record's is_deleted=true survived replication to target 1"

    api_call GET "/api/sync-tasks/$SYNC_TASK_ID" "$MASTER_KEY"
    LAST_SYNC_AFTER_SUCCESS=$(echo "$RESP_BODY" | jq -r '.last_sync_at')
    check_local "$([[ "$LAST_SYNC_AFTER_SUCCESS" != "null" ]] && echo yes || echo no)" "yes" \
        "last_sync_at advanced after a fully successful multi-vault sync"

    api_call GET "/api/sync-logs?job_id=$SYNC_TASK_ID" "$MASTER_KEY"
    check_jq ".[0].status" "SUCCESS" "sync_logs recorded the SUCCESS outcome"

    log_section "7. Multi-vault sync — partial failure resilience"

    echo "fail500" > "$TARGET2_MODE"
    api_call POST "/api/sync-tasks/$SYNC_TASK_ID/trigger" "$MASTER_KEY"
    check "200" "the trigger endpoint itself still returns 200 even though one target fails"
    check_jq ".status" "PARTIAL" "one target succeeding + one failing is reported as PARTIAL, not SUCCESS"

    api_call GET "/api/sync-tasks/$SYNC_TASK_ID" "$MASTER_KEY"
    LAST_SYNC_AFTER_PARTIAL=$(echo "$RESP_BODY" | jq -r '.last_sync_at')
    check_local "$LAST_SYNC_AFTER_PARTIAL" "$LAST_SYNC_AFTER_SUCCESS" \
        "last_sync_at does NOT advance on a partial failure (still equals the prior successful run's value)"

    api_call GET "/api/sync-logs?job_id=$SYNC_TASK_ID" "$MASTER_KEY"
    check_jq ".[0].status" "PARTIAL" "the newest sync_logs entry for this task records PARTIAL"

    T2_HITS_AFTER_FAIL=$(wc -l < "$TARGET2_LOG" | tr -d ' ')
    check_local "$T2_HITS_AFTER_FAIL" "2" "the failing target still received the delivery attempt (it just rejected it)"

    # Both targets down: nothing succeeds.
    echo "fail500" > "$TARGET1_MODE"
    api_call POST "/api/sync-tasks/$SYNC_TASK_ID/trigger" "$MASTER_KEY"
    check_jq ".status" "FAILED" "both targets failing is reported as FAILED, not PARTIAL"
    api_call GET "/api/sync-tasks/$SYNC_TASK_ID" "$MASTER_KEY"
    check_jq ".last_sync_at" "$LAST_SYNC_AFTER_SUCCESS" "last_sync_at is still untouched after a total failure"
    echo "ok" > "$TARGET1_MODE"
    echo "ok" > "$TARGET2_MODE"

    log_section "7a. Target group name override"

    # skip_bogon_filtering:true -- same TEST-NET-2 fixture data as the multi-vault task above.
    api_call POST "/api/sync-tasks" "$MASTER_KEY" \
        "{\"name\":\"override-e2e-task\",\"source_vault_id\":\"$SOURCE_VAULT_ID\",\"source_group_name\":\"src-group\",\"target_group_name\":\"DEFAULT_E2E_GROUP\",\"cron_schedule\":\"0 0 * * *\",\"is_active\":false,\"skip_bogon_filtering\":true,\"targets\":[{\"vault_endpoint_id\":\"$TARGET1_VAULT_ID\",\"target_group_name\":\"OVERRIDDEN_E2E_GROUP\"}]}"
    check "200" "create a sync task with a per-target group_name override"
    OVERRIDE_TASK_ID=$(echo "$RESP_BODY" | jq -r '.id')
    check_jq ".targets[0].target_group_name" "OVERRIDDEN_E2E_GROUP" "the created task reports the override back"

    api_call POST "/api/sync-tasks/$OVERRIDE_TASK_ID/trigger" "$MASTER_KEY"
    check "200" "trigger the override task"
    check_jq ".status" "SUCCESS" "override task ingestion succeeds"

    OVERRIDE_GROUP_SEEN=$(tail -n1 "$TARGET1_LOG" | jq -r '.body | fromjson | .group_name')
    check_local "$OVERRIDE_GROUP_SEEN" "OVERRIDDEN_E2E_GROUP" \
        "the batch pushed for the override task used OVERRIDDEN_E2E_GROUP, not the task's own default"

    api_call DELETE "/api/sync-tasks/$OVERRIDE_TASK_ID" "$MASTER_KEY"
    check "204" "clean up the override task"

    log_section "7b. On-the-fly credential rotation"

    ROTATED_API_KEY="rotated-mock-key-$RANDOM"
    api_call PATCH "/api/vaults/$TARGET1_VAULT_ID" "$MASTER_KEY" \
        "{\"api_key\":\"$ROTATED_API_KEY\",\"signing_secret\":\"rotated-mock-secret-$RANDOM\"}"
    check "200" "rotate target 1's api_key/signing_secret via the API while the daemon is running"

    api_call POST "/api/sync-tasks/$SYNC_TASK_ID/trigger" "$MASTER_KEY"
    check "200" "re-trigger the original multi-vault task after rotating one target's credentials"
    check_jq ".status" "SUCCESS" "the sync still succeeds — the client re-reads credentials from the DB on every run, no restart needed"

    ROTATED_KEY_SEEN=$(tail -n1 "$TARGET1_LOG" | jq -r '.api_key')
    check_local "$ROTATED_KEY_SEEN" "$ROTATED_API_KEY" \
        "the outbound request used the newly rotated api_key immediately, without a daemon restart"

    log_section "7c. Concurrent job triggers"

    CONCURRENT_DIR="$WORK_DIR/concurrent"
    mkdir -p "$CONCURRENT_DIR"
    CONCURRENT_PIDS=()
    for i in 1 2 3 4 5; do
        next_timestamp
        c_ts="$SIGNED_TS"
        c_sig=$(hmac_sign "$MASTER_SIGNING_SECRET" "POST" "/api/sync-tasks/$SYNC_TASK_ID/trigger" "$c_ts" "")
        (
            curl -s -o "$CONCURRENT_DIR/body_$i" -w "%{http_code}" -X POST \
                -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $c_ts" -H "X-Signature-256: $c_sig" \
                "$BASE_URL/api/sync-tasks/$SYNC_TASK_ID/trigger" > "$CONCURRENT_DIR/status_$i"
        ) &
        CONCURRENT_PIDS+=($!)
    done
    for pid in "${CONCURRENT_PIDS[@]}"; do
        wait "$pid"
    done

    CONCURRENT_200=0
    CONCURRENT_409=0
    CONCURRENT_OTHER=0
    for i in 1 2 3 4 5; do
        code=$(cat "$CONCURRENT_DIR/status_$i" 2>/dev/null || echo "?")
        case "$code" in
            200) CONCURRENT_200=$((CONCURRENT_200 + 1)) ;;
            409) CONCURRENT_409=$((CONCURRENT_409 + 1)) ;;
            *) CONCURRENT_OTHER=$((CONCURRENT_OTHER + 1)); warn "concurrent trigger $i returned unexpected status '$code'" ;;
        esac
    done
    log "Concurrent triggers: $CONCURRENT_200 succeeded (200), $CONCURRENT_409 rejected as already-in-progress (409), $CONCURRENT_OTHER unexpected"
    check_local "$CONCURRENT_OTHER" "0" "no concurrent trigger produced an unexpected status (no 500s, no hangs, no SQLite lock errors surfaced to the caller)"
    check_local "$([[ "$CONCURRENT_200" -ge 1 ]] && echo yes || echo no)" "yes" "at least one concurrent trigger completed successfully"
    check_local "$((CONCURRENT_200 + CONCURRENT_409))" "5" "every concurrent trigger was either accepted or cleanly refused as a duplicate — none fell through as something else"

    log_section "7d. Truncated / malformed signature header"

    TRUNC_TS=$(date +%s)
    raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $TRUNC_TS" -H "X-Signature-256: sha256=ab"
    check "401" "a truncated (2 hex char) X-Signature-256 is rejected cleanly, not a 500 from a hex-decode panic"

    raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $TRUNC_TS" -H "X-Signature-256: not-even-hex-at-all"
    check "401" "a X-Signature-256 that isn't hex at all is rejected cleanly"

    raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $TRUNC_TS" -H "X-Signature-256: "
    check "401" "an empty X-Signature-256 value is rejected cleanly"

    log_section "7e. Delta pagination — large multi-page source fetch (Task 1)"

    # client.rs::DELTA_PAGE_SIZE is 5,000, so 15,001 records forces exactly 4 GET /api/ips pages
    # (5000/5000/5000/1) — and, independently, jobs::MAX_BATCH_SIZE is also 5,000, so the same
    # number forces exactly 4 push chunks on delivery. Neither loop is allowed to drop or duplicate
    # a record at the page/chunk boundary.
    PAGINATION_TOTAL=15001
    python3 - "$EXTRA_DELTA" "$PAGINATION_TOTAL" <<'PYEOF'
import json
import sys

out_path = sys.argv[1]
total = int(sys.argv[2])
records = [
    {
        "id": f"{i:08x}-0000-0000-0000-000000000000",
        "target_address": f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}",
        "group_name": "pagination-group",
        "is_deleted": False,
        "created_at": "2026-01-01T00:00:00",
        "updated_at": "2026-01-01T00:00:00",
        "last_seen_at": "2026-01-01T00:00:00",
    }
    for i in range(total)
]
with open(out_path, "w") as f:
    json.dump(records, f)
PYEOF
    check_local "$([[ -s "$EXTRA_DELTA" ]] && echo yes || echo no)" "yes" "generated a $PAGINATION_TOTAL-record synthetic delta fixture"

    api_call POST "/api/vaults" "$MASTER_KEY" \
        "{\"name\":\"pagination-source-vault\",\"target_url\":\"http://127.0.0.1:$EXTRA_PORT\",\"api_key\":\"mock-key\",\"signing_secret\":\"mock-secret\"}"
    check "200" "register the large-delta source vault"
    PAGINATION_SOURCE_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/vaults" "$MASTER_KEY" \
        "{\"name\":\"resilience-target-vault\",\"target_url\":\"http://127.0.0.1:$RESILIENCE_PORT\",\"api_key\":\"mock-key\",\"signing_secret\":\"mock-secret\"}"
    check "200" "register the resilience target vault (reused across 7e/7f/7g/7h)"
    RESILIENCE_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

    # skip_bogon_filtering:true -- the synthetic pagination delta uses 10.0.0.0/8 (RFC 1918
    # private) addresses, which the bogon sanitizer would otherwise strip; this section is testing
    # pagination/chunking counts, not bogon filtering.
    api_call POST "/api/sync-tasks" "$MASTER_KEY" \
        "{\"name\":\"pagination-e2e-task\",\"source_vault_id\":\"$PAGINATION_SOURCE_VAULT_ID\",\"source_group_name\":\"pagination-group\",\"target_group_name\":\"pagination-dst\",\"cron_schedule\":\"0 0 * * *\",\"is_active\":false,\"skip_bogon_filtering\":true,\"targets\":[{\"vault_endpoint_id\":\"$RESILIENCE_VAULT_ID\"}]}"
    check "200" "create a sync task pulling the $PAGINATION_TOTAL-record delta"
    PAGINATION_TASK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    RESILIENCE_HITS_BEFORE=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    api_call POST "/api/sync-tasks/$PAGINATION_TASK_ID/trigger" "$MASTER_KEY"
    check "200" "trigger the pagination sync task"
    check_jq ".status" "SUCCESS" "the multi-page delta fetch completes successfully"
    check_jq ".items_processed" "$PAGINATION_TOTAL" "all $PAGINATION_TOTAL records survived pagination across 4 GET pages, none dropped or duplicated"
    check_jq ".chunks_sent" "4" "$PAGINATION_TOTAL records at MAX_BATCH_SIZE=5,000 push as 4 chunks (5000/5000/5000/1)"

    RESILIENCE_HITS_AFTER=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    check_local "$((RESILIENCE_HITS_AFTER - RESILIENCE_HITS_BEFORE))" "4" "the target vault received exactly 4 POST /api/records/batch calls, one per push chunk"

    DELIVERED_TOTAL=$(tail -n 4 "$RESILIENCE_LOG" | jq -s '[.[] | .body | fromjson | .records | length] | add')
    check_local "$DELIVERED_TOTAL" "$PAGINATION_TOTAL" "the 4 delivered chunks together carry all $PAGINATION_TOTAL records"

    log_section "7f. Outbound retry & exponential backoff (Task 2)"

    # skip_bogon_filtering:true -- same TEST-NET-2 fixture data as the multi-vault task above.
    api_call POST "/api/sync-tasks" "$MASTER_KEY" \
        "{\"name\":\"retry-e2e-task\",\"source_vault_id\":\"$SOURCE_VAULT_ID\",\"source_group_name\":\"src-group\",\"target_group_name\":\"retry-dst\",\"cron_schedule\":\"0 0 * * *\",\"is_active\":false,\"skip_bogon_filtering\":true,\"targets\":[{\"vault_endpoint_id\":\"$RESILIENCE_VAULT_ID\"}]}"
    check "200" "create a sync task targeting the resilience mock"
    RETRY_TASK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    echo "retry:503:2" > "$RESILIENCE_MODE"
    RESILIENCE_HITS_BEFORE=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    api_call POST "/api/sync-tasks/$RETRY_TASK_ID/trigger" "$MASTER_KEY"
    check "200" "trigger a task whose target fails twice with 503 before succeeding on the 3rd attempt"
    check_jq ".status" "SUCCESS" "the job succeeds once the target recovers, transparently, within the default OUTBOUND_MAX_RETRIES=3 budget"
    RESILIENCE_HITS_AFTER=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    check_local "$((RESILIENCE_HITS_AFTER - RESILIENCE_HITS_BEFORE))" "3" "exactly 2 failed attempts + 1 successful attempt reached the target"
    echo "ok" > "$RESILIENCE_MODE"

    api_call DELETE "/api/sync-tasks/$RETRY_TASK_ID" "$MASTER_KEY"
    check "204" "clean up the retry-recovery sync task"

    log_section "7g. Adaptive batch resizing on HTTP 413 (Task 3)"

    # Reuses the pagination task from 7e: MAX_BATCH_SIZE=5,000 means each push chunk is well above
    # the 2,000-record ceiling this subsection's mode enforces, so client::post_batch must
    # adaptively split every chunk. Per chunk: a >2000 chunk halves until every sub-chunk is <=2000
    # (5000 -> 2500+2500 -> 1250+1250+1250+1250: 3 rejected attempts + 4 delivered sub-batches per
    # 5000-record chunk; the trailing 1-record chunk never exceeds the ceiling and needs no split).
    # Three 5000-chunks + one 1-chunk => (3*(3+4)) + 1 = 22 total attempts, 13 delivered sub-batches.
    echo "split413:2000" > "$RESILIENCE_MODE"
    RESILIENCE_HITS_BEFORE=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    api_call POST "/api/sync-tasks/$PAGINATION_TASK_ID/trigger" "$MASTER_KEY"
    check "200" "re-trigger the pagination task against a target enforcing a 2,000-record payload ceiling"
    check_jq ".status" "SUCCESS" "adaptive splitting delivers the whole batch despite the ceiling"
    check_jq ".items_processed" "$PAGINATION_TOTAL" "item count is unaffected by how many wire requests the delivery took"
    check_jq ".chunks_sent" "4" "chunks_sent still counts job-level chunks (4), not the client's internal 413 sub-splits"

    RESILIENCE_HITS_AFTER=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    NEW_HITS=$((RESILIENCE_HITS_AFTER - RESILIENCE_HITS_BEFORE))
    check_local "$NEW_HITS" "22" "the 4 job-level chunks cascade through the 413 ceiling into 22 total POST attempts (3x7 + 1)"

    DELIVERED_TOTAL=$(tail -n "$NEW_HITS" "$RESILIENCE_LOG" | jq -s '[.[] | .body | fromjson | .records | length] | map(select(. <= 2000)) | add')
    check_local "$DELIVERED_TOTAL" "$PAGINATION_TOTAL" "the successfully delivered (<=2000-record) sub-batches together cover all $PAGINATION_TOTAL records"

    DELIVERED_COUNT=$(tail -n "$NEW_HITS" "$RESILIENCE_LOG" | jq -s '[.[] | .body | fromjson | .records | length] | map(select(. <= 2000)) | length')
    check_local "$DELIVERED_COUNT" "13" "exactly 13 sub-batches were small enough to be accepted (4+4+4+1, from the four job-level chunks)"

    echo "ok" > "$RESILIENCE_MODE"
    api_call DELETE "/api/sync-tasks/$PAGINATION_TASK_ID" "$MASTER_KEY"
    check "204" "clean up the pagination/413-split sync task"
    api_call DELETE "/api/vaults/$PAGINATION_SOURCE_VAULT_ID" "$MASTER_KEY"
    check "204" "clean up the pagination source vault"

    log_section "7h. Safe multi-chunk full_replace ingestion (Task 4)"

    FULL_REPLACE_TOTAL=12000
    python3 - "$EXTRA_FEED" "$FULL_REPLACE_TOTAL" <<'PYEOF'
import sys

out_path = sys.argv[1]
total = int(sys.argv[2])
with open(out_path, "w") as f:
    for i in range(total):
        f.write(f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}\n")
PYEOF
    check_local "$([[ -s "$EXTRA_FEED" ]] && echo yes || echo no)" "yes" "generated a $FULL_REPLACE_TOTAL-line synthetic feed fixture, now servable at EXTRA_MOCK's /feed.txt"

    # Dry-run this exact feed through /api/sources/test-fetch before creating the real source below
    # -- the same order an operator would actually use the WebUI's "Test Fetch" button in.
    api_call POST "/api/sources/test-fetch" "$MASTER_KEY" \
        "{\"source_url\":\"http://127.0.0.1:$EXTRA_PORT/feed.txt\",\"parser_type\":\"REGEX_LINE\"}"
    check "200" "test-fetch dry-run against the same feed the real source below will use"
    check_jq ".status" "SUCCESS" "test-fetch reports SUCCESS for the same feed"
    check_jq ".total_extracted" "$FULL_REPLACE_TOTAL" "test-fetch's total_extracted matches the feed's true record count, not just the truncated sample"
    check_jq ".truncated" "true" "a $FULL_REPLACE_TOTAL-record feed exceeds the sample cap"
    check_jq ".sample | length" "50" "the sample itself is capped, unlike total_extracted"

    api_call GET "/api/destination-groups" "$MASTER_KEY"
    check_jq "[.[] | select(.name == \"full-replace-e2e-group\")] | length" "0" \
        "test-fetch persisted nothing -- the real destination group below does not exist yet"

    # skip_bogon_filtering:true -- the synthetic feed fixture uses 10.0.0.0/8 (RFC 1918 private)
    # addresses, which the bogon sanitizer would otherwise strip; this section is testing
    # full_replace multi-chunk delivery, not bogon filtering.
    api_call POST "/api/destination-groups" "$MASTER_KEY" \
        "{\"name\":\"full-replace-e2e-group\",\"cron_schedule\":\"0 0 * * *\",\"target_group_name\":\"full-replace-dst\",\"mode\":\"full_replace\",\"is_active\":false,\"skip_bogon_filtering\":true,\"targets\":[{\"vault_endpoint_id\":\"$RESILIENCE_VAULT_ID\"}]}"
    check "200" "create a full_replace destination group ($FULL_REPLACE_TOTAL records => 3 chunks of 5000/5000/2000)"
    FULL_REPLACE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')
    check_jq ".mode" "full_replace" "the created group reports mode=full_replace"

    api_call POST "/api/destination-groups/$FULL_REPLACE_GROUP_ID/feeds" "$MASTER_KEY" \
        "{\"name\":\"full-replace-e2e-feed\",\"source_url\":\"http://127.0.0.1:$EXTRA_PORT/feed.txt\"}"
    check "200" "add a feed pointed at the synthetic feed fixture to the full_replace group"

    RESILIENCE_HITS_BEFORE=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    api_call POST "/api/destination-groups/$FULL_REPLACE_GROUP_ID/trigger" "$MASTER_KEY"
    check "200" "trigger the full_replace ingestion"
    check_jq ".status" "SUCCESS" "the full_replace multi-chunk ingestion succeeds"
    check_jq ".items_processed" "$FULL_REPLACE_TOTAL" "all $FULL_REPLACE_TOTAL records were parsed and pushed"
    check_jq ".chunks_sent" "3" "$FULL_REPLACE_TOTAL records at MAX_BATCH_SIZE=5,000 push as exactly 3 chunks"

    RESILIENCE_HITS_AFTER=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    NEW_HITS=$((RESILIENCE_HITS_AFTER - RESILIENCE_HITS_BEFORE))
    check_local "$NEW_HITS" "3" "the target received exactly 3 POST /api/records/batch calls, one per chunk"

    CHUNK_MODES=$(tail -n 3 "$RESILIENCE_LOG" | jq -s -r '[.[] | .body | fromjson | .mode] | join(",")')
    check_local "$CHUNK_MODES" "full_replace,upsert,upsert" \
        "only the first of the 3 chunks carries full_replace on the wire; chunks 2 and 3 are downgraded to upsert so neither erases what the previous chunk just delivered"

    CHUNK_TOTAL=$(tail -n 3 "$RESILIENCE_LOG" | jq -s '[.[] | .body | fromjson | .records | length] | add')
    check_local "$CHUNK_TOTAL" "$FULL_REPLACE_TOTAL" "the 3 chunks together carry all $FULL_REPLACE_TOTAL records — none lost mid-stream"

    api_call DELETE "/api/destination-groups/$FULL_REPLACE_GROUP_ID" "$MASTER_KEY"
    check "204" "clean up the full_replace group (cascades to its feed)"

    log_section "7i. Zip bomb / oversized decompressed archive rejection (Task 1)"

    # A single ~50MiB+1KiB member of highly compressible repeated bytes — deflate shrinks it to a
    # few tens of KB on disk, so this is fast to generate and fast to serve; MAX_DECOMPRESSED_BYTES
    # (default 50MiB) is what must abort ingestion, not the wire size.
    python3 - "$EXTRA_FEED" <<'PYEOF'
import sys
import zipfile

out_path = sys.argv[1]
oversized = b"a" * (50 * 1024 * 1024 + 1024)
with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("bomb.txt", oversized)
PYEOF
    ZIP_BOMB_SIZE=$(stat -c%s "$EXTRA_FEED" 2>/dev/null || stat -f%z "$EXTRA_FEED" 2>/dev/null)
    check_local "$([[ "$ZIP_BOMB_SIZE" -lt 1048576 ]] && echo yes || echo no)" "yes" \
        "the zip bomb fixture is far smaller on disk (${ZIP_BOMB_SIZE} bytes) than the >50MiB it decompresses to"

    echo "ok" > "$RESILIENCE_MODE"
    api_call POST "/api/vaults" "$MASTER_KEY" \
        "{\"name\":\"zipbomb-target-vault\",\"target_url\":\"http://127.0.0.1:$RESILIENCE_PORT\",\"api_key\":\"mock-key\",\"signing_secret\":\"mock-secret\"}"
    check "200" "register a target vault for the zip-bomb source"
    ZIPBOMB_TARGET_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/destination-groups" "$MASTER_KEY" \
        "{\"name\":\"zipbomb-e2e-group\",\"cron_schedule\":\"0 0 * * *\",\"target_group_name\":\"zipbomb-dst\",\"is_active\":false,\"targets\":[{\"vault_endpoint_id\":\"$ZIPBOMB_TARGET_VAULT_ID\"}]}"
    check "200" "create a destination group for the oversized zip fixture"
    ZIPBOMB_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/destination-groups/$ZIPBOMB_GROUP_ID/feeds" "$MASTER_KEY" \
        "{\"name\":\"zipbomb-e2e-feed\",\"source_url\":\"http://127.0.0.1:$EXTRA_PORT/feed.txt\"}"
    check "200" "register a feed pointed at the oversized zip fixture"

    api_call POST "/api/destination-groups/$ZIPBOMB_GROUP_ID/trigger" "$MASTER_KEY"
    check "200" "triggering ingestion of the zip bomb does not crash the daemon (no 500)"
    check_jq ".status" "FAILED" "a decompressed member exceeding MAX_DECOMPRESSED_BYTES must fail the job, not silently truncate or OOM"
    check_jq ".items_processed" "0" "no records are processed once the decompression-bomb guard trips"
    ERROR_MSG=$(echo "$RESP_BODY" | jq -r '.error_message')
    check_local "$(echo "$ERROR_MSG" | grep -qi "decompress" && echo yes || echo no)" "yes" \
        "the error message explains this is the decompression guard, not an opaque failure (got: $ERROR_MSG)"

    api_call DELETE "/api/destination-groups/$ZIPBOMB_GROUP_ID" "$MASTER_KEY"
    check "204" "clean up the zip-bomb group (cascades to its feed)"
    api_call DELETE "/api/vaults/$ZIPBOMB_TARGET_VAULT_ID" "$MASTER_KEY"
    check "204" "clean up the zip-bomb target vault"

    log_section "7j. Non-update of last_sync_at on a mid-run chunk failure (Task 2)"

    # Reuses EXTRA_MOCK as a source vault again (EXTRA_DELTA still holds the 15,001-record
    # pagination-group delta from 7e/7g — untouched by 7i/7h, which only ever rewrite EXTRA_FEED):
    # push chunks land as 5000/5000/5000/1. bad_target accepts chunk 1 then fails every chunk after
    # — chunks 2-4 must never reach it once chunk 2 fails partway through the run.
    api_call POST "/api/vaults" "$MASTER_KEY" \
        "{\"name\":\"midfail-source-vault\",\"target_url\":\"http://127.0.0.1:$EXTRA_PORT\",\"api_key\":\"mock-key\",\"signing_secret\":\"mock-secret\"}"
    check "200" "register EXTRA_MOCK again as a source vault for the mid-run-failure check"
    MIDFAIL_SOURCE_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

    echo "failafter:500:1" > "$RESILIENCE_MODE"
    api_call POST "/api/vaults" "$MASTER_KEY" \
        "{\"name\":\"midfail-bad-target-vault\",\"target_url\":\"http://127.0.0.1:$RESILIENCE_PORT\",\"api_key\":\"mock-key\",\"signing_secret\":\"mock-secret\"}"
    check "200" "register the bad (fails after chunk 1) target vault"
    MIDFAIL_BAD_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

    # skip_bogon_filtering:true -- reuses the 10.0.0.0/8 pagination-group delta.
    api_call POST "/api/sync-tasks" "$MASTER_KEY" \
        "{\"name\":\"midfail-e2e-task\",\"source_vault_id\":\"$MIDFAIL_SOURCE_VAULT_ID\",\"source_group_name\":\"pagination-group\",\"target_group_name\":\"midfail-dst\",\"cron_schedule\":\"0 0 * * *\",\"is_active\":false,\"skip_bogon_filtering\":true,\"targets\":[{\"vault_endpoint_id\":\"$TARGET1_VAULT_ID\"},{\"vault_endpoint_id\":\"$MIDFAIL_BAD_VAULT_ID\"}]}"
    check "200" "create a sync task fanning out to a good target and a target that fails after chunk 1"
    MIDFAIL_TASK_ID=$(echo "$RESP_BODY" | jq -r '.id')
    check_jq ".last_sync_at" "null" "a freshly created task has no last_sync_at yet"

    RESILIENCE_HITS_BEFORE=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    api_call POST "/api/sync-tasks/$MIDFAIL_TASK_ID/trigger" "$MASTER_KEY"
    check "200" "trigger the mid-run-failure sync task"
    check_jq ".status" "PARTIAL" "one target fully succeeding and the other failing mid-run must report PARTIAL"

    RESILIENCE_HITS_AFTER=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    check_local "$((RESILIENCE_HITS_AFTER - RESILIENCE_HITS_BEFORE))" "2" \
        "the bad target must receive exactly chunk 1 (succeeded) + chunk 2 (failed) — chunks 3 and 4 must never be attempted"

    api_call GET "/api/sync-tasks/$MIDFAIL_TASK_ID" "$MASTER_KEY"
    check_jq ".last_sync_at" "null" \
        "last_sync_at must remain withheld after a mid-run failure, so the next scheduled run re-syncs the entire delta"

    echo "ok" > "$RESILIENCE_MODE"
    api_call DELETE "/api/sync-tasks/$MIDFAIL_TASK_ID" "$MASTER_KEY"
    check "204" "clean up the mid-run-failure sync task"
    api_call DELETE "/api/vaults/$MIDFAIL_SOURCE_VAULT_ID" "$MASTER_KEY"
    check "204" "clean up the mid-run-failure source vault"
    api_call DELETE "/api/vaults/$MIDFAIL_BAD_VAULT_ID" "$MASTER_KEY"
    check "204" "clean up the mid-run-failure bad target vault"

    log_section "7k. Non-UTF-8 / raw binary feed body resilience (Task 3)"

    python3 - "$EXTRA_FEED" <<'PYEOF'
import sys

out_path = sys.argv[1]
with open(out_path, "wb") as f:
    f.write(b"# Liste \xe9 jour (Latin-1, pas UTF-8)\n")
    f.write(b"203.0.113.77\n")
    f.write(b"; commentaire avec un caract\xe8re \xe9trange\n")
    f.write(b"2001:db8::77\n")
PYEOF
    check_local "$([[ -s "$EXTRA_FEED" ]] && echo yes || echo no)" "yes" "generated a Latin-1/raw-binary feed fixture"

    api_call POST "/api/vaults" "$MASTER_KEY" \
        "{\"name\":\"nonutf8-target-vault\",\"target_url\":\"http://127.0.0.1:$RESILIENCE_PORT\",\"api_key\":\"mock-key\",\"signing_secret\":\"mock-secret\"}"
    check "200" "register a target vault for the non-UTF-8 feed source"
    NONUTF8_TARGET_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

    # skip_bogon_filtering:true -- the valid IPs in this fixture are TEST-NET-3 (203.0.113.0/24)
    # and IPv6 documentation-range (2001:db8::/32) addresses, both of which the bogon sanitizer
    # would otherwise strip; this section is testing non-UTF-8 body resilience, not bogon
    # filtering.
    api_call POST "/api/destination-groups" "$MASTER_KEY" \
        "{\"name\":\"nonutf8-e2e-group\",\"cron_schedule\":\"0 0 * * *\",\"target_group_name\":\"nonutf8-dst\",\"is_active\":false,\"skip_bogon_filtering\":true,\"targets\":[{\"vault_endpoint_id\":\"$NONUTF8_TARGET_VAULT_ID\"}]}"
    check "200" "create a destination group for the non-UTF-8/raw-binary feed fixture"
    NONUTF8_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/destination-groups/$NONUTF8_GROUP_ID/feeds" "$MASTER_KEY" \
        "{\"name\":\"nonutf8-e2e-feed\",\"source_url\":\"http://127.0.0.1:$EXTRA_PORT/feed.txt\"}"
    check "200" "register a feed pointed at the Latin-1/raw-binary feed fixture"

    RESILIENCE_HITS_BEFORE=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    api_call POST "/api/destination-groups/$NONUTF8_GROUP_ID/trigger" "$MASTER_KEY"
    check "200" "triggering ingestion of the non-UTF-8 feed does not crash the daemon (no 500)"
    check_jq ".status" "SUCCESS" "a feed with non-UTF-8 bytes elsewhere in the body must still succeed on the valid IPs it contains"
    check_jq ".items_processed" "2" "both valid IPs must survive lossy decoding despite the Latin-1 bytes around them"

    RESILIENCE_HITS_AFTER=$(wc -l < "$RESILIENCE_LOG" | tr -d ' ')
    check_local "$((RESILIENCE_HITS_AFTER - RESILIENCE_HITS_BEFORE))" "1" "exactly one batch was pushed"
    PUSHED_ADDRESSES=$(tail -n 1 "$RESILIENCE_LOG" | jq -r '.body | fromjson | .records | map(.target_address) | join(",")')
    check_local "$PUSHED_ADDRESSES" "203.0.113.77,2001:db8::77" "exactly the two valid IPs were extracted and pushed, none of the Latin-1 noise"

    api_call DELETE "/api/destination-groups/$NONUTF8_GROUP_ID" "$MASTER_KEY"
    check "204" "clean up the non-UTF-8 group (cascades to its feed)"
    api_call DELETE "/api/vaults/$NONUTF8_TARGET_VAULT_ID" "$MASTER_KEY"
    check "204" "clean up the non-UTF-8 target vault"

    api_call DELETE "/api/vaults/$RESILIENCE_VAULT_ID" "$MASTER_KEY"
    check "204" "clean up the resilience target vault"
else
    skip "sections 6-7k (multi-vault sync, target overrides, credential rotation, concurrency, pagination, retry, 413 split, full_replace, zip bomb, mid-run failure, non-utf8 feed): mock vaults unavailable"
fi

# ── 8–9. External feed ingestion ────────────────────────────────────────────
log_section "8–9. External feed ingestion through local HTTP fixtures"

if [[ "$PYTHON3_AVAILABLE" -eq 1 ]] && command -v zip >/dev/null 2>&1; then
    FIXTURE_DIR="$WORK_DIR/fixtures"
    mkdir -p "$FIXTURE_DIR"

    # StopForumSpam listed_ip_30_ipv6.zip shape: a single member listed_ip_30_ipv6.txt, one bare
    # IPv6 address per line, no comments — reproduced here rather than downloaded, to avoid the
    # rate limit / IP ban a real download during CI risks.
    SFS_ADDRESSES=("2001:268:7384:2aad::" "2001:268:c217:bc4b::" "2001:2d8:2057:d55c::" "2001:2d8:222a:fc74::" "2001:2d8:222f:e65e::")
    SFS_TXT="$WORK_DIR/listed_ip_30_ipv6.txt"
    printf '%s\n' "${SFS_ADDRESSES[@]}" > "$SFS_TXT"
    (cd "$WORK_DIR" && zip -q "$FIXTURE_DIR/listed_ip_30_ipv6.zip" "listed_ip_30_ipv6.txt")

    # Spamhaus drop_v6.json shape: newline-delimited JSON (NOT an array), one {"cidr":...} object
    # per line, plus a trailing {"type":"metadata",...} footer with no "cidr" field.
    SPAMHAUS_CIDRS=("2001:678:254::/48" "2001:678:6c0::/48" "2001:678:724::/48")
    {
        for i in "${!SPAMHAUS_CIDRS[@]}"; do
            printf '{"cidr":"%s","sblid":"SBL%d","rir":"ripencc"}\n' "${SPAMHAUS_CIDRS[$i]}" "$i"
        done
        printf '{"type":"metadata","timestamp":1786614242,"size":123,"records":%d,"copyright":"(c) 2026 The Spamhaus Project SLU"}\n' "${#SPAMHAUS_CIDRS[@]}"
    } > "$FIXTURE_DIR/drop_v6.json"

    printf '# scanner hosts\n192.0.2.10\n198.51.100.11 # tagged\n' > "$FIXTURE_DIR/scanners.txt"
    printf '198.51.100.20\n203.0.113.21\n' > "$FIXTURE_DIR/doh-ipv4.txt"
    printf '203.0.113.0/28\n198.51.100.32/28\n' > "$FIXTURE_DIR/vpn-ipv4.txt"
    printf '2001:db8::10\n2001:db8::20\n' > "$FIXTURE_DIR/doh-ipv6.txt"

    FIXTURE_PORT="$(pick_port 18800 18820 "local fixture file server")"
    # `--directory` (not `(cd "$FIXTURE_DIR" && ...) &`) deliberately: wrapping in a `( ... ) &`
    # subshell means `$!` captures the *subshell's* pid, and bash is not guaranteed to exec()
    # python3 directly in its place — a killed subshell can leave python3 running as an orphaned
    # child. This bit a first draft of this script: three leaked `http.server` processes were
    # found still listening after three separate runs. `--directory` avoids the subshell entirely,
    # so `$!` is unambiguously python3's own pid and `kill` in cleanup() actually reaches it.
    python3 -m http.server "$FIXTURE_PORT" --bind 127.0.0.1 --directory "$FIXTURE_DIR" >"$WORK_DIR/fixture_server.log" 2>&1 &
    FIXTURE_SERVER_PID=$!
    sleep 0.3

    if kill -0 "$FIXTURE_SERVER_PID" 2>/dev/null; then
        FIXTURE_BASE="http://127.0.0.1:$FIXTURE_PORT"
        log "Local fixture server up on $FIXTURE_BASE, serving $FIXTURE_DIR"

        for fixture in scanners doh-ipv4 vpn-ipv4 doh-ipv6; do
            api_call POST "/api/destination-groups" "$MASTER_KEY" \
                "{\"name\":\"fixture-$fixture-group\",\"cron_schedule\":\"0 0 * * *\",\"target_group_name\":\"fixtures\",\"is_active\":false,\"skip_bogon_filtering\":true}"
            check "200" "create destination group for $fixture"
            GROUP_ID=$(jq -r '.id' <<< "$RESP_BODY")
            api_call POST "/api/destination-groups/$GROUP_ID/feeds" "$MASTER_KEY" \
                "{\"name\":\"fixture-$fixture\",\"source_url\":\"$FIXTURE_BASE/$fixture.txt\",\"parser_type\":\"REGEX_LINE\"}"
            check "200" "register the $fixture feed"
            api_call POST "/api/destination-groups/$GROUP_ID/trigger" "$MASTER_KEY"
            check "200" "trigger ingestion of $fixture"
            check_jq ".status" "SUCCESS" "$fixture ingestion reports SUCCESS"
            check_jq ".items_processed" "2" "$fixture yields the two expected addresses"
            api_call DELETE "/api/destination-groups/$GROUP_ID" "$MASTER_KEY"
            check "204" "clean up the $fixture destination group"
        done

        api_call POST "/api/destination-groups" "$MASTER_KEY" \
            "{\"name\":\"fixture-sfs-ipv6-zip-group\",\"cron_schedule\":\"0 0 * * *\",\"target_group_name\":\"fixtures\",\"is_active\":false}"
        check "200" "create destination group for the StopForumSpam-shaped ZIP fixture"
        ZIP_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')
        api_call POST "/api/destination-groups/$ZIP_GROUP_ID/feeds" "$MASTER_KEY" \
            "{\"name\":\"fixture-sfs-ipv6-zip\",\"source_url\":\"$FIXTURE_BASE/listed_ip_30_ipv6.zip\",\"parser_type\":\"REGEX_LINE\"}"
        check "200" "register the StopForumSpam-shaped ZIP fixture feed"
        api_call POST "/api/destination-groups/$ZIP_GROUP_ID/trigger" "$MASTER_KEY"
        check "200" "trigger ingestion of the ZIP fixture"
        check_jq ".status" "SUCCESS" "ZIP fixture ingestion reports SUCCESS (the ingestion pipeline decompressed it)"
        check_jq ".items_processed" "${#SFS_ADDRESSES[@]}" "all ${#SFS_ADDRESSES[@]} IPv6 addresses inside the zip were extracted"
        api_call DELETE "/api/destination-groups/$ZIP_GROUP_ID" "$MASTER_KEY"
        check "204" "clean up the ZIP fixture group (cascades to its feed)"

        # parser_config_json now uses the $.-prefixed target_address selector (the old ip_field key
        # was removed) -- the fixture's per-line shape is {"cidr": "...", "sblid": "...", "rir": "..."}.
        api_call POST "/api/destination-groups" "$MASTER_KEY" \
            "{\"name\":\"fixture-spamhaus-drop-v6-group\",\"cron_schedule\":\"0 0 * * *\",\"target_group_name\":\"fixtures\",\"is_active\":false}"
        check "200" "create destination group for the Spamhaus-shaped JSONL fixture"
        JSONL_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')
        api_call POST "/api/destination-groups/$JSONL_GROUP_ID/feeds" "$MASTER_KEY" \
            "{\"name\":\"fixture-spamhaus-drop-v6\",\"source_url\":\"$FIXTURE_BASE/drop_v6.json\",\"parser_type\":\"JSON_PATH\",\"parser_config_json\":\"{\\\"jsonl\\\":true,\\\"target_address\\\":\\\"\$.cidr\\\"}\"}"
        check "200" "register the Spamhaus-shaped JSONL fixture feed"
        api_call POST "/api/destination-groups/$JSONL_GROUP_ID/trigger" "$MASTER_KEY"
        check "200" "trigger ingestion of the JSONL fixture"
        check_jq ".status" "SUCCESS" "JSONL fixture ingestion reports SUCCESS"
        check_jq ".items_processed" "${#SPAMHAUS_CIDRS[@]}" \
            "all ${#SPAMHAUS_CIDRS[@]} CIDRs extracted, metadata footer line correctly skipped"
        api_call DELETE "/api/destination-groups/$JSONL_GROUP_ID" "$MASTER_KEY"
        check "204" "clean up the JSONL fixture group (cascades to its feed)"

        # Task 4: a feed host returning 200 OK with an HTML block/error page instead of its real
        # content — the same shape as a Cloudflare challenge, WAF block, or captive-portal redirect.
        cat > "$FIXTURE_DIR/html_masquerade.txt" <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>Attention Required! | Cloudflare</title></head>
<body>
<div class="cf-error-details">
  <h1>Sorry, you have been blocked</h1>
  <p>You are unable to access this site.</p>
  <p>Ray ID: 8f2a1c9d4b3e7f10</p>
</div>
</body>
</html>
HTMLEOF
        api_call POST "/api/destination-groups" "$MASTER_KEY" \
            "{\"name\":\"fixture-html-masquerade-group\",\"cron_schedule\":\"0 0 * * *\",\"target_group_name\":\"fixtures\",\"is_active\":false}"
        check "200" "create destination group for an HTML block-page fixture (200 OK, no real feed content)"
        HTML_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')
        api_call POST "/api/destination-groups/$HTML_GROUP_ID/feeds" "$MASTER_KEY" \
            "{\"name\":\"fixture-html-masquerade\",\"source_url\":\"$FIXTURE_BASE/html_masquerade.txt\",\"parser_type\":\"REGEX_LINE\"}"
        check "200" "register a feed pointed at the HTML block-page fixture"
        api_call POST "/api/destination-groups/$HTML_GROUP_ID/trigger" "$MASTER_KEY"
        check "200" "triggering ingestion of the HTML masquerade does not crash the daemon (no 500)"
        check_jq ".status" "PARTIAL" "an HTML body yielding zero parseable entries is flagged PARTIAL, not silently SUCCESS"
        check_jq ".items_processed" "0" "zero IP-shaped tokens are extracted from the HTML block page"

        api_call GET "/api/sync-logs?job_id=$HTML_GROUP_ID" "$MASTER_KEY"
        check_jq ".[0].status" "PARTIAL" "sync_logs records the PARTIAL outcome for the HTML masquerade"

        api_call DELETE "/api/destination-groups/$HTML_GROUP_ID" "$MASTER_KEY"
        check "204" "clean up the HTML masquerade fixture group (cascades to its feed)"
    else
        check_local "stopped" "running" "local fixture file server starts"
    fi
    # Fixture files themselves live under $WORK_DIR and are removed by the exit trap; no separate
    # cleanup step is needed even if a check above fails partway through.
else
    skip "local fixture ingestion checks (python3 and/or zip unavailable)"
fi

# ── 10. Additional hardening & edge cases ────────────────────────────────────
log_section "10. Additional hardening & edge cases"

raw_call POST "/api/destination-groups" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $(date +%s)" \
    -H "X-Signature-256: sha256=deadbeef" -H "Content-Type: application/json" --data-binary '{not valid json'
check "401" "malformed JSON body with an (unverifiable, since body is now unparseable) signature is still rejected at auth, before ever reaching JSON parsing"

next_timestamp
BAD_JSON_TS="$SIGNED_TS"
BAD_JSON_BODY='{"name": "x", invalid}'
BAD_JSON_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "POST" "/api/destination-groups" "$BAD_JSON_TS" "$BAD_JSON_BODY")
raw_call POST "/api/destination-groups" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $BAD_JSON_TS" \
    -H "X-Signature-256: $BAD_JSON_SIG" -H "Content-Type: application/json" --data-binary "$BAD_JSON_BODY"
check "400" "syntactically invalid JSON with a *valid* signature is 400, not 500"

api_call POST "/api/destination-groups" "$MASTER_KEY" '{"name":"bad-parser-type-group","cron_schedule":"0 0 * * *","target_group_name":"g"}'
check "200" "create a scratch destination group for the bad-parser-type feed check"
BAD_PARSER_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')
api_call POST "/api/destination-groups/$BAD_PARSER_GROUP_ID/feeds" "$MASTER_KEY" '{"name":"bad-parser-type","source_url":"http://x","parser_type":"XML"}'
check "400" "an unknown parser_type is rejected with 400"
api_call DELETE "/api/destination-groups/$BAD_PARSER_GROUP_ID" "$MASTER_KEY"
check "204" "clean up the bad-parser-type scratch group"

api_call POST "/api/destination-groups" "$MASTER_KEY" '{"name":"unknown-field-group","cron_schedule":"0 0 * * *","target_group_name":"g","totally_unexpected_field":true}'
check "400" "a payload carrying an unexpected field is rejected (deny_unknown_fields), not silently ignored"

raw_call GET "/api/this-route-does-not-exist"
check "404" "an unknown route is a plain 404, not a 401 masquerading as one"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"scoped-daughter-key"}'
check "200" "create a daughter key with no elevated rights"
DAUGHTER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
DAUGHTER_SECRET=$(echo "$RESP_BODY" | jq -r '.plaintext_signing_secret')
DAUGHTER_ID=$(echo "$RESP_BODY" | jq -r '.key.id')
register_key_secret "$DAUGHTER_KEY" "$DAUGHTER_SECRET"

api_call POST "/api/destination-groups" "$DAUGHTER_KEY" '{"name":"daughter-attempt","cron_schedule":"0 0 * * *","target_group_name":"g"}'
check "403" "a daughter key without can_manage_sources cannot create a destination group"

api_call POST "/api/keys" "$DAUGHTER_KEY" '{"name":"privilege-escalation-attempt","can_manage_sources":true}'
check "403" "a non-master key cannot grant can_manage_sources to a new key it creates (RBAC R4)"

log_section "10a. RBAC delegation (R1/R6) & enumeration resistance (2026-08-17 peer-audit findings)"

# R1 (non-amplification): a Parent-tier key holding only `can_manage` (not `can_sync`) on a
# resource must be refused when attempting to grant `can_sync` to another key — manage rights
# alone (R2) are not enough; the granter must hold the verb it's trying to hand out.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"r1-granter-key","can_manage_keys":true}'
check "200" "create a Parent-tier key for the R1 non-amplification check"
R1_GRANTER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
R1_GRANTER_SECRET=$(echo "$RESP_BODY" | jq -r '.plaintext_signing_secret')
R1_GRANTER_ID=$(echo "$RESP_BODY" | jq -r '.key.id')
register_key_secret "$R1_GRANTER_KEY" "$R1_GRANTER_SECRET"

api_call PUT "/api/keys/$R1_GRANTER_ID/permissions" "$MASTER_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$SCRATCH_VAULT_ID\",\"can_manage\":true}"
check "200" "grant the R1 granter can_manage (but not can_sync) on the scratch vault"

api_call PUT "/api/keys/$DAUGHTER_ID/permissions" "$R1_GRANTER_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$SCRATCH_VAULT_ID\",\"can_sync\":true}"
check "403" "R1: cannot grant can_sync without holding it yourself on the resource, even with manage rights (R2)"

# R6 (revocation is never escalation): revoking a permission needs only manage rights on the
# resource — the revoker need not hold the verb being removed.
api_call PUT "/api/keys/$DAUGHTER_ID/permissions" "$MASTER_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$SCRATCH_VAULT_ID\",\"can_sync\":true}"
check "200" "master grants the daughter can_sync directly (bypassing R1 for test setup)"
DAUGHTER_PERMISSION_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call DELETE "/api/keys/$DAUGHTER_ID/permissions/$DAUGHTER_PERMISSION_ID" "$R1_GRANTER_KEY"
check "204" "R6: revocation succeeds with only manage rights — the revoker need not hold can_sync itself"

api_call DELETE "/api/keys/$R1_GRANTER_ID" "$MASTER_KEY"
check "204" "clean up the R1/R6 granter key"

# Enumeration resistance (oracle discipline): a resource the caller has no visibility into and a
# resource id that doesn't exist at all must be indistinguishable — same status, same body — or an
# attacker could enumerate real ids by noticing which 404s look subtly different.
api_call GET "/api/vaults/$SCRATCH_VAULT_ID" "$DAUGHTER_KEY"
check "404" "a vault the daughter has no visibility into is 404, not 403 (which would itself leak that the id exists)"
OUT_OF_SCOPE_BODY="$RESP_BODY"
NONEXISTENT_UUID="00000000-0000-0000-0000-000000000000"
api_call GET "/api/vaults/$NONEXISTENT_UUID" "$DAUGHTER_KEY"
check "404" "a vault id that doesn't exist at all is also 404"
check_local "$OUT_OF_SCOPE_BODY" "$RESP_BODY" "an out-of-scope vault and a nonexistent one return byte-identical response bodies"

# An oversized inbound body must be rejected cleanly (413), not a 500 or a hang — regardless of
# whether the (deliberately garbage) signature would have verified, since the body-size check in
# auth_middleware runs before signature verification. Written to a file rather than passed as a
# shell argument: an 11MB `--data-binary "$VAR"` blows past the OS's ARG_MAX ("Argument list too
# long"), which curl reports as a generic exec failure with no HTTP status at all, not the 413 this
# check exists to assert; `--data-binary @file` streams it instead. curl sets Content-Length from
# the file size automatically, so this exercises auth_middleware's Content-Length pre-check path
# (reject before reading), matching the ecosystem-standard status code every peer service answers
# with (`simply_ip_vault`/`simply_hook_executor`/`simply_ip_exporter` all return 413 here too).
OVERSIZED_BODY_FILE="$WORK_DIR/oversized_body"
head -c 11000000 /dev/zero | tr '\0' 'a' > "$OVERSIZED_BODY_FILE"
next_timestamp
raw_call POST "/api/destination-groups" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $SIGNED_TS" \
    -H "X-Signature-256: sha256=0000000000000000000000000000000000000000000000000000000000000000" \
    -H "Content-Type: application/json" --data-binary "@$OVERSIZED_BODY_FILE"
check "413" "a body over MAX_BODY_SIZE_MIB (10 MiB default) is rejected cleanly (413) rather than a 500 or a hang"
check_jq ".error" "Request body exceeds the maximum allowed size" "the 413 still carries the standard {\"error\": ...} JSON envelope"

# Vault credentials must never round-trip in any response — creating and then reading back a vault
# endpoint is the one place a naive `#[derive(Serialize)]` directly on the entity (rather than a
# dedicated response struct omitting the two credential fields) would leak them.
DISTINCTIVE_API_KEY="e2e-credential-leak-canary-api-key-$RANDOM"
DISTINCTIVE_SIGNING_SECRET="e2e-credential-leak-canary-signing-secret-$RANDOM"
api_call POST "/api/vaults" "$MASTER_KEY" \
    "{\"name\":\"credential-leak-canary-vault\",\"target_url\":\"http://127.0.0.1:1\",\"api_key\":\"$DISTINCTIVE_API_KEY\",\"signing_secret\":\"$DISTINCTIVE_SIGNING_SECRET\"}"
check "200" "create a vault endpoint carrying distinctive, greppable credential values"
check_not_contains "$DISTINCTIVE_API_KEY" "the create response does not echo the plaintext api_key back"
check_not_contains "$DISTINCTIVE_SIGNING_SECRET" "the create response does not echo the plaintext signing_secret back"
CREDENTIAL_LEAK_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call GET "/api/vaults/$CREDENTIAL_LEAK_VAULT_ID" "$MASTER_KEY"
check "200" "read the vault endpoint back"
check_not_contains "$DISTINCTIVE_API_KEY" "GET /api/vaults/{id} never returns the plaintext api_key"
check_not_contains "$DISTINCTIVE_SIGNING_SECRET" "GET /api/vaults/{id} never returns the plaintext signing_secret"

api_call GET "/api/vaults" "$MASTER_KEY"
check "200" "list vault endpoints"
check_not_contains "$DISTINCTIVE_API_KEY" "GET /api/vaults (list) never returns the plaintext api_key"
check_not_contains "$DISTINCTIVE_SIGNING_SECRET" "GET /api/vaults (list) never returns the plaintext signing_secret"

api_call DELETE "/api/vaults/$CREDENTIAL_LEAK_VAULT_ID" "$MASTER_KEY"
check "204" "clean up the credential-leak canary vault"

api_call PATCH "/api/keys/$MASTER_ID" "$MASTER_KEY" '{"name":"Renamed Master"}'
check "403" "the Master key cannot be renamed through the API (RBAC §5)"

api_call POST "/api/keys/$MASTER_ID/rotate" "$MASTER_KEY"
check "403" "the Master key's credentials can never be rotated through the API (RBAC §5)"

api_call DELETE "/api/keys/$DAUGHTER_ID" "$MASTER_KEY"
check "204" "clean up the scratch daughter key"

if [[ "$MULTI_VAULT_AVAILABLE" -eq 1 ]]; then
    api_call DELETE "/api/sync-tasks/$SYNC_TASK_ID" "$MASTER_KEY"
    check "204" "clean up the multi-vault sync task"
    for vid in "$SOURCE_VAULT_ID" "$TARGET1_VAULT_ID" "$TARGET2_VAULT_ID"; do
        api_call DELETE "/api/vaults/$vid" "$MASTER_KEY"
        check "204" "clean up mock vault endpoint $vid"
    done
fi
api_call DELETE "/api/vaults/$SCRATCH_VAULT_ID" "$MASTER_KEY"
check "204" "clean up the cron-validation scratch vault"

# ── 10b. Edge-Case / Boundary / Security E2E ─────────────────────────────────
log_section "10b. Edge-Case / Boundary / Security E2E"

# 1. Target Master forbidden on /permissions + R6 pure-reduction & revocation guard.
api_call POST "/api/vaults" "$MASTER_KEY" \
    '{"name":"edge-security-scratch-vault","target_url":"http://127.0.0.1:1","api_key":"edge-k","signing_secret":"edge-s"}'
check "200" "10b: create scratch vault for permissions & R6 boundary checks"
EDGE_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call PUT "/api/keys/$MASTER_ID/permissions" "$MASTER_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$EDGE_VAULT_ID\",\"can_sync\":true,\"can_manage\":true,\"can_view_logs\":true}"
check "400" "10b: PUT /api/keys/{master_id}/permissions is rejected with 400 (RBAC §5)"
check_true '.error | contains("Master key")' "10b: error explains M:N permissions cannot be configured on Master"

api_call DELETE "/api/keys/$MASTER_ID/permissions/00000000-0000-0000-0000-000000000000" "$MASTER_KEY"
check "400" "10b: DELETE /api/keys/{master_id}/permissions/{perm_id} is rejected with 400 (RBAC §5)"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"edge-unpriv-key","can_manage_keys":false}'
check "200" "10b: create unprivileged daughter key"
EDGE_UNPRIV_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
EDGE_UNPRIV_SECRET=$(echo "$RESP_BODY" | jq -r '.plaintext_signing_secret')
EDGE_UNPRIV_ID=$(echo "$RESP_BODY" | jq -r '.key.id')
register_key_secret "$EDGE_UNPRIV_KEY" "$EDGE_UNPRIV_SECRET"

api_call PUT "/api/keys/$MASTER_ID/permissions" "$EDGE_UNPRIV_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$EDGE_VAULT_ID\",\"can_sync\":true}"
check "403" "10b: unprivileged key attempting PUT /api/keys/{master_id}/permissions is rejected with 403"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"edge-r6-delegator-key","can_manage_keys":true}'
check "200" "10b: create R6 delegator key with can_manage_keys=true"
EDGE_DELEGATOR_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
EDGE_DELEGATOR_SECRET=$(echo "$RESP_BODY" | jq -r '.plaintext_signing_secret')
EDGE_DELEGATOR_ID=$(echo "$RESP_BODY" | jq -r '.key.id')
register_key_secret "$EDGE_DELEGATOR_KEY" "$EDGE_DELEGATOR_SECRET"

api_call PUT "/api/keys/$MASTER_ID/permissions" "$EDGE_DELEGATOR_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$EDGE_VAULT_ID\",\"can_sync\":true}"
check "400" "10b: can_manage_keys delegator attempting PUT /api/keys/{master_id}/permissions is rejected with 400"

api_call DELETE "/api/keys/$MASTER_ID/permissions/00000000-0000-0000-0000-000000000000" "$EDGE_DELEGATOR_KEY"
check "400" "10b: can_manage_keys delegator attempting DELETE /api/keys/{master_id}/permissions/{id} is rejected with 400"

# R6 guard: delegator holds ONLY can_manage on EDGE_VAULT_ID (neither can_sync nor can_view_logs).
api_call PUT "/api/keys/$EDGE_DELEGATOR_ID/permissions" "$MASTER_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$EDGE_VAULT_ID\",\"can_manage\":true,\"can_sync\":false,\"can_view_logs\":false}"
check "200" "10b: Master grants delegator can_manage-only on scratch vault"

api_call PUT "/api/keys/$EDGE_UNPRIV_ID/permissions" "$MASTER_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$EDGE_VAULT_ID\",\"can_sync\":true,\"can_view_logs\":true}"
check "200" "10b: Master grants unprivileged key can_sync+can_view_logs on scratch vault"
EDGE_UNPRIV_PERM_ID=$(echo "$RESP_BODY" | jq -r '.id')

# R6 pure reduction via PUT: delegator does not hold can_view_logs, yet can drop can_sync while keeping can_view_logs.
api_call PUT "/api/keys/$EDGE_UNPRIV_ID/permissions" "$EDGE_DELEGATOR_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$EDGE_VAULT_ID\",\"can_sync\":false,\"can_view_logs\":true}"
check "200" "10b: R6 pure reduction via PUT succeeds even when revoker does not hold surviving can_view_logs"
check_jq ".can_sync" "false" "10b: R6 reduction dropped can_sync to false"
check_jq ".can_view_logs" "true" "10b: R6 reduction preserved can_view_logs=true"

# R1/R7 widening guard: delegator cannot re-widen can_sync back to true without holding can_sync.
api_call PUT "/api/keys/$EDGE_UNPRIV_ID/permissions" "$EDGE_DELEGATOR_KEY" \
    "{\"resource_type\":\"vault_endpoint\",\"resource_id\":\"$EDGE_VAULT_ID\",\"can_sync\":true,\"can_view_logs\":true}"
check "403" "10b: R1/R7 prevents delegator from re-widening can_sync back to true"

api_call DELETE "/api/keys/$EDGE_UNPRIV_ID/permissions/$EDGE_UNPRIV_PERM_ID" "$EDGE_DELEGATOR_KEY"
check "204" "10b: R6 full revocation via DELETE succeeds with can_manage alone"

api_call DELETE "/api/keys/$EDGE_DELEGATOR_ID" "$MASTER_KEY"
check "204" "10b: clean up R6 delegator key"
api_call DELETE "/api/keys/$EDGE_UNPRIV_ID" "$MASTER_KEY"
check "204" "10b: clean up unprivileged daughter key"
api_call DELETE "/api/vaults/$EDGE_VAULT_ID" "$MASTER_KEY"
check "204" "10b: clean up scratch vault"

# 2. At-rest encryption check on vault_endpoints.api_key (and signing_secret).
AT_REST_PLAIN_API_KEY="e2e-at-rest-vault-api-key-canary-${RANDOM}-987654"
AT_REST_PLAIN_SIGNING_SECRET="e2e-at-rest-vault-signing-secret-canary-${RANDOM}-123456"
api_call POST "/api/vaults" "$MASTER_KEY" \
    "{\"name\":\"at-rest-cipher-vault\",\"target_url\":\"http://127.0.0.1:1\",\"api_key\":\"$AT_REST_PLAIN_API_KEY\",\"signing_secret\":\"$AT_REST_PLAIN_SIGNING_SECRET\"}"
check "200" "10b: create vault endpoint with distinctive api_key & signing_secret for at-rest SQLite inspection"
AT_REST_VAULT_ID=$(echo "$RESP_BODY" | jq -r '.id')

STORED_VAULT_API_KEY=$(sqlite3 "$DB_PATH" "SELECT api_key FROM vault_endpoints WHERE name = 'at-rest-cipher-vault';")
STORED_VAULT_SIGNING_SECRET=$(sqlite3 "$DB_PATH" "SELECT signing_secret FROM vault_endpoints WHERE name = 'at-rest-cipher-vault';")
check_matches "$STORED_VAULT_API_KEY" '^v1\.xchacha20poly1305\.[0-9a-f]{48}\.[0-9a-f]+$' \
    "10b: vault_endpoints.api_key is sealed with v1.xchacha20poly1305.<nonce>.<ciphertext> in SQLite"
check_matches "$STORED_VAULT_SIGNING_SECRET" '^v1\.xchacha20poly1305\.[0-9a-f]{48}\.[0-9a-f]+$' \
    "10b: vault_endpoints.signing_secret is sealed with v1.xchacha20poly1305.<nonce>.<ciphertext> in SQLite"

SQLITE_DUMP_CONTENT="$(sqlite3 "$DB_PATH" ".dump")"
if [[ "$SQLITE_DUMP_CONTENT" == *"$AT_REST_PLAIN_API_KEY"* ]] || grep -aq "$AT_REST_PLAIN_API_KEY" "$DB_PATH" "${DB_PATH}-wal" 2>/dev/null; then
    check_local "plaintext-leaked" "sealed-only" "10b: plaintext vault_endpoints.api_key never appears in sqlite3 dump or DB files"
else
    check_local "sealed-only" "sealed-only" "10b: plaintext vault_endpoints.api_key never appears in sqlite3 dump or DB files"
fi
if [[ "$SQLITE_DUMP_CONTENT" == *"$AT_REST_PLAIN_SIGNING_SECRET"* ]] || grep -aq "$AT_REST_PLAIN_SIGNING_SECRET" "$DB_PATH" "${DB_PATH}-wal" 2>/dev/null; then
    check_local "plaintext-leaked" "sealed-only" "10b: plaintext vault_endpoints.signing_secret never appears in sqlite3 dump or DB files"
else
    check_local "sealed-only" "sealed-only" "10b: plaintext vault_endpoints.signing_secret never appears in sqlite3 dump or DB files"
fi

AT_REST_ROTATED_API_KEY="e2e-at-rest-vault-api-key-rotated-${RANDOM}-654321"
api_call PATCH "/api/vaults/$AT_REST_VAULT_ID" "$MASTER_KEY" \
    "{\"api_key\":\"$AT_REST_ROTATED_API_KEY\"}"
check "200" "10b: PATCH vault_endpoints.api_key"
STORED_ROTATED_API_KEY=$(sqlite3 "$DB_PATH" "SELECT api_key FROM vault_endpoints WHERE name = 'at-rest-cipher-vault';")
check_matches "$STORED_ROTATED_API_KEY" '^v1\.xchacha20poly1305\.[0-9a-f]{48}\.[0-9a-f]+$' \
    "10b: updated vault_endpoints.api_key remains XChaCha20-Poly1305 sealed in SQLite"
if sqlite3 "$DB_PATH" ".dump" | grep -Fq "$AT_REST_ROTATED_API_KEY"; then
    check_local "plaintext-leaked" "sealed-only" "10b: updated vault_endpoints.api_key plaintext never appears in sqlite3 dump"
else
    check_local "sealed-only" "sealed-only" "10b: updated vault_endpoints.api_key plaintext never appears in sqlite3 dump"
fi

api_call DELETE "/api/vaults/$AT_REST_VAULT_ID" "$MASTER_KEY"
check "204" "10b: clean up at-rest cipher check vault"

# 3. External Feed SSRF rejection (loopback, cloud metadata 169.254.169.254, non-http scheme).
api_call POST "/api/sources/test-fetch" "$MASTER_KEY" \
    '{"source_url":"file:///etc/passwd","parser_type":"REGEX_LINE"}'
check "200" "10b: test-fetch against file:///etc/passwd returns structured FAILED report"
check_jq ".status" "FAILED" "10b: file:// scheme is rejected even when ALLOW_PRIVATE_INGEST_URLS_FOR_TEST=true"
check_true '.error | contains("blocked source URL")' "10b: file:// rejection carries blocked source URL message"

# Boot an isolated production-posture instance (without ALLOW_PRIVATE_INGEST_URLS_FOR_TEST) on an
# ephemeral port and temporary SQLite DB to verify live SSRF rejection against loopback & IMDSv1/v2.
SSRF_PORT="$(pick_port 25000 29999 "simply_ip_sync-ssrf")" || exit 1
SSRF_BASE_URL="http://$BIND_HOST:$SSRF_PORT"
SSRF_DB_PATH="$WORK_DIR/ssrf_e2e.db"
SSRF_SERVER_LOG="$WORK_DIR/ssrf_server.log"

DATABASE_URL="sqlite://$SSRF_DB_PATH?mode=rwc" \
    RUST_LOG=info \
    INITIAL_MASTER_KEY="$MASTER_KEY" \
    INITIAL_MASTER_SIGNING_SECRET="$MASTER_SIGNING_SECRET" \
    SYNC_ENCRYPTION_KEY="$E2E_ENCRYPTION_KEY" \
    ALLOW_PRIVATE_INGEST_URLS_FOR_TEST=false \
    BIND_HOST="$BIND_HOST" \
    PORT="$SSRF_PORT" \
    TRUSTED_PROXIES="127.0.0.1/32" \
    "$BINARY" >"$SSRF_SERVER_LOG" 2>&1 &
SSRF_SERVER_PID=$!

SSRF_READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$SSRF_SERVER_PID" 2>/dev/null; then
        break
    fi
    SC=$(curl -s -o /dev/null -w "%{http_code}" "$SSRF_BASE_URL/ready" 2>/dev/null)
    if [[ "$SC" == "200" ]]; then
        SSRF_READY=1
        break
    fi
    sleep 0.25
done
check_local "$SSRF_READY" "1" "10b: isolated SSRF-enforcing instance (ALLOW_PRIVATE_INGEST_URLS_FOR_TEST=false) boots cleanly"

if [[ "$SSRF_READY" -eq 1 ]]; then
    SAVED_BASE_URL="$BASE_URL"
    BASE_URL="$SSRF_BASE_URL"

    for ssrf_url in "http://127.0.0.1:$SERVER_PORT/health" "http://169.254.169.254/latest/meta-data/" "http://100.64.0.1/feed.txt" "http://[::1]/feed.txt"; do
        api_call POST "/api/sources/test-fetch" "$MASTER_KEY" \
            "{\"source_url\":\"$ssrf_url\",\"parser_type\":\"REGEX_LINE\"}"
        check "200" "10b: test-fetch against SSRF target $ssrf_url completes without server crash"
        check_jq ".status" "FAILED" "10b: test-fetch rejects SSRF target $ssrf_url with status=FAILED"
        check_true '.error | contains("blocked source URL")' "10b: SSRF rejection for $ssrf_url reports blocked source URL"
    done

    api_call POST "/api/destination-groups" "$MASTER_KEY" \
        '{"name":"ssrf-blocked-group","cron_schedule":"0 0 * * *","target_group_name":"ssrf-target","mode":"upsert"}'
    check "200" "10b: create destination group on SSRF-enforcing instance"
    SSRF_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/destination-groups/$SSRF_GROUP_ID/feeds" "$MASTER_KEY" \
        "{\"name\":\"ssrf-loopback-feed\",\"source_url\":\"http://127.0.0.1:$SERVER_PORT/health\",\"parser_type\":\"REGEX_LINE\"}"
    check "200" "10b: register loopback feed on SSRF-enforcing instance"

    api_call POST "/api/destination-groups/$SSRF_GROUP_ID/feeds" "$MASTER_KEY" \
        '{"name":"ssrf-imds-feed","source_url":"http://169.254.169.254/latest/meta-data/","parser_type":"REGEX_LINE"}'
    check "200" "10b: register link-local metadata feed on SSRF-enforcing instance"

    api_call POST "/api/destination-groups/$SSRF_GROUP_ID/trigger" "$MASTER_KEY"
    check "200" "10b: trigger ingestion of SSRF feeds"
    check_jq ".status" "FAILED" "10b: ingestion job fails closed when all feeds target blocked SSRF addresses"
    check_jq ".items_processed" "0" "10b: zero items ingested from SSRF-blocked feeds"
    check_true '.error_message | contains("blocked source URL")' "10b: job summary records blocked source URL reason"

    BASE_URL="$SAVED_BASE_URL"
fi

if [[ -n "$SSRF_SERVER_PID" ]] && kill -0 "$SSRF_SERVER_PID" 2>/dev/null; then
    kill -TERM "$SSRF_SERVER_PID" 2>/dev/null || true
    wait "$SSRF_SERVER_PID" 2>/dev/null || true
    SSRF_SERVER_PID=""
fi

# 4. /api/audit-logs inclusive `until` boundary & malformed RFC3339 rejection (400).
api_call GET "/api/audit-logs?limit=1" "$MASTER_KEY"
check "200" "10b: fetch latest audit log entry for boundary testing"
AUDIT_BOUNDARY_ID=$(echo "$RESP_BODY" | jq -r '.[0].id')
AUDIT_BOUNDARY_TS=$(echo "$RESP_BODY" | jq -r '.[0].timestamp')

api_call GET "/api/audit-logs?until=$AUDIT_BOUNDARY_TS&limit=50" "$MASTER_KEY"
check "200" "10b: GET /api/audit-logs?until=<exact-timestamp> succeeds"
check_true "any(.[]; .id == \"$AUDIT_BOUNDARY_ID\")" \
    "10b: /api/audit-logs 'until' boundary is inclusive (<= includes row at exact timestamp)"

api_call GET "/api/audit-logs?since=$AUDIT_BOUNDARY_TS&until=$AUDIT_BOUNDARY_TS" "$MASTER_KEY"
check "200" "10b: GET /api/audit-logs with identical since & until timestamp succeeds"
check_true "any(.[]; .id == \"$AUDIT_BOUNDARY_ID\")" \
    "10b: identical since and until bounds return the row at that exact instant"

api_call GET "/api/audit-logs?until=not-a-valid-rfc3339-timestamp" "$MASTER_KEY"
check "400" "10b: malformed 'until' timestamp on /api/audit-logs is rejected with 400"
check_true '.error | contains("invalid until timestamp")' "10b: malformed until error message names field"

api_call GET "/api/audit-logs?since=2026-99-99T99:99:99Z" "$MASTER_KEY"
check "400" "10b: malformed 'since' timestamp on /api/audit-logs is rejected with 400"
check_true '.error | contains("invalid since timestamp")' "10b: malformed since error message names field"

# 5. Runtime MasterPin tamper resistance: direct SQLite promotion of a Daughter key while running.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"tamper-daughter-key","can_manage_keys":false,"can_manage_sources":false,"can_manage_vaults":false}'
check "200" "10b: create unprivileged daughter key for runtime MasterPin tamper test"
TAMPER_DAUGHTER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
TAMPER_DAUGHTER_SECRET=$(echo "$RESP_BODY" | jq -r '.plaintext_signing_secret')
TAMPER_DAUGHTER_ID=$(echo "$RESP_BODY" | jq -r '.key.id')
register_key_secret "$TAMPER_DAUGHTER_KEY" "$TAMPER_DAUGHTER_SECRET"

MASTER_PREFIX="${MASTER_KEY:0:8}"
# Directly mutate SQLite under the live process: demote real Master first (satisfying the unique
# index over the generated master_marker column), then mark the Daughter row is_master = 1.
sqlite3 "$DB_PATH" "UPDATE api_keys SET is_master = 0 WHERE is_master = 1; UPDATE api_keys SET is_master = 1 WHERE name = 'tamper-daughter-key';"
TAMPER_DB_FLAG=$(sqlite3 "$DB_PATH" "SELECT is_master FROM api_keys WHERE name = 'tamper-daughter-key';")
check_local "$TAMPER_DB_FLAG" "1" "10b: direct SQLite UPDATE set is_master=1 on tamper-daughter-key row"

# Despite is_master=1 in SQLite, MasterPin (OnceLock pinned at boot) demotes the key in memory.
api_call GET "/api/auth/me" "$TAMPER_DAUGHTER_KEY"
check "200" "10b: tampered daughter key still authenticates (no auth oracle)"
check_jq ".is_master" "false" "10b: MasterPin demotes runtime-promoted daughter key to is_master=false"

api_call GET "/api/audit-logs" "$TAMPER_DAUGHTER_KEY"
check "403" "10b: runtime-promoted daughter key is STILL rejected (403) on Master-only GET /api/audit-logs without restart"

api_call POST "/api/keys" "$TAMPER_DAUGHTER_KEY" '{"name":"tamper-escalation-attempt","can_manage_keys":true}'
check "403" "10b: runtime-promoted daughter key is STILL rejected (403) on Master-only scope elevation without restart"

if grep -q "TAMPER: key claims is_master=true" "$SERVER_LOG" 2>/dev/null; then
    check_local "logged" "logged" "10b: MasterPin logs a TAMPER alert when a non-pinned key claims is_master=true"
else
    check_local "missing" "logged" "10b: MasterPin logs a TAMPER alert when a non-pinned key claims is_master=true"
fi

# Restore the real Master row in SQLite and remove the tamper test key.
sqlite3 "$DB_PATH" "UPDATE api_keys SET is_master = 0 WHERE name = 'tamper-daughter-key'; UPDATE api_keys SET is_master = 1 WHERE prefix = '$MASTER_PREFIX';"
api_call GET "/api/auth/me" "$MASTER_KEY"
check "200" "10b: restored Master key authenticates after SQLite rollback"
check_jq ".is_master" "true" "10b: restored Master key matches pinned MasterPin identity"

api_call DELETE "/api/keys/$TAMPER_DAUGHTER_ID" "$MASTER_KEY"
check "204" "10b: clean up tamper-daughter-key"

# ── 11. SQLite text boundaries, write burst, and key ownership ─────────────────
log_section "11. SQLite text boundaries, write burst, and key ownership"

printf -v LONG_TEXT '%.0sabcdefghij' {1..33}
LONG_TARGET_URL="http://127.0.0.1:1/vault/$LONG_TEXT"
LONG_SOURCE_URL="http://127.0.0.1:1/feed/$LONG_TEXT"
LONG_BOUND_IPS=$(printf '192.0.2.%s/32,' {1..24})
# Put the actual client address beyond character 300 so truncation also breaks authentication.
LONG_BOUND_IPS+="127.0.0.1/32"

api_call POST "/api/keys" "$MASTER_KEY" \
    "{\"name\":\"sqlite-boundary-owner\",\"can_manage_sources\":true,\"can_manage_vaults\":true,\"bound_ips\":\"$LONG_BOUND_IPS\"}"
check "200" "create the boundary key with a long CIDR list"
BOUNDARY_KEY_ID=$(jq -r '.key.id' <<< "$RESP_BODY")
BOUNDARY_KEY=$(jq -r '.plaintext_key' <<< "$RESP_BODY")
register_key_secret "$BOUNDARY_KEY" "$(jq -r '.plaintext_signing_secret' <<< "$RESP_BODY")"

api_call GET "/api/keys/$BOUNDARY_KEY_ID" "$MASTER_KEY"
check "200" "read the boundary key from SQLite"
check_jq '.bound_ips' "$LONG_BOUND_IPS" "api_keys.bound_ips round-trips the complete CIDR list"
api_call GET "/api/auth/me" "$BOUNDARY_KEY"
check "200" "authenticate with the CIDR at the end of the stored list"

api_call POST "/api/destination-groups" "$BOUNDARY_KEY" \
    "{\"name\":\"sqlite-boundary-group\",\"cron_schedule\":\"0 0 * * *\",\"target_group_name\":\"$LONG_TEXT\",\"is_active\":false}"
check "200" "create an owned group with a long target group name"
BOUNDARY_GROUP_ID=$(jq -r '.id' <<< "$RESP_BODY")
BOUNDARY_GROUP_PATH="/api/destination-groups/$BOUNDARY_GROUP_ID"

api_call DELETE "/api/keys/$BOUNDARY_KEY_ID" "$MASTER_KEY"
check "409" "a destination group alone blocks key deletion"
check_true ".owned_resources == [{type:\"destination_group\", id:\"$BOUNDARY_GROUP_ID\", name:\"sqlite-boundary-group\", owner_key_id:\"$BOUNDARY_KEY_ID\"}]" \
    "the ownership inventory identifies the destination group"

api_call POST "$BOUNDARY_GROUP_PATH/feeds" "$MASTER_KEY" \
    "{\"name\":\"sqlite-boundary-feed\",\"source_url\":\"$LONG_SOURCE_URL\"}"
check "200" "create a feed with a long source URL"
BOUNDARY_FEED_ID=$(jq -r '.id' <<< "$RESP_BODY")

api_call GET "$BOUNDARY_GROUP_PATH" "$MASTER_KEY"
check "200" "read the boundary group and feed from SQLite"
check_jq '.target_group_name' "$LONG_TEXT" "destination_groups.target_group_name round-trips the complete name"
check_jq ".feeds[] | select(.id == \"$BOUNDARY_FEED_ID\") | .source_url" "$LONG_SOURCE_URL" \
    "external_sources.source_url round-trips the complete URL"

api_call POST "/api/vaults" "$BOUNDARY_KEY" \
    "{\"name\":\"sqlite-boundary-vault\",\"target_url\":\"$LONG_TARGET_URL\",\"api_key\":\"boundary-token\",\"signing_secret\":\"boundary-secret\"}"
check "200" "create an owned vault endpoint with a long target URL"
BOUNDARY_VAULT_ID=$(jq -r '.id' <<< "$RESP_BODY")
api_call GET "/api/vaults/$BOUNDARY_VAULT_ID" "$MASTER_KEY"
check "200" "read the boundary vault endpoint from SQLite"
check_jq '.target_url' "$LONG_TARGET_URL" "vault_endpoints.target_url round-trips the complete URL"

check_local "$(sqlite3 "$DB_PATH" "PRAGMA journal_mode;")" "wal" "the daemon database uses SQLite WAL"
BURST_DIR="$WORK_DIR/sqlite-write-burst"
mkdir -p "$BURST_DIR"
BURST_BODY='{"is_active":false}'
BURST_TIMESTAMPS=()
BURST_SIGNATURES=()
BURST_PIDS=()
# Sign first so curl launches are not paced by openssl. Allocate timestamps in the parent shell.
for i in {1..20}; do
    next_timestamp
    BURST_TIMESTAMPS[$i]="$SIGNED_TS"
    BURST_SIGNATURES[$i]=$(hmac_sign "$MASTER_SIGNING_SECRET" PATCH "$BOUNDARY_GROUP_PATH" "$SIGNED_TS" "$BURST_BODY")
done
BURST_LOG_OFFSET=$(wc -c < "$SERVER_LOG")
for i in {1..20}; do
    curl --silent --show-error --max-time 30 --output "$BURST_DIR/body_$i" --write-out '%{http_code}' \
        -X PATCH -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: ${BURST_TIMESTAMPS[$i]}" \
        -H "X-Signature-256: ${BURST_SIGNATURES[$i]}" -H 'Content-Type: application/json' \
        --data-binary "$BURST_BODY" "$BASE_URL$BOUNDARY_GROUP_PATH" > "$BURST_DIR/status_$i" &
    BURST_PIDS[$i]=$!
done
BURST_OK=0
for i in {1..20}; do
    if wait "${BURST_PIDS[$i]}" && [[ "$(cat "$BURST_DIR/status_$i")" == "200" ]]; then
        BURST_OK=$((BURST_OK + 1))
    else
        warn "SQLite write burst request $i returned HTTP $(cat "$BURST_DIR/status_$i")"
    fi
done
check_local "$BURST_OK" "20" "all 20 concurrent authenticated writes return 200"
tail -c "+$((BURST_LOG_OFFSET + 1))" "$SERVER_LOG" > "$BURST_DIR/server.log"
BURST_LOCK_ERRORS=0
if grep -Ei 'database.*(locked|busy)|SQLITE_(BUSY|LOCKED)' "$BURST_DIR"/body_* "$BURST_DIR/server.log"; then
    BURST_LOCK_ERRORS=1
fi
check_local "$BURST_LOCK_ERRORS" "0" "the burst produces zero SQLite lock errors in responses or server logs"

api_call DELETE "$BOUNDARY_GROUP_PATH/feeds/$BOUNDARY_FEED_ID" "$MASTER_KEY"
check "204" "delete the boundary feed"
api_call DELETE "$BOUNDARY_GROUP_PATH" "$MASTER_KEY"
check "204" "delete the boundary destination group"

api_call DELETE "/api/keys/$BOUNDARY_KEY_ID" "$MASTER_KEY"
check "409" "a vault endpoint alone blocks key deletion after group cleanup"
check_true ".owned_resources == [{type:\"vault_endpoint\", id:\"$BOUNDARY_VAULT_ID\", name:\"sqlite-boundary-vault\", owner_key_id:\"$BOUNDARY_KEY_ID\"}]" \
    "the ownership inventory identifies only the remaining vault endpoint"
api_call DELETE "/api/vaults/$BOUNDARY_VAULT_ID" "$MASTER_KEY"
check "204" "delete the boundary vault endpoint"
api_call DELETE "/api/keys/$BOUNDARY_KEY_ID" "$MASTER_KEY"
check "204" "delete the boundary key after all owned resources are removed"

# ── 12. Graceful shutdown ────────────────────────────────────────────────────
log_section "12. Graceful shutdown"

log "Sending SIGTERM to pid $SERVER_PID and waiting for exit..."
kill -TERM "$SERVER_PID" 2>/dev/null || true
SHUTDOWN_OK=0
for _ in $(seq 1 20); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        SHUTDOWN_OK=1
        break
    fi
    sleep 0.25
done
check_local "$SHUTDOWN_OK" "1" "the server exits within 5s of SIGTERM (graceful shutdown, not a hang)"
if [[ "$SHUTDOWN_OK" -eq 1 ]]; then
    SERVER_PID=""  # already exited; cleanup() should not try to kill it again
fi

# ── Summary ───────────────────────────────────────────────────────────────────
log_section "Summary"
echo -e "$(ts) ${GREEN}Passed: $PASS_COUNT${RESET}   ${RED}Failed: $FAIL_COUNT${RESET}   ${YELLOW}Skipped: $SKIP_COUNT${RESET}" >&2

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    err "E2E suite FAILED ($FAIL_COUNT failing check(s))."
    exit 1
fi

log "E2E suite PASSED — all $PASS_COUNT checks succeeded ($SKIP_COUNT skipped)."
exit 0
