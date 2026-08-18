#!/usr/bin/env bash
#
# verify_convergence.sh — mechanical drift detection between simply_ip_sync and simply_ip_vault.
#
# `simply_ip_sync` is not in scope of `simply_ip_vault`/`simply_hook_executor`'s shared,
# byte-identical `RBAC_MODEL.md` (see this repo's own RBAC_MODEL.md status line) — it is the
# ecosystem's third peer, converging on the same security primitives by deliberate cross-reading
# rather than a shared specification file. That means this script cannot diff RBAC_MODEL.md for
# byte-identity the way the original pair's script does; instead it checks that this service's own
# RBAC_MODEL.md carries the same normative structure (tiers, R1-R7, §3-§7) and that every rule has
# a compliance test, which is the check that actually matters: agreement on what the rules say,
# proven by evidence that they are enforced, not agreement on the literal bytes of a document this
# service was never a party to.
#
# WHAT IT DOES NOT DO: decide whether a divergence is wrong. Several are deliberate and documented
# — most prominently the retention/body-size defaults, which differ because this service's domain
# (sync task/audit log history) and the peer's (soft-deleted IP records) are not the same thing. A
# reported difference is a prompt to check the rationale, not a bug.
#
# Usage:
#   scripts/verify_convergence.sh            # summary, exit 1 on unexpected divergence
#   scripts/verify_convergence.sh --verbose  # also print the normalized diffs
#
# Exit status: 0 when every tracked primitive matches (or diverges as documented), 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PEER_ROOT="$PROJECT_ROOT/example/simply_ip_vault"

VERBOSE=0
[ "${1:-}" == "--verbose" ] && VERBOSE=1

if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

MATCH_COUNT=0
DRIFT_COUNT=0
EXPECTED_COUNT=0

# ─────────────────────────────────────────────────────────────
# Peer sync — compare against the peer's current HEAD, not a stale one
# ─────────────────────────────────────────────────────────────
#
# The clone under `example/` has its own remote and falls behind. A convergence check run against
# a stale clone certifies agreement with code that no longer exists, and does so *silently*: every
# assertion passes and the summary reads clean.
#
# **Never fatal.** This gate must stay usable offline, on a laptop with no route to the forge, and
# in CI without credentials. Every failure below degrades to a warning and the check proceeds
# against whatever is on disk, which is still worth running.
#
# Set `SKIP_PEER_SYNC=1` to bypass entirely — for an air-gapped run, or to pin a comparison to a
# known peer commit while investigating a drift report.
sync_peer_repositories() {
    if [ "${SKIP_PEER_SYNC:-0}" == "1" ]; then
        echo "  ${YELLOW}⚠${RESET}  peer sync skipped (SKIP_PEER_SYNC=1) — comparing against the local checkout"
        return
    fi

    local git_dir peer name
    local found=0
    for git_dir in "$PROJECT_ROOT"/example/*/.git; do
        [ -e "$git_dir" ] || continue
        found=1
        peer="$(dirname "$git_dir")"
        name="$(basename "$peer")"

        # Refuse to pull over local modifications. A dirty peer worktree means somebody is
        # mid-edit, and merging on top of that either fails noisily or silently mixes the two —
        # neither belongs in a check that is supposed to only observe.
        if [ -n "$(git -C "$peer" status --porcelain 2>/dev/null)" ]; then
            echo "  ${YELLOW}⚠${RESET}  $name has local changes — not pulling, comparing against the working tree as-is"
            continue
        fi

        if GIT_TERMINAL_PROMPT=0 timeout 60 git -C "$peer" pull --quiet --ff-only 2>/dev/null; then
            echo "  ${GREEN}✓${RESET} $name synced — now at $(git -C "$peer" rev-parse --short HEAD)"
        else
            echo "  ${YELLOW}⚠️  Warning: Could not pull peer repository, continuing with local version...${RESET}"
            echo "     $name stays at $(git -C "$peer" rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
                 "— offline, no credentials, or the branch has diverged."
        fi
    done

    [ "$found" == "1" ] || echo "  ${BLUE}·${RESET}  no git clone under example/ — comparing against the files on disk"
}

echo "${BOLD}Peer synchronization${RESET}"
sync_peer_repositories
echo

if [ ! -d "$PEER_ROOT" ]; then
    echo "${YELLOW}SKIP${RESET} peer service not found at $PEER_ROOT" >&2
    echo "Mount simply_ip_vault there (read-only is fine) to enable drift detection." >&2
    exit 0
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Prints the body of a Rust function, from its signature to the closing brace at the same
# indentation. Deliberately awk rather than a real parser: the targets are all top-level `fn`s with
# rustfmt-normalized bodies, so brace-depth counting is exact for them.
# Usage: extract_fn FILE FUNCTION_NAME
extract_fn() {
    local file="$1" name="$2"
    [ -f "$file" ] || return 1
    awk -v target="$name" '
        !inside && $0 ~ ("(^|[^a-zA-Z0-9_])fn[ \t]+" target "[ \t]*[(<]") {
            inside = 1; depth = 0
        }
        inside {
            print
            n = gsub(/\{/, "{"); depth += n
            n = gsub(/\}/, "}"); depth -= n
            if (depth == 0 && seen_brace) { exit }
            if (depth > 0) seen_brace = 1
        }
    ' "$file"
}

# Strips the differences that are expected between the two crates, so the diff reports behaviour
# rather than vocabulary — including how rustfmt happens to have wrapped a signature. A function
# whose parameter list rustfmt put on one line versus one-per-line is not a behavioural difference,
# but a per-line diff sees it as one; joining every remaining line into a single normalized line
# (after whitespace/comment/blank-line stripping) makes the comparison see through wrapping exactly
# the way a reader would, while still catching a genuine token-level difference anywhere in the body.
normalize() {
    sed -E \
        -e 's/[[:space:]]+$//' \
        -e '/^[[:space:]]*\/\//d' \
        -e '/^[[:space:]]*$/d' \
        -e 's/^pub fn /fn /' \
        -e 's/^pub async fn /async fn /' \
        -e 's/simply_ip_sync/CRATE/g' \
        -e 's/simply_ip_vault/CRATE/g' \
        -e 's/SYNC_ENCRYPTION_KEY/ENCRYPTION_KEY/g' \
        -e 's/VAULT_ENCRYPTION_KEY/ENCRYPTION_KEY/g' \
        -e 's/[[:space:]]+/ /g' \
        | tr '\n' ' ' \
        | sed -E 's/[[:space:]]+/ /g; s/^[[:space:]]+|[[:space:]]+$//g; s/,[[:space:]]*\)/)/g; s/\([[:space:]]+/(/g'
    echo
}

# Compares one function between the two trees.
# Usage: compare_fn LABEL OUR_FILE OUR_FN PEER_FILE PEER_FN [expected-divergence-reason]
compare_fn() {
    local label="$1" our_file="$2" our_fn="$3" peer_file="$4" peer_fn="$5" expected="${6:-}"

    extract_fn "$PROJECT_ROOT/$our_file" "$our_fn" | normalize > "$WORK_DIR/ours.txt"
    extract_fn "$PEER_ROOT/$peer_file" "$peer_fn" | normalize > "$WORK_DIR/peer.txt"

    if [ ! -s "$WORK_DIR/ours.txt" ]; then
        echo "  ${RED}✗ MISSING${RESET} $label — could not find \`fn $our_fn\` in $our_file"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi
    if [ ! -s "$WORK_DIR/peer.txt" ]; then
        echo "  ${YELLOW}~ ABSENT${RESET}  $label — the peer has no \`fn $peer_fn\` in $peer_file"
        EXPECTED_COUNT=$((EXPECTED_COUNT + 1))
        return
    fi

    if diff -q "$WORK_DIR/ours.txt" "$WORK_DIR/peer.txt" >/dev/null 2>&1; then
        echo "  ${GREEN}✓ MATCH${RESET}   $label"
        MATCH_COUNT=$((MATCH_COUNT + 1))
        return
    fi

    if [ -n "$expected" ]; then
        echo "  ${YELLOW}~ DIVERGES${RESET} $label — expected: $expected"
        EXPECTED_COUNT=$((EXPECTED_COUNT + 1))
    else
        echo "  ${RED}✗ DRIFT${RESET}   $label — the two implementations no longer agree"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
    fi

    if [ "$VERBOSE" == "1" ]; then
        echo "${BLUE}--- ours ($our_file::$our_fn) / peer ($peer_file::$peer_fn) ---${RESET}"
        diff -u "$WORK_DIR/ours.txt" "$WORK_DIR/peer.txt" | sed 's/^/    /'
        echo
    fi
}

# Asserts that a pattern appears in one of our files.
# Usage: assert_present LABEL FILE PATTERN
assert_present() {
    local label="$1" file="$2" pattern="$3"
    if grep -qE "$pattern" "$PROJECT_ROOT/$file" 2>/dev/null; then
        echo "  ${GREEN}✓ PRESENT${RESET} $label"
        MATCH_COUNT=$((MATCH_COUNT + 1))
    else
        echo "  ${RED}✗ ABSENT${RESET}  $label — expected /$pattern/ in $file"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
    fi
}

# Asserts that a pattern appears NOWHERE in src/.
# Usage: assert_absent LABEL PATTERN
assert_absent() {
    local label="$1" pattern="$2"
    local hits
    hits=$(grep -rnE "$pattern" "$PROJECT_ROOT/src" 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*)' || true)
    if [ -z "$hits" ]; then
        echo "  ${GREEN}✓ CLEAN${RESET}   $label"
        MATCH_COUNT=$((MATCH_COUNT + 1))
    else
        echo "  ${RED}✗ FOUND${RESET}   $label"
        echo "$hits" | sed 's/^/      /'
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
    fi
}

echo
echo "${BOLD}Convergence check: simply_ip_sync  ↔  simply_ip_vault${RESET}"
echo "  this repo: $PROJECT_ROOT"
echo "  peer:      $PEER_ROOT"
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 0 — Authorization model${RESET}"
# `RBAC_MODEL.md` here is a *restatement*, not a byte-identical copy — this service's own file says
# so in its status line, and is not diffed by the peer's own convergence script either. What this
# check verifies instead is structural: every normative section the peer's document has (Tiers,
# R1-R7, §3-§7) is present here too, under this service's own terminology.
check_rbac_structure() {
    local label="RBAC_MODEL.md restates every normative section the peer's specification has"
    local ours="$PROJECT_ROOT/RBAC_MODEL.md"
    if [ ! -f "$ours" ]; then
        echo "  ${RED}✗ MISSING${RESET} $label — $ours does not exist"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi
    local missing=""
    for heading in "R1" "R2" "R3" "R4" "R5" "R6" "R7" \
                   "Resource Lifecycle" "Visibility" "Master Key Guarantees" \
                   "Cascade Deletion" "Database Constraints"; do
        grep -qF "$heading" "$ours" || missing="$missing\n    - $heading"
    done
    if [ -n "$missing" ]; then
        echo "  ${RED}✗ GAP${RESET}     $label — missing:"
        echo -e "$missing"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi
    echo "  ${GREEN}✓ MATCH${RESET}   $label"
    MATCH_COUNT=$((MATCH_COUNT + 1))
}
check_rbac_structure

# Rule coverage: every rule and section named above must have at least one compliance test, named
# after it, in the file that indexes this service's own RBAC compliance suite.
check_rule_coverage() {
    local suite="$PROJECT_ROOT/tests/rbac_model_compliance.rs"
    local label="every RBAC_MODEL.md rule has a compliance test"

    if [ ! -f "$suite" ]; then
        echo "  ${RED}✗ MISSING${RESET} $label — $suite does not exist"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi

    local uncovered=""
    local covered=0
    for rule in r1 r2 r3 r4 r5 r6 r7 s3 s4 s5 s6 s7; do
        if grep -qE "^\s*async fn ${rule}_|^\s*fn ${rule}_" "$suite"; then
            covered=$((covered + 1))
        else
            uncovered="$uncovered $rule"
        fi
    done

    if [ -n "$uncovered" ]; then
        echo "  ${RED}✗ GAP${RESET}     $label — no test for:$uncovered"
        echo "             add one to tests/rbac_model_compliance.rs named <rule>_<what it asserts>"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi

    echo "  ${GREEN}✓ MATCH${RESET}   $label ($covered/12 rules and sections)"
    MATCH_COUNT=$((MATCH_COUNT + 1))
}
check_rule_coverage

# Adversarial coverage: the two rules whose guarantee lives below the application (§5 the master
# marker, §7 the schema's own constraints/indexes) must be proven against an uncooperative writer,
# not only through the API. R1-R7, §3, §4 and §6 are authorization *decisions* made by handlers, and
# a caller exercising the API is the correct way to test them — they are deliberately excluded here.
check_adversarial_coverage() {
    local suite="$PROJECT_ROOT/tests/rbac_model_compliance.rs"
    local label="every infrastructure-level rule has an adversarial test"

    if [ ! -f "$suite" ]; then
        echo "  ${RED}✗ MISSING${RESET} $label — $suite does not exist"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi

    local uncovered=""
    local covered=0
    for rule in "§5" "§7"; do
        if grep -qF "ADVERSARIAL(${rule})" "$suite"; then
            covered=$((covered + 1))
        else
            uncovered="$uncovered $rule"
        fi
    done

    if [ -n "$uncovered" ]; then
        echo "  ${RED}✗ GAP${RESET}     $label — no adversarial test for:$uncovered"
        echo "             Mark it \`ADVERSARIAL(<rule>)\` in the test's doc comment."
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi

    local total
    total=$(grep -cF "ADVERSARIAL(" "$suite")
    echo "  ${GREEN}✓ MATCH${RESET}   $label ($covered/2 rules, $total adversarial test(s))"
    MATCH_COUNT=$((MATCH_COUNT + 1))
}
check_adversarial_coverage

assert_present "the master marker is generated by the engine, not by the application" \
    "src/migration/m20260101_000002_derive_master_marker.rs" "GENERATED ALWAYS AS"
assert_present "the generated column is per-backend: STORED on Postgres, VIRTUAL elsewhere" \
    "src/migration/m20260101_000002_derive_master_marker.rs" 'DatabaseBackend::Postgres => "STORED"'
assert_absent "no code writes the master marker" \
    "master_marker:[[:space:]]*Set\("
if grep -qE '^\s*pub master_marker' "$PROJECT_ROOT/src/entities/api_key.rs"; then
    echo "  ${RED}✗ FOUND${RESET}   api_key::Model declares master_marker — the column must stay unmodelled"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
else
    echo "  ${GREEN}✓ CLEAN${RESET}   api_key::Model does not model the derived marker"
    MATCH_COUNT=$((MATCH_COUNT + 1))
fi
marker_dml=$(grep -rniE "(INSERT INTO|UPDATE)[^\"]*master_marker" "$PROJECT_ROOT/src" 2>/dev/null \
    | grep -v "/src/migration/" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*)' || true)
if [ -z "$marker_dml" ]; then
    echo "  ${GREEN}✓ CLEAN${RESET}   no raw DML names master_marker outside src/migration/"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ FOUND${RESET}   raw DML naming master_marker:"
    echo "$marker_dml" | sed 's/^/      /'
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi

assert_present "the master key id is pinned once at startup" \
    "src/master.rs" "pub async fn pin_at_boot\("
assert_present "the pin is write-once, not a reassignable field" \
    "src/master.rs" "cell: OnceLock<Uuid>"
assert_present "startup aborts rather than serving with an unpinnable master" \
    "src/main.rs" "state.master_pin.pin_at_boot\(&state.db\).await?"
assert_present "the demotion is applied at one choke point, in the middleware" \
    "src/middleware.rs" "state.master_pin.authenticate\(&state.db, &mut key_record\)"
assert_present "a key claiming master is demoted unless it is the pinned one" \
    "src/master.rs" "key\.is_master = false"
assert_present "the §5/§7 uniqueness index is re-checked at runtime, not just in the migration" \
    "src/master.rs" "has_index\("
assert_present "the runtime index check works on every supported backend" \
    "src/db.rs" "pub async fn has_index\("

demotion_files=$(grep -rln "key\.is_master = false" "$PROJECT_ROOT/src" --include='*.rs' \
    | grep -v "/src/migration/" | wc -l)
if [ "$demotion_files" -eq 1 ]; then
    echo "  ${GREEN}✓ MATCH${RESET}   the demotion has exactly one implementation in src/"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ DRIFT${RESET}   the demotion must live in exactly one file (found $demotion_files)"
    grep -rn "key\.is_master = false" "$PROJECT_ROOT/src" --include='*.rs' \
        | grep -v "/src/migration/" | sed 's/^/             /'
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi

assert_present "liveness is mounted outside the authenticated nest" \
    "src/lib.rs" 'route\("/health", get\(api::health_check\)\)'
assert_present "readiness is mounted outside the authenticated nest" \
    "src/lib.rs" 'route\("/ready", get\(api::readiness_check\)\)'
assert_present "the /healthz alias matches the peer's spelling" \
    "src/lib.rs" 'route\("/healthz", get\(api::health_check\)\)'
assert_present "the /readyz alias matches the peer's spelling" \
    "src/lib.rs" 'route\("/readyz", get\(api::readiness_check\)\)'
if [ -f "$PROJECT_ROOT/src/api/health.rs" ] && [ -f "$PEER_ROOT/src/api/health.rs" ]; then
    echo "  ${GREEN}✓ MATCH${RESET}   the probes live in src/api/health.rs on both sides"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ DRIFT${RESET}   src/api/health.rs is missing on one side"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi
assert_absent "no public probe discloses the build version" \
    '"version":[[:space:]]*env!'

assert_present "foreign key enforcement is set at connection time" \
    "src/db.rs" "\.foreign_keys\(true\)"
assert_present "synchronous=NORMAL is set at connection time" \
    "src/db.rs" "PRAGMA synchronous = NORMAL"

# No raw SQL for DML anywhere in `src/`, migrations excepted.
check_no_raw_sql() {
    local label="no raw SQL outside migrations (PRAGMA excepted)"
    local hits=""
    local file
    while IFS= read -r file; do
        local found
        found=$(awk -v path="${file#"$PROJECT_ROOT/"}" '
            { L[NR] = $0 }
            END {
                for (i = 1; i <= NR; i++) {
                    line = L[i]
                    if (line !~ /execute_unprepared|Statement::from_(string|sql)|(query_one|query_all|execute)_raw/) continue
                    if (line ~ /^[ \t]*(\/\/|\/\*|\*)/) continue
                    flag = 1
                    if (path == "src/db.rs") {
                        flag = 0
                        lo = i - 6; if (lo < 1) lo = 1
                        hi = i + 6; if (hi > NR) hi = NR
                        catalog = 0
                        for (j = lo; j <= hi; j++) {
                            if (toupper(L[j]) ~ /SELECT |INSERT INTO|UPDATE |DELETE FROM/) flag = 1
                            # Engine catalog tables (sqlite_master, pg_indexes,
                            # information_schema) are metadata, never an applications own row —
                            # a SELECT against one is `has_index`s index-existence check, the
                            # same class of exemption PRAGMA gets, not smuggled DML.
                            if (L[j] ~ /sqlite_master|pg_indexes|information_schema/) catalog = 1
                        }
                        if (catalog) flag = 0
                    }
                    if (flag) printf "%s:%d:%s\n", path, i, line
                }
            }
        ' "$file")
        [ -n "$found" ] && hits="${hits}${found}"$'\n'
    done < <(find "$PROJECT_ROOT/src" -name '*.rs' -not -path "$PROJECT_ROOT/src/migration/*")
    hits=$(printf '%s' "$hits" | sed '/^$/d')

    if [ -z "$hits" ]; then
        echo "  ${GREEN}✓ CLEAN${RESET}   $label"
        MATCH_COUNT=$((MATCH_COUNT + 1))
        return
    fi
    echo "  ${RED}✗ FOUND${RESET}   $label — use typed entity methods or SeaQuery instead"
    echo "$hits" | sed 's|^'"$PROJECT_ROOT"'/|      |'
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
}
check_no_raw_sql
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 1 — Proxy resolution & X-Forwarded-For${RESET}"
compare_fn "X-Forwarded-For chain walk" \
    "src/config.rs" "resolve_client_ip" \
    "src/config.rs" "resolve_client_ip"
compare_fn "IPv4-mapped normalization" \
    "src/config.rs" "normalize_ip" \
    "src/config.rs" "normalize_ip"
compare_fn "trusted-network membership" \
    "src/config.rs" "is_trusted" \
    "src/config.rs" "is_trusted"
# The peer splits bind-address resolution into `resolve_bind_addr()` (env lookup) and
# `parse_bind_addr(host, port)` (pure parsing, unit-testable without touching the environment).
# This service keeps the two fused into one `resolve_bind_addr()` — a real structural difference,
# not a rename, so it is asserted rather than diffed function-for-function.
if grep -qE "fn parse_bind_addr\(" "$PEER_ROOT/src/config.rs" 2>/dev/null; then
    echo "  ${YELLOW}~ DIVERGES${RESET} bind-address parsing — expected: the peer factors parsing out of env lookup" \
         "(parse_bind_addr); this service keeps both in resolve_bind_addr()"
    EXPECTED_COUNT=$((EXPECTED_COUNT + 1))
else
    echo "  ${BLUE}·${RESET}  peer has no separate parse_bind_addr either — nothing to compare"
fi
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 2 — Cryptography${RESET}"
if grep -qE '^chacha20poly1305\s*=' "$PROJECT_ROOT/Cargo.toml"; then
    echo "  ${GREEN}✓ PRESENT${RESET} chacha20poly1305 is a declared dependency"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ ABSENT${RESET}  chacha20poly1305 is not declared in Cargo.toml"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi
if grep -qE '^aes[-_]gcm\s*=' "$PROJECT_ROOT/Cargo.toml"; then
    echo "  ${RED}✗ DRIFT${RESET}   aes-gcm is present in Cargo.toml — the 96-bit-nonce AEAD the ecosystem retired"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
else
    echo "  ${GREEN}✓ CLEAN${RESET}   aes-gcm is not a dependency"
    MATCH_COUNT=$((MATCH_COUNT + 1))
fi

assert_present "XChaCha20-Poly1305 is the at-rest AEAD" \
    "src/crypto.rs" "XChaCha20Poly1305"
assert_present "192-bit nonce width" \
    "src/crypto.rs" "NONCE_LEN: usize = 24"
assert_present "constant-time signature comparison" \
    "src/crypto.rs" "verify_slice"
assert_present "the encryption key is length-checked, not hashed into shape" \
    "src/crypto.rs" "KEY_LEN"
assert_present "the sha256= prefix is mandatory, not stripped-if-present" \
    "src/crypto.rs" 'strip_prefix\(SIGNATURE_PREFIX\)\?'
assert_absent "no bare-hex signature fallback" \
    'strip_prefix\("sha256="\)[[:space:]]*\.unwrap_or'
assert_absent "no equality comparison on a signature or MAC" \
    '(signature|hmac|mac|digest|secret)[a-z_]*[[:space:]]*==[[:space:]]*[^=]|==[[:space:]]*[a-z_]*(signature|hmac|digest)'
# This service additionally canary-checks the encryption key at boot — the peer, per its own
# AGENT_NOTES.MD (audited independently, not read here to preserve this script's own neutrality),
# does not yet have this. Asserted as a one-sided presence check, not a compare_fn: there is no
# peer implementation to diff against.
assert_present "a boot-time canary proves the encryption key is correct, not just well-formed" \
    "src/crypto.rs" "pub fn check_key_canary\("
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 3 — Pipeline ordering & memory bounds${RESET}"
assert_present "the router-wide body limit resolves through the shared config function" \
    "src/lib.rs" "DefaultBodyLimit::max\(max_request_body_bytes\(\)\)"
assert_present "the signature buffer resolves through the same function as the router limit" \
    "src/middleware.rs" "crate::config::max_body_bytes\(\)"
OUR_MW="$PROJECT_ROOT/src/middleware.rs"
SIG_LINE=$(grep -n "verify_signature" "$OUR_MW" | head -1 | cut -d: -f1)
CIDR_LINE=$(grep -n "bound_ips" "$OUR_MW" | grep -v "^\s*//" | tail -1 | cut -d: -f1)
if [ -n "$SIG_LINE" ] && [ -n "$CIDR_LINE" ] && [ "$SIG_LINE" -lt "$CIDR_LINE" ]; then
    echo "  ${GREEN}✓ ORDERED${RESET} authentication precedes the bound_ips check (line $SIG_LINE < $CIDR_LINE)"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ ORDER${RESET}   authentication must precede the bound_ips check — a 401/403 oracle otherwise"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi
assert_present "anti-replay guard is consulted" \
    "src/middleware.rs" "replay\.check_and_record"
assert_present "anti-replay tracking has a dedicated module" \
    "src/replay.rs" "pub struct ReplayGuard"
assert_present "replay entries expire on the monotonic clock" \
    "src/replay.rs" "Instant"
assert_absent "replay expiry does not consult the wall clock" \
    "chrono::Utc::now\(\).*Instant|Instant.*chrono::Utc::now"
assert_absent "a saturated replay guard is never flushed" \
    "seen\.clear\(\)"
assert_present "replay entries are keyed on the raw digest" \
    "src/replay.rs" "digest: Vec<u8>"
assert_present "the full request target — path and query — is signed" \
    "src/middleware.rs" "path_and_query"
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 4 — Database resilience & retention${RESET}"
compare_fn "SQLite pragma initialization" \
    "src/db.rs" "apply_sqlite_pragmas" \
    "src/db.rs" "apply_sqlite_pragmas" \
    "each service's pragma set is tuned to its own connection-pool history; both are 4-pragma sets today but were not derived from a shared list"
if grep -A40 "pub async fn apply_sqlite_pragmas" "$PROJECT_ROOT/src/db.rs" | grep -qE '\?;\s*$'; then
    echo "  ${RED}✗ FATAL${RESET}   apply_sqlite_pragmas propagates an error — it must degrade, not abort"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
else
    echo "  ${GREEN}✓ SOFT${RESET}    apply_sqlite_pragmas cannot abort startup"
    MATCH_COUNT=$((MATCH_COUNT + 1))
fi
# Retention is a genuinely different concern on each side of this comparison: the peer purges
# soft-deleted IP records (its resources are recoverable-by-design); this service has no
# soft-deleted resource rows at all (RBAC_MODEL.md §6 uses hard-delete-with-cascade-inventory
# instead) and purges historic sync_logs/audit_logs rows on independent windows instead. Both are
# asserted as one-sided presences rather than diffed against each other.
assert_present "sync_logs retention window is environment-configurable" \
    "src/retention.rs" "SYNC_LOG_RETENTION_DAYS_ENV"
assert_present "audit_logs retention window is environment-configurable, independently" \
    "src/retention.rs" "AUDIT_LOG_RETENTION_DAYS_ENV"
assert_present "a non-positive retention window disables purging rather than purging everything" \
    "src/retention.rs" "if retention_days <= 0"
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Summary${RESET}"
echo "  ${GREEN}$MATCH_COUNT matching${RESET}   ${YELLOW}$EXPECTED_COUNT documented divergence(s)${RESET}   ${RED}$DRIFT_COUNT unexplained${RESET}"
echo

if [ "$DRIFT_COUNT" -gt 0 ]; then
    echo "${RED}Convergence check FAILED${RESET} — $DRIFT_COUNT primitive(s) drifted." >&2
    echo "Re-run with --verbose to see the normalized diffs." >&2
    exit 1
fi

echo "${GREEN}Convergence check PASSED${RESET} — every tracked primitive agrees or diverges as documented."
exit 0
