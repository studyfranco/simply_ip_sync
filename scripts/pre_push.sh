#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

test_log="$(mktemp "${TMPDIR:-.}/simply_ip_sync-tests.XXXXXX")"
trap 'rm -f "$test_log"' EXIT
cargo test "$@" 2>&1 | tee "$test_log"
awk '
    /^test result:/ {
        seen = 1
        if ($0 !~ /; 0 failed; 0 ignored;/) bad = 1
    }
    END {
        if (!seen || bad) {
            print "Expected every Cargo test suite to report 0 failed and 0 ignored" > "/dev/stderr"
            exit 1
        }
    }
' "$test_log"
cargo audit --deny warnings
bash -n scripts/test_e2e.sh
