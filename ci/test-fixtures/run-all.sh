#!/usr/bin/env bash
# run-all.sh — test runner for ci/identity-audit.sh fixtures (A–N, P, Q).
#
# This is the reference implementation of the Type3 protocol.
# Normative behaviour is defined in spec/. Where they differ, spec/ wins.
#
# Stability: test harness; run from any working directory. Story 7-11 Task 1.
# Usage: bash teleproto3/ci/test-fixtures/run-all.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDIT_SCRIPT="$(cd "$SCRIPT_DIR/.." && pwd)/identity-audit.sh"
SETUP_SCRIPT="$(cd "$SCRIPT_DIR/../../../_bmad-output/security" 2>/dev/null && pwd)/setup-public-repo.sh" || SETUP_SCRIPT=""

if [ ! -x "$AUDIT_SCRIPT" ]; then
    printf 'ERROR: audit script not found or not executable: %s\n' "$AUDIT_SCRIPT" >&2
    exit 1
fi

# ── Counters ─────────────────────────────────────────────────────────────────
PASS=0; FAIL=0; SKIP=0

_pass() { printf '  PASS: %s\n' "$1"; PASS=$((PASS+1)); }
_fail() { printf '  FAIL: %s — %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
_skip() { printf '  SKIP: %s — %s\n' "$1" "$2"; SKIP=$((SKIP+1)); }

# ── Generic fixture runner ────────────────────────────────────────────────────
# run_fixture <label> <token-list> <commit-mock|-> <diff-mock|-> <expected-rc> <stdout-grep>
run_fixture() {
    local label="$1" tlist="$2" cmock="$3" dmock="$4" expected_rc="$5" grep_pat="$6"

    local tmpout; tmpout=$(mktemp)
    local actual_rc=0

    local env_args=("IDENTITY_AUDIT_TOKEN_LIST=$tlist")
    [ "$cmock" != "-" ] && env_args+=("IDENTITY_AUDIT_MOCK_COMMIT_LOG=$cmock")
    [ "$dmock" != "-" ] && env_args+=("IDENTITY_AUDIT_MOCK_DIFF=$dmock")

    env "${env_args[@]}" bash "$AUDIT_SCRIPT" > "$tmpout" 2>&1 || actual_rc=$?

    if [ "$actual_rc" -ne "$expected_rc" ]; then
        _fail "$label" "exit $actual_rc, expected $expected_rc (output: $(cat "$tmpout" | head -3))"
        rm -f "$tmpout"; return
    fi

    if [ -n "$grep_pat" ]; then
        if ! grep -qE "$grep_pat" "$tmpout" 2>/dev/null; then
            _fail "$label" "stdout does not match /$grep_pat/ (got: $(cat "$tmpout" | head -3))"
            rm -f "$tmpout"; return
        fi
    fi

    _pass "$label"
    rm -f "$tmpout"
}

# ── Fixture A: denylist match in diff → exit 1 ───────────────────────────────
printf '\nFixture A:\n'
run_fixture "A: diff match exit 1" \
    "$SCRIPT_DIR/fixture-a/token-list.yaml" \
    "$SCRIPT_DIR/fixture-a/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-a/mock-diff.txt" \
    1 "REDACTED:rule=test-1:stream=diff"

# ── Fixture B: no match → exit 0 ─────────────────────────────────────────────
printf '\nFixture B:\n'
run_fixture "B: no match exit 0" \
    "$SCRIPT_DIR/fixture-b/token-list.yaml" \
    "$SCRIPT_DIR/fixture-b/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-b/mock-diff.txt" \
    0 ""

# ── Fixture C: allowlist suppresses FP → exit 0 ──────────────────────────────
printf '\nFixture C:\n'
run_fixture "C: allowlist suppresses FP" \
    "$SCRIPT_DIR/fixture-c/token-list.yaml" \
    "$SCRIPT_DIR/fixture-c/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-c/mock-diff.txt" \
    0 ""

# ── Fixture D: malformed token list → exit 2 ─────────────────────────────────
printf '\nFixture D:\n'
run_fixture "D: malformed token list" \
    "$SCRIPT_DIR/fixture-d/token-list.yaml" \
    "$SCRIPT_DIR/fixture-d/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-d/mock-diff.txt" \
    2 "setup-error"

# ── Fixture E: no env var and empty stdin → exit 2 ───────────────────────────
printf '\nFixture E:\n'
_tmpout_e=$(mktemp)
_rc_e=0
bash "$AUDIT_SCRIPT" < /dev/null > "$_tmpout_e" 2>&1 || _rc_e=$?
if [ "$_rc_e" -ne 2 ]; then
    _fail "E: no token list, empty stdin" "exit $_rc_e, expected 2"
elif ! grep -qE 'setup-error' "$_tmpout_e" 2>/dev/null; then
    _fail "E: no token list, empty stdin" "stdout missing setup-error diagnostic"
else
    _pass "E: no token list, empty stdin → exit 2"
fi
rm -f "$_tmpout_e"

# ── Fixture F: scope=commit-metadata, commit token → exit 1 ──────────────────
printf '\nFixture F:\n'
run_fixture "F: commit-metadata scope fires on commit" \
    "$SCRIPT_DIR/fixture-f/token-list.yaml" \
    "$SCRIPT_DIR/fixture-f/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-f/mock-diff.txt" \
    1 "REDACTED:rule=meta-only:stream=commit-metadata"

# ── Fixture G: scope=diff, diff token → exit 1 ───────────────────────────────
printf '\nFixture G:\n'
run_fixture "G: diff scope fires on diff" \
    "$SCRIPT_DIR/fixture-g/token-list.yaml" \
    "$SCRIPT_DIR/fixture-g/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-g/mock-diff.txt" \
    1 "REDACTED:rule=diff-only:stream=diff"

# ── Fixture H: scope=both, token in commit → exit 1 ──────────────────────────
printf '\nFixture H:\n'
run_fixture "H: both-scope fires on commit" \
    "$SCRIPT_DIR/fixture-h/token-list.yaml" \
    "$SCRIPT_DIR/fixture-h/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-h/mock-diff.txt" \
    1 "REDACTED:rule=both-test:stream=commit-metadata"

# Fixture H sub-run: token in diff also fires
_hd=$(mktemp); printf '+line with bothword here\n' > "$_hd"
_hc=$(mktemp); printf 'clean commit\n' > "$_hc"
run_fixture "H': both-scope fires on diff" \
    "$SCRIPT_DIR/fixture-h/token-list.yaml" \
    "$_hc" "$_hd" 1 "REDACTED:rule=both-test:stream=diff"
rm -f "$_hd" "$_hc"

# ── Fixture I: ^- line not scanned, ^+ line scanned ──────────────────────────
printf '\nFixture I:\n'
# Sub-run 1: token only in removed line → exit 0
run_fixture "I: token in removed (-) line → exit 0" \
    "$SCRIPT_DIR/fixture-i/token-list.yaml" \
    "$SCRIPT_DIR/fixture-i/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-i/mock-diff-removed.txt" \
    0 ""

# Sub-run 2: token only in added line → exit 1
run_fixture "I': token in added (+) line → exit 1" \
    "$SCRIPT_DIR/fixture-i/token-list.yaml" \
    "$SCRIPT_DIR/fixture-i/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-i/mock-diff-added.txt" \
    1 "REDACTED:rule=scan-test:stream=diff"

# ── Fixture J: merge-base computation via real git repo ───────────────────────
printf '\nFixture J:\n'
_jdir=$(mktemp -d)
_jrc=0
(
    cd "$_jdir"
    git init -q
    git config user.email "test@example.com"
    git config user.name "Test User"
    # Main branch: base commit
    printf 'base content\n' > file.txt
    git add file.txt
    git commit -q -m "Base commit"
    _base=$(git rev-parse HEAD)
    # Feature branch: add content that should be caught
    git checkout -q -b feature
    printf '+new-content-only\n' >> file.txt
    git add file.txt
    git commit -q -m "Feature commit adding new-content-only"
    _head=$(git rev-parse HEAD)
    # Set up origin ref for merge-base
    git checkout -q main 2>/dev/null || git checkout -q master 2>/dev/null || true
    _main_branch=$(git rev-parse --abbrev-ref HEAD)
    git checkout -q feature

    # Export remote ref manually (simulate origin/main)
    git update-ref "refs/remotes/origin/$_main_branch" "$_base"

    _tmpout_j=$(mktemp)
    _rc_j=0
    IDENTITY_AUDIT_TOKEN_LIST="$SCRIPT_DIR/fixture-j/token-list.yaml" \
        BASE_SHA=$(git merge-base "origin/$_main_branch" HEAD) \
        HEAD_SHA="$_head" \
        bash "$AUDIT_SCRIPT" > "$_tmpout_j" 2>&1 || _rc_j=$?

    if [ "$_rc_j" -ne 1 ]; then
        printf '  FAIL: J: merge-base test exit %s, expected 1\n' "$_rc_j"
        cat "$_tmpout_j"
        rm -f "$_tmpout_j"
        exit 1
    fi
    if ! grep -qE 'REDACTED:rule=merge-test:stream=diff' "$_tmpout_j" 2>/dev/null; then
        printf '  FAIL: J: merge-base test stdout missing expected REDACTED entry\n'
        cat "$_tmpout_j"
        rm -f "$_tmpout_j"
        exit 1
    fi
    printf '  PASS: J: merge-base recomputes correctly, PR-range content detected\n'
    rm -f "$_tmpout_j"
) || _jrc=$?
rm -rf "$_jdir"
if [ "$_jrc" -ne 0 ]; then
    FAIL=$((FAIL+1))
else
    PASS=$((PASS+1))
fi

# ── Fixture K: allowlist-overreach detection → exit 2 ────────────────────────
printf '\nFixture K:\n'
run_fixture "K: allowlist-overreach exits 2" \
    "$SCRIPT_DIR/fixture-k/token-list.yaml" \
    "/dev/null" "/dev/null" \
    2 "allowlist-overreach"

# ── Fixture L: 3 rules all match → all 3 in stdout ───────────────────────────
printf '\nFixture L:\n'
_ltmp=$(mktemp)
_lrc=0
IDENTITY_AUDIT_TOKEN_LIST="$SCRIPT_DIR/fixture-l/token-list.yaml" \
    IDENTITY_AUDIT_MOCK_COMMIT_LOG="$SCRIPT_DIR/fixture-l/mock-commit.txt" \
    IDENTITY_AUDIT_MOCK_DIFF="$SCRIPT_DIR/fixture-l/mock-diff.txt" \
    bash "$AUDIT_SCRIPT" > "$_ltmp" 2>&1 || _lrc=$?

if [ "$_lrc" -ne 1 ]; then
    _fail "L: 3 rules non-short-circuit" "exit $_lrc, expected 1"
else
    _l_count=0
    grep -cE 'REDACTED:rule=rule-l[123]' "$_ltmp" > /dev/null 2>&1 || true
    for _rid in rule-l1 rule-l2 rule-l3; do
        if grep -qE "REDACTED:rule=$_rid" "$_ltmp" 2>/dev/null; then
            _l_count=$((_l_count + 1))
        fi
    done
    if [ "$_l_count" -eq 3 ]; then
        _pass "L: all 3 rules reported (non-short-circuit)"
    else
        _fail "L: 3 rules non-short-circuit" "only $_l_count/3 rules in output"
    fi
fi
rm -f "$_ltmp"

# Fixture L': no matches at all
run_fixture "L': no matches → exit 0" \
    "$SCRIPT_DIR/fixture-l-prime/token-list.yaml" \
    "$SCRIPT_DIR/fixture-l-prime/mock-commit.txt" \
    "$SCRIPT_DIR/fixture-l-prime/mock-diff.txt" \
    0 ""

# ── Fixture M: token list tracked in git repo → exit 2 ───────────────────────
printf '\nFixture M:\n'
_mdir=$(mktemp -d)
_mrc=0
(
    cd "$_mdir"
    git init -q
    git config user.email "test@example.com"
    git config user.name "Test"
    mkdir -p security
    cp "$SCRIPT_DIR/fixture-m/token-list.yaml" security/identity-tokens.list
    git add security/identity-tokens.list
    git commit -q -m "Add token list"
    # Now run audit pointing at this tracked file
    _mtmp=$(mktemp)
    _mrc2=0
    IDENTITY_AUDIT_TOKEN_LIST="$_mdir/security/identity-tokens.list" \
        IDENTITY_AUDIT_MOCK_COMMIT_LOG=/dev/null \
        IDENTITY_AUDIT_MOCK_DIFF=/dev/null \
        bash "$AUDIT_SCRIPT" > "$_mtmp" 2>&1 || _mrc2=$?
    if [ "$_mrc2" -ne 2 ]; then
        printf '  FAIL: M: tracked token list exit %s, expected 2\n' "$_mrc2"
        cat "$_mtmp"; rm -f "$_mtmp"; exit 1
    fi
    if ! grep -qE 'token-list-tracked-in-public-repo' "$_mtmp" 2>/dev/null; then
        printf '  FAIL: M: missing token-list-tracked-in-public-repo diagnostic\n'
        cat "$_mtmp"; rm -f "$_mtmp"; exit 1
    fi
    printf '  PASS: M: token list tracked in repo → exit 2\n'
    rm -f "$_mtmp"
) || _mrc=$?
rm -rf "$_mdir"
[ "$_mrc" -ne 0 ] && FAIL=$((FAIL+1)) || PASS=$((PASS+1))

# ── Fixture N: idempotency — two runs produce identical output ────────────────
printf '\nFixture N:\n'
_nout1=$(mktemp); _nout2=$(mktemp)
_nrc1=0; _nrc2=0
IDENTITY_AUDIT_TOKEN_LIST="$SCRIPT_DIR/fixture-n/token-list.yaml" \
    IDENTITY_AUDIT_MOCK_COMMIT_LOG="$SCRIPT_DIR/fixture-n/mock-commit.txt" \
    IDENTITY_AUDIT_MOCK_DIFF="$SCRIPT_DIR/fixture-n/mock-diff.txt" \
    bash "$AUDIT_SCRIPT" > "$_nout1" 2>&1 || _nrc1=$?
IDENTITY_AUDIT_TOKEN_LIST="$SCRIPT_DIR/fixture-n/token-list.yaml" \
    IDENTITY_AUDIT_MOCK_COMMIT_LOG="$SCRIPT_DIR/fixture-n/mock-commit.txt" \
    IDENTITY_AUDIT_MOCK_DIFF="$SCRIPT_DIR/fixture-n/mock-diff.txt" \
    bash "$AUDIT_SCRIPT" > "$_nout2" 2>&1 || _nrc2=$?

if [ "$_nrc1" -ne 1 ] || [ "$_nrc2" -ne 1 ]; then
    _fail "N: idempotency" "unexpected exit codes: run1=$_nrc1 run2=$_nrc2"
elif ! diff -q "$_nout1" "$_nout2" >/dev/null 2>&1; then
    _fail "N: idempotency" "two runs produced different stdout"
else
    _pass "N: two runs identical output (idempotency)"
fi
rm -f "$_nout1" "$_nout2"

# ── Setup Fixture P: setup script idempotency (skip if script absent) ─────────
printf '\nSetup Fixture P:\n'
if [ -n "$SETUP_SCRIPT" ] && [ -x "$SETUP_SCRIPT" ]; then
    _pdir=$(mktemp -d)
    (
        cd "$_pdir"; git init -q
        # Use -c to inject author for the commit without setting local config
        # so setup-public-repo.sh sees an empty local user.name on first run
        printf 'content\n' > file.txt; git add file.txt
        git -c user.name="ankuper" -c user.email="test@example.com" commit -q -m "init"
        _pout1=$("$SETUP_SCRIPT" --repo-path "$_pdir" --persona-email "ankuper@example.com" 2>&1 || true)
        _pout2=$("$SETUP_SCRIPT" --repo-path "$_pdir" --persona-email "ankuper@example.com" 2>&1 || true)
        # Second run should report all steps as already-set (idempotent)
        if echo "$_pout2" | grep -qiE 'OK-ALREADY-SET|already.set|no.change|idempotent|already present'; then
            printf '  PASS: P: setup script idempotent on second run\n'
        else
            printf '  FAIL: P: setup script second run unexpected output: %s\n' "$_pout2"
            exit 1
        fi
    ) || { FAIL=$((FAIL+1)); rm -rf "$_pdir"; }
    [ -d "$_pdir" ] && { PASS=$((PASS+1)); rm -rf "$_pdir"; } || true
else
    _skip "P: setup script idempotency" "setup-public-repo.sh not found"
fi

# ── Setup Fixture Q: exits 3 on real-name git config ──────────────────────────
printf '\nSetup Fixture Q:\n'
if [ -n "$SETUP_SCRIPT" ] && [ -x "$SETUP_SCRIPT" ]; then
    _qdir=$(mktemp -d)
    (
        cd "$_qdir"; git init -q
        # Pre-set a real-name token in git config
        git config user.name "Real Name Token"
        git config user.email "realname@example.com"
        printf 'content\n' > file.txt; git add file.txt
        git -c user.name="Real Name Token" -c user.email="realname@example.com" commit -q -m "init"
        _qrc=0
        "$SETUP_SCRIPT" --repo-path "$_qdir" --persona-email "ankuper@example.com" > /dev/null 2>&1 || _qrc=$?
        if [ "$_qrc" -eq 3 ]; then
            printf '  PASS: Q: setup exits 3 with FIX_REQUIRED on existing real-name config\n'
        else
            printf '  FAIL: Q: expected exit 3, got %s\n' "$_qrc"
            exit 1
        fi
    ) || { FAIL=$((FAIL+1)); rm -rf "$_qdir"; }
    [ -d "$_qdir" ] && { PASS=$((PASS+1)); rm -rf "$_qdir"; } || true
else
    _skip "Q: setup FIX_REQUIRED exit 3" "setup-public-repo.sh not found"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n══════════════════════════════════════════\n'
printf 'Results: %s PASS  %s FAIL  %s SKIP\n' "$PASS" "$FAIL" "$SKIP"
printf '══════════════════════════════════════════\n'

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
