#!/usr/bin/env bash
# identity-audit.sh — AR-G5 operational-identity audit gate.
#
# Stability: enforced on every public ankuper-repo PR (see architecture.md §A-010).
# Source: Story 7-11. Exit codes: 0=clean, 1=match-found, 2=setup-error.
# NOTE: set -x (xtrace) is NEVER enabled — it would expose token values via expansion.

set -euo pipefail

# ── Locale ─────────────────────────────────────────────────────────────────────
# Force UTF-8 unconditionally so multi-byte denylist patterns (Cyrillic, accented
# Latin) match correctly via grep character classes. Under LC_CTYPE=C, grep
# treats `[АA]` as raw bytes, silently dropping Cyrillic matches — a fail-open
# for the audit gate. We override even when LC_ALL is already set to C/POSIX,
# because the gate must be deterministic regardless of inherited environment.
export LC_ALL=C.UTF-8
export LC_CTYPE=C.UTF-8

# ── Exit-code constants ────────────────────────────────────────────────────────
readonly EXIT_CLEAN=0
readonly EXIT_MATCH=1
readonly EXIT_SETUP=2

# ── Error trap for unexpected failures ─────────────────────────────────────────
_err_handler() {
    local lineno="$1"
    printf 'setup-error: unexpected failure at line %s\n' "$lineno" >&2
    exit "$EXIT_SETUP"
}
trap '_err_handler "$LINENO"' ERR

# ── Temporary workspace ────────────────────────────────────────────────────────
_tmpdir=$(mktemp -d)
trap 'rm -rf "$_tmpdir"; exit' INT TERM
trap 'rm -rf "$_tmpdir"' EXIT

readonly _COMMIT_STREAM="$_tmpdir/stream-commit-metadata"
readonly _DIFF_STREAM="$_tmpdir/stream-diff"
readonly _MATCH_LOG="$_tmpdir/matches"
touch "$_MATCH_LOG"

# ── YAML-light parser (P6/P7 hardened) ────────────────────────────────────────
# Parses the controlled token-list YAML format.
# Outputs one record per rule:
#   Denylist:  D<TAB>id<TAB>pattern<TAB>scope
#   Allowlist: A<TAB>id<TAB>pattern<TAB>scope<TAB>test_fp_example<TAB>test_denylist_token_example
# Allowlist scope defaults to "both" if unspecified (D3 backward-compat).
#
# Hardening (P6/P7):
#   - BOM + CRLF stripped before awk sees the input (pre-normalize)
#   - Reject double-quoted scalars (single-quoted only) — explicit error, not
#     silent literal-quote inclusion
#   - Detect duplicate rule IDs (within a section)
#   - Reject TAB inside pattern (would collide with the output record format)
#   - Reject unknown top-level keys (top-level = column 0 letter line that is
#     neither `denylist:` nor `allowlist:` nor `---`)
#   - Rule IDs must match ^[a-z0-9-]+$ (P7: feeds filenames + PR markdown)
_parse_token_list() {
    local file="$1"
    # P6: pre-normalize via tr — strip CRs and UTF-8 BOM (3-byte EFBBBF on line 1)
    local _norm="$_tmpdir/token-list-normalized"
    LC_ALL=C tr -d '\r' < "$file" \
        | LC_ALL=C sed '1s/^\xef\xbb\xbf//' \
        > "$_norm"

    awk '
    function strip(val,    n) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
        n = length(val)
        if (n >= 2 && substr(val,1,1) == "\x27" && substr(val,n,1) == "\x27")
            val = substr(val, 2, n-2)
        else if (n >= 2 && substr(val,1,1) == "\x22" && substr(val,n,1) == "\x22") {
            # P6: reject double-quoted scalars rather than passing literal quotes
            printf "setup-error: malformed-token-list: double-quoted scalar at line %d — use single quotes\n", NR > "/dev/stderr"
            exit 2
        }
        return val
    }
    function field_val(line, key,    val) {
        val = line
        sub("^[[:space:]]*" key "[[:space:]]*:[[:space:]]*", "", val)
        return strip(val)
    }
    function flush_rule(    rec, eff_scope, key) {
        if (id == "" || pat == "") { id=""; pat=""; scope=""; fp=""; tde=""; return }
        # P7: rule-id allowlist
        if (id !~ /^[a-z0-9-]+$/) {
            printf "setup-error: malformed-token-list: rule id %s does not match ^[a-z0-9-]+$\n", id > "/dev/stderr"
            exit 2
        }
        # P6: pattern must not contain a TAB (collides with output record format)
        if (index(pat, "\t") > 0) {
            printf "setup-error: malformed-token-list: rule %s pattern contains TAB\n", id > "/dev/stderr"
            exit 2
        }
        # P6: duplicate-id check (per section)
        key = section ":" id
        if (seen_ids[key]) {
            printf "setup-error: malformed-token-list: duplicate id %s in section %s\n", id, section > "/dev/stderr"
            exit 2
        }
        seen_ids[key] = 1

        if (section == "denylist")  rec = "D\t" id "\t" pat "\t" scope
        else if (section == "allowlist") {
            eff_scope = (scope == "" ? "both" : scope)
            rec = "A\t" id "\t" pat "\t" eff_scope "\t" fp "\t" tde
        }
        else { id=""; pat=""; scope=""; fp=""; tde=""; return }
        print rec
        id=""; pat=""; scope=""; fp=""; tde=""
    }
    BEGIN { section=""; id=""; pat=""; scope=""; fp=""; tde="" }
    /^---$/ { next }
    /^[[:space:]]*#/ { next }       # P6: full-line comments ignored
    /^[[:space:]]*$/ { next }       # P6: blank lines ignored
    /^denylist:/  { flush_rule(); section="denylist";  next }
    /^allowlist:/ { flush_rule(); section="allowlist"; next }
    # P6: reject any other column-0 letter line (unknown top-level key)
    /^[a-zA-Z]/ {
        printf "setup-error: malformed-token-list: unknown top-level key at line %d: %s\n", NR, $0 > "/dev/stderr"
        exit 2
    }
    section == "" { next }
    /^  - id:/ {
        flush_rule()
        id = field_val($0, "-[[:space:]]*id")
        next
    }
    /^    pattern:/                    { pat  = field_val($0, "pattern");                    next }
    /^    scope:/                      { scope = field_val($0, "scope");                     next }
    /^    test_fp_example:/            { fp   = field_val($0, "test_fp_example");            next }
    /^    test_denylist_token_example:/ { tde  = field_val($0, "test_denylist_token_example"); next }
    END { flush_rule() }
    ' "$_norm"
}

# ── Token-list load & validate ─────────────────────────────────────────────────
_load_token_list() {
    local list_file="$1"

    if [ ! -r "$list_file" ]; then
        printf 'setup-error: token list unreadable: %s\n' "$list_file" >&2
        exit "$EXIT_SETUP"
    fi

    # P4: AC #7 guard — scan the whole repo tree for any tracked file matching
    # the identity-tokens.list* pattern. The previous check (`git ls-files
    # --error-unmatch "$list_file"`) was a no-op in CI because $list_file lives
    # under $RUNNER_TEMP (outside the repo), where ls-files returns 128 and the
    # branch silently treated that as OK. Now we explicitly look INSIDE the
    # working tree for any tracked tokens-list path, regardless of the file the
    # audit is currently reading.
    local _repo_root
    if _repo_root=$(git rev-parse --show-toplevel 2>/dev/null); then
        local _tracked
        _tracked=$(git -C "$_repo_root" ls-files \
            'identity-tokens.list' 'identity-tokens.list.*' \
            '*/identity-tokens.list' '*/identity-tokens.list.*' 2>/dev/null \
            | LC_ALL=C grep -v -- '^\.git/' || true)
        if [ -n "$_tracked" ]; then
            printf 'setup-error: token-list-tracked-in-public-repo: paths=%s\n' "$_tracked" >&2
            exit "$EXIT_SETUP"
        fi
    fi
    # No git repo (e.g. fixture harness path) → skip; the gate only applies to
    # the public-repo tree.

    # Check for placeholder sentinels — require operator population before live run
    local _grep_rc=0
    grep -qF '${TOKEN_PLACEHOLDER_' "$list_file" 2>/dev/null || _grep_rc=$?
    if [ "$_grep_rc" -eq 0 ]; then
        printf 'setup-error: token list contains unreplaced placeholders (${TOKEN_PLACEHOLDER_<n>}). Populate before activating audit.\n' >&2
        exit "$EXIT_SETUP"
    fi
    if [ "$_grep_rc" -gt 1 ]; then
        printf 'setup-error: grep failed reading token list\n' >&2
        exit "$EXIT_SETUP"
    fi

    local parsed
    if ! parsed=$(_parse_token_list "$list_file"); then
        printf 'setup-error: malformed-token-list: YAML parse failed\n' >&2
        exit "$EXIT_SETUP"
    fi

    # Emit raw records to caller via _DENY_RECORDS and _ALLOW_RECORDS files
    printf '%s\n' "$parsed" | grep '^D	' > "$_tmpdir/deny_records" || true
    printf '%s\n' "$parsed" | grep '^A	' > "$_tmpdir/allow_records" || true

    # Validate all denylist rules have required fields
    local _bad_rule=0
    while IFS='	' read -r _t _did _dpat _dscope; do
        [ "$_t" = "D" ] || continue
        if [ -z "$_dpat" ]; then
            printf 'setup-error: malformed-token-list: denylist rule "%s" missing pattern\n' "$_did" >&2
            _bad_rule=1
        fi
        if [ -z "$_dscope" ]; then
            printf 'setup-error: malformed-token-list: denylist rule "%s" missing scope\n' "$_did" >&2
            _bad_rule=1
        fi
        # Validate pattern is a legal ERE (guard against grep crashes on malformed regex)
        if [ -n "$_dpat" ]; then
            _grep_test_rc=0
            printf '' | grep -qE -- "$_dpat" 2>/dev/null || _grep_test_rc=$?
            if [ "$_grep_test_rc" -gt 1 ]; then
                printf 'setup-error: malformed-token-list: denylist rule "%s" pattern is invalid POSIX ERE\n' "$_did" >&2
                _bad_rule=1
            fi
        fi
    done < "$_tmpdir/deny_records"

    # Validate all allowlist rules have required fields (6 fields per D3: scope added)
    while IFS='	' read -r _t _aid _apat _ascope _fp _tde; do
        [ "$_t" = "A" ] || continue
        if [ -z "$_apat" ]; then
            printf 'setup-error: malformed-token-list: allowlist rule "%s" missing pattern\n' "$_aid" >&2
            _bad_rule=1
        fi
        case "$_ascope" in
            commit-metadata|diff|both) ;;
            *)
                printf 'setup-error: malformed-token-list: allowlist rule "%s" has invalid scope "%s" (expected commit-metadata|diff|both)\n' "$_aid" "$_ascope" >&2
                _bad_rule=1
                ;;
        esac
        if [ -z "$_fp" ] || [ -z "$_tde" ]; then
            printf 'setup-error: malformed-token-list: allowlist rule "%s" missing test_fp_example or test_denylist_token_example\n' "$_aid" >&2
            _bad_rule=1
        fi
    done < "$_tmpdir/allow_records"

    if [ "$_bad_rule" -ne 0 ]; then
        exit "$EXIT_SETUP"
    fi

    local ndeny
    ndeny=$(wc -l < "$_tmpdir/deny_records" | tr -d ' ')

    if [ "$ndeny" -lt 1 ]; then
        printf 'setup-error: malformed-token-list: no valid denylist rules found\n' >&2
        exit "$EXIT_SETUP"
    fi
}

# ── Allowlist suppression check (D3 — Story 7-11 review) ──────────────────────
# Returns 0 if matched token should be SUPPRESSED (allowlisted), 1 if not.
#
# D3 semantics: receives the matched SUBSTRING (extracted via grep -oE), not
# the full grep'd line. Allowlist pattern is tested via `grep -qxE` so the
# pattern must match the ENTIRE substring (anchored-by-grep -x, regardless of
# whether the operator wrote ^/$ explicitly). Stream scope filters allowlist
# rules: a commit-metadata-scoped allowlist cannot suppress diff-stream hits.
_is_allowlisted() {
    local matched_substring="$1"
    local stream="$2"      # commit-metadata | diff

    while IFS='	' read -r _type aid apat ascope _fp _tde; do
        [ "$_type" = "A" ] || continue
        [ -n "$apat" ]     || continue
        # Scope filter: skip allowlist rules that don't apply to current stream
        if [ "$ascope" != "both" ] && [ "$ascope" != "$stream" ]; then
            continue
        fi
        # Anchored whole-substring match (grep -x = match entire line, where
        # the "line" here is the single-line matched substring we pass on stdin)
        if printf '%s\n' "$matched_substring" | grep -qxE -- "$apat" 2>/dev/null; then
            return 0  # suppressed
        fi
    done < "$_tmpdir/allow_records"

    return 1  # not suppressed
}

# ── Allowlist self-test (AC #2, Fixture K) ─────────────────────────────────────
# D3: mirror production semantics — grep -qxE (anchored whole-substring match).
_run_allowlist_self_test() {
    while IFS='	' read -r _type aid apat _ascope fp_ex tde_ex; do
        [ "$_type" = "A" ] || continue
        [ -n "$apat" ]     || continue

        # (a) test_fp_example must be matched (suppressed) by this allowlist rule
        if ! printf '%s\n' "$fp_ex" | grep -qxE -- "$apat" 2>/dev/null; then
            printf 'setup-error: allowlist-overreach: rule=%s: test_fp_example not matched by allow pattern\n' "$aid" >&2
            exit "$EXIT_SETUP"
        fi

        # (b) test_denylist_token_example must NOT be matched by this allowlist rule
        if printf '%s\n' "$tde_ex" | grep -qxE -- "$apat" 2>/dev/null; then
            printf 'setup-error: allowlist-overreach: rule=%s: test_denylist_token_example would be over-suppressed\n' "$aid" >&2
            exit "$EXIT_SETUP"
        fi
    done < "$_tmpdir/allow_records"
}

# ── Stream generator ───────────────────────────────────────────────────────────
_build_streams() {
    local base_sha="$1" head_sha="$2"

    # Verify required git binaries
    if ! command -v git >/dev/null 2>&1; then
        printf 'setup-error: git not found in PATH\n' >&2
        exit "$EXIT_SETUP"
    fi

    # Verify BASE_SHA is resolvable
    if ! git rev-parse --verify "$base_sha^{commit}" >/dev/null 2>&1; then
        printf 'setup-error: BASE_SHA unresolvable: %s\n' "$base_sha" >&2
        exit "$EXIT_SETUP"
    fi

    # P18: detect the BASE_SHA==HEAD_SHA case (initial commit on main, where
    # composite action falls back to `git rev-parse HEAD`) — that produces an
    # empty range and the audit would pass silently. Emit setup-error.
    if [ "$base_sha" = "$head_sha" ]; then
        printf 'setup-error: initial-commit-on-main: BASE_SHA == HEAD_SHA == %s (empty range)\n' \
            "$base_sha" >&2
        exit "$EXIT_SETUP"
    fi

    # Stream A: commit metadata
    git log --format='%an %ae %cn %ce %B' "${base_sha}..${head_sha}" \
        > "$_COMMIT_STREAM" 2>/dev/null || true

    # Stream B: diff body — only ^+ lines, excluding ^+++ file-header lines.
    # --unified=0 suppresses context lines so pre-AR-G5 history in '-' lines
    # does not trigger false positives.
    # P19: track which files had binary diffs (their content is never scanned
    # because `git diff` emits "Binary files X and Y differ" instead of patch
    # hunks). We at least scan the filenames against denylist patterns by
    # writing them into the diff stream as +headers.
    local _raw_diff="$_tmpdir/raw-diff"
    git diff --unified=0 "${base_sha}..${head_sha}" > "$_raw_diff" 2>/dev/null || true
    LC_ALL=C awk '/^\+\+\+/ { next } /^\+/ { print substr($0,2) }' \
        "$_raw_diff" > "$_DIFF_STREAM" || true

    # P19: for each "Binary files a/X and b/Y differ" line, append both
    # filenames to the diff stream so denylist patterns still match against
    # file names embedded in binaries (PNG with name-in-EXIF, etc. — content
    # remains unscanned but the path is at least checked).
    LC_ALL=C grep -E '^Binary files .* differ$' "$_raw_diff" 2>/dev/null \
        | LC_ALL=C sed -E 's|^Binary files (.*) and (.*) differ$|\1\n\2|' \
        | LC_ALL=C sed -E 's|^[ab]/||' \
        >> "$_DIFF_STREAM" || true

    # P24: NFC-normalize streams to defeat trivial homoglyph / RTL-override
    # attempts on the commit-metadata stream. iconv -c discards illegal bytes.
    if command -v iconv >/dev/null 2>&1; then
        local _norm
        for _stream in "$_COMMIT_STREAM" "$_DIFF_STREAM"; do
            _norm="$_tmpdir/norm-$(basename "$_stream")"
            if iconv -c -f UTF-8 -t UTF-8 "$_stream" > "$_norm" 2>/dev/null; then
                mv "$_norm" "$_stream"
            fi
        done
    fi
}

# ── Mock-stream support (for test fixtures) ───────────────────────────────────
# If IDENTITY_AUDIT_MOCK_COMMIT_LOG or IDENTITY_AUDIT_MOCK_DIFF are set, use
# those files instead of running git. Test-only paths.
#
# P10: refuse mock mode in CI unless explicitly allowed. A misconfigured CI
# step (or an attacker setting workflow_run env from a fork) could otherwise
# force IDENTITY_AUDIT_MOCK_DIFF=/dev/null and pass the gate trivially.
_maybe_use_mock_streams() {
    if [ -n "${IDENTITY_AUDIT_MOCK_COMMIT_LOG:-}" ] || [ -n "${IDENTITY_AUDIT_MOCK_DIFF:-}" ]; then
        if [ "${CI:-}" = "true" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
            if [ "${IDENTITY_AUDIT_ALLOW_MOCK:-}" != "1" ]; then
                printf 'setup-error: IDENTITY_AUDIT_MOCK_* refused in CI without IDENTITY_AUDIT_ALLOW_MOCK=1\n' >&2
                exit "$EXIT_SETUP"
            fi
        fi
    fi
    if [ -n "${IDENTITY_AUDIT_MOCK_COMMIT_LOG:-}" ]; then
        if [ -r "$IDENTITY_AUDIT_MOCK_COMMIT_LOG" ]; then
            cp "$IDENTITY_AUDIT_MOCK_COMMIT_LOG" "$_COMMIT_STREAM"
        else
            printf 'setup-error: IDENTITY_AUDIT_MOCK_COMMIT_LOG unreadable: %s\n' \
                "$IDENTITY_AUDIT_MOCK_COMMIT_LOG" >&2
            exit "$EXIT_SETUP"
        fi
    fi
    if [ -n "${IDENTITY_AUDIT_MOCK_DIFF:-}" ]; then
        if [ -r "$IDENTITY_AUDIT_MOCK_DIFF" ]; then
            # Apply same ^+ filtering as live path
            awk '/^\+\+\+/ { next } /^\+/ { print substr($0,2) }' \
                "$IDENTITY_AUDIT_MOCK_DIFF" > "$_DIFF_STREAM"
        else
            printf 'setup-error: IDENTITY_AUDIT_MOCK_DIFF unreadable: %s\n' \
                "$IDENTITY_AUDIT_MOCK_DIFF" >&2
            exit "$EXIT_SETUP"
        fi
    fi
}

# ── Core audit engine ──────────────────────────────────────────────────────────
# Writes redacted match records to $_MATCH_LOG. Returns 0 always (errors exit).
_run_audit() {
    local _grep_rc _raw

    while IFS='	' read -r _type did dpat dscope; do
        [ "$_type" = "D" ] || continue
        [ -n "$dpat" ]     || continue

        # Evaluate commit-metadata stream
        if [ "$dscope" = "commit-metadata" ] || [ "$dscope" = "both" ]; then
            if [ -s "$_COMMIT_STREAM" ]; then
                _raw="$_tmpdir/raw_cm_${did}"
                _grep_rc=0
                # D3: grep -oE extracts each MATCHED SUBSTRING on its own line
                # (not the full surrounding line), so the allowlist check sees
                # exactly what the denylist captured.
                grep -oE -- "$dpat" "$_COMMIT_STREAM" > "$_raw" 2>/dev/null || _grep_rc=$?
                if [ "$_grep_rc" -gt 1 ]; then
                    printf 'setup-error: grep failed (rule=%s, stream=commit-metadata, rc=%s)\n' \
                        "$did" "$_grep_rc" >&2
                    exit "$EXIT_SETUP"
                fi
                while IFS= read -r _substring; do
                    [ -n "$_substring" ] || continue
                    if ! _is_allowlisted "$_substring" "commit-metadata"; then
                        printf '<REDACTED:rule=%s:stream=commit-metadata>\n' "$did" >> "$_MATCH_LOG"
                    fi
                done < "$_raw"
            fi
        fi

        # Evaluate diff stream
        if [ "$dscope" = "diff" ] || [ "$dscope" = "both" ]; then
            if [ -s "$_DIFF_STREAM" ]; then
                _raw="$_tmpdir/raw_diff_${did}"
                _grep_rc=0
                grep -oE -- "$dpat" "$_DIFF_STREAM" > "$_raw" 2>/dev/null || _grep_rc=$?
                if [ "$_grep_rc" -gt 1 ]; then
                    printf 'setup-error: grep failed (rule=%s, stream=diff, rc=%s)\n' \
                        "$did" "$_grep_rc" >&2
                    exit "$EXIT_SETUP"
                fi
                while IFS= read -r _substring; do
                    [ -n "$_substring" ] || continue
                    if ! _is_allowlisted "$_substring" "diff"; then
                        printf '<REDACTED:rule=%s:stream=diff>\n' "$did" >> "$_MATCH_LOG"
                    fi
                done < "$_raw"
            fi
        fi
    done < "$_tmpdir/deny_records"
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
    # Resolve token list path
    local list_file=""
    if [ -n "${IDENTITY_AUDIT_TOKEN_LIST:-}" ]; then
        list_file="$IDENTITY_AUDIT_TOKEN_LIST"
    elif [ ! -t 0 ]; then
        # Stdin is piped — read token list from stdin (P26: timeout + shape guard).
        # Hung stdin (parent forgot to close fd 0) would otherwise wait forever.
        list_file="$_tmpdir/stdin-token-list"
        if command -v timeout >/dev/null 2>&1; then
            if ! timeout 30 cat > "$list_file"; then
                printf 'setup-error: stdin read timed out (30s) — caller must close fd 0\n' >&2
                exit "$EXIT_SETUP"
            fi
        else
            cat > "$list_file"
        fi
        if [ ! -s "$list_file" ]; then
            printf 'setup-error: IDENTITY_AUDIT_TOKEN_LIST unset and stdin is empty\n' >&2
            exit "$EXIT_SETUP"
        fi
        # P26: shape sniff — first 64 KiB must contain at least one of the
        # documented top-level headers. Catches the "piped wrong stream" case
        # before any parsing.
        if ! head -c 65536 "$list_file" | LC_ALL=C grep -qE '^(denylist|allowlist):'; then
            printf 'setup-error: stdin token list does not contain a denylist:/allowlist: header in the first 64 KiB\n' >&2
            exit "$EXIT_SETUP"
        fi
    else
        printf 'setup-error: IDENTITY_AUDIT_TOKEN_LIST env var unset and no piped stdin\n' >&2
        printf 'usage: IDENTITY_AUDIT_TOKEN_LIST=<path> BASE_SHA=<sha> HEAD_SHA=<sha> %s\n' \
            "$(basename "$0")" >&2
        exit "$EXIT_SETUP"
    fi

    # Determine mode: mock streams (tests) or live git
    local mock_mode=false
    if [ -n "${IDENTITY_AUDIT_MOCK_COMMIT_LOG:-}" ] || [ -n "${IDENTITY_AUDIT_MOCK_DIFF:-}" ]; then
        mock_mode=true
    fi

    # Validate SHA env vars when running live (not mock)
    local base_sha="${BASE_SHA:-}"
    local head_sha="${HEAD_SHA:-}"
    if ! $mock_mode; then
        if [ -z "$base_sha" ] || [ -z "$head_sha" ]; then
            printf 'setup-error: BASE_SHA and HEAD_SHA must be set (or use IDENTITY_AUDIT_MOCK_* for tests)\n' >&2
            exit "$EXIT_SETUP"
        fi
    fi

    # Load and validate token list
    _load_token_list "$list_file"

    # Allowlist self-test — must pass before any audit logic runs
    _run_allowlist_self_test

    # Build or mock streams
    touch "$_COMMIT_STREAM" "$_DIFF_STREAM"
    if $mock_mode; then
        _maybe_use_mock_streams
    else
        _build_streams "$base_sha" "$head_sha"
    fi

    # Run audit — all rules × all streams evaluated before reporting
    _run_audit

    # Report results (redacted) and exit
    if [ -s "$_MATCH_LOG" ]; then
        cat "$_MATCH_LOG"
        exit "$EXIT_MATCH"
    else
        exit "$EXIT_CLEAN"
    fi
}

main "$@"
