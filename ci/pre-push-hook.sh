#!/usr/bin/env bash
# pre-push-hook.sh — AR-G5 pre-push pre-flight audit.
#
# Source: Story 7-11 P34 (incident AR-G5-INC-2026-05-12-01). Installed into
# every public ankuper repo's .git/hooks/pre-push via setup-public-repo.sh
# so the AR-G5 firewall becomes fail-closed (refuse the push) rather than
# fail-fast-but-still-leaked (post-hoc workflow detection).
#
# Operator contract:
#   - The local identity-tokens.list lives in the private workspace (gitignored
#     across all repos) — operator must export IDENTITY_AUDIT_TOKEN_LIST in
#     their shell profile to point at that file.
#   - If the env var is unset, the hook walks a small list of well-known
#     locations as a fallback.
#   - If neither yields a readable token list, the hook FAILS CLOSED with
#     a clear diagnostic (rather than passing the push through).
#
# Git pre-push contract: stdin receives one line per ref being pushed:
#   <local_ref> <local_sha> <remote_ref> <remote_sha>
# A zero SHA on either side means "creating" or "deleting".
#
# Exit codes:
#   0 — all pushed ranges pass the audit
#   1 — at least one range failed the audit (push refused)
#   2 — setup error (token list missing, etc.) — push refused

set -euo pipefail

readonly ZERO_SHA="0000000000000000000000000000000000000000"

# Locate ci/identity-audit.sh relative to this hook file (the hook lives in
# .git/hooks/pre-push, so the repo root is two levels up).
_repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$_repo_root" ]; then
    printf 'AR-G5 pre-push: not a git repo — aborting push\n' >&2
    exit 2
fi
AUDIT_SCRIPT="${_repo_root}/ci/identity-audit.sh"
if [ ! -x "$AUDIT_SCRIPT" ]; then
    printf 'AR-G5 pre-push: %s not found or not executable — aborting push\n' \
        "$AUDIT_SCRIPT" >&2
    printf 'Reinstall via setup-public-repo.sh, then retry.\n' >&2
    exit 2
fi

# Find the operator's token list.
_token_list=""
for _candidate in \
    "${IDENTITY_AUDIT_TOKEN_LIST:-}" \
    "${HOME}/.config/ar-g5/identity-tokens.list" \
    "${HOME}/Documents/Workspace/MTProxy/_bmad-output/security/identity-tokens.list" \
    "/Volumes/dx/dev/_home/MTProxy/_bmad-output/security/identity-tokens.list"; do
    if [ -n "$_candidate" ] && [ -r "$_candidate" ]; then
        _token_list="$_candidate"
        break
    fi
done

if [ -z "$_token_list" ]; then
    printf 'AR-G5 pre-push: IDENTITY_AUDIT_TOKEN_LIST unset and no token list found at well-known paths\n' >&2
    printf 'Refusing to push without operator-identity firewall.\n' >&2
    printf 'Set in your shell profile: export IDENTITY_AUDIT_TOKEN_LIST=<abs path>\n' >&2
    exit 2
fi

_failed=0
while read -r local_ref local_sha remote_ref remote_sha; do
    # Skip ref deletions
    if [ "$local_sha" = "$ZERO_SHA" ]; then
        continue
    fi

    if [ "$remote_sha" = "$ZERO_SHA" ]; then
        # New branch — audit all commits reachable from local_sha that are not
        # already on any other remote ref. Use --not --remotes to scope.
        _range=$(git rev-list "$local_sha" --not --remotes 2>/dev/null | tail -n1)
        if [ -z "$_range" ]; then
            # Already fully pushed somewhere — nothing to audit
            continue
        fi
        BASE_SHA=$(git rev-parse "${_range}^" 2>/dev/null || git rev-parse "$_range")
    else
        BASE_SHA="$remote_sha"
    fi
    HEAD_SHA="$local_sha"

    if [ "$BASE_SHA" = "$HEAD_SHA" ]; then
        continue
    fi

    printf 'AR-G5 pre-push: auditing %s..%s on %s\n' \
        "${BASE_SHA:0:7}" "${HEAD_SHA:0:7}" "${local_ref}" >&2

    _rc=0
    IDENTITY_AUDIT_TOKEN_LIST="$_token_list" \
    BASE_SHA="$BASE_SHA" \
    HEAD_SHA="$HEAD_SHA" \
        bash "$AUDIT_SCRIPT" >&2 || _rc=$?

    if [ "$_rc" -eq 1 ]; then
        printf 'AR-G5 pre-push: MATCH on %s — push refused.\n' "$local_ref" >&2
        printf 'Rewrite history to remove the flagged content before retrying.\n' >&2
        _failed=1
    elif [ "$_rc" -eq 2 ]; then
        printf 'AR-G5 pre-push: SETUP ERROR auditing %s — push refused.\n' "$local_ref" >&2
        _failed=1
    fi
done

if [ "$_failed" -ne 0 ]; then
    exit 1
fi

exit 0
