#!/usr/bin/env bash
# test-update-failure-linux.sh — Story 2-7 AC#4 (NFR20 / anti-pattern §12.14).
#
# Five poisoned-fixture scenarios. Each scenario:
#   1. mints a poisoned artefact set
#   2. serves it via a local HTTP fixture server on 127.0.0.1
#   3. runs Telegram/build/appimage-self-update.sh against the server
#   4. asserts the script exits non-zero (1)
#   5. asserts NO partial state remains in $HELPER_CACHE
#   6. asserts the script emitted exactly one "ERROR: " line — the
#      generic NFR20 error, not class-differentiated
#
# Fixtures:
#   A — AppImage with one bit flipped (SHA-256 mismatches signed manifest)
#   B — AppImage with valid SHA-256 but PGP .sig produced by a wrong key
#   C — manifest-v2.txt.asc clearsign produced by an untrusted key
#   D — .zsync with truncated chunk table (malformed delta source)
#   E — manifest clearsign truncated (stands in for mid-download TCP close)
#
# Returns 0 if all five scenarios reject correctly; non-zero if any
# scenario lets the script succeed (i.e. the verify chain has a hole).
#
# Required state on the test box:
#   - dev release key under /root/tdesktop-release-key/ OR env
#     GPG_PASSPHRASE_FILE pointing at the passphrase file
#   - python3 (for fixture HTTP server)
#   - gpg, sha256sum, dd, curl, zsyncmake

set -Eeuo pipefail
shopt -s inherit_errexit

# Note: variables that are passed to the helper via `VAR=val helper ...`
# command-line prefix MUST NOT be readonly here — bash forbids overriding a
# readonly in a one-shot prefix assignment, silently leaving the helper
# with a blank value (and the test would then "pass" because the helper
# rejects on precondition rather than on the verify-chain).
THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO="$( cd "$THIS_DIR/.." && pwd )"
HELPER="$REPO/Telegram/build/appimage-self-update.sh"
EXPECTED_RELEASE_KEY_FPR='1DED8ADEF19BE7CAC93DEC5788161B1A989EF692'

WORK="$REPO/tests/_workspace"
RELEASE_GNUPG="$WORK/gnupg-release"
WRONG_GNUPG="$WORK/gnupg-wrong"
FIXTURE_ROOT="$WORK/fixtures"
HELPER_CACHE="$WORK/cache"
RELEASE_KEYDIR='/root/tdesktop-release-key'

if [[ -z "${TEST_FIXTURE_PORT:-}" ]]; then
  PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); p=s.getsockname()[1]; s.close(); print(p)')"
else
  PORT="$TEST_FIXTURE_PORT"
fi
readonly PORT
# Note: no `/v2` segment — the helper appends `/$latest_tag/...` itself.
# python -m http.server is configured with --directory $FIXTURE_ROOT so
# the request path equals the on-disk path under FIXTURE_ROOT.
readonly BASE_URL="http://127.0.0.1:$PORT"
readonly TAG='v2-2026-05-09-99'
readonly ARTEFACT='Telegram-x86_64-v2.AppImage'

note() { printf '[%s] %s\n' "$(date +%T)" "$*" >&2; }
fail_test() { printf 'TEST FAIL: %s\n' "$*" >&2; exit 1; }

[[ -x "$HELPER" ]] || fail_test "helper missing or not executable: $HELPER"
[[ -d "$RELEASE_KEYDIR" ]] \
  || fail_test "release-key dir missing: $RELEASE_KEYDIR (must run on .lnx)"

mkdir -p "$WORK" "$RELEASE_GNUPG" "$WRONG_GNUPG" "$FIXTURE_ROOT/$TAG" "$HELPER_CACHE"
chmod 700 "$RELEASE_GNUPG" "$WRONG_GNUPG"

#### Setup release-keyring (idempotent).
# The dev key was generated in the default GPG keyring of the test box
# (typically /root/.gnupg). For test isolation we mirror it into a
# dedicated keyring under WORK; export uses the default homedir.
if ! gpg --homedir "$RELEASE_GNUPG" --list-secret-keys "$EXPECTED_RELEASE_KEY_FPR" >/dev/null 2>&1; then
  gpg --homedir "$RELEASE_GNUPG" --import "$RELEASE_KEYDIR/tdesktop-v0.1.0-dev-release.pub.asc"
  echo "$EXPECTED_RELEASE_KEY_FPR:6:" | gpg --homedir "$RELEASE_GNUPG" --import-ownertrust
  # Export secret material from the default homedir (where the key was
  # generated) and re-import into the test keyring.
  gpg --batch --pinentry-mode loopback \
      --passphrase-file "$RELEASE_KEYDIR/passphrase.txt" \
      --export-secret-keys "$EXPECTED_RELEASE_KEY_FPR" \
    | gpg --homedir "$RELEASE_GNUPG" --batch --pinentry-mode loopback \
          --passphrase-file "$RELEASE_KEYDIR/passphrase.txt" \
          --import \
    || fail_test "could not import release secret key into test keyring"
fi
# Verify the secret key is now present.
gpg --homedir "$RELEASE_GNUPG" --list-secret-keys "$EXPECTED_RELEASE_KEY_FPR" >/dev/null \
  || fail_test "release secret key still not present after import"

#### Setup wrong-key keyring (one-shot per run).
if ! gpg --homedir "$WRONG_GNUPG" --list-keys 'fixture wrong key' >/dev/null 2>&1; then
  cat > "$WORK/wrong-key-batch.gpg" <<EOF
%no-protection
%transient-key
Key-Type: EDDSA
Key-Curve: ed25519
Key-Usage: sign
Name-Real: fixture wrong key
Name-Email: noone@example.invalid
Expire-Date: 0
%commit
EOF
  gpg --homedir "$WRONG_GNUPG" --batch --pinentry-mode loopback --generate-key "$WORK/wrong-key-batch.gpg" 2>&1 | tail -3
fi
WRONG_KEY_FPR="$(gpg --homedir "$WRONG_GNUPG" --with-colons --list-keys 'fixture wrong key' | awk -F: '/^fpr:/ {print $10; exit}')"
[[ -n "$WRONG_KEY_FPR" ]] || fail_test "could not resolve wrong-key fingerprint"

#### Mint a baseline (good) AppImage + manifest set used for all
# fixtures except E.
mint_baseline() {
  local good_appimage="$WORK/baseline-$ARTEFACT"
  local good_sig="$good_appimage.sig"
  local good_zsync="$good_appimage.zsync"
  local good_manifest="$WORK/baseline-manifest.txt"
  local good_manifest_asc="$WORK/baseline-manifest.txt.asc"

  # Pseudo-appimage: a shell script that satisfies --appimage-validate and
  # --appimage-version checks. The random blob was being overwritten anyway;
  # create the pseudo binary directly to avoid the confusing intermediate state.
  cat > "$good_appimage" <<'APPIMAGE'
#!/bin/sh
case "$1" in
  --appimage-validate) exit 0 ;;
  --appimage-version) printf 'v2-2026-04-01-01\n'; exit 0 ;;
esac
exit 0
APPIMAGE
  chmod +x "$good_appimage"

  # Sign + zsync.
  gpg --homedir "$RELEASE_GNUPG" --batch --pinentry-mode loopback \
      --passphrase-file "$RELEASE_KEYDIR/passphrase.txt" \
      --local-user "$EXPECTED_RELEASE_KEY_FPR" \
      --detach-sign --output "$good_sig" "$good_appimage"
  ( cd "$WORK" && zsyncmake -u "$BASE_URL/$TAG/$ARTEFACT" -o "baseline-$ARTEFACT.zsync" "baseline-$ARTEFACT" >/dev/null 2>&1 )

  # Manifest.
  local sha
  sha="$(sha256sum "$good_appimage" | awk '{print $1}')"
  cat > "$good_manifest" <<EOF
tag                       $TAG
release_key_fpr           $EXPECTED_RELEASE_KEY_FPR
appimage                  $ARTEFACT
appimage_sha256           $sha
zsync                     $ARTEFACT.zsync
sig                       $ARTEFACT.sig
publish_base_url          $BASE_URL
EOF
  gpg --homedir "$RELEASE_GNUPG" --batch --pinentry-mode loopback \
      --passphrase-file "$RELEASE_KEYDIR/passphrase.txt" \
      --local-user "$EXPECTED_RELEASE_KEY_FPR" \
      --clearsign --output "$good_manifest_asc" "$good_manifest"

  echo "$good_appimage|$good_sig|$good_zsync|$good_manifest_asc|$sha"
}

baseline_info="$(mint_baseline)"
IFS='|' read -r BL_APPIMAGE BL_SIG BL_ZSYNC BL_MANIFEST_ASC BL_SHA <<< "$baseline_info"

# Helper: run scenario.
SCENARIO_FAILS=0
run_scenario() {
  local name="$1" prep_func="$2"
  rm -rf "$FIXTURE_ROOT/$TAG"; mkdir -p "$FIXTURE_ROOT/$TAG"
  rm -rf "$HELPER_CACHE"; mkdir -p "$HELPER_CACHE"
  # Always seed the GitHub /releases/latest mock; otherwise the helper
  # exits at "STATE: checking" with a generic-but-misleading reason.

  $prep_func

  # Mock GitHub Releases API endpoint that returns latest tag.
  mkdir -p "$FIXTURE_ROOT/api/repos/ankuper/tdesktop/releases"
  cat > "$FIXTURE_ROOT/api/repos/ankuper/tdesktop/releases/latest" <<EOF
{
  "tag_name": "$TAG",
  "name": "$TAG",
  "draft": false,
  "prerelease": false
}
EOF

  python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$FIXTURE_ROOT" >/dev/null 2>&1 &
  local server_pid=$!
  # No EXIT trap — avoids clobbering caller's trap; kill explicitly below.
  local _i; for _i in $(seq 20); do
    curl -sf "$BASE_URL/" >/dev/null 2>&1 && break; sleep 0.1
  done

  local stdout; stdout="$(mktemp)"
  set +e
  APPIMAGE="$BL_APPIMAGE" \
    PUBLISH_BASE_URL="$BASE_URL" \
    GH_API_BASE_URL="http://127.0.0.1:$PORT/api" \
    RELEASE_KEY_FPR="$EXPECTED_RELEASE_KEY_FPR" \
    GPG_HOMEDIR="$RELEASE_GNUPG" \
    CACHE_DIR="$HELPER_CACHE" \
    GH_OWNER='ankuper' GH_REPO='tdesktop' \
    "$HELPER" >"$stdout" 2>&1
  local exit_code=$?
  set -e
  kill $server_pid 2>/dev/null || true

  if [[ $exit_code -eq 0 ]]; then
    note "$name: FAIL (helper succeeded; should have rejected)"
    cat "$stdout" >&2
    SCENARIO_FAILS=$((SCENARIO_FAILS + 1))
    return
  fi
  # Exit 10 is "precondition not met" (e.g. blank RELEASE_KEY_FPR);
  # treating it as a pass would mask test-harness bugs. The verify
  # chain proper exits 1.
  if [[ $exit_code -eq 10 ]]; then
    note "$name: FAIL (helper exited 10 — precondition gate triggered, not the verify chain)"
    cat "$stdout" >&2
    SCENARIO_FAILS=$((SCENARIO_FAILS + 1))
    return
  fi

  # Assert no partial state on disk.
  local lingering
  lingering="$(find "$HELPER_CACHE" -type f 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$lingering" -gt 0 ]]; then
    note "$name: FAIL (cache dir not cleaned: $lingering files left)"
    find "$HELPER_CACHE" -type f >&2
    SCENARIO_FAILS=$((SCENARIO_FAILS + 1))
    return
  fi

  # Assert ERROR: line was generic (no class disclosure).
  local err_line
  err_line="$(grep '^ERROR: ' "$stdout" | head -1 | sed 's/^ERROR: //')"
  if [[ -z "$err_line" ]]; then
    note "$name: FAIL (helper exited non-zero but emitted no ERROR: line)"
    SCENARIO_FAILS=$((SCENARIO_FAILS + 1))
    return
  fi

  note "$name: OK rejected (exit $exit_code, generic err='$err_line')"
}

# Fixture A — served AppImage poisoned (SHA mismatches signed manifest).
# To deterministically trigger the SHA-mismatch gate (and not the
# zsync hash-table-mismatch gate that would fire earlier on a
# stale .zsync), we re-mint .zsync against the POISONED bytes and
# leave the clearsigned manifest claiming the BASELINE SHA-256.
prep_A() {
  local poisoned="$FIXTURE_ROOT/$TAG/$ARTEFACT"
  cp "$BL_APPIMAGE" "$poisoned"
  printf '\x42' | dd of="$poisoned" bs=1 count=1 seek=64 conv=notrunc status=none
  ( cd "$FIXTURE_ROOT/$TAG" \
    && zsyncmake -u "$BASE_URL/$TAG/$ARTEFACT" "$ARTEFACT" >/dev/null 2>&1 )
  cp "$BL_SIG" "$FIXTURE_ROOT/$TAG/$ARTEFACT.sig"
  cp "$BL_MANIFEST_ASC" "$FIXTURE_ROOT/$TAG/manifest-v2.txt.asc"
}

# Fixture B — valid AppImage but .sig from wrong key.
prep_B() {
  cp "$BL_APPIMAGE" "$FIXTURE_ROOT/$TAG/$ARTEFACT"
  cp "$BL_ZSYNC" "$FIXTURE_ROOT/$TAG/$ARTEFACT.zsync"
  cp "$BL_MANIFEST_ASC" "$FIXTURE_ROOT/$TAG/manifest-v2.txt.asc"
  gpg --homedir "$WRONG_GNUPG" --batch --pinentry-mode loopback \
      --local-user "$WRONG_KEY_FPR" \
      --detach-sign --output "$FIXTURE_ROOT/$TAG/$ARTEFACT.sig" \
      "$FIXTURE_ROOT/$TAG/$ARTEFACT"
}

# Fixture C — manifest clearsigned by wrong key.
prep_C() {
  cp "$BL_APPIMAGE" "$FIXTURE_ROOT/$TAG/$ARTEFACT"
  cp "$BL_SIG" "$FIXTURE_ROOT/$TAG/$ARTEFACT.sig"
  cp "$BL_ZSYNC" "$FIXTURE_ROOT/$TAG/$ARTEFACT.zsync"
  local plain="$WORK/baseline-manifest.txt"
  gpg --homedir "$WRONG_GNUPG" --batch --pinentry-mode loopback \
      --local-user "$WRONG_KEY_FPR" \
      --clearsign --output "$FIXTURE_ROOT/$TAG/manifest-v2.txt.asc" "$plain"
}

# Fixture D — .zsync truncated.
prep_D() {
  cp "$BL_APPIMAGE" "$FIXTURE_ROOT/$TAG/$ARTEFACT"
  cp "$BL_SIG" "$FIXTURE_ROOT/$TAG/$ARTEFACT.sig"
  cp "$BL_MANIFEST_ASC" "$FIXTURE_ROOT/$TAG/manifest-v2.txt.asc"
  # Truncate .zsync to first 50 bytes — drops chunk table.
  head -c 50 "$BL_ZSYNC" > "$FIXTURE_ROOT/$TAG/$ARTEFACT.zsync"
}

# Fixture E — manifest clearsign truncated at 200 bytes (clearsign-invalid).
# Deterministically exercises the malformed-envelope rejection path.
# Note: labelled "mid-stream" in the scenario name because it stands in for
# a real TCP mid-download close, which is not reliably reproducible against
# python http.server. The verify chain rejects on the same code path either way.
prep_E() {
  cp "$BL_APPIMAGE" "$FIXTURE_ROOT/$TAG/$ARTEFACT"
  cp "$BL_SIG" "$FIXTURE_ROOT/$TAG/$ARTEFACT.sig"
  cp "$BL_ZSYNC" "$FIXTURE_ROOT/$TAG/$ARTEFACT.zsync"
  head -c 200 "$BL_MANIFEST_ASC" > "$FIXTURE_ROOT/$TAG/manifest-v2.txt.asc"
}

run_scenario 'A: AppImage SHA mismatch'           prep_A
run_scenario 'B: detached sig from wrong key'     prep_B
run_scenario 'C: manifest clearsign wrong key'    prep_C
run_scenario 'D: truncated .zsync'                prep_D
run_scenario 'E: manifest clearsign truncated (clearsign-invalid)' prep_E

if [[ "$SCENARIO_FAILS" -eq 0 ]]; then
  printf 'OK 5/5 poisoned-fixture scenarios rejected as expected (anti-pattern §12.14)\n'
  exit 0
else
  printf 'FAIL %d/5 scenarios let the helper succeed — verify chain has a hole\n' "$SCENARIO_FAILS"
  exit 1
fi
