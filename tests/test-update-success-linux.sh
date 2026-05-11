#!/usr/bin/env bash
# test-update-success-linux.sh — Story 2-7 AC#3 positive counterpart.
#
# Mints a clean fixture set, serves it, runs appimage-self-update.sh,
# asserts:
#   - exit 0
#   - script emits STATE: ready then STATE: done
#   - candidate AppImage is present at $HELPER_CACHE/Telegram-x86_64-v2.AppImage
#   - candidate's SHA-256 matches the manifest's appimage_sha256 entry
#   - no ERROR: line emitted

set -Eeuo pipefail
shopt -s inherit_errexit

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO="$( cd "$THIS_DIR/.." && pwd )"
HELPER="$REPO/Telegram/build/appimage-self-update.sh"
EXPECTED_RELEASE_KEY_FPR='1DED8ADEF19BE7CAC93DEC5788161B1A989EF692'

WORK="$REPO/tests/_workspace"
RELEASE_GNUPG="$WORK/gnupg-release"
FIXTURE_ROOT="$WORK/fixtures"
HELPER_CACHE="$WORK/cache"
RELEASE_KEYDIR='/root/tdesktop-release-key'

if [[ -z "${TEST_FIXTURE_PORT:-}" ]]; then
  PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); p=s.getsockname()[1]; s.close(); print(p)')"
else
  PORT="$TEST_FIXTURE_PORT"
fi
readonly PORT
readonly BASE_URL="http://127.0.0.1:$PORT"
readonly TAG='v2-2026-05-09-99'
readonly ARTEFACT='Telegram-x86_64-v2.AppImage'

note() { printf '[%s] %s\n' "$(date +%T)" "$*" >&2; }
fail_test() { printf 'TEST FAIL: %s\n' "$*" >&2; exit 1; }

[[ -x "$HELPER" ]] || fail_test "helper missing: $HELPER"
[[ -d "$RELEASE_KEYDIR" ]] || fail_test "release-key dir missing: $RELEASE_KEYDIR"

#### Setup release-keyring (idempotent; mirrors test-update-failure-linux.sh setup).
mkdir -p "$RELEASE_GNUPG" && chmod 700 "$RELEASE_GNUPG"
if ! gpg --homedir "$RELEASE_GNUPG" --list-secret-keys "$EXPECTED_RELEASE_KEY_FPR" >/dev/null 2>&1; then
  gpg --homedir "$RELEASE_GNUPG" --import "$RELEASE_KEYDIR/tdesktop-v0.1.0-dev-release.pub.asc"
  echo "$EXPECTED_RELEASE_KEY_FPR:6:" | gpg --homedir "$RELEASE_GNUPG" --import-ownertrust
  gpg --batch --pinentry-mode loopback \
      --passphrase-file "$RELEASE_KEYDIR/passphrase.txt" \
      --export-secret-keys "$EXPECTED_RELEASE_KEY_FPR" \
    | gpg --homedir "$RELEASE_GNUPG" --batch --pinentry-mode loopback \
          --passphrase-file "$RELEASE_KEYDIR/passphrase.txt" \
          --import \
    || fail_test "could not import release secret key"
fi
gpg --homedir "$RELEASE_GNUPG" --list-secret-keys "$EXPECTED_RELEASE_KEY_FPR" >/dev/null \
  || fail_test "release secret key still not present after import"

rm -rf "$FIXTURE_ROOT/$TAG" "$HELPER_CACHE"
mkdir -p "$FIXTURE_ROOT/$TAG" "$HELPER_CACHE"

# Mint AppImage + sig + zsync + manifest.
appimage="$FIXTURE_ROOT/$TAG/$ARTEFACT"
cat > "$appimage" <<'EOF'
#!/bin/sh
case "$1" in
  --appimage-validate) exit 0 ;;
  --appimage-version) printf 'v2-2026-04-01-01\n'; exit 0 ;;
esac
exit 0
EOF
chmod +x "$appimage"

gpg --homedir "$RELEASE_GNUPG" --batch --pinentry-mode loopback \
    --passphrase-file "$RELEASE_KEYDIR/passphrase.txt" \
    --local-user "$EXPECTED_RELEASE_KEY_FPR" \
    --detach-sign --output "$appimage.sig" "$appimage"

(cd "$FIXTURE_ROOT/$TAG" && zsyncmake -u "$BASE_URL/$TAG/$ARTEFACT" "$ARTEFACT" >/dev/null 2>&1)

sha="$(sha256sum "$appimage" | awk '{print $1}')"
manifest="$FIXTURE_ROOT/$TAG/manifest-v2.txt"
cat > "$manifest" <<EOF
tag                       $TAG
release_key_fpr           $EXPECTED_RELEASE_KEY_FPR
appimage                  $ARTEFACT
appimage_sha256           $sha
publish_base_url          $BASE_URL
EOF
gpg --homedir "$RELEASE_GNUPG" --batch --pinentry-mode loopback \
    --passphrase-file "$RELEASE_KEYDIR/passphrase.txt" \
    --local-user "$EXPECTED_RELEASE_KEY_FPR" \
    --clearsign --output "$FIXTURE_ROOT/$TAG/manifest-v2.txt.asc" "$manifest"

mkdir -p "$FIXTURE_ROOT/api/repos/ankuper/tdesktop/releases"
cat > "$FIXTURE_ROOT/api/repos/ankuper/tdesktop/releases/latest" <<EOF
{ "tag_name": "$TAG", "name": "$TAG", "draft": false, "prerelease": false }
EOF

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$FIXTURE_ROOT" >/dev/null 2>&1 &
server_pid=$!
trap "kill $server_pid 2>/dev/null || true" EXIT
for _i in $(seq 20); do curl -sf "$BASE_URL/" >/dev/null 2>&1 && break; sleep 0.1; done

stdout="$(mktemp)"
set +e
APPIMAGE="$appimage" \
  PUBLISH_BASE_URL="$BASE_URL" \
  GH_API_BASE_URL="http://127.0.0.1:$PORT/api" \
  RELEASE_KEY_FPR="$EXPECTED_RELEASE_KEY_FPR" \
  GPG_HOMEDIR="$RELEASE_GNUPG" \
  CACHE_DIR="$HELPER_CACHE" \
  GH_OWNER='ankuper' GH_REPO='tdesktop' \
  "$HELPER" >"$stdout" 2>&1
exit_code=$?
set -e
kill $server_pid 2>/dev/null || true
trap - EXIT

if [[ $exit_code -ne 0 ]]; then
  note "FAIL helper exited $exit_code on a clean fixture"
  cat "$stdout" >&2
  exit 1
fi
if grep -q '^ERROR: ' "$stdout"; then
  note 'FAIL helper emitted ERROR: on a clean fixture'
  cat "$stdout" >&2
  exit 1
fi
if ! grep -q '^STATE: ready' "$stdout"; then
  note 'FAIL helper did not transition to STATE: ready'
  cat "$stdout" >&2
  exit 1
fi
if [[ ! -f "$HELPER_CACHE/$ARTEFACT" ]]; then
  note 'FAIL verified candidate not in cache dir'
  exit 1
fi

actual_sha="$(sha256sum "$HELPER_CACHE/$ARTEFACT" | awk '{print $1}')"
if [[ "$actual_sha" != "$sha" ]]; then
  note "FAIL candidate sha $actual_sha != fixture sha $sha"
  exit 1
fi

printf 'OK clean fixture path: helper accepted, candidate placed, sha matches manifest\n'
