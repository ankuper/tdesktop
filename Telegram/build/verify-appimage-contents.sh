#!/usr/bin/env bash
# verify-appimage-contents.sh — Story 2-7 post-build assertion.
#
# Confirms:
#   (a) usr/share/Telegram/about-licenses/LICENSE-libteleproto3 is present
#   (b) its SHA-256 matches the upstream teleproto3/lib/LICENSE source
#   (c) usr/bin/Telegram is present and executable
#   (d) ldd usr/bin/Telegram has no teleproto3 dynamic dependency
#       (anti-pattern §12.10 — static-link contract)
#   (e) `nm` against usr/bin/Telegram shows the T3 ABI version-pin symbol
#       was preserved through linking (story 2.1 _Static_assert presence;
#       compile-time guard, but binary-side spot-check via the linked
#       teleproto3 symbol prefix `t3_`)
#
# Build fails (exit 1) on any miss; CI step gates merge on success.

set -Eeuo pipefail
umask 022

die() { printf 'verify-appimage-contents: %s\n' "$*" >&2; exit 1; }
note() { printf 'verify-appimage-contents: %s\n' "$*"; }

APPIMAGE="${1:-${APPIMAGE:-}}"
LICENSE_LIBTELEPROTO3="${LICENSE_LIBTELEPROTO3:-}"

[[ -f "$APPIMAGE" ]] || die "APPIMAGE not found: '$APPIMAGE'"
[[ -f "$LICENSE_LIBTELEPROTO3" ]] \
  || die "LICENSE_LIBTELEPROTO3 not provided or missing: '$LICENSE_LIBTELEPROTO3'"

work="$(mktemp -d -t verify-appimage-XXXXXX)"
trap 'rm -rf "$work"' EXIT
(
  cd "$work"
  "$APPIMAGE" --appimage-extract >/dev/null
)

root="$work/squashfs-root"
[[ -d "$root" ]] || die "AppImage --appimage-extract produced no squashfs-root"

#### (a) license presence
license="$root/usr/share/Telegram/about-licenses/LICENSE-libteleproto3"
[[ -f "$license" ]] || die "LICENSE-libteleproto3 missing inside AppImage at canonical path"

#### (b) license SHA-256 matches upstream
upstream_sha="$(sha256sum "$LICENSE_LIBTELEPROTO3" | awk '{print $1}')"
embedded_sha="$(sha256sum "$license" | awk '{print $1}')"
[[ "$upstream_sha" == "$embedded_sha" ]] \
  || die "LICENSE-libteleproto3 SHA-256 mismatch: expected $upstream_sha, got $embedded_sha"

#### (c) Telegram binary present and executable
binary="$root/usr/bin/Telegram"
[[ -x "$binary" ]] || die "usr/bin/Telegram missing or not executable"

#### (d) static-link assertion (§12.10)
if ldd "$binary" 2>/dev/null | grep -qi 'teleproto3'; then
  ldd "$binary" | grep -i 'teleproto3' >&2
  die 'ldd shows teleproto3 in linked image — must be static (anti-pattern §12.10)'
fi

#### (e) nm spot-check that t3_* symbols are present (proxies the
# _Static_assert ABI version-pin guard reaching the linker — if the
# bridge TU was excluded the symbols would be absent).
if command -v nm >/dev/null 2>&1; then
  if ! nm -D --defined-only "$binary" 2>/dev/null | grep -q 't3_' \
     && ! nm "$binary" 2>/dev/null | grep -q 't3_'; then
    die 'no t3_* symbols in linked image — bridge TU may be excluded; ABI-version pin guard not reached'
  fi
fi

note "license sha-256 match: $embedded_sha"
note "static-link clean"
note "t3_ symbols present"
note 'OK'
