#!/usr/bin/env bash
# sign-appimage-linux.sh — Story 2-7 AC#2 PGP detached signature + .zsync +
# clear-signed publish manifest.
#
# Inputs:
#   $1 / TAG                — release tag (v2-YYYY-MM-DD-NN)
#   $2 / OUT_DIR            — directory containing the .AppImage from
#                             release-linux-appimage.sh and where this script
#                             writes .sig, .zsync, manifest-v2.txt + .asc
#   RELEASE_KEY_FPR         — release key fingerprint (40-hex no spaces)
#   GPG_PASSPHRASE_FILE     — path to a file holding the passphrase
#                             (CI feeds this via mktemp from the
#                             TDESKTOP_RELEASE_GPG_PASSPHRASE secret;
#                             never written to a workflow log; mode 600)
#   PUBLISH_BASE_URL        — default https://github.com/ankuper/tdesktop/releases/download
#
# The clearsigned manifest is the trust root; AppImageUpdate verifies it
# first, then SHA-256 of the AppImage against the manifest entry, then
# the detached signature against the same release key.
#
# Per AC#4 / anti-pattern §12.14 — there is NO partial-success state
# here: every external command is checked, and on first failure the
# script exits non-zero with no half-published artefacts.

set -Eeuo pipefail
shopt -s inherit_errexit
umask 022
LC_ALL=C
TZ=UTC
export LC_ALL TZ

readonly TAG_RE='^v2-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}$'
readonly ARTEFACT_NAME='Telegram-x86_64-v2.AppImage'

die() { printf 'sign-appimage-linux: %s\n' "$*" >&2; exit 1; }
note() { printf 'sign-appimage-linux: %s\n' "$*"; }

TAG="${1:-${TAG:-}}"
OUT_DIR="${2:-${OUT_DIR:-}}"
[[ "$TAG" =~ $TAG_RE ]] || die "TAG must match v2-YYYY-MM-DD-NN; got '$TAG'"
[[ -d "$OUT_DIR" ]] || die "OUT_DIR not a directory: '$OUT_DIR'"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

RELEASE_KEY_FPR="${RELEASE_KEY_FPR:-}"
[[ "$RELEASE_KEY_FPR" =~ ^[A-Fa-f0-9]{40}$ ]] \
  || die "RELEASE_KEY_FPR must be 40 hex chars; got '$RELEASE_KEY_FPR'"

GPG_PASSPHRASE_FILE="${GPG_PASSPHRASE_FILE:-}"
[[ -f "$GPG_PASSPHRASE_FILE" ]] \
  || die "GPG_PASSPHRASE_FILE missing: '$GPG_PASSPHRASE_FILE'"

PUBLISH_BASE_URL="${PUBLISH_BASE_URL:-https://github.com/ankuper/tdesktop/releases/download}"

appimage="$OUT_DIR/$ARTEFACT_NAME"
[[ -f "$appimage" ]] || die "AppImage not found: $appimage"

manifest_in="$OUT_DIR/release-manifest-linux.txt"
[[ -f "$manifest_in" ]] || die "release-manifest-linux.txt missing — did you run release-linux-appimage.sh?"

#### 1. Detached signature.
sig_path="$appimage.sig"
note 'producing detached PGP signature'
gpg --batch --yes \
    --pinentry-mode loopback \
    --passphrase-file "$GPG_PASSPHRASE_FILE" \
    --local-user "$RELEASE_KEY_FPR" \
    --detach-sign --output "$sig_path" "$appimage"

[[ -f "$sig_path" ]] || die "detached signature not produced"

# Self-check via --status-fd (locale-independent; VALIDSIG $12 = primary key fpr).
gpg_out="$(gpg --batch --status-fd 1 \
               --verify "$sig_path" "$appimage" 2>/dev/null || true)"
printf '%s\n' "$gpg_out" \
  | awk -v fpr="$RELEASE_KEY_FPR" \
        '/^\[GNUPG:\] VALIDSIG / && $12 == fpr {found=1} END {exit !found}' \
  || die 'detached signature self-verify failed against expected fingerprint'

#### 2. .zsync delta-information file.
zsync_path="$appimage.zsync"
note 'generating .zsync'
publish_url="$PUBLISH_BASE_URL/$TAG/$ARTEFACT_NAME"
(
  cd "$OUT_DIR"
  zsyncmake -u "$publish_url" "$ARTEFACT_NAME"
)
[[ -f "$zsync_path" ]] || die ".zsync not produced"

# Confirm zsync URL field matches publish_url byte-exact (most common
# AppImageUpdate failure-in-the-wild).
zsync_url_field="$(grep -m1 '^URL:' "$zsync_path" | awk '{print $2}')"
[[ "$zsync_url_field" == "$publish_url" ]] \
  || die "zsync URL field ($zsync_url_field) does not match publish URL ($publish_url)"

#### 3. publish manifest + clearsign.
manifest_pub="$OUT_DIR/manifest-v2.txt"
appimage_sha="$(sha256sum "$appimage" | awk '{print $1}')"
zsync_sha="$(sha256sum "$zsync_path" | awk '{print $1}')"
sig_sha="$(sha256sum "$sig_path" | awk '{print $1}')"
libteleproto3_sha="$(awk '$1 == "libteleproto3_a_sha256" {print $2}' "$manifest_in")"

{
  printf 'tag                       %s\n' "$TAG"
  printf 'release_key_fpr           %s\n' "$RELEASE_KEY_FPR"
  printf 'appimage                  %s\n' "$ARTEFACT_NAME"
  printf 'appimage_sha256           %s\n' "$appimage_sha"
  printf 'zsync                     %s\n' "$ARTEFACT_NAME.zsync"
  printf 'zsync_sha256              %s\n' "$zsync_sha"
  printf 'sig                       %s\n' "$ARTEFACT_NAME.sig"
  printf 'sig_sha256                %s\n' "$sig_sha"
  printf 'libteleproto3_a_sha256    %s\n' "${libteleproto3_sha:-unknown}"
  printf 'publish_base_url          %s\n' "$PUBLISH_BASE_URL"
} > "$manifest_pub"

manifest_asc="$OUT_DIR/manifest-v2.txt.asc"
note 'clearsigning publish manifest'
gpg --batch --yes \
    --pinentry-mode loopback \
    --passphrase-file "$GPG_PASSPHRASE_FILE" \
    --local-user "$RELEASE_KEY_FPR" \
    --clearsign --output "$manifest_asc" "$manifest_pub"

[[ -f "$manifest_asc" ]] || die 'clearsign manifest not produced'

# Self-verify via --status-fd (locale-independent; VALIDSIG $12 = primary key fpr).
gpg_out="$(gpg --batch --status-fd 1 \
               --verify "$manifest_asc" 2>/dev/null || true)"
printf '%s\n' "$gpg_out" \
  | awk -v fpr="$RELEASE_KEY_FPR" \
        '/^\[GNUPG:\] VALIDSIG / && $12 == fpr {found=1} END {exit !found}' \
  || die 'clearsign self-verify failed against expected fingerprint'

note "OK: $appimage ($appimage_sha)"
note "OK: $sig_path"
note "OK: $zsync_path (URL: $zsync_url_field)"
note "OK: $manifest_asc"
