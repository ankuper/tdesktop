#!/usr/bin/env bash
# appimage-self-update.sh — Story 2-7 AC#3 / AC#4 verify+replace shell.
#
# Invoked by core/update_linux_appimage.cpp on Linux when the running
# binary is an AppImage. Performs the verify chain in the order
# mandated by Epic 2 §12.14 (anti-pattern: update-across-signature-failure).
# Any single failure short-circuits to UPDATE_REJECTED with no partial
# state on disk — the existing binary continues to run unchanged.
#
# Protocol (stdout, one line per event, parsed by C++ wrapper):
#   STATE: <enum>            — checking|downloading|verifying|ready|failed|done
#   PROGRESS: <bytes_done> <bytes_total>
#   VERSION: <new-tag>       — upon manifest parse
#   SIZE: <bytes>            — upon manifest parse (delta size from .zsync)
#   FINGERPRINT: <fpr>       — pinned release-key fingerprint, displayed in consent prompt
#   ERROR: <generic>         — failure (NFR20 — no class differentiation)
#
# Exit codes:
#   0   — verified candidate ready at $CACHE_DIR/Telegram-x86_64-v2.AppImage
#         (replacement does not happen here; consent + atomic-replace is
#         the C++ wrapper's responsibility)
#   1   — UPDATE_REJECTED (any verify failure or transient network error)
#   10  — usage / not-running-from-AppImage / preconditions not met
#
# Inputs:
#   APPIMAGE                  — env var auto-set by AppImage runtime;
#                               filled with absolute path of the running
#                               AppImage. Required.
#   PUBLISH_BASE_URL          — default https://github.com/ankuper/tdesktop/releases/download
#   RELEASE_KEY_FPR           — pinned fingerprint (40-hex no spaces);
#                               REQUIRED — fail if unset
#   GPG_HOMEDIR               — default $XDG_CONFIG_HOME/Telegram/gnupg-tdesktop
#   CACHE_DIR                 — default $XDG_CACHE_HOME/Telegram/update
#   GH_OWNER                  — default ankuper
#   GH_REPO                   — default tdesktop
#   ARTEFACT_NAME             — default Telegram-x86_64-v2.AppImage

set -Eeuo pipefail
shopt -s inherit_errexit

LC_ALL=C; export LC_ALL
umask 077

readonly ARTEFACT_NAME="${ARTEFACT_NAME:-Telegram-x86_64-v2.AppImage}"
readonly GH_OWNER="${GH_OWNER:-ankuper}"
readonly GH_REPO="${GH_REPO:-tdesktop}"
readonly PUBLISH_BASE_URL="${PUBLISH_BASE_URL:-https://github.com/${GH_OWNER}/${GH_REPO}/releases/download}"
# GH_API_BASE_URL is overridable for tests against a local fixture
# server. In production it's the real GitHub API endpoint.
readonly GH_API_BASE_URL="${GH_API_BASE_URL:-https://api.github.com}"
_cache_base="${XDG_CACHE_HOME:-}"
if [[ -z "$_cache_base" ]]; then
  if [[ -z "${HOME:-}" ]]; then
    printf 'ERROR: HOME and XDG_CACHE_HOME both unset; cannot determine cache dir\n'
    exit 10
  fi
  _cache_base="$HOME/.cache"
fi
readonly CACHE_DIR="${CACHE_DIR:-$_cache_base/Telegram/update}"
readonly GPG_HOMEDIR="${GPG_HOMEDIR:-${XDG_CONFIG_HOME:-$HOME/.config}/Telegram/gnupg-tdesktop}"
readonly LOCK_FILE="$CACHE_DIR/.lock"

emit() { printf '%s\n' "$*"; }
die_generic() {
  # NFR20 — fixed opaque token on stdout (C++ maps to lng_update_failed_generic);
  # developer detail routed to stderr only so it never reaches the user surface.
  emit "ERROR: update-failed"
  printf 'ERROR_DETAIL: %s\n' "$*" >&2
  cleanup_partial
  exit 1
}
die_usage() {
  emit "ERROR: $*"
  exit 10
}

cleanup_partial() {
  # Anti-pattern §12.14 — leave NO partial state on disk. Sweep the
  # entire cache directory rather than enumerating known names: zsync
  # writes a `.part` intermediate, gpg may write a temporary, and a
  # future tool change could leave another stale file.
  # .lock is last: explicit flock -u then unlink (spec §5 — lock last).
  if [[ -d "$CACHE_DIR" ]]; then
    find "$CACHE_DIR" -mindepth 1 -maxdepth 1 -type f \
      ! -name '.lock' -delete 2>/dev/null || true
    flock -u 9 2>/dev/null || true
    rm -f "$LOCK_FILE" 2>/dev/null || true
  fi
}

trap 'cleanup_partial' ERR

#### Preconditions.
[[ -n "${APPIMAGE:-}" ]] \
  || die_usage 'not running from an AppImage (APPIMAGE env unset)'
[[ -f "$APPIMAGE" ]] \
  || die_usage "APPIMAGE path does not exist: $APPIMAGE"

RELEASE_KEY_FPR="${RELEASE_KEY_FPR:-}"
[[ "$RELEASE_KEY_FPR" =~ ^[A-Fa-f0-9]{40}$ ]] \
  || die_usage "RELEASE_KEY_FPR not pinned (must be 40 hex chars)"

for tool in curl gpg sha256sum zsync; do
  command -v "$tool" >/dev/null \
    || die_usage "required tool missing: $tool"
done

mkdir -p "$CACHE_DIR" "$GPG_HOMEDIR"
chmod 700 "$GPG_HOMEDIR"

# Advisory lock — prevent concurrent self-updaters on the same cache.
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  die_usage 'another updater is already running'
fi

emit 'STATE: checking'

#### 1. Resolve latest release tag from GitHub Releases API.
# We use the unauthenticated public endpoint — no telemetry, no token.
latest_json="$(curl -sSL --max-time 30 \
  -H 'Accept: application/vnd.github+json' \
  "$GH_API_BASE_URL/repos/${GH_OWNER}/${GH_REPO}/releases/latest" \
  || true)"
[[ -n "$latest_json" ]] \
  || die_generic 'cannot reach release manifest endpoint'

latest_tag="$(printf '%s' "$latest_json" | grep -oE '"tag_name":\s*"v2-[0-9-]+"' | head -1 | sed -E 's/.*"(v2-[0-9-]+)".*/\1/')"
[[ "$latest_tag" =~ ^v2-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}$ ]] \
  || die_generic 'no current release matching v2 tag scheme'


emit "VERSION: $latest_tag"
emit "FINGERPRINT: $RELEASE_KEY_FPR"

#### 2. Download manifest-v2.txt.asc + clearsign verify.
manifest_url="$PUBLISH_BASE_URL/$latest_tag/manifest-v2.txt.asc"
manifest_asc="$CACHE_DIR/manifest-v2.txt.asc"

emit 'STATE: downloading'
curl -sSL --max-time 60 --fail -o "$manifest_asc" "$manifest_url" \
  || die_generic 'manifest download failed'

# Self-import release key pubring once, idempotently. The pinned key
# is bundled with the running AppImage at usr/share/Telegram/about-licenses/
# tdesktop-release.pub.asc — extracted on first run.
pubring="$GPG_HOMEDIR/release-pubring.kbx"
if ! gpg --homedir "$GPG_HOMEDIR" --list-keys "$RELEASE_KEY_FPR" >/dev/null 2>&1; then
  # $APPDIR is set by the AppImage runtime to the extracted squashfs mountpoint.
  # Fallback: dev-tree path for running outside an AppImage.
  if [[ -n "${APPDIR:-}" && -f "$APPDIR/usr/share/Telegram/about-licenses/tdesktop-release.pub.asc" ]]; then
    bundled_pub="$APPDIR/usr/share/Telegram/about-licenses/tdesktop-release.pub.asc"
  else
    bundled_pub=""
  fi
  [[ -f "$bundled_pub" ]] \
    || die_generic 'release pubring missing in running AppImage'
  gpg --homedir "$GPG_HOMEDIR" --import "$bundled_pub" >/dev/null 2>&1 \
    || die_generic 'release pubring import failed'
  # Pin trust to ultimate to permit non-interactive verify.
  echo "$RELEASE_KEY_FPR:6:" \
    | gpg --homedir "$GPG_HOMEDIR" --import-ownertrust >/dev/null 2>&1 \
    || die_generic 'release pubring ownertrust pin failed'
fi

emit 'STATE: verifying'

# Clearsign verify.
#
# Note on the VALIDSIG line (gpg --status-fd 1 protocol):
# the FIRST fingerprint after `VALIDSIG` is the SIGNING-key (which
# may be a subkey); field $12 (per the status-line format VALIDSIG
# <sigkey> <date> <ts> <expire> <ver> <reserved> <pkalgo> <halgo>
# <sigclass> <primary-key>) is the PRIMARY-key fingerprint. We pin
# against the primary fingerprint by matching $12 with awk.
gpg_out="$(gpg --homedir "$GPG_HOMEDIR" --batch --status-fd 1 \
                --verify "$manifest_asc" 2>/dev/null || true)"
printf '%s\n' "$gpg_out" \
  | awk -v fpr="$RELEASE_KEY_FPR" '/^\[GNUPG:\] VALIDSIG / && $12 == fpr {found=1} END {exit !found}' \
  || die_generic 'manifest clearsign failed'

# Strip the clearsign envelope to plain manifest (already verified above).
# --decrypt is wrong for cleartext; parse the armor directly.
manifest_plain="$CACHE_DIR/manifest-v2.txt"
awk '/^-----BEGIN PGP SIGNATURE-----/{exit}
     /^-----BEGIN PGP SIGNED MESSAGE-----/{in_hdr=1; next}
     in_hdr && /^$/{in_hdr=0; next}
     in_hdr{next}
     {print}' "$manifest_asc" > "$manifest_plain" \
  || die_generic 'manifest clearsign envelope strip failed'
[[ -s "$manifest_plain" ]] \
  || die_generic 'manifest plaintext empty after clearsign strip'

# Extract expected SHA-256 of new AppImage from the manifest.
expected_sha="$(awk '$1 == "appimage_sha256" {print $2}' "$manifest_plain")"
[[ "$expected_sha" =~ ^[a-fA-F0-9]{64}$ ]] \
  || die_generic 'manifest does not carry a valid appimage_sha256'

#### 3. Fetch the new AppImage via .zsync (delta-only).
appimage_dst="$CACHE_DIR/$ARTEFACT_NAME"
zsync_url="$PUBLISH_BASE_URL/$latest_tag/$ARTEFACT_NAME.zsync"

# Pre-existing AppImage in cache used as zsync seed for delta-fetch.
zsync_seed_args=()
if [[ -f "$APPIMAGE" ]]; then
  zsync_seed_args+=(-i "$APPIMAGE")
fi

emit 'STATE: downloading'
( cd "$CACHE_DIR" && zsync "${zsync_seed_args[@]}" -o "$ARTEFACT_NAME" "$zsync_url" >/dev/null 2>&1 ) \
  || die_generic 'delta-fetch failed (zsync)'

[[ -f "$appimage_dst" ]] \
  || die_generic 'reconstructed AppImage missing after zsync'

#### 4. SHA-256 match against signed manifest.
emit 'STATE: verifying'
actual_sha="$(sha256sum "$appimage_dst" | awk '{print $1}')"
[[ "$actual_sha" == "$expected_sha" ]] \
  || die_generic 'reconstructed AppImage hash mismatch'

#### 5. Detached signature verify.
sig_url="$PUBLISH_BASE_URL/$latest_tag/$ARTEFACT_NAME.sig"
sig_dst="$appimage_dst.sig"
curl -sSL --max-time 60 --fail -o "$sig_dst" "$sig_url" \
  || die_generic 'sig download failed'

gpg_out="$(gpg --homedir "$GPG_HOMEDIR" --batch --status-fd 1 \
                --verify "$sig_dst" "$appimage_dst" 2>/dev/null || true)"
printf '%s\n' "$gpg_out" \
  | awk -v fpr="$RELEASE_KEY_FPR" '/^\[GNUPG:\] VALIDSIG / && $12 == fpr {found=1} END {exit !found}' \
  || die_generic 'detached signature verify failed'

#### 6. AppImage --appimage-validate (offline integrity check).
chmod 0755 "$appimage_dst"
"$appimage_dst" --appimage-validate >/dev/null 2>&1 \
  || die_generic 'AppImage self-validate failed'

# All gates passed. Hand the verified candidate to the C++ wrapper for
# atomic replacement upon user consent.
size="$(stat -c %s "$appimage_dst")"
emit "SIZE: $size"
emit 'STATE: ready'
emit 'STATE: done'
exit 0
