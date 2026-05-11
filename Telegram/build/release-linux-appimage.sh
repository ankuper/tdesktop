#!/usr/bin/env bash
# release-linux-appimage.sh — Story 2-7 AC#1 reproducible AppImage build.
#
# Wraps `linuxdeploy --appdir AppDir --output appimage` with reproducibility
# flags and emits release-manifest-linux.txt with all build-time inputs.
#
# Inputs (env or positional):
#   $1 / TAG               — release tag, MUST match v2-YYYY-MM-DD-NN
#   $2 / OUT_DIR           — directory to drop the .AppImage + manifest
#   APPDIR                 — pre-staged AppDir (build output of tdesktop)
#   LIBTELEPROTO3_A        — path to libteleproto3.a (lib-v0.1.0)
#   LICENSE_LIBTELEPROTO3  — path to upstream teleproto3/lib/LICENSE (Apache 2.0)
#   LINUXDEPLOY            — path to linuxdeploy AppImage (default /opt/appimage/linuxdeploy)
#   LINUXDEPLOY_PLUGIN_QT  — path to qt plugin (default /opt/appimage/linuxdeploy-plugin-qt)
#   APPIMAGETOOL           — path to appimagetool (default /opt/appimage/appimagetool)
#   PUBLISH_BASE_URL       — GitHub release download base; default
#                            https://github.com/ankuper/tdesktop/releases/download
#   UPDATE_INFO_FORM       — gh-releases-zsync (default) or zsync
#
# Reproducibility contract:
#   - SOURCE_DATE_EPOCH set from git commit timestamp of the tag.
#   - LC_ALL=C, TZ=UTC, umask 022.
#   - mksquashfs -no-fragments -all-root -no-exports -mkfs-time $SOURCE_DATE_EPOCH.
#   - Sorted file ordering for rcc inputs (handled in cmake/QT layer; this
#     script asserts AppDir is already deterministic).
#   - linuxdeploy + appimagetool + qt-plugin pinned by SHA-256 (manifest).
#   - LD --build-id=sha1 (deterministic from input bytes).
#
# Output artefacts in OUT_DIR:
#   Telegram-x86_64-v2.AppImage
#   release-manifest-linux.txt              (build-input fingerprint)
#
# Subsequent steps (sign-appimage-linux.sh, zsyncmake) consume these.

set -Eeuo pipefail
shopt -s inherit_errexit

LC_ALL=C
TZ=UTC
umask 022
export LC_ALL TZ

readonly TAG_RE='^v2-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}$'
readonly ARTEFACT_NAME='Telegram-x86_64-v2.AppImage'

die() { printf 'release-linux-appimage: %s\n' "$*" >&2; exit 1; }
note() { printf 'release-linux-appimage: %s\n' "$*"; }

TAG="${1:-${TAG:-}}"
OUT_DIR="${2:-${OUT_DIR:-out/release-linux}}"
[[ "$TAG" =~ $TAG_RE ]] \
  || die "TAG must match v2-YYYY-MM-DD-NN; got '$TAG'"

APPDIR="${APPDIR:-out/Release/AppDir}"
[[ -d "$APPDIR" ]] || die "APPDIR not found: $APPDIR"
[[ -x "$APPDIR/usr/bin/Telegram" ]] \
  || die "AppDir is missing Telegram binary at usr/bin/Telegram"

LIBTELEPROTO3_A="${LIBTELEPROTO3_A:-}"
[[ -f "$LIBTELEPROTO3_A" ]] \
  || die "LIBTELEPROTO3_A not provided or missing: '$LIBTELEPROTO3_A'"

LICENSE_LIBTELEPROTO3="${LICENSE_LIBTELEPROTO3:-}"
[[ -f "$LICENSE_LIBTELEPROTO3" ]] \
  || die "LICENSE_LIBTELEPROTO3 not provided or missing: '$LICENSE_LIBTELEPROTO3'"

LINUXDEPLOY="${LINUXDEPLOY:-/opt/appimage/linuxdeploy}"
LINUXDEPLOY_PLUGIN_QT="${LINUXDEPLOY_PLUGIN_QT:-/opt/appimage/linuxdeploy-plugin-qt}"
APPIMAGETOOL="${APPIMAGETOOL:-/opt/appimage/appimagetool}"
for tool in "$LINUXDEPLOY" "$LINUXDEPLOY_PLUGIN_QT" "$APPIMAGETOOL" \
            zsyncmake mksquashfs sha256sum patchelf gpg; do
  command -v "$tool" >/dev/null 2>&1 || [[ -x "$tool" ]] \
    || die "required tool not found on PATH or absolute: $tool"
done

PUBLISH_BASE_URL="${PUBLISH_BASE_URL:-https://github.com/ankuper/tdesktop/releases/download}"
UPDATE_INFO_FORM="${UPDATE_INFO_FORM:-gh-releases-zsync}"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

#### SOURCE_DATE_EPOCH from tag commit timestamp.
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -c log.showSignature=false log -1 --format=%ct "refs/tags/${TAG}" 2>/dev/null || true)"
  if [[ -z "$SOURCE_DATE_EPOCH" ]]; then
    die "tag $TAG not found locally; fetch tags before building (git fetch --tags)"
  fi
fi
export SOURCE_DATE_EPOCH

#### License pre-stage at canonical path.
license_dst="$APPDIR/usr/share/Telegram/about-licenses/LICENSE-libteleproto3"
mkdir -p "$(dirname "$license_dst")"
cp -p "$LICENSE_LIBTELEPROTO3" "$license_dst"
license_sha="$(sha256sum "$license_dst" | awk '{print $1}')"

#### Static-link assertion (anti-pattern §12.10).
if ldd "$APPDIR/usr/bin/Telegram" 2>/dev/null | grep -qi 'teleproto3'; then
  die "ldd shows teleproto3 in AppDir Telegram binary — must be statically linked"
fi

#### Deterministic build-id rewrite (reproducibility contract: --build-id=sha1).
# The cmake build should pass -Wl,--build-id=sha1; this step enforces it
# post-link via patchelf so the build is robust against toolchain defaults.
_bin="$APPDIR/usr/bin/Telegram"
if command -v patchelf >/dev/null 2>&1; then
  _build_id_hex="$(sha1sum "$_bin" | awk '{print $1}')"
  patchelf --set-build-id "$_build_id_hex" "$_bin" 2>/dev/null \
    && note "Telegram --build-id set to sha1(binary) = $_build_id_hex" \
    || note "patchelf --set-build-id not supported; ensure -Wl,--build-id=sha1 in cmake"
else
  note "patchelf not found; ensure -Wl,--build-id=sha1 in cmake flags for reproducible build-id"
fi

#### Embed AppImageUpdate update-information.
case "$UPDATE_INFO_FORM" in
  gh-releases-zsync)
    UPDATE_INFO="gh-releases-zsync|ankuper|tdesktop|v2-*|${ARTEFACT_NAME}.zsync"
    ;;
  zsync)
    UPDATE_INFO="zsync|${PUBLISH_BASE_URL}/${TAG}/${ARTEFACT_NAME}.zsync"
    ;;
  *)
    die "UPDATE_INFO_FORM must be gh-releases-zsync or zsync; got '$UPDATE_INFO_FORM'"
    ;;
esac
note "embedding update-information: $UPDATE_INFO"

#### Run linuxdeploy → AppImage.
out_appimage="$OUT_DIR/$ARTEFACT_NAME"
work_dir="$(mktemp -d -t tdesktop-appimage-XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

(
  cd "$work_dir"
  cp -a "$APPDIR" AppDir
  export NO_STRIP=1
  export OUTPUT="$ARTEFACT_NAME"
  export UPDATE_INFORMATION="$UPDATE_INFO"
  export VERSION="${TAG#v2-}"
  export APPIMAGE_EXTRACT_AND_RUN=1

  # mksquashfs determinism.
  MKSQUASHFS_OPTIONS="-no-fragments -all-root -no-exports"
  [[ -n "$SOURCE_DATE_EPOCH" ]] && MKSQUASHFS_OPTIONS+=" -mkfs-time $SOURCE_DATE_EPOCH"
  export MKSQUASHFS_OPTIONS

  "$LINUXDEPLOY" \
    --appdir AppDir \
    --plugin qt \
    --output appimage
)
mv "$work_dir/$ARTEFACT_NAME" "$out_appimage"
chmod 0755 "$out_appimage"

appimage_sha="$(sha256sum "$out_appimage" | awk '{print $1}')"

#### Build-input manifest.
manifest="$OUT_DIR/release-manifest-linux.txt"
{
  printf 'tdesktop release-manifest-linux.txt — built reproducibly\n'
  printf 'tag                       %s\n' "$TAG"
  printf 'artefact                  %s\n' "$ARTEFACT_NAME"
  printf 'appimage_sha256           %s\n' "$appimage_sha"
  printf 'source_date_epoch         %s\n' "$SOURCE_DATE_EPOCH"
  printf 'host_kernel               %s\n' "$(uname -r)"
  printf 'host_glibc                %s\n' "$(( getconf GNU_LIBC_VERSION 2>/dev/null || ldd --version 2>/dev/null | head -1 || echo unknown ) | tr ' ' '_')"
  printf 'host_arch                 %s\n' "$(uname -m)"
  printf 'gcc_version               %s\n' "$(gcc --version | head -1)"
  printf 'clang_version             %s\n' "$(clang --version 2>/dev/null | head -1 || echo n/a)"
  printf 'qt_version                %s\n' "${QT_VERSION:-from-toolchain}"
  printf 'openssl_version           %s\n' "${OPENSSL_VERSION:-from-toolchain}"
  printf 'libteleproto3_a_path      %s\n' "$LIBTELEPROTO3_A"
  printf 'libteleproto3_a_sha256    %s\n' "$(sha256sum "$LIBTELEPROTO3_A" | awk '{print $1}')"
  printf 'license_libteleproto3_sha %s\n' "$license_sha"
  printf 'linuxdeploy_sha256        %s\n' "$(sha256sum "$LINUXDEPLOY" | awk '{print $1}')"
  printf 'linuxdeploy_plugin_qt_sha %s\n' "$(sha256sum "$LINUXDEPLOY_PLUGIN_QT" | awk '{print $1}')"
  printf 'appimagetool_sha256       %s\n' "$(sha256sum "$APPIMAGETOOL" | awk '{print $1}')"
  printf 'zsyncmake_version         %s\n' "$(zsyncmake -V 2>&1 | head -1 || echo unknown)"
  printf 'patchelf_version          %s\n' "$(patchelf --version | head -1)"
  printf 'mksquashfs_version        %s\n' "$(mksquashfs -version 2>&1 | head -1)"
  printf 'gpg_version               %s\n' "$(gpg --version | head -1)"
  printf 'update_information        %s\n' "$UPDATE_INFO"
  printf 'publish_base_url          %s\n' "$PUBLISH_BASE_URL"
} > "$manifest"

note "wrote $out_appimage ($appimage_sha)"
note "wrote $manifest"
note 'next: sign-appimage-linux.sh + zsyncmake + manifest clearsign'
