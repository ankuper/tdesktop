## Build instructions for Linux using Docker

### Prepare folder

Choose a folder for the future build, for example **/home/user/TBuild**. It will be named ***BuildPath*** in the rest of this document. All commands will be launched from Terminal.

### Obtain your API credentials

You will require **api_id** and **api_hash** to access the Telegram API servers. To learn how to obtain them [click here][api_credentials].

### Clone source code and prepare libraries

Install [poetry](https://python-poetry.org), go to ***BuildPath*** and run

    git clone --recursive https://github.com/telegramdesktop/tdesktop.git
    ./tdesktop/Telegram/build/prepare/linux.sh

### Building the project

Go to ***BuildPath*/tdesktop** and run (using [your **api_id** and **api_hash**](#obtain-your-api-credentials))

    docker run --rm -it \
        -u $(id -u) \
        -v "$PWD:/usr/src/tdesktop" \
        tdesktop:centos_env \
        /usr/src/tdesktop/Telegram/build/docker/centos_env/build.sh \
        -D TDESKTOP_API_ID=YOUR_API_ID \
        -D TDESKTOP_API_HASH=YOUR_API_HASH

Or, to create a debug build, run (also using [your **api_id** and **api_hash**](#obtain-your-api-credentials))

    docker run --rm -it \
        -u $(id -u) \
        -v "$PWD:/usr/src/tdesktop" \
        -e CONFIG=Debug \
        tdesktop:centos_env \
        /usr/src/tdesktop/Telegram/build/docker/centos_env/build.sh \
        -D TDESKTOP_API_ID=YOUR_API_ID \
        -D TDESKTOP_API_HASH=YOUR_API_HASH

The built files will be in the `out` directory.

### Visual Studio Code integration

Ensure you've followed the instruction up to the [**Clone source code and prepare libraries**](#clone-source-code-and-prepare-libraries) step at least.

Open the repository in Visual Studio Code, install the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension and add the following to `.vscode/settings.json` (using [your **api_id** and **api_hash**](#obtain-your-api-credentials)):

    {
        "cmake.configureSettings": {
            "TDESKTOP_API_ID": "YOUR_API_ID",
            "TDESKTOP_API_HASH": "YOUR_API_HASH"
        }
    }

After that, choose **Reopen in Container** via the menu triggered by the green button in bottom left corner and you're done.

![Quick actions Status bar item](https://code.visualstudio.com/assets/docs/devcontainers/containers/remote-dev-status-bar.png)

[api_credentials]: api_credentials.md

## Toolchain version pinning (Story 2-7 — AppImage release)

The Story 2-7 reproducible AppImage build (`Telegram/build/release-linux-appimage.sh`)
requires exact-version pins for every input. Two independent CI runs of
the same release tag MUST produce byte-identical `.AppImage`. Bumping
any pin below requires a Spec-edit amendment to this section AND a
fresh dual-CI run that confirms the bump still produces byte-equal
output.

### Pinned versions (v0.1.0 dev-build)

| Tool | Version | Source |
|------|---------|--------|
| GCC (centos_env build container) | `gcc-toolset-12` (12.3.x) | `Telegram/build/docker/centos_env/Dockerfile` |
| Clang (host fallback) | 18.x | Ubuntu 24.04 default |
| Qt | 6.x (host) — pinned via `Telegram/build/qt_version.py` | upstream tag |
| OpenSSL | 3.0.x | distro / centos_env |
| AppImageKit (`appimagetool`) | continuous | `https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage` |
| linuxdeploy | continuous | `https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage` |
| linuxdeploy-plugin-qt | continuous | `https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage` |
| zsync (`zsyncmake`) | 0.6.2 | `apt install zsync` (Ubuntu 24.04+) |
| patchelf | 0.18 | `apt install patchelf` |
| mksquashfs (`squashfs-tools`) | 4.6.1 | `apt install squashfs-tools` |
| GnuPG | 2.4.x | `apt install gnupg` |
| pa11y (Story 2-7 AC#5 a11y audit) | ^7 | `npm install -g pa11y` |

The SHA-256 of each AppImage-toolchain binary
(`appimagetool`, `linuxdeploy`, `linuxdeploy-plugin-qt`) is recorded
in `release-manifest-linux.txt` per release. Manifest divergence is
the gate that catches an upstream-rotation under our feet.

### Reproducibility flags

The release script enforces:

- `SOURCE_DATE_EPOCH` from the tag commit timestamp.
- `LC_ALL=C TZ=UTC umask 022`.
- `mksquashfs -no-fragments -all-root -no-exports -mkfs-time $SOURCE_DATE_EPOCH`.
- `LD --build-id=sha1` (deterministic from input bytes; default
  `--build-id=uuid` reads `/dev/urandom` and breaks reproducibility).
- Sorted file ordering for `rcc` inputs (the cmake/qt layer must
  emit `find ... | sort` rather than relying on `readdir` ordering).

### CI assertion

`.github/workflows/appimage-reproducible.yml` runs the build twice
on two distinct runner classes (`ubuntu-22.04` and `ubuntu-24.04`)
and asserts byte-equality on the resulting `.AppImage` SHA-256 plus
the `release-manifest-linux.txt`. A divergence is a hard fail.

### Bumping a pin

1. Update the table above.
2. Update `release-linux-appimage.sh` if a script-level invocation
   changes (e.g. new linuxdeploy CLI flag).
3. Run `appimage-reproducible.yml` manually via
   `workflow_dispatch` against a synthetic tag.
4. Confirm both runner classes produce byte-equal output.
5. Commit the bump with a Change Log entry citing the SHA-256 of
   each rotated binary.
