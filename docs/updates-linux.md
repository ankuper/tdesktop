---
doc_version: 0.1.0-draft
last_updated: 2026-05-09
status: draft
---

> **Operational contract.** This document defines required behaviour for the
> tdesktop Type3 client release flow. Where this document and the build
> pipeline differ, this document wins; the pipeline is corrected, not the
> contract.

# tdesktop Linux release & update flow (Story 2-7)

This document specifies the v0.1.0 dev-quality Linux release artefact and its
update mechanism. AppImageUpdate is the update carrier; signed manifest +
detached signature on the AppImage form the trust chain. The existing
tdesktop updater (`Telegram/SourceFiles/core/update_checker.cpp`) is the
single updater per AR-G1; on Linux it dispatches to the AppImage path
implemented in `Telegram/SourceFiles/core/update_linux_appimage.{cpp,h}`.

## §1 Update flow

1. **Trigger.** Application launch (`MainWindow::createWindow()`) or
   user-invoked "Check for updates" action in Settings.

2. **AppImageUpdate handshake.** The updater reads the embedded
   `update-information` string from the running AppImage at offset
   `.upd_info` ELF section. The string format (Story 2-7 spec-edit
   divergence §B-10 — substituted for v0.1.0 from the
   `zsync|<URL>` form) is:

   ```
   gh-releases-zsync|ankuper|tdesktop|v2-*|Telegram-x86_64-v2.AppImage.zsync
   ```

3. **Manifest fetch + clearsign verify.** Updater downloads
   `manifest-v2.txt.asc` from the resolved release URL into
   `${XDG_CACHE_HOME:-$HOME/.cache}/Telegram/update/` and runs
   `gpg --verify` against the pinned release-key fingerprint
   (see §pubkey-rotation). Mismatch → §3.

4. **`.zsync` delta fetch.** Updater consumes `Telegram-x86_64-v2.AppImage.zsync`
   and reconstructs the new AppImage by streaming only the changed
   chunks per RFC-zsync. Fetch failure or malformed `.zsync` → §3.

5. **SHA-256 match against signed manifest.** Reconstructed AppImage's
   SHA-256 is matched byte-exact against the `appimage_sha256` field
   in the clearsigned manifest. Mismatch → §3.

6. **Detached PGP signature verify.** Updater downloads
   `Telegram-x86_64-v2.AppImage.sig` and runs
   `gpg --verify Telegram-x86_64-v2.AppImage.sig
   Telegram-x86_64-v2.AppImage` against the same release key.
   Mismatch → §3.

7. **User consent prompt (FR38 — explicit consent, no silent install).**
   Modal dialog with:
   - new version tag (`v2-YYYY-MM-DD-NN`)
   - delta download size (already exposed by AppImageUpdate)
   - "About this update" expandable showing the release-key fingerprint
     for out-of-band cross-check

   Buttons: **Cancel** (default focus) / **Apply update**. Esc cancels;
   Enter does not auto-accept. If the user takes no action for ≥ 24 h
   the prompt is dismissed and the next launch re-shows it. Auto-apply
   after timeout is forbidden.

8. **Atomic replacement.** On consent: `rename(2)` of the new AppImage
   over the running binary's path, followed by `fsync(2)` on the parent
   directory. The running process continues with the old binary in
   memory; the new binary takes effect at next launch. The `.lock`
   advisory file in the cache directory is released last.

## §2 Pubkey rotation

### §current-key (v0.1.0 dev release)

```
fingerprint   1DED 8ADE F19B E7CA C93D  EC57 8816 1B1A 989E F692
long-id       88161B1A989EF692
algorithm     ed25519 (sign + cert) / nistp256 (sign subkey)
expires       2028-05-08
custody       single key, generated 2026-05-09 on .lnx (192.168.30.191);
              passphrase known only to project stakeholder; private
              keyring at /root/tdesktop-release-key/ (encrypted backup
              deferred to v1.0). NOT a long-lived offline master + CI
              subkey scheme — that scheme is documented in §future-rotation
              and adopted at v1.0 public release.
identity      tdesktop Type3 v0.1.0 dev release
              (dev-self-use; rotation deferred to v1.0)
              <anton.afanassiev+tdesktop-release@gmail.com>
```

The fingerprint is also self-referenced in the clearsigned
`manifest-v2.txt.asc` and printed at the bottom of the release-page
README. Three independent locations are the intended cross-check
surface; suspicious users compare them.

### §future-rotation (v1.0 path; not yet adopted)

For v1.0 we adopt the long-lived master + annual-rotated subkey scheme:

- Master key generated offline, never on a CI host; private material
  on a hardware key (YubiKey or equivalent).
- CI-resident signing subkey rotated annually; subkey rotation is
  routine and does not require a publish-side ceremony.
- Key-rotation announcement: publish the new key signed by the OLD
  master for a ≥ 30-day overlap window. During overlap, the manifest
  carries both signatures (clearsigned by both, OR a sidecar `.asc`
  from the new key); clients accept either. After overlap expiry,
  only the new key is accepted.
- Emergency revocation: publish a revocation manifest signed by the
  OLD key listing the compromised fingerprint. Clients refuse to
  update past the last good release until the user explicitly imports
  a new pinned key out-of-band (printed on the project README; also
  echoed in the running app's About dialog).

## §3 Signature-verification failure handling

On any of:

- AppImage SHA-256 mismatches the signed manifest entry
- detached PGP `.sig` fails verification against the pinned release key
- `manifest-v2.txt.asc` clearsign is invalid or signed by a non-pinned key
- malformed `.zsync` (truncated chunk table; missing URL field)
- AppImage `--appimage-validate` returns non-zero
- network-truncated download (ConnectionAborted, mid-chunk EOF, etc.)

the updater MUST:

1. **Refuse the update** before any binary replacement.
2. **Unlink** every file in `${XDG_CACHE_HOME:-$HOME/.cache}/Telegram/update/`
   (manifest, in-progress AppImage, `.sig`, advisory `.lock`).
3. **Surface the generic NFR20 error** via `lng_update_failed_generic`:
   _"Update could not be applied. The current version will continue to
   work. Please try again later or download the update manually from the
   official site."_ The string MUST NOT differentiate failure class —
   no mention of "signature", "key", "verification", "tampered", or any
   token that lets a network adversary distinguish an integrity attack
   from a transient network failure (NFR20).
4. **Leave the running binary intact** — the existing process continues
   without restart.
5. **Log** the failure class to `Logs::Main()` at error level (developer
   diagnostic; never surfaced to UI).

Updating across a signature failure is forbidden — see anti-pattern
[Epic 2 style-guide §12.14](epic-2-style-guide.md#1214-update-across-signature-failure).
The verify-functions' return values gate the replace step: every
`verify_*` call is followed by an early-return on the failure branch
BEFORE any `rename`/`copy`/`fchmodat`/`mv` system call. Reviewers grep
the diff for `verify_*` calls and confirm this pattern.

## §4 Offline-update fallback

When a user cannot rely on the in-app updater (corporate firewall,
distrust of the running binary, paranoia), the manual procedure is:

1. Download the four artefacts from the release page directly via a
   browser:
   - `Telegram-x86_64-v2.AppImage`
   - `Telegram-x86_64-v2.AppImage.sig`
   - `manifest-v2.txt.asc`

   (the `.zsync` is unused in this path)

2. Import the release public key (on first run only):

   ```sh
   curl -fLo tdesktop-release.pub.asc https://github.com/ankuper/tdesktop/raw/dev/.github/tdesktop-v0.1.0-dev-release.pub.asc
   gpg --import tdesktop-release.pub.asc
   gpg --list-keys --with-fingerprint anton.afanassiev+tdesktop-release@gmail.com
   ```

   Confirm the printed fingerprint matches the pinned value in
   §current-key above. If it does not match, **stop** — the update
   may be compromised.

3. Verify the manifest clearsign:

   ```sh
   gpg --verify manifest-v2.txt.asc
   ```

   Output MUST contain the fingerprint from §current-key. If not, stop.

4. Verify the AppImage SHA-256 matches the manifest:

   ```sh
   gpg --output manifest-v2.txt --decrypt manifest-v2.txt.asc 2>/dev/null
   grep '^appimage_sha256' manifest-v2.txt
   sha256sum Telegram-x86_64-v2.AppImage
   ```

   The two SHA-256 values MUST match byte-exact.

5. Verify the detached signature:

   ```sh
   gpg --verify Telegram-x86_64-v2.AppImage.sig Telegram-x86_64-v2.AppImage
   ```

   Output MUST contain the fingerprint from §current-key.

6. Replace the existing AppImage:

   ```sh
   chmod +x Telegram-x86_64-v2.AppImage
   mv Telegram-x86_64-v2.AppImage ~/.local/bin/Telegram
   sync
   ```

   The path `~/.local/bin/Telegram` may be wherever the user keeps the
   running AppImage; substitute as appropriate.

If any step fails, do not proceed. The previously-running binary
continues to work.

## §5 Update cache layout (XDG)

```
${XDG_CACHE_HOME:-$HOME/.cache}/Telegram/update/
├── manifest-v2.txt.asc          # downloaded, clearsign-verified
├── Telegram-x86_64-v2.AppImage  # delta-reconstructed via .zsync
├── Telegram-x86_64-v2.AppImage.sig  # detached signature
└── .lock                        # advisory lock; prevents concurrent updaters
```

On any failure (per §3), every file in the directory MUST be unlinked
before the function returns control to the UI thread. The `.lock` file
is the last to go (released via `flock(LOCK_UN)` then `unlink`).
Failure to unlink is not silently swallowed — surfaced via
`Logs::Main()` at error level.

## §6 Anti-patterns (cross-references)

- §12.4 — telemetry SDKs: forbidden in the binary (gated by
  `ar-s12-nm-audit.yml` — owner story 2-1, read-only consumer here).
- §12.10 — dynamic linking of `libteleproto3`: forbidden; `ldd` against
  the unpacked `usr/bin/Telegram` MUST return no `teleproto3` line.
- §12.13 — ABI version-pin: `_Static_assert` in `teleproto3_bridge.cpp`
  is a compile-time guard; failing builds never reach AppImage assembly.
- §12.14 — update-across-signature-failure: any `verify_*` returning
  failure MUST early-return before any `rename`/`copy`/`fchmodat`/`mv`.
  Diff reviewers grep the patch for this pattern.

## §7 NFR20 generic error string

In `Telegram/SourceFiles/lang/lang_keys.h`:

```c
"lng_update_failed_generic" = "Update could not be applied. The current "
                              "version will continue to work. Please try "
                              "again later or download the update manually "
                              "from the official site."
```

Variants per locale (en/ru/fa/zh) MUST be ban-list-clean (UI ban-list
§4 — seven banned tokens). The string MUST NOT differentiate failure
cause (NFR20). Codegen feed from `spec/ux-strings.yaml` (story 1.4
plumbing) — explicit literal addition for v0.1.0 with TODO marker.

## §8 v0.1.0 dev-quality deviations from public-release norms

This v0.1.0 ships as a dev-quality build (not public-release). The
following deviations are explicit and time-bounded:

- single GPG release key, no offline master + subkey rotation (see
  §future-rotation for the v1.0 plan)
- single distribution channel (GitHub Releases on `ankuper/tdesktop`),
  no CDN
- no public Linux-distribution packaging (snap/flatpak/distro-store);
  AppImage is the only carrier
- no telemetry of update success/failure counts (NFR20 / no-telemetry
  contract preserved)

These deviations are recorded explicitly so a future v1.0 release-cut
worksheet can enumerate them and close them. None are silent
shortcuts; each has a documented escalation path.
