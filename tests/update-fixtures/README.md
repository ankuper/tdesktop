# Story 2-7 update-fixture harness

Fixtures consumed by `tests/test-update-failure-linux.sh` (AC#4 — five
poisoned scenarios A–E) and `tests/test-update-success-linux.sh`
(positive counterpart).

## Layout

The harness mints fixtures dynamically at run-time so binary inputs do
not bloat the repo. Static inputs:

- `unsigned-publish-manifest.txt` — publish-manifest template, fields
  filled in by the harness.
- `wrong-key.gpg` — armoured **untrusted** key generated on first run
  (different from the pinned release key). Used for fixtures B + C.

## Trust roots

- **Pinned release key:** `1DED8ADEF19BE7CAC93DEC5788161B1A989EF692`
  (v0.1.0 dev release; see `docs/updates-linux.md §current-key`).
- **Untrusted key:** `wrong-key.gpg`, generated dynamically per-run on
  first invocation; not registered in the helper's GPG_HOMEDIR.

Both keyrings are scoped to `tests/_workspace/gnupg-{release,wrong}/`
during the run; cleaned up at the end. The release-keyring import on
the test box must be primed once via:

```sh
gpg --homedir tests/_workspace/gnupg-release --import \
    /root/tdesktop-release-key/tdesktop-v0.1.0-dev-release.pub.asc
echo '1DED8ADEF19BE7CAC93DEC5788161B1A989EF692:6:' \
  | gpg --homedir tests/_workspace/gnupg-release --import-ownertrust
```

The harness does this automatically when run on a box with the dev
release key present at `/root/tdesktop-release-key/`.
