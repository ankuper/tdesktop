---
doc_version: 0.1.0-draft
last_updated: 2026-04-30
status: draft
---
> **Operational contract.** This document defines required behaviour for the
> tdesktop Type3 client release flow. Where this document and the build
> pipeline differ, this document wins; the pipeline is corrected, not the
> contract.

# tdesktop ↔ libteleproto3 license-compatibility analysis

## 1. Apache-2.0 ↔ GPLv3 compatibility verdict

The Free Software Foundation lists Apache 2.0 as GPLv3-compatible
(https://www.gnu.org/licenses/license-list.html#apache2). Statically linking
Apache-2.0-licensed `libteleproto3` into GPLv3-licensed `tdesktop` produces
a combined work that downstream consumers receive under GPLv3 by absorption.
The `libteleproto3` object code retains its Apache 2.0 license inside the
combined archive.

**Basis:** The FSF states that Apache 2.0 is compatible with GPLv3 (but not
GPLv2) because Apache 2.0 §3's patent termination clause is permitted under
GPLv3 §7's further-restriction carve-out (see
https://www.gnu.org/licenses/license-list.html#apache2). The combined work
must be distributed under GPLv3 terms; recipients who receive the combined
binary also receive the Apache 2.0 license for the `libteleproto3` component
via the `Resources/LICENSE-libteleproto3` notice file.

## 2. Patent termination clause propagation (Apache 2.0 §3)

Apache 2.0 §3 grants users a perpetual, worldwide, non-exclusive,
no-charge, royalty-free patent license for claims licensable by the
contributor. This grant terminates automatically if the user initiates
patent litigation alleging the licensed work itself (or a contribution
incorporated therein) infringes a patent.

This clause propagates with the lib symbols; tdesktop downstream must
honour it — recorded here for legal traceability. Specifically:

- Any entity that distributes a combined `tdesktop` + `libteleproto3` binary
  retains the obligation to provide the Apache 2.0 patent grant to its users.
- Any entity that sues over `libteleproto3` patent claims loses the patent
  grant for the entire `libteleproto3` codebase.

## 3. Notice obligation (Apache 2.0 §4(d))

The unmodified Apache 2.0 license text MUST ship with derivative works.
`Resources/LICENSE-libteleproto3` is staged into every release artefact:

- `Telegram-x86_64-v2.AppImage` (Linux release, story 2.7)
- `Telegram-Setup-v2.msix` (Windows release, story 2.8)
- `Telegram-v2.dmg` (macOS release, story 2.9)

Forward-citation: stories 2.7 / 2.8 / 2.9 own the per-platform packaging
hook that places this file inside each artefact container.

CI gate (post-build script): asserts the file is present inside each
artefact before the build is considered successful. Implementation deferred
to the platform packaging stories; this document records the contractual
obligation so it cannot be omitted.

## 4. Static-vs-dynamic decision

Static linkage is chosen per Epic 2 anti-pattern §12.10. Two independent
reasons:

1. **Compatibility:** FSF guidance treats Apache-2.0-into-GPLv3 static
   linkage as well-established. Dynamic linkage adds no compatibility
   benefit under this licence combination.
2. **Auditability:** Static linkage makes the AR-S12 nm-audit tractable
   — the linker produces a single binary whose symbol table can be scanned
   for banned host-stack symbols. A dynamic library boundary obscures symbol
   provenance and would require separate auditing of the `.so`/`.dll` at
   every deployment site.

Dynamic linking is therefore rejected for both legal and engineering reasons.
