---
doc_version: 0.1.0-draft
last_updated: 2026-05-09
status: draft
---

> **Operational contract.** This document defines required behaviour for the
> tdesktop Type3 client release flow. Where this document and the build
> pipeline differ, this document wins; the pipeline is corrected, not the
> contract.

# tdesktop Linux WCAG 2.1 AA audit (Story 2-7 / UX-DR19)

This document specifies the release-time WCAG 2.1 AA audit run against
the Linux Type3 build of tdesktop, the targets, the test matrix, the
exemption discipline, and the baseline emission contract.

## §1 Audit targets

The Linux audit covers three views:

1. **Import dialog** — `Telegram/SourceFiles/boxes/connection_box.cpp`
   `ConnectionBox::prepare()` and the inline import-from-link sub-flow.
2. **Proxy list** — same file; the saved-config list with c1/c2/c3 row
   indicators.
3. **C1 indicator widget** — `Telegram/SourceFiles/ui/proxy_indicator_c1.cpp`
   (story 2.5 owner). Tested standalone (`ProxyIndicatorC1::renderForA11y`)
   AND in-context within the proxy list.

## §2 Tool

We use **pa11y** (`pa11y@^7`, JavaScript-based, runs against an
accessibility tree exposed via the AT-SPI 2 bridge). pa11y was chosen
over `axe-linux` because pa11y reads the AT-SPI tree directly without
an embedded browser-engine — Qt widgets present an AT-SPI tree
natively when `QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1` is set, and pa11y
walks that tree.

The pa11y version is pinned in `docs/building-linux.md` §Toolchain
versions (Story 2-7 toolchain section). Bumping pa11y requires
re-running this audit and emitting a fresh baseline.

## §3 Test matrix

The audit runs in a 2 × 2 matrix:

| Locale | Reduced-motion | Required pass |
|--------|----------------|---------------|
| en-US  | off            | yes |
| en-US  | on             | yes |
| fa-IR  | off            | yes |
| fa-IR  | on             | yes |

- **fa-IR** is selected per Epic 2 style-guide §5 RTL-C1 — confirms
  a11y-tree labelling survives glyph-mirroring under
  `qApp->setLayoutDirection(Qt::RightToLeft)`.
- **Reduced motion** is bridged via `QStyleHints::showIsAnimated()` —
  see Epic 2 style-guide §5; UX-DR21 mandates that the reduced-motion
  variant of the C1 indicator (fade-only, no spin/pulse) also passes
  the audit.

## §4 Pre-audit Qt bridge enablement

Without the AT-SPI bridge enabled, the audit produces false-clean
reports — pa11y walks an empty tree and finds zero violations. The
pre-audit step asserts the bridge:

```sh
export QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1
busctl --user list | grep -i accessibility \
  || { echo 'AT-SPI bus not running'; exit 1; }
```

The CI workflow (`a11y-audit-linux.yml`) wraps the audit in `xvfb-run`
with `--auto-servernum` and starts `at-spi-bus-launcher` as a
session-scope process before launching the tdesktop binary.

## §5 Exemption discipline

When pa11y reports a violation:

1. Try to fix it. "Fix it" beats "exempt it" for every violation that
   is not host-app-inherited.
2. If the violation is host-app-inheritance — host font, host theme,
   host contrast tokens (per UX-DR25) — record the exemption in §6
   below with:
   - violation ID
   - WCAG Success Criterion reference (e.g. 1.4.3 Contrast Minimum,
     2.1.1 Keyboard, 4.1.2 Name, Role, Value)
   - current behaviour
   - host-app-inheritance rationale: which host attribute drives the
     observed value, and what would have to change in the host for the
     value to become compliant
3. "We'll fix it later" is **not** a valid exemption. Either fix it or
   record a host-inheritance rationale.

Exempted violations subtract from the baseline-emitted
`wcag_violations` count; the baseline gate is
`wcag_violations - wcag_exempted_with_justification > 0` → fail.

## §6 Violations log

_Populated on each release-tag PR. Below is the v0.1.0 dev-build
state, recorded 2026-05-09 ahead of the first audit run. The first
audit run will replace this section with concrete pa11y output._

### v0.1.0 dev (placeholder)

No audit data yet. The first dev-build audit-run on .lnx
(192.168.30.191) populates this section. Each subsequent release-tag
PR refreshes the section.

Format for each entry:

```
- [WCAG <SC#>] <id> — <view> — <one-line description>
  Current behaviour: <what happens>
  Decision: fix | exempt
  Justification (if exempt): <host-app-inheritance reason>
```

## §7 Baseline emission

The audit emits aggregate-only metrics to
`baselines/2-7-a11y-linux.yml` per Epic 2 style-guide §9 (no per-event
raw data). Schema:

```yaml
wcag_total_checks: integer
wcag_violations: integer
wcag_exempted_with_justification: integer
tool_name: pa11y
tool_version: <semver>
audit_date: YYYY-MM-DD
locale_set: [en-US, fa-IR]
reduced_motion_set: [off, on]
```

Schema is invariant; field-set drift requires an explicit Spec-edit
amendment to this document before merge.

## §8 CI gate

`a11y-audit-linux.yml` runs the audit on every release-tag PR and
fails when `wcag_violations - wcag_exempted_with_justification > 0`.
Permissions: `contents: read` (Epic 1 style-guide §13) — the
workflow does not push, open PRs, or comment on issues.
