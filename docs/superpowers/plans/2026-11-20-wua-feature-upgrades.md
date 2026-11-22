# WUA Feature Upgrades Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox syntax.

**Goal:** Continue a genuine, applicable full WUA feature offer through the existing preboot hook and WinRE checks without requiring the user to supply an ISO.

**Architecture:** Probe the exact update ID and revision in a disposable VM first. Reuse deferred Windows Setup if WUA delivers a complete Setup source. Evaluate native WUA installation only if a verifiable precommit gate can be demonstrated.

**Tech stack:** WUA COM APIs, Windows PowerShell, Windows Setup, WinRE and pytest.

**Spec:** `docs/superpowers/specs/2026-11-20-feature-upgrade-0.4.1rc1-design.md`

## Global constraints

- Use a disposable Windows VM and a genuine full WUA offer. Preserve the sealed base image and separate EFI disk.
- Require exact offer identity, verified applicability, existing license and backup consent, a WinRE gate, and verified hooks before the replacement Windows boots.
- Keep the explicit ISO path available for offers whose source or commit gate cannot be verified.

## Identify a usable feature offer and source

- [ ] Clone the retained 25H2 checkpoint into copy-on-write disks and copy firmware and TPM state. Give only the guest network egress. Run the same `Microsoft.Update.Session` search as `wuo`. Record the build, non-sensitive title, identity and revision, `IsDownloaded` and bundled update metadata. Confirm the offer is a full upgrade and avoid installing during discovery.
- [ ] If a full offer is available, WUA downloads only that offer. Try `IUpdate::CopyFromCache` for it and each bundle component. Record whether the copy contains a signed Setup program and a complete, matching Setup image. If no offer is available, record the search result and inspect existing lab sources for a supported older Windows build to test instead.
- [ ] On a disposable clone, verify that a complete source supports a compatibility scan and deferred Setup. If necessary, use a second clone to examine the native WUA installer's actual callback timing and commit gate. Test rejection in that clone before enabling installation in the product.

## Route verified WUA offers

- [ ] Add failing tests for exact offer selection, ambiguous offers, incomplete payload, wrong edition or architecture, absence of readiness proof and preserving the explicit ISO path.
- [ ] Add only the validated WUA path to `src/wuo/feature_upgrade.py`, `src/wuo/update.py` and the applicable native runner. Keep the existing menu and backup authorization. Release any partially downloaded staging files cleanly when validation fails.
- [ ] Verify an actual cross-build update and deliberate hook failure without attaching a target ISO. Run the full Windows suite, Ruff, mypy and build, and review the finished diff.

The retained 25H2 Pro lab found `Windows 11, version 26H2`, update ID
`aa272a56-7dbf-4349-b410-10ae6defc750` revision `1`. The `Upgrades` metadata
reported KB5132061. The exact offer's completed download held about 8.42 GiB
and its cache plan selected KB5121794, a CBS enablement package. The selected
CAB matched the plan's SHA-256 and contained three valid Microsoft catalogs.
The plan's Media and SetupDU sections were empty. This applies to the same
core OS family and provides no full Setup offer for the commit gate test.
The documented prerequisite is KB5124010 or later. A genuine replacement
offer from an earlier Windows release is still needed for the full-upgrade
path. [Microsoft KB5121794](https://support.microsoft.com/en-gb/servicing/os/windows-11/2026/09/kb5121794-feature-update-to-windows-11-version-26h2)

The exact CAB applied through the installed WinRE to a separate, prerequisite-
ready split-EFI guest. The guest cold-booted from 26200.9974 to 26300.9974. The
five USB4 registry values were 0 after boot, and the EFI fallback matched the
baseline hash. This used the validated CAB directly in the lab. Automatic
selection and export of an enablement package from WUA still need integration.
