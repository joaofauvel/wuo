# Boot Preservation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox syntax.

**Goal:** Preserve UEFI boot order and the existing EFI fallback loader when requested for a full feature upgrade.

**Architecture:** A native PowerShell helper captures a protected per-job snapshot and restores it once the upgrade reaches a verified terminal state. The feature CLI, Setup callbacks and WinRE rollback use that snapshot and expose the result in `wuo status`.

**Tech stack:** Windows PowerShell 5.1, UEFI variables, Python 3.15, pytest and a disposable split-EFI VM.

**Spec:** `docs/superpowers/specs/2026-11-20-feature-upgrade-0.4.1rc1-design.md`

## Global constraints

- The opt-in `--preserve-boot-order` flag is independent of `--backup-drive`.
- Verify the ESP and the original firmware entries before writing. Preserve new entries and the installer-directed intermediate restarts.
- Scope the fallback restore to the original EFI partition and architecture-specific path after identifying the current file as Windows Setup's replacement.
- Run any firmware or real EFI writes only in the disposable lab until verified.

## Native snapshot and restore

Files `src/wuo/feature_boot.ps1` and `tests/test_feature_boot.py`.

- [ ] Write PowerShell-backed tests for retaining new entries, rejecting ambiguous or changed identities, restoring only a proven replacement fallback, and verifying the result after a simulated write failure. Run `uv run --locked pytest -q tests/test_feature_boot.py` and observe the missing behavior.
- [ ] Implement `feature_boot.ps1 -JobPath <path> -Mode Preview|Capture|Restore`. Preview is read-only. Capture writes `boot-order.json` and the optional `boot-fallback.efi` inside the job directory. Restore rejects unsafe paths or identity mismatches, writes `boot-order-result.json` with a status for each operation, and prints JSON to stdout. Restore can be repeated against a verified job. Use Windows-native firmware reads and writes, and a verified system ESP. Keep one-time boot settings under Setup control.
- [ ] Run the tests on Windows with synthetic firmware and a temporary EFI tree. Lint and format the touched Python files, then commit this component.

## Feature job integration

Files `src/wuo/cli.py`, `src/wuo/feature_upgrade.py`, `src/wuo/winre_menu.py` and the existing Setup continuation and rollback files. Tests in `tests/test_feature_upgrade.py` and `tests/test_winre_menu.py`.

- [ ] Add tests for CLI flag forwarding, preview isolation, capture before staging, manifest carriage, warning on missing result and actionable failures. Confirm they fail before adding integration.
- [ ] Add the opt-in argument and wire native capture, protected job assets, and terminal completion. Keep existing jobs compatible and the pending status available until the restoration result can be reported. Export required restoration assets with an external backup when supplied.
- [ ] Rehearse verified completion and rollback in a UEFI split-EFI VM with a distinct first entry and non-Windows fallback. Verify both after cold boot. Record which routes reached a verified result.
- [ ] Run the full Windows suite, Ruff, mypy and build. Review the finished diff before release decisions.

The native helper restored an altered firmware order and a systemd-boot
fallback in the disposable split-EFI VM. The retry reported both unchanged.
Offline readback after a firmware restart matched the original order and the
fallback SHA-256, and the firmware loaded Windows Boot Manager. The full Setup
completion and rollback paths remain separate lab acceptance cases.

Preserve a staged RC1 job until a transition is rehearsed. It contains RC1
scripts and a previously captured backup. Check authorization and claim state
before any conversion or restaging, and verify the original Windows remains
bootable before applying that procedure outside the lab.
