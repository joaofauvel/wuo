# Feature upgrades in 0.4.1-rc1

The release candidate will cover two improvements to full Windows feature
upgrades. Users can opt in to preserving their UEFI boot order and existing
third-party EFI fallback loader. When Windows Update Agent (WUA) offers a
compatible full upgrade, `wuo update` can use that offer without asking the
user for an ISO, once a real offer passes the lab checks below.

Both paths use **Troubleshoot → wuo** for authorization and the job's captured
hooks before the replacement Windows installation first boots. The explicit
ISO path remains available for systems where the desired upgrade is absent
from WUA. Standalone enablement packages continue through offline package
servicing.

## Boot order and fallback loader

The selected approach is an opt-in `--preserve-boot-order` flag for full feature
upgrades. The registry hooks run before the first replacement boot, while
firmware restoration needs to wait until Setup has completed its restarts.
Microsoft offers `/AddBootMgrLast` for launches from WinPE. The existing
upgrade launches Setup from Windows.

Before staging, capture the persistent UEFI boot order, the identities of its
entries, and the original architecture-specific fallback file on the EFI
partition Windows Setup uses. Keep the snapshot in the protected job directory
and include it with the portable restore files when a backup drive is supplied.
The flag and `--backup-drive` can be selected independently. A dry run shows
which EFI partition, boot entries, and fallback file are eligible for capture.
If the requested snapshot cannot be verified, stop before staging.

Run restoration automatically after Setup completes successfully or a wuo
rollback restores and verifies the previous installation. On a native Setup
failure, use a verified return to the original Windows installation as the
completion condition. Verify the target installation and EFI partition again
before writing. Setup controls all intermediate restarts and its one-time boot
selection. Restore the saved relative order after matching every original
entry to a unique current entry with the same loader identity. Append new
entries in their current relative order. A missing, ambiguous, or changed
entry blocks writes to the firmware order and is reported in `wuo status`.

Restore the saved fallback bytes only when they came from the same EFI
partition, represented a loader distinct from Windows Boot Manager, and a
verified Windows Setup fallback has replaced them. Scope the successful
upgrade's file write to that one fallback path. Verify the hash after writing
and retain a recoverable copy if the write is interrupted. `wuo status` reports
the results for boot order and fallback, including any manual recovery needed.
Retrying uses the saved job and current identities, so a verified restoration
can be repeated safely.

## Feature offers from Windows Update Agent

Use the exact WUA update ID and revision, downloaded on the Windows installation
that will apply it. Verify applicability again before staging. `wuo update`
automatically considers this route for a full offer selected by the normal scan,
including `--only features`. `--dry-run` reports the selected source and any
checks still needed without staging or installing. Match the target build,
edition, architecture, and system UI language through verified payload metadata
and the staged Windows image. Accept `--backup-drive` and any explicit Setup
license consent for this route without `--feature-iso`. Use WUA's existing
license acceptance or obtain explicit acceptance before accepting new terms.
Apply the same hook selection, backup-drive validation, and confirmation when
a backup drive is omitted as for the ISO route. Continue existing update
ordering and rescan applicability after earlier updates finish. An explicitly
supplied ISO selects the existing media route, with its current checks against
any selected full offer.

First determine whether `CopyFromCache` on a genuine full WUA offer yields a
complete, verifiable Windows Setup source. If it does, use the verified Setup
directory with the existing deferred path and its precommit callback. Validate
the complete source because Microsoft documents that WUA can download only
the payload needed by an individual client.

If the payload needs the native WUA installer, test WUA's ability to install
the exact offer with the per-job Windows Setup custom actions and the same
recovery authorization. The native route needs to demonstrate a gate before
commit, including when a required callback is missing or cannot run. WinRE
must verify the captured job and any requested backup before authorizing it.
Demonstrate that the replacement cannot boot if validation or the hooks fail.
Require evidence of the actual commit gate. Route offers with an unverified
gate to the existing explicit ISO option and report the reason.

## Lab acceptance

- Use a disposable UEFI VM with a genuine full feature offer. The comparison
  run must actually cross Windows builds and preserve apps and a test document.
  Use a split EFI layout for the dual-boot test. Add a distinct test fallback
  and an independent first firmware boot entry, and verify both after a cold
  reboot. Confirm that an added firmware entry survives and that an ambiguous
  or missing entry yields an actionable result.
- Exercise successful upgrades, requested rollback, an intentionally failed
  precommit hook, and a missing or changed backup drive. Observe the captured
  SYSTEM hive values before the first replacement kernel boot and verify the
  original Windows can cold-boot when Setup is rejected.
- Prove the WUA route without attaching or supplying feature media to the
  guest. Use a real WUA full offer and demonstrate that WinRE authorization
  precedes commit. Rehearse the same success and failure behavior with the ISO
  route to catch regressions in shared code.
- If the lab has no full offer, retain the ISO-path evidence and record the
  blocked WUA validation. Release claims for the ISO-free path require a full
  upgrade from a real offer.

The target is one `0.4.1-rc1` containing both verified changes. If the WUA
checks block that route, report what failed and ask before publishing a
release candidate with narrower scope.

[Windows Setup custom actions](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-enable-custom-actions?view=windows-11)

[Windows Setup command-line options](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-command-line-options?view=windows-11)

[Windows Update Agent cache export](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdate-copyfromcache)
