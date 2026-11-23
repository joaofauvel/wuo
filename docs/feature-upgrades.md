# Feature upgrades from a Windows ISO

## Protected upgrades with post hooks

Use the protected route with an x64 English (United States) Microsoft ISO,
a GPT Ventoy USB drive, and a separate NTFS backup drive. Wuo uses the
generated recovery image to apply the captured post hooks before the upgraded
Windows boots. Keep both drives connected through the upgrade.

Firmware can try another boot entry if the recovery USB is unplugged or
unavailable during startup. If protected recovery reports a failure, use its
restore option before selecting Windows directly.

If an older release installed your WinRE menu, finish any pending job,
run `wuo remove`, and run `wuo setup` with your selected hooks again.

```powershell
wuo update --only features --feature-iso $iso --iso-sha256 $sha256 --accept-setup-eula --backup-drive D: --recovery-drive E: --preserve-boot-order
```

1. Save your work and run the command from administrator PowerShell. Wuo backs
   up Windows and EFI, prepares the recovery image, and reports progress while
   Windows Setup runs. Keep power and both drives connected.
2. Wuo restarts automatically. The recovery image checks access to the original
   Windows, EFI, and backup volumes, then exits and starts the offline phase
   of Windows Setup. After Setup replaces Windows, the image runs again to
   apply and verify the captured post hooks.
3. Run `wuo status` when you return to Windows. It reports the upgrade result and
   restores the original Ventoy configuration after a verified upgrade or rollback.

If the initial recovery check fails, Wuo returns to the original Windows when
it can verify that the original loader is safe to start. If the post hooks
fail after the swap, Wuo holds in recovery. Use the restore command shown
there to restore the saved Windows and EFI files. Restore requires confirmation.
`wuo status` clears an early failure when it can verify that Windows Setup is
idle and the original boot order is restored. The backup and logs are kept.
Use `wuo status --discard` to clear a staged job before Windows Setup starts.

Windows Backup warns about restoring with virtualization-based security enabled.
Microsoft's UEFI revocation policy can prevent old backups or recovery media
from booting. Check the recovery media and backup against your system's policy
before starting. [Microsoft's VBS rollback guidance](https://support.microsoft.com/en-us/servicing/os/windows/2024/07/guidance-for-blocking-rollback-of-virtualization-based-security-vbs-related-security-updates)

## Compatibility preview

The normal `wuo update` scan includes feature upgrades. Use
`wuo update --dry-run --only features` to list just those offers.

The development branch checks whether Windows Setup can keep apps and data
using a downloaded Microsoft ISO. You can supply the ISO even when Windows
Update Agent has no feature offer. Windows Update offers still go through
their normal package checks.
Use an administrator PowerShell and get the SHA-256 for the exact ISO from
the **Verify your download** section of Microsoft's download page.
The preview compares the entire file against the digest you supply and checks
the Setup signature. Use the published digest independently of the copy you
want to verify. [Microsoft Windows 11 downloads](https://www.microsoft.com/en-us/software-download/windows11)

```powershell
wuo update --dry-run --only features --feature-iso 'C:\Downloads\Windows11.iso' --iso-sha256 '<Microsoft SHA-256>' --accept-setup-eula
```

Without a full feature offer, the ISO must contain one newer Windows 11 image
matching the installed edition, architecture and default system UI language.
When previewing against a full feature offer, that image must also match
the offered base build. Setup runs a compatibility scan and can write Panther
logs. The preview stages no
recovery job and requests no restart. `--accept-setup-eula` accepts the
applicable Microsoft software license terms for the scan.

## Opt in to rollback

Add `--backup-drive F:` to enable wuo rollback for that feature upgrade. Choose
a healthy NTFS volume on a disk separate from Windows and EFI. Allow enough
space for the used Windows volume and EFI files. The option also works with
`--dry-run` to show the plan.
Windows Setup retains its own recovery behavior either way.

Without a backup drive, a failed upgrade can leave Windows unbootable with
no wuo backup to restore. Before staging, wuo asks for confirmation in an
interactive terminal. The default answer is No. Noninteractive feature
upgrades require a backup drive.

Before staging, wuo backs up Windows and the Windows EFI files. It puts a
copy of the rollback launcher in
`F:\WUO-Rollback\<job>\recovery\restore.cmd`. WinRE identifies the volumes
by ID and verifies the backup before authorizing Setup. When Windows resumes,
wuo rechecks the backup catalog before committing the upgrade. Keep the drive
connected through both steps.

Under **Troubleshoot → wuo**, a compatible pending rollback is offered for
confirmation. From independent WinRE, use the backup drive's recovery
letter and run `restore.cmd check` to check eligibility before `restore.cmd apply`.

Rollback restores Windows Boot Manager's files and BCD on EFI.

## Preserve the UEFI boot order

Add `--preserve-boot-order` to a full feature upgrade to save the current
firmware boot order and eligible EFI fallback loader. The flag is available
with or without `--backup-drive`. Use `--dry-run` to see the EFI partition,
boot order, and fallback file before staging.

The saved snapshot belongs to the job that captured it. If an older job is
already staged, `wuo status` shows that job and its hooks. Keep the staged
files and backup until you have a tested way to replace the deferred job.

After Setup completes, wuo restores the saved order by matching the original
entries to their current loader identities. It keeps newly added entries.
If Setup replaced an existing third-party fallback with the verified Windows
Boot Manager, wuo restores the captured file. `wuo status` shows the outcome
and identifies entries or files that need manual attention.

## Retry a precommit failure

Use an administrator PowerShell to review a failed legacy feature job.

```powershell
wuo status
wuo retry-feature --dry-run
```

RC4 reports the block for a captured post hook before checking its rollback
backup. Leave such a job unapproved and retain its recovery files. For eligible
jobs without post hooks, the preview checks the current Windows installation
and the original backup catalog for that job.

## Preboot hooks

The required sequence is:

1. Setup applies the replacement Windows installation and finishes the registry
   changes that could overwrite the selected hook values.
2. While that installation is offline, identify and back up its SYSTEM hive,
   resolve its default control set, apply the captured hooks, and verify them.
3. Allow the replacement installation to boot only after those checks succeed.

The original installation, Setup's recovery environment, and the replacement
installation can have different SYSTEM hives. Modifying one does not establish
that the others contain the same values.

## Documented Setup boundaries

Microsoft documents pre-install and pre-commit custom actions before application
and reboot, plus completion actions after Setup finishes. These descriptions do
not establish a callback after the replacement hive's final changes and before
its first boot. A completion action cannot fix a boot dependency that has already
prevented Windows from starting.
[Setup custom actions](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-enable-custom-actions)

`/NoReboot` suppresses the restart after Setup's down-level phase. `/SkipFinalize`
prepares an upgrade without committing; `/Finalize` completes that preparation
and immediately restarts into the offline phase. These options do not by
themselves provide the required handoff after the offline phase.
[Setup command-line options](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-command-line-options)

Registry edits to a staged image, polling for hive files, or changing boot order
at an assumed time are not sufficient evidence of that guarantee. Setup can
perform more work after the edit or replace the boot configuration.

## Validation before using a production installation

Use a disposable VM with a full replacement upgrade, rather than an enablement
package, to record when each new hive is created, loaded, migrated and finalized.
Probe the documented custom actions without changing boot-critical values first.

A proposed handoff must then demonstrate that it stops before the first boot of
the replacement installation, applies the captured profile to the correct hive,
and preserves Setup's ability to continue or roll back. Test failed hooks,
interrupted servicing, unexpected partitions, and Windows/EFI on separate disks.
Failure must leave an accessible recovery route without automatically attempting
the unverified boot.

An enablement package follows the CBS servicing route instead. Its build number
can change without a full replacement upgrade; `wuo` verifies the actual CBS
package identities and applies recovery hooks before restarting Windows.
