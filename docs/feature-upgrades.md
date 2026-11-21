# Hooks before the first boot of a feature upgrade

The release candidate can prepare a full Windows Setup upgrade from an
ISO and continue it from **Troubleshoot → wuo** in the installed Windows
Recovery Environment (WinRE). The full upgrade and recovery paths have been
rehearsed in a split-EFI VM. Physical Limine setups still require validation.

The `wuo` CLI blocks staging, offering a restart, and retrying a full ISO
job whose profile sets a driver's `Start` to `0` in a post hook. This
includes `official/usb4`. Windows Setup can continue past SafeOS without
a final check of the drivers needed to boot the replacement installation.
`wuo retry-feature --dry-run` reports this block before checking the
backup. ISO compatibility previews still check the media. Keep your boot
hooks enabled for cumulative updates, drivers, and enablement packages.
An already installed WinRE menu can still authorize a job staged by an
earlier release. Leave such a job unapproved and retain its recovery files.

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

If Setup stopped with `0xC19001E3` before the current job ran its precommit
hooks, `wuo retry-feature` can prepare the same ISO again under the same job ID.
It reuses that job's rollback image, keeps the captured post-update hooks and EFI files,
and archives verified callbacks from earlier abandoned jobs.

Use an administrator PowerShell. Keep the ISO and the rollback drive connected.

```powershell
wuo retry-feature --dry-run
wuo retry-feature
wuo status
```

The dry run checks the job, the running Windows installation, and the backup
catalog. The retry requires the boot preservation result to be complete. Once
status reports **Feature upgrade staged**, run `wuo update` to enter recovery
and select **Troubleshoot → wuo**. The existing backup still represents the
original snapshot time.

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
