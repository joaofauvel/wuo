# wuo

`wuo` finds applicable updates through Windows Update Agent. It installs security
components in Windows and prepares Windows packages and drivers for installation
from the Windows Recovery Environment (WinRE).

> [!WARNING]
> **Experimental software.** **This tool changes Windows recovery configuration
> and services an offline Windows installation. Failures can leave Windows or
> WinRE unable to boot and may cause data loss.**
> 
> Keep a current, restorable backup of your Windows and EFI partitions, separate
> recovery media, and any BitLocker recovery keys before using setup or applying
> updates. Recovery may require another computer and manual repairs.
> The recovery-menu workflow has been tested in disposable Windows 11 VMs,
> including a layout with Windows and EFI on separate disks. A USB4 external
> Windows installation with Limine dual boot has also completed cumulative and
> driver servicing. This does not establish compatibility with other hardware.
> 
> Hook profiles apply registry changes with system-level privileges. Review the
> profile and confirm that its settings fit your installation before selecting
> it. The USB4 profile changes boot-critical service settings.

## Set up once

Install with `uv tool install wuo`. If `uv`
asks you to update your PATH, run `uv tool update-shell` and reopen PowerShell.
In an administrator PowerShell, run the setup command.

```powershell
wuo setup
```

For one-off commands, use `uvx wuo` in place of `wuo`. From a source checkout,
use `uv run --locked wuo`.

Setup backs up the installed recovery image and adds **wuo**
to a copy of it. If setup fails, it attempts to restore the original image and
registration. If restoration fails, it reports the backup location for manual
recovery.

If your Windows installation needs the USB4 and storage service settings to
boot, select the bundled [USB4 profile](hooks/usb4.toml). Setup saves a copy for
later updates.

```powershell
wuo setup --hook official/usb4
```

Repeat `--hook` to combine profiles. Local TOML files also work:
`wuo setup --profile .\usb4.toml` saves a local profile, and
`wuo update --profile <path>` selects one for a single update.

## Hook profiles and sources

The `official` profiles are bundled with `wuo` and available without fetching a
repository. List profiles, saved selections, source revisions and freshness:

```powershell
wuo hooks list
```

Register a Git repository to make its profiles available. Only regular TOML
files directly under its root `hooks/` directory are read. Registration does
not enable a profile.

```powershell
wuo hooks add <repo> --name vendor
wuo setup --hook vendor/name
```

Add `--ref <branch-or-tag>` when registering a source to track a particular ref.
Repositories can use HTTPS, SSH or a local path. Git is required to register or
refresh sources and to check source freshness. Bundled and saved profiles still
work without Git; freshness checks report when their result is unknown.

Use `wuo update --hook vendor/name` to select a profile for one run, repeating
`--hook` to combine profiles. Without an override, updates use the saved setup
selection. Use `wuo update --no-hooks` to explicitly disable hooks for one run.

Setup, update and status show the effective profiles and their registry changes,
including when no hooks apply. They show a pending job's captured selection
separately from the saved setup selection. Recovery prints the captured registry
changes before applying the job.

```powershell
wuo hooks refresh
wuo hooks refresh vendor
wuo hooks remove vendor
```

Refresh updates available profiles. Saved selections never change automatically;
rerun setup with `--hook` to save a refreshed selection. Removing a source keeps
the saved profile copy. Setup, update and status warn when a selected profile has
changed, was removed, or cannot be checked. A prepared job keeps its captured
profile until it completes or is explicitly discarded.

To change hooks for a pending job, finish it or clear it with
`wuo status --discard` before staging a new job. Hook selection flags stop at
an existing job so that a one-run override cannot restart it with different
settings.

## Install updates

1. In an administrator PowerShell, run `wuo update`. Security components install
   in Windows. If Windows requires a restart, restart normally and run the same
   command again. When `wuo` prepares a recovery job, accept the prompt to restart
   into WinRE.
2. In WinRE, choose **Troubleshoot → wuo**. The tool checks
   and installs the prepared job, then restarts Windows on success.

An existing recovery installation may still show **Windows Offline Update**.
That entry still works. To change its label, finish any pending job and check
`wuo status` to make sure your selected profiles are still available and match
the saved selection. Then run `wuo remove` and repeat `wuo setup` with those
profiles. Keep the existing entry if you need its saved profile copy.

On a dual-boot PC, select your usual Windows entry after the restart. Run
`wuo status` in Windows to check the result. Run `wuo update` again after recovery
to rescan and continue any remaining updates. Windows package jobs precede driver
jobs; the tool checks the new Windows baseline before preparing the next job.

`wuo update` scans all categories that Windows Update Agent offers to this PC.
Use `wuo update --dry-run` to preview without installing. Limit a scan with
`--only monthly`, `--only dotnet`, `--only drivers`, `--only defender`,
`--only security-platform`, or `--only features`. Repeat `--only` to combine them.
Existing Windows Update policies, pauses, and safeguards still affect the offers.

Downloads go to `Downloads\WindowsOfflineUpdates` in your user folder.

To remove the recovery menu entry, run `wuo remove` in an administrator PowerShell.

## Supported updates

- **Drivers.** Recovery jobs use signed drivers exported from Windows Update
  Agent. `wuo` checks the offered revision, hardware, architecture, version, and
  signature. Windows Plug and Play selects the active driver after restart.
- **Cumulative, .NET, and other CBS packages.** Recovery uses standalone Microsoft
  MSU/CAB payloads, their actual package identities and architecture, and native
  DISM servicing. There is no KB or OS-build allowlist. Checkpoint MSUs remain
  together so DISM can find prerequisite packages. Preparation requires `7z.exe`
  on PATH or its path passed with `--extractor`. Missing standalone payloads,
  unidentified metadata, or dependencies whose order cannot be established are
  reported as incomplete.
- **Defender and Windows Security.** The exact offered revisions of Defender
  platform (KB4052623), Windows Security app/service (KB5007651), and Defender
  intelligence with its included engine (KB2267602) install through Windows
  Update Agent. Platform updates precede intelligence. Each result is recorded
  and independently checked; a restart requirement stops the next phase.
- **Feature updates.** Standalone CBS enablement packages can use recovery
  servicing. Full Windows Setup upgrades appear in the scan. See the
  [feature-upgrade instructions](docs/feature-upgrades.md) for checking an ISO
  and using the protected recovery handoff.
- **Other installers.** Downloading a package does not count as installing it.
  Offers without a supported installation route are listed with their files and
  remain incomplete.

Selected registry hooks also run before and after the Windows security phase.
The tool captures the profile, saves SYSTEM backups for both phases, uses the
default control set, and verifies written DWORDs. Post hooks are attempted even
when the native installer fails. It never schedules a Windows restart from this
phase. Results, captured hooks and backups are kept under
`C:\ProgramData\WinOfflineUpdate\menu` on the Windows volume.

## Download manually

Search by KB number, title, or hardware ID. Use the update ID for your Windows
release and architecture to show or download the package.

```powershell
wuo search KB5132061 --arch x64
wuo show 950b2422-28ad-4493-a96c-03725fd0d8c2
wuo download 950b2422-28ad-4493-a96c-03725fd0d8c2
```

Run `wuo update --manual` to download and prepare updates for manual servicing.
See `wuo prepare --help` for the supported cumulative update or
`wuo prepare-drivers --help` for a verified driver export. To archive a staged
or interrupted recovery job, run `wuo status --discard` in an administrator
PowerShell.

If Windows Update offers a driver without an export or standalone package, look
up a signed driver for the reported hardware ID and version from the PC or
device manufacturer. [Recovery validation notes](docs/validation/first-winre-update.md)

Run `wuo --help` to see the main commands.

## License

[GNU General Public License, version 3 or later](LICENSE).
