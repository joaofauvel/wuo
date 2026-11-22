"""Command-line entry point."""

import argparse
import asyncio
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, replace
from pathlib import Path

lazy import httpx

from .models import DownloadManifest, Update
lazy from . import bundle, catalog, downloads, feeds, target
lazy from .feature_upgrade import FeatureMedia
lazy from .hook_registry import HookRegistry
lazy from .hook_selection import describe_selection, read_selection, resolve_selection
lazy from .hooks import require_full_upgrade_hook_support
lazy from .update import PreparedUpdates, run_update
lazy from .winre_menu import Menu

_DOWNLOADS = Path("Downloads/WindowsOfflineUpdates")


def _write_updates(updates: list[Update], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps([asdict(update) for update in updates], indent=2))
        return
    if not updates:
        print("No matches on the first Microsoft Catalog results page.")
    for update in updates:
        print(f"{update.id}  {update.title}")
        details = [
            update.product,
            update.architecture or "",
            update.classification,
            update.date,
        ]
        print(f"  {' | '.join(filter(None, details))} | {update.source}")
        if update.files:
            print(f"  {update.route}")
            print(f"  Details: {update.details_url}")
            for file in update.files:
                print(f"  {file.name}\n    {file.url}")


async def _resolve(client: httpx.AsyncClient, update_id: str) -> Update:
    if update_id.startswith("defender-"):
        return feeds.defender(update_id.removeprefix("defender-"))
    return await catalog.show(client, update_id)


async def _update(client: httpx.AsyncClient, args: argparse.Namespace) -> int:
    identity = await asyncio.to_thread(target.read_target, read_loader=False)
    menu = Menu(identity)
    configured = not args.manual and menu.installed
    output = args.output or Path.home() / _DOWNLOADS
    if configured and not args.dry_run:
        allow_restart = not (args.hook or args.profile or args.no_hooks)
        if not await asyncio.to_thread(
            menu.resume,
            allow_restart=allow_restart,
            require_boot_preservation=getattr(args, "preserve_boot_order", False),
        ):
            return 1 if menu.windows_incomplete else 0
    with tempfile.TemporaryDirectory(prefix="wuo-hooks-") as temporary:
        if args.hook or args.profile or args.no_hooks or not menu.installed:
            selected = resolve_selection(args.hook, args.profile, Path(temporary))
        else:
            selected = read_selection(menu.profile)
        await asyncio.to_thread(describe_selection, selected)
        return await _stage_update(
            client, args, identity, menu, configured, output, selected.path
        )


def _confirm_feature_without_backup() -> bool:
    print(
        "Warning: A failed feature upgrade can leave Windows unbootable. "
        "Without a backup drive, wuo has no Windows or EFI backup to restore.",
        file=sys.stderr,
    )
    if sys.stdin is None or not sys.stdin.isatty():
        print(
            "Use an interactive terminal to confirm or pass --backup-drive LETTER:.",
            file=sys.stderr,
        )
        return False
    try:
        return input(
            "Continue without a wuo rollback backup? [y/N] "
        ).strip().casefold() in {
            "y",
            "yes",
        }
    except EOFError:
        return False


async def _stage_update(
    client: httpx.AsyncClient,
    args: argparse.Namespace,
    identity: target.TargetIdentity,
    menu: Menu,
    configured: bool,
    output: Path,
    profile: Path | None,
) -> int:
    iso = getattr(args, "feature_iso", None)
    feature_media = (
        FeatureMedia(
            iso,
            args.iso_sha256,
            rollback=bool(args.backup_drive),
            preserve_boot_order=getattr(args, "preserve_boot_order", False),
            recovery_drive=getattr(args, "recovery_drive", None),
        )
        if iso is not None
        else None
    )
    if args.dry_run and feature_media and feature_media.recovery_drive:
        from .feature_upgrade import feature_recovery_selection

        recovery = await asyncio.to_thread(
            feature_recovery_selection,
            identity,
            feature_media.recovery_drive,
            args.backup_drive,
        )
        print(
            f"Verified independent recovery entry {recovery['id']} "
            f"on the Ventoy drive {feature_media.recovery_drive}."
        )

    async def scan(
        prepared: PreparedUpdates | None = None, *, dry_run: bool = args.dry_run
    ) -> int:
        return await run_update(
            client,
            identity,
            output,
            only=tuple(args.only),
            dry_run=dry_run,
            driver_cache_fallback=args.driver_cache,
            profile=profile,
            extractor=args.extractor,
            prepared=prepared,
            feature_media=feature_media,
        )

    if not configured:
        if getattr(args, "manual", False):
            return await scan()
        result = await scan(PreparedUpdates(output), dry_run=True)
        if args.dry_run:
            return result
        print(
            "Run wuo setup to enable staging and recovery servicing. Use --manual to download packages for manual installation."
        )
        return 1
    if args.dry_run:
        return await scan(PreparedUpdates(menu.root))

    with tempfile.TemporaryDirectory(dir=menu.root, prefix="scan-") as temporary:
        prepared = PreparedUpdates(Path(temporary))
        result = await scan(prepared)
        if prepared.security:
            installed = await asyncio.to_thread(
                menu.install_windows,
                prepared.security,
                profile,
                hooks_explicit=bool(
                    getattr(args, "hook", ())
                    or getattr(args, "profile", None)
                    or getattr(args, "no_hooks", False)
                ),
            )
            if not installed.complete:
                print(
                    "Recovery servicing has not started. Finish the Windows phase first."
                )
                return 1
        if not await asyncio.to_thread(menu.check_windows):
            print(
                "The previous Windows installation phase is still incomplete. Run wuo status and resolve it before entering recovery."
            )
            return 1
        if prepared.manual:
            print(f"{len(prepared.manual)} update(s) still require installation.")
            result = 1
        if not prepared.drivers and not prepared.monthly:
            if prepared.feature is None or feature_media is None:
                print("No update was staged for WinRE.")
                return result
            if result:
                print(
                    "Resolve the other update failures before preparing the full feature upgrade."
                )
                return result
            if feature_media.recovery_drive is None:
                require_full_upgrade_hook_support(read_selection(profile).hooks)
            current = await asyncio.to_thread(target.read_target)
            if replace(current, loader_guid=identity.loader_guid) != identity:
                raise ValueError("The running Windows build changed during the scan.")
            menu = Menu(current)
            if not feature_media.rollback and not _confirm_feature_without_backup():
                print("Feature upgrade canceled before staging.")
                return 1
            if feature_media.recovery_drive is None:
                print(
                    "Preparing Windows Setup. Use Troubleshoot > wuo to continue after preparation."
                )
            else:
                print("Preparing the rollback backup and independent Ventoy recovery.")
            job = await asyncio.to_thread(
                menu.stage_feature,
                feature_media,
                prepared.feature,
                profile,
                backup_drive=args.backup_drive,
            )
            print("Feature upgrade staged.")
            if feature_media.recovery_drive is None:
                await asyncio.to_thread(menu.offer_restart)
            else:
                print(
                    f"Boot Ventoy once and let it select WUO-Recovery-{job.name}.iso automatically. "
                    "Return to Windows and run wuo update after it succeeds."
                )
            return 0
        category = "monthly" if prepared.monthly else "drivers"
        if prepared.feature is not None:
            print(
                "The full feature upgrade will wait for these updates. Run the same command after restarting."
            )
        remaining = (
            len(prepared.monthly) - 1 + bool(prepared.drivers)
            if prepared.monthly
            else 0
        )
        if remaining:
            print(
                "Windows packages are serviced before drivers. After this restart, "
                "run wuo update again to rescan and continue the remaining updates."
            )

        current = await asyncio.to_thread(target.read_target)
        if replace(current, loader_guid=identity.loader_guid) != identity:
            raise ValueError("The running Windows build changed during the scan.")
        menu = Menu(current)
        if category == "drivers":
            source = prepared.directory / "drivers"
            await asyncio.to_thread(
                bundle.prepare_drivers,
                prepared.drivers,
                current,
                source,
                profile=profile,
            )
        else:
            source = prepared.monthly[0]
        await asyncio.to_thread(menu.publish, source)

    print("Update staged.")
    await asyncio.to_thread(menu.offer_restart)
    return result


async def _run(args: argparse.Namespace) -> int:
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0)) as client:
        if args.command == "update":
            return await _update(client, args)
        if args.command == "search":
            updates = await catalog.search(client, args.query)
            updates = [
                item
                for item in updates
                if (args.arch is None or args.arch == item.architecture)
                and (
                    args.product is None
                    or args.product.casefold() in item.product.casefold()
                )
                and (
                    args.kind is None
                    or args.kind.casefold() in item.classification.casefold()
                )
            ]
        elif args.command == "latest":
            if args.defender:
                updates = [feeds.defender(args.arch)]
            elif args.release:
                updates = [await feeds.latest(client, args.release.upper(), args.arch)]
            else:
                raise ValueError(
                    "Supply --release for a cumulative update or use --defender."
                )
        elif args.command == "show":
            updates = [await _resolve(client, args.update_id)]
        elif args.command == "prepare":
            update_id = args.update_id or await asyncio.to_thread(
                bundle.read_update_id, args.download
            )
            selected = await _resolve(client, update_id)
            identity = await asyncio.to_thread(target.read_target)
            plan = await asyncio.to_thread(
                bundle.prepare,
                selected,
                identity,
                args.download,
                args.output,
                profile=args.profile,
                extractor=args.extractor,
            )
            print(
                f"Prepared {selected.kb} for Windows {identity.release} ({identity.build}.{identity.revision})."
            )
            print(f"Package order: {' then '.join(plan.commands)}")
            print(f"Configured registry hooks: {len(plan.hooks)}")
            return 0
        else:
            selected = await _resolve(client, args.update_id)
            print(
                f"Downloading {len(selected.files)} package(s) for {selected.title}",
                file=sys.stderr,
            )
            output = args.output
            if output is None:
                if not downloads.safe_name(selected.id):
                    raise ValueError("The update has an invalid download folder name.")
                output = Path.home() / _DOWNLOADS / selected.id
            result: DownloadManifest = await downloads.download(
                client, selected, output, concurrency=args.jobs
            )
            if args.json:
                print(json.dumps(asdict(result), indent=2))
            else:
                print(f"Saved {len(result.files)} file(s) to {output.resolve()}")
            return 0
    _write_updates(updates, json_output=args.json)
    return 0


def _hooks_command(args: argparse.Namespace) -> int:
    registry = HookRegistry()
    if args.hook_action == "add":
        profiles = registry.add(args.repo, args.name, args.ref)
        print(f"Registered {args.name}. Select a profile with --hook.")
    elif args.hook_action == "refresh":
        profiles = registry.refresh(args.source)
        print(
            "Available profiles refreshed. Saved selections keep their captured contents."
        )
    elif args.hook_action == "remove":
        registry.remove(args.source)
        print(
            f"Removed source {args.source}. Saved profiles keep their captured contents."
        )
        profiles = []
    else:
        profiles = registry.list_profiles()
    for profile in profiles:
        origin = profile.origin
        print(f"{origin.name}  revision={origin.revision}  sha256={origin.sha256}")
        if args.hook_action == "list":
            freshness = registry.check(origin)
            print(f"  Source content: {freshness.state}. {freshness.detail}")
            if freshness.state in {"changed", "removed"}:
                print(
                    f"  Warning: refresh available profiles with wuo hooks refresh {origin.source}."
                )
    if os.name == "nt":
        try:
            menu = Menu(target.read_target(read_loader=False))
            menu.describe_hooks(registry)
        except (ValueError, OSError) as error:
            print(f"Could not read the saved selection: {error}")
    else:
        print("Saved Windows selections are available on Windows through wuo status.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wuo",
        description="Download Windows updates and install supported updates in recovery.",
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    setup = commands.add_parser("setup", help="Add wuo to the recovery menu.")
    setup_hooks = setup.add_mutually_exclusive_group()
    setup_hooks.add_argument(
        "--profile", type=Path, help="Save a local registry-hook profile."
    )
    setup_hooks.add_argument(
        "--hook",
        action="append",
        default=[],
        help="Save a named profile, for example official/usb4. Repeat to combine.",
    )
    setup_hooks.add_argument(
        "--no-hooks", action="store_true", help="Save a selection with no hooks."
    )
    workflow = commands.add_parser(
        "update",
        help="Find and stage updates for this PC.",
    )
    workflow.add_argument(
        "--only",
        action="append",
        default=[],
        choices=(
            "monthly",
            "features",
            "dotnet",
            "drivers",
            "defender",
            "security-platform",
            "other",
        ),
        help="Limit updates to a category. Repeat to include several.",
    )
    workflow.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview planned installation and recovery servicing.",
    )
    workflow.add_argument(
        "--feature-iso",
        type=Path,
        metavar="ISO",
        help="Use a downloaded Microsoft ISO for a full feature upgrade, even without a Windows Update offer.",
    )
    workflow.add_argument(
        "--iso-sha256",
        metavar="SHA256",
        help="Microsoft-published SHA-256 of the feature ISO.",
    )
    workflow.add_argument(
        "--accept-setup-eula",
        action="store_true",
        help="Accept the Windows Setup license terms for the selected media.",
    )
    feature_backup = workflow.add_mutually_exclusive_group()
    feature_backup.add_argument(
        "--no-rollback", action="store_true", help=argparse.SUPPRESS
    )
    feature_backup.add_argument(
        "--backup-drive",
        metavar="LETTER:",
        help="Enable wuo rollback for the feature upgrade using this separate NTFS drive.",
    )
    workflow.add_argument(
        "--preserve-boot-order",
        action="store_true",
        help="Preserve UEFI boot order and the existing EFI fallback loader after a full feature upgrade.",
    )
    workflow.add_argument(
        "--recovery-drive",
        metavar="DRIVE",
        help="Use a separate GPT Ventoy USB drive for protected feature-upgrade hooks and recovery.",
    )
    workflow.add_argument(
        "--driver-cache",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use Windows Update Agent to export drivers (default: enabled).",
    )
    workflow.add_argument(
        "--output",
        type=Path,
        help="Choose a download folder.",
    )
    update_hooks = workflow.add_mutually_exclusive_group()
    update_hooks.add_argument(
        "--profile",
        type=Path,
        help="Use a registry-hook profile for this run.",
    )
    update_hooks.add_argument(
        "--hook",
        action="append",
        default=[],
        help="Use a named profile for this run. Repeat to combine.",
    )
    update_hooks.add_argument(
        "--no-hooks", action="store_true", help="Run this update without hooks."
    )
    workflow.add_argument(
        "--extractor", default="7z.exe", help="Path to the 7-Zip CLI."
    )
    workflow.add_argument(
        "--manual",
        action="store_true",
        help="Download or prepare files for manual servicing.",
    )
    status = commands.add_parser(
        "status", help="Check the staged update or verify the result."
    )
    status.add_argument(
        "--discard",
        action="store_true",
        help="Clear the pending job and keep its files and logs.",
    )
    retry = commands.add_parser(
        "retry-feature",
        help="Restage a failed feature upgrade with its existing rollback backup.",
    )
    retry.add_argument(
        "--dry-run",
        action="store_true",
        help="Check retry eligibility without staging.",
    )
    commands.add_parser("remove", help="Remove wuo from the recovery menu.")
    hook_commands = commands.add_parser(
        "hooks", help="List profiles and manage Git sources."
    )
    hook_actions = hook_commands.add_subparsers(
        dest="hook_action", required=True, metavar="COMMAND"
    )
    hook_actions.add_parser("list", help="Show available and selected hooks.")
    hook_add = hook_actions.add_parser(
        "add", help="Register profiles from a Git repository."
    )
    hook_add.add_argument("repo")
    hook_add.add_argument("--name", required=True, help="Source name.")
    hook_add.add_argument("--ref", default="HEAD", help="Branch or tag to track.")
    hook_refresh = hook_actions.add_parser(
        "refresh", help="Refresh available profiles."
    )
    hook_refresh.add_argument("source", nargs="?")
    hook_remove = hook_actions.add_parser(
        "remove", help="Remove a source from discovery."
    )
    hook_remove.add_argument("source")
    search = commands.add_parser(
        "search", help="Find published Microsoft Catalog updates."
    )
    search.add_argument("query", help="KB number, title, or quoted hardware ID.")
    search.add_argument("--arch", choices=("x64", "arm64", "x86"))
    search.add_argument("--product")
    search.add_argument(
        "--kind", help="Match a Catalog classification such as Drivers."
    )
    show = commands.add_parser("show", description="Show an update and its files.")
    show.add_argument("update_id")
    download = commands.add_parser(
        "download", help="Download all files for a selected update."
    )
    download.add_argument("update_id")
    download.add_argument("--output", type=Path, help="Choose a download folder.")
    download.add_argument("--jobs", type=int, default=3)
    latest = commands.add_parser(
        "latest", description="Find a cumulative or Defender intelligence update."
    )
    latest.add_argument("--release", help="Windows release, for example 25H2.")
    latest.add_argument("--arch", choices=("x64", "arm64", "x86"), default="x64")
    latest.add_argument("--defender", action="store_true")
    commands.add_parser(
        "media", description="Show the Windows Setup media download page."
    )
    prepare = commands.add_parser(
        "prepare", description="Prepare a verified offline servicing bundle."
    )
    prepare.add_argument(
        "--download", type=Path, required=True, help="Folder containing package files."
    )
    prepare.add_argument(
        "--update-id", help="Microsoft Catalog ID when importing existing packages."
    )
    prepare.add_argument(
        "--output", type=Path, required=True, help="New recovery bundle directory."
    )
    prepare.add_argument(
        "--profile", type=Path, help="Optional local registry-hook TOML."
    )
    prepare.add_argument("--extractor", default="7z.exe", help="Path to the 7-Zip CLI.")
    drivers = commands.add_parser(
        "prepare-drivers",
        description="Prepare signed driver exports for offline servicing.",
    )
    drivers.add_argument(
        "--export",
        type=Path,
        action="append",
        required=True,
        help="Driver export directory. Repeat for multiple drivers.",
    )
    drivers.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New bundle directory on the target Windows volume.",
    )
    drivers.add_argument(
        "--profile", type=Path, help="Optional local registry-hook TOML."
    )
    winpe = commands.add_parser(
        "winpe", description="Build a WinPE ISO for a prepared recovery bundle."
    )
    winpe.add_argument("--bundle", type=Path, required=True)
    winpe.add_argument("--output", type=Path, required=True, help="New .iso file.")
    winpe.add_argument(
        "--check-only",
        action="store_true",
        help="Verify in WinPE and pause before servicing.",
    )
    winpe.add_argument(
        "--bootex",
        action="store_true",
        help="Use Windows UEFI CA 2023 boot media with a compatible ADK.",
    )
    verify = commands.add_parser(
        "verify", description="Verify a recovery bundle and optional post-boot state."
    )
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--post-boot", action="store_true")
    for command in (search, show, download, latest):
        command.add_argument(
            "--json", action="store_true", help="Print machine-readable results."
        )
    try:
        args = parser.parse_args(argv)
        if args.command == "update":
            if args.feature_iso is not None:
                if not args.iso_sha256 or not args.accept_setup_eula:
                    workflow.error(
                        "--feature-iso requires --iso-sha256 and --accept-setup-eula"
                    )
                if args.recovery_drive and (
                    not args.backup_drive or not args.preserve_boot_order
                ):
                    workflow.error(
                        "--recovery-drive requires --backup-drive and --preserve-boot-order"
                    )
                preparing = not args.dry_run and (
                    not args.only or "features" in args.only
                )
                if preparing and args.manual:
                    workflow.error(
                        "Use --dry-run to check a feature ISO in manual mode."
                    )
            elif (
                args.iso_sha256
                or args.accept_setup_eula
                or args.no_rollback
                or args.backup_drive
                or args.preserve_boot_order
                or args.recovery_drive
            ):
                workflow.error("ISO and feature recovery options require --feature-iso")
    except SystemExit as result:
        return int(result.code) if isinstance(result.code, int) else 1
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "media":
        print(feeds.WINDOWS_MEDIA)
        return 0
    try:
        if args.command == "hooks":
            return _hooks_command(args)
        if args.command in {"setup", "status", "remove", "retry-feature"}:
            menu = Menu(target.read_target(read_loader=False))
            if args.command == "setup":
                with tempfile.TemporaryDirectory(prefix="wuo-hooks-") as temporary:
                    if menu.installed and not (
                        args.hook or args.profile or args.no_hooks
                    ):
                        selected = read_selection(menu.profile)
                    else:
                        selected = resolve_selection(
                            args.hook, args.profile, Path(temporary)
                        )
                    registry = HookRegistry()
                    print("Hooks selected for future jobs")
                    describe_selection(selected, registry)
                    menu.configure("install", selected.path)
                    menu.describe_pending_hooks(registry)
            elif args.command == "remove":
                menu.remove()
            elif args.command == "retry-feature":
                menu.retry_feature(dry_run=args.dry_run)
            elif args.discard:
                menu.discard()
            else:
                menu.status()
            return 0
        if args.command == "prepare-drivers":
            plan = bundle.prepare_drivers(
                args.export, target.read_target(), args.output, profile=args.profile
            )
            print(
                f"Driver bundle prepared at {args.output} ({len(plan.commands)} INF files)."
            )
            return 0
        if args.command == "winpe":
            from .winpe import build_iso

            build_iso(
                args.bundle, args.output, check_only=args.check_only, bootex=args.bootex
            )
            print(f"Bootable WinPE ISO prepared at {args.output}.")
            return 0
        if args.command == "verify":
            bundle.verify(args.bundle, post_boot=args.post_boot)
            print("Verification passed.")
            return 0
        return asyncio.run(_run(args))
    except (ValueError, OSError, httpx.HTTPError) as error:
        print(f"wuo: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Canceled.", file=sys.stderr)
        return 130
