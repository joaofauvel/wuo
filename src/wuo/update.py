"""Discover applicable updates and prepare their standalone packages."""

import asyncio
import json
import re
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit
from uuid import UUID

import httpx

from . import bundle, catalog, downloads, feeds, target
from .models import Update
from .target import TargetIdentity
lazy from . import driver_cache, feature_upgrade

_UPGRADES = "3689bdc8-b205-4af4-8d4a-a63924c5e9d5"
_ARCH = re.compile(
    r"(?<![^\W_])(x86[-_]64|amd64|x64|aarch64|arm64|x86|i[3-6]86|arm)"
    r"(?:fre)?(?![^\W_])",
    re.IGNORECASE,
)
_ARCH_NAMES = {
    "x86-64": "x64",
    "x86_64": "x64",
    "amd64": "x64",
    "aarch64": "arm64",
    "i386": "x86",
    "i486": "x86",
    "i586": "x86",
    "i686": "x86",
}
_RELEASE = re.compile(r"\b[0-9]{2}H[12]\b", re.IGNORECASE)
_BUILD = re.compile(r"\b(?:10\.0\.)?([0-9]{5})\.([0-9]{3,5})\b")
_KB = re.compile(r"\bKB[0-9]+\b", re.IGNORECASE)
_PACKAGE_VERSION = re.compile(r"\b[0-9]+(?:\.[0-9]+){3}\b")
_DRIVER_RELEASE = re.compile(
    r"Windows 11(?: Client(?: S)?)?,?\s+version\s+([0-9]{2}H[12])( and later)?",
    re.IGNORECASE,
)
_SERVICING = re.compile(
    r"\b(cumulative|security|rollup|servicing stack)\b", re.IGNORECASE
)
_SPECIAL_PACKAGE = re.compile(r"\b(dynamic|preview|setup|safe os)\b", re.IGNORECASE)

_SCAN = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'wuo'
$searcher = $session.CreateUpdateSearcher()
$searcher.Online = $true
$result = $searcher.Search('IsInstalled=0 and IsHidden=0')
$updates = @(
    for ($i = 0; $i -lt $result.Updates.Count; $i++) {
        $update = $result.Updates.Item($i)
        $hardwareId = ''
        if ($update.Type -eq 2) {
            try { $hardwareId = [string]$update.DriverHardwareID } catch {}
        }
        $payloads = @()
        if ($update.Title -match '\bKB5007651\b') {
            try {
                $payloads = @(
                    $components = @($update)
                    for ($j = 0; $j -lt $update.BundledUpdates.Count; $j++) {
                        $components += $update.BundledUpdates.Item($j)
                    }
                    foreach ($component in $components) {
                        for ($j = 0; $j -lt $component.DownloadContents.Count; $j++) {
                            $content = $component.DownloadContents.Item($j)
                            if (!$content.IsDeltaCompressedContent) { [string]$content.DownloadUrl }
                        }
                    }
                )
            } catch {}
        }
        @{
            id = [string]$update.Identity.UpdateID
            revision = [int]$update.Identity.RevisionNumber
            title = [string]$update.Title
            type = [int]$update.Type
            hardware = $hardwareId
            payloads = $payloads
            kb_articles = @(
                for ($j = 0; $j -lt $update.KBArticleIDs.Count; $j++) {
                    [string]$update.KBArticleIDs.Item($j)
                }
            )
            categories = @(
                for ($j = 0; $j -lt $update.Categories.Count; $j++) {
                    [string]$update.Categories.Item($j).CategoryID
                }
            )
        }
    }
)
$hardware = @()
if ($updates.type -contains 2) {
    try {
        $hardware = @(
            Get-CimInstance Win32_PnPEntity -Filter 'Present=TRUE' | ForEach-Object {
                $_.HardwareID
                $_.CompatibleID
            } | Where-Object { $_ }
        )
    } catch {}
}
@{ status = [int]$result.ResultCode; updates = $updates; hardware = $hardware } |
    ConvertTo-Json -Depth 4 -Compress
"""


@dataclass(frozen=True, slots=True)
class Offer:
    id: str
    title: str
    category: str
    hardware_id: str = ""
    hardware_verified: bool = False
    payload_names: tuple[str, ...] = ()
    revision: int | None = None
    kb_articles: tuple[str, ...] = ()


def _builds(title: str) -> set[tuple[int, int]]:
    return {(int(build), int(revision)) for build, revision in _BUILD.findall(title)}


def _category(title: str, kind: int, categories: set[str]) -> str:
    name = title.casefold()
    if kind == 2:
        return "drivers"
    if _UPGRADES in categories or re.fullmatch(
        r"windows 11,? version \d{2}h[12].*", name
    ):
        return "features"
    if "kb5007651" in name or "windows security platform" in name:
        return "security-platform"
    if "defender" in name or re.search(r"\bkb(?:2267602|4052623)\b", name):
        return "defender"
    if ".net" in name or "dotnet" in name:
        return "dotnet"
    if _SERVICING.search(name) and (
        "windows 11" in name
        or "windows 10" in name
        or bool(_builds(name) and _KB.search(name))
    ):
        return "monthly"
    return "other"


def parse_offers(raw: str) -> tuple[list[Offer], str | None]:
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get("status") not in (2, 3):
        raise ValueError("Windows Update Agent scan did not succeed.")
    if not isinstance(data.get("updates"), list):
        raise ValueError("Windows Update Agent returned an invalid offer list.")
    hardware = {item.casefold() for item in _strings(data.get("hardware"))}
    issue = (
        "Windows Update Agent returned partial results."
        if data["status"] == 3
        else None
    )
    offers = {}
    for item in data["updates"]:
        if not isinstance(item, dict):
            raise ValueError("Windows Update Agent returned an invalid offer.")
        update_id = str(UUID(str(item.get("id"))))
        title = item.get("title")
        kind = item.get("type")
        if not isinstance(title, str) or kind not in (1, 2):
            raise ValueError("Windows Update Agent returned an invalid offer.")
        categories = {value.casefold() for value in _strings(item.get("categories"))}
        hardware_id = item.get("hardware")
        hardware_id = hardware_id if isinstance(hardware_id, str) else ""
        revision = item.get("revision")
        kb_numbers = (
            value.strip().upper().removeprefix("KB")
            for value in _strings(item.get("kb_articles"))
        )
        offers[update_id] = Offer(
            update_id,
            title,
            _category(title, kind, categories),
            hardware_id,
            bool(hardware_id) and hardware_id.casefold() in hardware,
            tuple(
                urlsplit(url).path.rsplit("/", 1)[-1]
                for url in _strings(item.get("payloads"))
            ),
            revision
            if isinstance(revision, int) and not isinstance(revision, bool)
            else None,
            tuple(
                dict.fromkeys(
                    f"KB{number}"
                    for number in kb_numbers
                    if re.fullmatch(r"[0-9]+", number)
                )
            ),
        )
    return list(offers.values()), issue


def _strings(items: object) -> list[str]:
    return (
        [item for item in items if isinstance(item, str)]
        if isinstance(items, list)
        else []
    )


def scan_offers(identity: TargetIdentity) -> tuple[list[Offer], str | None]:
    powershell = identity.windows / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", _SCAN],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or "Windows Update Agent scan failed.")
    return parse_offers(result.stdout)


def _architectures(value: str) -> set[str]:
    return {_ARCH_NAMES.get(match, match) for match in _ARCH.findall(value.casefold())}


def _check_driver(offer: Offer) -> None:
    if offer.category == "drivers" and not offer.hardware_verified:
        raise ValueError(
            "The offered driver hardware ID could not be matched to a present device."
        )


def validate_applicability(
    offer: Offer, update: Update, identity: TargetIdentity
) -> Update:
    _check_driver(offer)
    if offer.id != update.id:
        raise ValueError("The package does not match the offered update ID.")
    for title in (offer.title, update.title):
        architectures = _architectures(title)
        if architectures and identity.architecture not in architectures:
            raise ValueError(
                f"The update title targets a different architecture: {title}"
            )
        releases = set(_RELEASE.findall(title.upper()))
        if (
            offer.category != "features"
            and releases
            and identity.release.upper() not in releases
        ):
            raise ValueError(
                f"The update title targets a different Windows release: {title}"
            )
        builds = _builds(title)
        if (
            offer.category == "monthly"
            and builds
            and not any(
                build == identity.build and revision > identity.revision
                for build, revision in builds
            )
        ):
            raise ValueError(
                f"The update title has no newer build for this Windows release: {title}"
            )
    if update.architecture and update.architecture != identity.architecture:
        raise ValueError("The package targets a different architecture.")
    if (
        offer.category == "drivers"
        and update.classification
        and not update.classification.casefold().startswith("drivers")
    ):
        raise ValueError("The Catalog entry is not classified as a driver.")
    files = []
    found_tagged = found_native = False
    for file in update.files:
        architectures = _architectures(file.name)
        if architectures:
            found_tagged = True
            if architectures != {identity.architecture}:
                continue
            found_native = True
        downloads.catalog_download_url(file.url)
        if not downloads.safe_name(file.name):
            raise ValueError(f"Unsafe standalone package name: {file.name}")
        files.append(file)
    if found_tagged and not found_native:
        raise ValueError(
            f"No standalone package matches the {identity.architecture} architecture."
        )
    if not files:
        raise ValueError("No standalone packages are available for this update.")
    if offer.category == "drivers":
        if not update.architecture and any(
            not _architectures(file.name) for file in files
        ):
            raise ValueError(
                "Could not verify the architecture of the offered driver package."
            )
        offered_versions = set(_PACKAGE_VERSION.findall(offer.title))
        if offered_versions and not offered_versions.intersection(
            _PACKAGE_VERSION.findall(update.title)
        ):
            raise ValueError(
                "The standalone driver version differs from the offered driver."
            )
        driver_releases = _DRIVER_RELEASE.findall(update.product)
        if driver_releases and not any(
            identity.release.upper() == release.upper()
            or (later and identity.release.upper() > release.upper())
            for release, later in driver_releases
        ):
            raise ValueError("The Catalog driver does not list this Windows release.")
    if offer.category == "security-platform" and offer.payload_names:
        expected = {name.casefold() for name in offer.payload_names}
        files = [file for file in files if file.name.casefold() in expected]
        if {file.name.casefold() for file in files} != expected:
            raise ValueError(
                "The standalone files differ from the device's Windows Security payload."
            )
    elif offer.category == "security-platform":
        if found_native:
            files = [
                file
                for file in files
                if _architectures(file.name) == {identity.architecture}
            ]
        if len(files) != 1 or not (found_native or update.architecture):
            raise ValueError(
                "Could not establish the architecture of the Windows Security package."
            )
    return replace(update, files=tuple(files))


def _matches_kb(item: Update, offer: Offer, identity: TargetIdentity, kb: str) -> bool:
    if (
        identity.installation_type.casefold() != "client"
        or identity.build < 22000
        or item.kb != kb
        or item.product.casefold() != "windows 11"
        or item.architecture != identity.architecture
        or identity.release.upper() not in _RELEASE.findall(item.title.upper())
        or _category(item.title, 1, set()) != offer.category
        or {flag.casefold() for flag in _SPECIAL_PACKAGE.findall(item.title)}
        != {flag.casefold() for flag in _SPECIAL_PACKAGE.findall(offer.title)}
    ):
        return False
    if offer.category == "monthly":
        offered_builds = {
            (build, rev)
            for build, rev in _builds(offer.title)
            if build == identity.build and rev > identity.revision
        }
        return bool(offered_builds & _builds(item.title))
    return not any(
        flag in item.title.casefold() for flag in ("dynamic update", "setup dynamic")
    )


async def _package(
    client: httpx.AsyncClient, offer: Offer, identity: TargetIdentity
) -> Update:
    _check_driver(offer)
    try:
        selected = await catalog.show(client, offer.id)
    except catalog.SourceError:
        kb = _KB.search(offer.title)
        if kb is None:
            raise
        kb_id = kb.group().upper()
        if offer.category == "defender" and kb_id == "KB2267602":
            selected = await _defender_package(client, offer, identity)
        elif offer.category in {"monthly", "dotnet"}:
            matches = [
                item
                for item in await catalog.search(client, kb_id)
                if _matches_kb(item, offer, identity, kb_id)
            ]
            if len(matches) != 1:
                raise ValueError(
                    f"No unique standalone {kb_id} for Windows {identity.release} {identity.architecture}."
                ) from None
            selected = await catalog.show(client, matches[0].id)
            if not _matches_kb(selected, offer, identity, kb_id):
                raise ValueError(
                    f"The Catalog details do not confirm the matching {kb_id} package."
                ) from None
            return validate_applicability(
                replace(offer, id=matches[0].id), selected, identity
            )
        else:
            raise
    return validate_applicability(offer, selected, identity)


async def _defender_package(
    client: httpx.AsyncClient, offer: Offer, identity: TargetIdentity
) -> Update:
    version = _PACKAGE_VERSION.search(offer.title)
    if version is None:
        raise ValueError(
            "Could not identify the offered Defender intelligence version."
        )
    native = {"x64": "amd64", "arm64": "arm64", "x86": "x86"}[identity.architecture]
    feed = feeds.defender(identity.architecture)
    file = feed.files[0]
    url = file.url
    for _ in range(5):
        downloads.checked_url(url)
        parsed = urlsplit(url)
        if (
            parsed.hostname == "definitionupdates.microsoft.com"
            and parsed.path.startswith("/packages/content/")
        ):
            query = parse_qs(parsed.query)
            if (
                query.get("packageVersion") != [version.group()]
                or query.get("arch") != [native]
                or query.get("packageType") != ["Signatures"]
            ):
                raise ValueError(
                    "The standalone Defender feed does not match the offered version and architecture."
                )
            return replace(
                feed, id=offer.id, title=offer.title, files=(replace(file, url=url),)
            )
        response = await client.head(url, follow_redirects=False)
        if not response.is_redirect or not response.headers.get("Location"):
            break
        url = urljoin(url, response.headers["Location"])
    raise ValueError(
        "Microsoft did not supply a versioned Defender intelligence download."
    )


async def _show_driver_candidates(
    client: httpx.AsyncClient, offer: Offer, identity: TargetIdentity
) -> None:
    if _PACKAGE_VERSION.search(offer.title) is None:
        return
    try:
        candidates = await catalog.search(client, offer.hardware_id)
    except (ValueError, httpx.HTTPError) as error:
        print(f"  Could not search the Catalog for alternatives: {error}")
        return
    seen = set()
    for candidate in candidates:
        if (
            candidate.id == offer.id
            or candidate.title.casefold() != offer.title.casefold()
            or not candidate.classification.casefold().startswith("drivers")
            or not _DRIVER_RELEASE.search(candidate.product)
        ):
            continue
        try:
            details = await catalog.show(client, candidate.id)
            if not _DRIVER_RELEASE.search(details.product):
                continue
            alternative = validate_applicability(
                replace(offer, id=candidate.id), details, identity
            )
        except ValueError, httpx.HTTPError:
            continue
        if not all(
            file.sha256 and file.name.casefold().endswith(".cab")
            for file in alternative.files
        ):
            continue
        digests = frozenset(file.sha256 for file in alternative.files)
        if digests not in seen:
            print(
                f"  Catalog candidate for review: {alternative.id} ({identity.architecture})."
            )
            if alternative.details_url:
                print(f"    {alternative.details_url}")
            seen.add(digests)
    if seen:
        print(
            "  Download a reviewed candidate with wuo download <Catalog ID> --output <directory>."
        )


@dataclass
class ManualUpdate:
    category: str
    title: str
    directory: Path
    route: str


@dataclass
class PreparedUpdates:
    directory: Path
    drivers: list[Path] = field(default_factory=list)
    monthly: list[Path] = field(default_factory=list)
    manual: list[ManualUpdate] = field(default_factory=list)
    security: list[Offer] = field(default_factory=list)
    feature: feature_upgrade.FeatureImage | None = None


async def _export_driver(
    offer: Offer, identity: TargetIdentity, output: Path, dry_run: bool
) -> Path | None:
    revision = driver_cache.check_offer(offer)
    if dry_run:
        print(
            f"  Would export driver revision {revision} through Windows Update Agent."
        )
        return None
    print(
        f"  Exporting driver revision {revision} through Windows Update Agent.",
        flush=True,
    )
    location = await driver_cache.export_driver(offer, identity, output)
    print(f"  Verified driver export in {location}")
    return location


async def _process_offer(
    client: httpx.AsyncClient,
    identity: TargetIdentity,
    output: Path,
    offer: Offer,
    *,
    dry_run: bool,
    driver_cache_fallback: bool,
    profile: Path | None,
    extractor: str,
    prepared: PreparedUpdates | None,
    setup_candidates: list[Offer] | None = None,
) -> bool:
    print(f"\n[{offer.category}] {offer.title} ({offer.id})", flush=True)
    if prepared is not None:
        from .windows_updates import eligible

        if eligible(offer):
            prepared.security.append(offer)
            print(
                "  Install in Windows through this exact Windows Update Agent revision."
            )
            return True
    if offer.category == "drivers" and offer.hardware_id:
        print(f"  Windows Update Agent hardware ID: {offer.hardware_id}")
    tried_driver_cache = False
    try:
        if (
            prepared is not None
            and offer.category == "drivers"
            and driver_cache_fallback
        ):
            tried_driver_cache = True
            try:
                location = await _export_driver(offer, identity, output, dry_run)
            except (ValueError, OSError) as error:
                print(
                    f"  Could not stage a driver through Windows Update Agent: {error}"
                )
            else:
                if location is not None:
                    prepared.drivers.append(location)
                return True
        try:
            selected = await _package(client, offer, identity)
        except catalog.SourceError:
            if (
                setup_candidates is not None
                and feature_upgrade.offered_release(offer, identity) is not None
            ):
                setup_candidates.append(offer)
                return True
            if (
                tried_driver_cache
                or not driver_cache_fallback
                or offer.category != "drivers"
            ):
                raise
            tried_driver_cache = not dry_run
            location = await _export_driver(offer, identity, output, dry_run)
            if location is not None:
                print(
                    "  Manual servicing: use the matching INF listed in manifest.json."
                )
            return True
        if selected.id != offer.id:
            print(f"  Matched {selected.kb} to standalone Catalog entry {selected.id}")
        elif selected.source != "Microsoft Update Catalog":
            print(f"  Using {selected.source}: {selected.title}")
        try:
            bundle.resolve_plan(selected, identity)
        except ValueError:
            automatic = False
        else:
            automatic = True
        if dry_run:
            print(f"  Would download {', '.join(file.name for file in selected.files)}")
            if automatic:
                print("  Would prepare a bundle for WinRE from an elevated terminal.")
        else:
            destination = output / selected.id
            if selected.source == "Microsoft Security Intelligence":
                version = _PACKAGE_VERSION.search(offer.title)
                if version is None:
                    raise ValueError(
                        "Could not identify the offered Defender intelligence version."
                    )
                destination /= version.group()
            if (destination / "manifest.json").exists():
                await asyncio.to_thread(
                    downloads.verify_download, selected, destination
                )
                print(f"  Reused verified packages in {destination}")
            else:
                await downloads.download(client, selected, destination)
                print(f"  Downloaded to {destination}")
            if automatic:
                recovery = (
                    output if prepared is None else prepared.directory
                ) / f"{selected.id}-recovery"
                if recovery.exists():
                    raise ValueError(
                        f"A bundle already exists at {recovery}. Review that job or move the bundle folder to prepare a fresh one."
                    )
                elevated = await asyncio.to_thread(target.read_target)
                if replace(elevated, loader_guid=identity.loader_guid) != identity:
                    raise ValueError(
                        "The running Windows identity changed during the update run."
                    )
                await asyncio.to_thread(
                    bundle.prepare,
                    selected,
                    elevated,
                    destination,
                    recovery,
                    profile=profile,
                    extractor=extractor,
                )
                if prepared is None:
                    print(f"  Prepared recovery bundle in {recovery}")
                    print(
                        "  In WinRE, locate this bundle and identify the Windows and EFI volume letters."
                    )
                    print(
                        '  Run "<bundle path>\\recovery.cmd" check W: S:, then use apply with the same letters.'
                    )
                else:
                    prepared.monthly.append(recovery)
        if not automatic:
            print(f"  Manual servicing: {selected.route}")
            if not dry_run and prepared is not None:
                prepared.manual.append(
                    ManualUpdate(
                        offer.category, selected.title, destination, selected.route
                    )
                )
            if selected.details_url:
                print(f"  Microsoft details: {selected.details_url}")
        return True
    except (OSError, ValueError, httpx.HTTPError) as error:
        print(f"  Needs review: {error}")
        if offer.category == "drivers" and offer.hardware_verified:
            if tried_driver_cache:
                await _show_driver_candidates(client, offer, identity)
            print(
                f"  Check the PC or device manufacturer's signed package for Windows "
                f"{identity.release} {identity.architecture} and the hardware ID above."
            )
        elif offer.category == "features":
            if offer.kb_articles:
                print(f"  Windows Update articles: {', '.join(offer.kb_articles)}")
            if feature_upgrade.offered_release(offer, identity) is not None:
                print(
                    "  Use --dry-run --feature-iso to check compatibility with Microsoft Setup media."
                )
            print(f"  Microsoft Setup media: {feeds.WINDOWS_MEDIA}")
        elif offer.category == "defender":
            print(f"  Security intelligence downloads: {feeds.DEFENDER}")
        return False


async def run_update(
    client: httpx.AsyncClient,
    identity: TargetIdentity,
    output: Path,
    *,
    only: tuple[str, ...] = (),
    dry_run: bool = False,
    driver_cache_fallback: bool = True,
    profile: Path | None = None,
    extractor: str = "7z.exe",
    prepared: PreparedUpdates | None = None,
    feature_media: feature_upgrade.FeatureMedia | None = None,
) -> int:
    if only and "features" not in only:
        feature_media = None
    if feature_media is not None and not dry_run and prepared is None:
        raise ValueError(
            "Preparing a full feature upgrade requires the installed WinRE menu."
        )
    print(
        f"Scanning Windows {identity.release} {identity.architecture} ({identity.build}.{identity.revision}) via Windows Update Agent…",
        flush=True,
    )
    try:
        offers, issue = await asyncio.to_thread(scan_offers, identity)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        offers = []
        issue = f"Could not discover applicable updates: {error}"
    if issue:
        print(issue)
    selected = [offer for offer in offers if not only or offer.category in only]
    if not selected:
        print("No matching offers from this scan.")
        if feature_media is None:
            return int(bool(issue))
    failures = 0
    setup_candidates: list[Offer] | None = [] if feature_media is not None else None
    for offer in selected:
        completed = await _process_offer(
            client,
            identity,
            output,
            offer,
            dry_run=dry_run,
            driver_cache_fallback=driver_cache_fallback,
            profile=profile,
            extractor=extractor,
            prepared=prepared,
            setup_candidates=setup_candidates,
        )
        failures += not completed
    if feature_media is not None:
        from .winre_menu import Menu

        try:
            with Menu(identity).feature_preview():
                image = await feature_upgrade.check_feature(
                    client,
                    identity,
                    setup_candidates or [],
                    feature_media,
                    preview=dry_run,
                )
                if prepared is not None:
                    prepared.feature = image
        except (OSError, ValueError, httpx.HTTPError) as error:
            print(f"Feature compatibility check incomplete: {error}")
            failures += max(1, len(setup_candidates or []))
    print(
        f"\n{len(selected)} offer(s) checked, {failures} lookup, download, or compatibility failure(s)."
    )
    if prepared is not None:
        if prepared.security:
            print(
                f"Ready for Windows installation: {len(prepared.security)} security update(s)."
            )
        print(
            f"Ready for recovery: {len(prepared.drivers)} driver export(s), {len(prepared.monthly)} Windows package job(s)."
        )
        if prepared.manual:
            print("Downloaded only; each update below requires installation:")
            for item in prepared.manual:
                print(f"  [{item.category}] {item.title}")
                print(f"    Files: {item.directory}")
                print(f"    {item.route}")
    iso_only = feature_media is not None and set(only) == {"features"}
    return int(bool(failures or (issue and not iso_only)))
