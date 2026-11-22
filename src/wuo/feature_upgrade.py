"""Check whether Windows Setup can upgrade from a selected ISO."""

import asyncio
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from hashlib import sha256
from importlib.resources import as_file, files
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from uuid import UUID

import httpx
from bs4 import BeautifulSoup

from .recovery import render_feature_precommit
from .target import TargetIdentity, read_target

if TYPE_CHECKING:
    from .hooks import Hook
    from .update import Offer

_RELEASE_HISTORY = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
_RELEASE = re.compile(r"\b[0-9]{2}H[12]\b", re.I)
_HEADING = re.compile(r"Version ([0-9]{2}H[12]) \(OS build ([0-9]+)\)", re.I)


@dataclass(frozen=True, slots=True)
class FeatureMedia:
    iso: Path
    sha256: str
    rollback: bool = False
    preserve_boot_order: bool = False
    recovery_drive: str | None = None


@dataclass(frozen=True, slots=True)
class FeatureImage:
    index: int
    build: int
    revision: int
    edition: str
    architecture: str
    language: str


def feature_setup_assets(
    job: UUID,
    identity: TargetIdentity,
    media: FeatureMedia,
    image: FeatureImage,
    hooks: tuple[Hook, ...],
) -> tuple[bytes, bytes]:
    """Build the request and callback for the protected Windows continuation."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", media.sha256):
        raise ValueError("Supply the ISO's Microsoft-published SHA-256 digest.")
    if image.architecture != identity.architecture:
        raise ValueError("The verified image does not match the running architecture.")
    protected = media.recovery_drive is not None
    if protected and not (media.rollback and media.preserve_boot_order):
        raise ValueError(
            "Protected feature upgrades require backup and boot preservation."
        )
    callback = render_feature_precommit(
        str(job), identity, image, () if protected else hooks, rollback=media.rollback
    ).encode("ascii")
    request = {
        "schema": 2 if protected else 1,
        "id": str(job),
        "machine": str(UUID(identity.machine_guid)),
        "source": f"{identity.build}.{identity.revision}",
        "iso": str(media.iso),
        "sha256": media.sha256.lower(),
        "image": asdict(image),
        "callback_sha256": sha256(callback).hexdigest(),
        "rollback": media.rollback,
    }
    return json.dumps(request, sort_keys=True).encode("ascii"), callback


def render_feature_safeos(
    job: UUID,
    windows_volume: str,
    efi_volume: str,
    recovery_entry: str,
    loader: str,
    recovery_efi_volume: str,
) -> bytes:
    volume = re.compile(
        r"\\\\\?\\Volume\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}\\", re.I
    )
    volumes = {
        path.lower() for path in (windows_volume, efi_volume, recovery_efi_volume)
    }
    if len(volumes) != 3 or any(not volume.fullmatch(path) for path in volumes):
        raise ValueError(
            "The SafeOS gate requires distinct Windows and EFI volume identifiers."
        )
    if not re.fullmatch(r"\\EFI\\Boot\\boot(?:x64|aa64)\.efi", loader, re.I):
        raise ValueError("The SafeOS gate requires a verified removable EFI loader.")
    guid = str(UUID(recovery_entry.strip("{}")))
    if recovery_entry.lower() != f"{{{guid}}}":
        raise ValueError("Invalid recovery firmware application ID.")
    script = files("wuo").joinpath("feature_safeos.cmd.in").read_text(encoding="ascii")
    for key, value in {
        "JOB": str(job),
        "WINDOWS": windows_volume,
        "EFI": efi_volume,
        "RECOVERY_EFI": recovery_efi_volume,
        "RECOVERY": recovery_entry.lower(),
        "LOADER": loader,
    }.items():
        script = script.replace(f"@@{key}@@", value)
    return script.replace("\n", "\r\n").encode("ascii")


def offered_release(offer: Offer, identity: TargetIdentity) -> str | None:
    """Find offers eligible for an explicitly requested Setup preview."""
    if (
        identity.installation_type.casefold() != "client"
        or not _RELEASE.fullmatch(identity.release)
        or offer.category != "features"
        or offer.revision is None
        or offer.revision < 1
        or offer.kb_articles
        or not re.search(r"\bWindows 11\b", offer.title, re.I)
        or re.search(r"\b(KB[0-9]+|enablement)\b", offer.title, re.I)
    ):
        return None
    releases = [match.group() for match in _RELEASE.finditer(offer.title)]
    if len(releases) == 1 and releases[0].upper() > identity.release.upper():
        return releases[0].upper()
    return None


def select_offer(offers: list[Offer], identity: TargetIdentity) -> tuple[Offer, str]:
    candidates = [
        (offer, release)
        for offer in offers
        if (release := offered_release(offer, identity)) is not None
    ]
    if not candidates:
        raise ValueError("No eligible Windows 11 feature offer for a Setup preview.")
    if len(candidates) != 1:
        raise ValueError(
            "Multiple Windows Setup preview candidates matched this installation."
        )
    return candidates[0]


def release_build(
    history: str, offer: Offer, release: str, identity: TargetIdentity
) -> int:
    builds = set()
    for heading in BeautifulSoup(history, "html.parser").find_all(
        ["strong", "summary", "h2", "h3", "h4"]
    ):
        match = _HEADING.fullmatch(heading.get_text(" ", strip=True))
        if match and match[1].upper() == release:
            builds.add(int(match[2]))
    if len(builds) != 1:
        raise ValueError(
            f"Could not confirm the Windows {release} base build with Microsoft."
        )
    build = builds.pop()
    if build <= identity.build:
        raise ValueError(f"Windows {release} does not have a newer base build.")
    explicit = {
        int(value) for value in re.findall(r"\b([0-9]{5})\.[0-9]+\b", offer.title)
    }
    if explicit and explicit != {build}:
        raise ValueError(
            "The offer specifies a different base build from release history."
        )
    return build


def require_scan_success(code: int) -> None:
    code &= 0xFFFFFFFF
    if code == 0xC1900210:
        return
    message = {
        0xC1900200: "this device does not meet the upgrade requirements",
        0xC1900204: "Setup cannot keep apps and data",
        0xC1900208: "Setup found a compatibility block",
        0xC190020E: "Setup needs more free disk space",
        0xC1900215: "Setup could not select a matching Windows image",
    }.get(code, "Setup did not confirm compatibility")
    raise ValueError(f"{message} (0x{code:08X}). Check the Windows Setup Panther logs.")


def _run_media(
    identity: TargetIdentity,
    iso: Path,
    digest: str,
    build: int | None,
    *,
    expected: FeatureImage | None = None,
    retry_job: str | None = None,
) -> FeatureImage:
    iso = iso.resolve(strict=True)
    if (
        not re.fullmatch(r"[A-Za-z]:", iso.drive)
        or iso.suffix.casefold() != ".iso"
        or not iso.is_file()
    ):
        raise ValueError("Supply a local Microsoft Windows installation ISO.")
    settings = {
        "WUO_FEATURE_ISO": str(iso),
        "WUO_FEATURE_SHA256": digest,
        "WUO_FEATURE_SOURCE": f"{identity.build}.{identity.revision}",
        "WUO_FEATURE_BUILD": "" if build is None else str(build),
        "WUO_FEATURE_ARCH": identity.architecture,
    }
    operation = "feature compatibility check"
    arguments = []
    if expected is not None:
        operation = "deferred feature preparation"
        arguments.append("-Prepare")
        if retry_job is not None:
            arguments.extend(("-RetryPrepareJob", retry_job))
        settings.update(
            WUO_FEATURE_INDEX=str(expected.index),
            WUO_FEATURE_REVISION=str(expected.revision),
            WUO_FEATURE_EDITION=expected.edition,
            WUO_FEATURE_LANGUAGE=expected.language,
        )
    report = json.loads(
        _run_native(identity, "feature_upgrade.ps1", operation, arguments, settings)
    )
    if (
        not isinstance(report, dict)
        or type(report.get("setup_code")) is not int
        or type(report.get("index")) is not int
        or report["index"] < 1
        or type(report.get("revision")) is not int
        or report["revision"] < 0
        or type(report.get("build")) is not int
        or report["build"] <= identity.build
        or (build is not None and report["build"] != build)
        or report.get("architecture") != identity.architecture
        or not isinstance(report.get("edition"), str)
        or not isinstance(report.get("language"), str)
    ):
        raise ValueError("The native feature check returned an invalid result.")
    image = FeatureImage(
        index=report["index"],
        build=report["build"],
        revision=report["revision"],
        edition=report["edition"],
        architecture=report["architecture"],
        language=report["language"],
    )
    if expected is None:
        require_scan_success(report["setup_code"])
    elif report["setup_code"] != 0 or image != expected:
        raise ValueError("Windows Setup did not prepare the verified image.")
    print(
        f"  Image {image.index}, {image.edition}, {image.architecture}, "
        f"{image.language}, build {image.build}.{image.revision}."
    )
    return image


def _run_native(
    identity: TargetIdentity,
    filename: str,
    operation: str,
    arguments: list[str],
    settings: dict[str, str],
) -> str:
    # Use the native PowerShell modules even from PowerShell 7 or a 32-bit caller.
    native = identity.windows / "Sysnative"
    if not native.is_dir():
        native = identity.windows / "System32"
    powershell = native / "WindowsPowerShell/v1.0/powershell.exe"
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper() != "PSMODULEPATH"
    }
    with (
        as_file(files("wuo").joinpath(filename)) as script,
        subprocess.Popen(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script,
                *arguments,
            ],
            env={**environment, **settings},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
        ) as process,
    ):
        while True:
            try:
                stdout, stderr = process.communicate(timeout=30)
                break
            except subprocess.TimeoutExpired:
                print(f"The {operation} is still running…", flush=True)
    if process.returncode:
        raise ValueError(stderr.strip() or f"The native {operation} failed.")
    return stdout


def feature_boot(
    identity: TargetIdentity,
    mode: Literal["Preview", "Capture"],
    job: Path | None = None,
) -> dict[str, object]:
    arguments = ["-Mode", mode]
    if job is not None:
        arguments.extend(("-JobPath", str(job)))
    report = json.loads(
        _run_native(identity, "feature_boot.ps1", "UEFI boot snapshot", arguments, {})
    )
    if not isinstance(report, dict) or report.get("schema") != 1:
        raise ValueError("The UEFI boot snapshot could not be verified.")
    return report


def feature_recovery_selection(
    identity: TargetIdentity, recovery_drive: str, backup_drive: str
) -> dict[str, object]:
    for drive in (recovery_drive, backup_drive):
        if not re.fullmatch(r"[A-Z]:", drive, re.I):
            raise ValueError(
                "Specify the Ventoy and backup drive letters as E: and D:."
            )
    report = json.loads(
        _run_native(
            identity,
            "feature_boot.ps1",
            "independent recovery discovery",
            [
                "-Mode",
                "Recovery",
                "-RecoveryDrive",
                recovery_drive.upper(),
                "-BackupDrive",
                backup_drive.upper(),
            ],
            {},
        )
    )
    if (
        not isinstance(report, dict)
        or report.get("schema") != 1
        or not isinstance(report.get("windows_entry"), dict)
        or any(
            not isinstance(report.get(key), str)
            for key in (
                "id",
                "identity",
                "bcd_id",
                "loader",
                "loader_sha256",
                "efi",
                "efi_volume",
                "media",
                "media_volume",
            )
        )
    ):
        raise ValueError(
            "The independent firmware recovery entry could not be verified."
        )
    return report


def prepare_independent_recovery(
    identity: TargetIdentity,
    media: FeatureMedia,
    image: FeatureImage,
    job: Path,
    hooks: tuple[Hook, ...],
    selection: dict[str, object],
    rollback: bytes,
) -> dict[str, object]:
    from .feature_media import build_recovery_iso
    from .feature_recovery import feature_recovery_receipt, render_feature_recovery
    from .feature_ventoy import deploy_recovery_iso

    if image.architecture != "x64" or image.language.lower() != "en-us":
        raise ValueError(
            "The protected recovery image currently requires x64 en-US media."
        )
    job_id = UUID(job.name)
    volumes = json.loads(rollback)
    restore = job / "restore.cmd"
    receipt = feature_recovery_receipt(job_id, image, hooks)
    runner = render_feature_recovery(
        job_id,
        identity,
        image,
        hooks,
        windows_volume=volumes["windows"],
        efi_volume=volumes["efi"],
        backup_volume=volumes["volume"],
        recovery_entry=str(selection["bcd_id"]),
        recovery_path=str(selection["loader"]),
        recovery_efi_volume=str(selection["efi_volume"]),
        recovery_loader_sha256=str(selection["loader_sha256"]),
        restore_sha256=sha256(restore.read_bytes()).hexdigest(),
        rollback_sha256=sha256(rollback).hexdigest(),
    )
    wrapper = render_feature_safeos(
        job_id,
        volumes["windows"],
        volumes["efi"],
        str(selection["bcd_id"]),
        str(selection["loader"]),
        str(selection["efi_volume"]),
    )
    helper = files("wuo").joinpath("feature_safeos.ps1").read_bytes()
    (job / "feature_safeos.ps1").write_bytes(helper)
    (job / "feature_safeos.cmd").write_bytes(wrapper)
    (job / "independent-preflight.sha256").write_bytes(
        (sha256(receipt).hexdigest() + "\r\n").encode("ascii")
    )
    local_iso = job / "feature-recovery.iso"
    digest = build_recovery_iso(
        media.iso, media.sha256, local_iso, {"start.cmd": runner}, index=image.index
    )
    deployment = job / "ventoy-state.json"
    deploy_recovery_iso(
        Path(str(selection["media_volume"])), local_iso, digest, job_id, deployment
    )
    ventoy = json.loads(deployment.read_bytes())
    return {
        "entry": selection,
        "receipt": receipt.decode("ascii").removesuffix("\r\n"),
        "iso_sha256": digest,
        "config_sha256": ventoy["config_sha256"],
        "helper_sha256": sha256(helper).hexdigest(),
        "wrapper_sha256": sha256(wrapper).hexdigest(),
    }


def backup_feature(
    identity: TargetIdentity, job: UUID, drive: str
) -> tuple[bytes, Path]:
    """Snapshot Windows and the active EFI files before any Setup preparation."""
    if not re.fullmatch(r"[A-Z]:", drive, re.I | re.ASCII):
        raise ValueError("Select a local rollback drive letter, such as E:.")
    source = f"{identity.build}.{identity.revision}"
    machine = str(UUID(identity.machine_guid))
    stdout = _run_native(
        identity,
        "feature_backup.ps1",
        "feature rollback backup",
        [
            "-Job",
            str(job),
            "-Machine",
            machine,
            "-SourceBuild",
            source,
            "-BackupDrive",
            drive.upper(),
        ],
        {},
    )
    report = json.loads(stdout)
    volume = report.get("volume") if isinstance(report, dict) else None
    if (
        not isinstance(report, dict)
        or report.get("schema") != 1
        or report.get("id") != str(job)
        or report.get("machine") != machine
        or report.get("source") != source
        or not re.fullmatch(
            r"[0-9]{2}/[0-9]{2}/[0-9]{4}-[0-9]{2}:[0-9]{2}", str(report.get("catalog"))
        )
        or not isinstance(report.get("boot_files"), list)
        or not report["boot_files"]
        or not isinstance(volume, str)
        or not re.fullmatch(
            r"\\\\\?\\Volume\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}\\",
            volume,
            re.I | re.ASCII,
        )
    ):
        raise ValueError("The native feature backup returned an invalid receipt.")
    snapshot = Path(volume) / "WUO-Rollback" / str(job)
    receipt = (snapshot / "rollback.json").read_bytes()
    if json.loads(receipt) != report:
        raise ValueError(
            "The saved feature backup receipt does not match the verified catalog."
        )
    return receipt, snapshot


def _scan_media(
    identity: TargetIdentity, iso: Path, digest: str, build: int | None
) -> FeatureImage:
    return _run_media(identity, iso, digest, build)


def prepare_media(
    identity: TargetIdentity,
    media: FeatureMedia,
    image: FeatureImage,
    *,
    retry_job: str | None = None,
) -> FeatureImage:
    """Prepare the verified image in Windows without committing the upgrade."""
    if image.build <= identity.build or image.architecture != identity.architecture:
        raise ValueError(
            "The verified feature image does not match the running Windows."
        )
    return _run_media(
        identity,
        media.iso,
        media.sha256.lower(),
        image.build,
        expected=image,
        retry_job=retry_job,
    )


def check_feature_retry(identity: TargetIdentity, job: str, *, staged: bool) -> None:
    arguments = ["-CheckRetryJob", job]
    if staged:
        arguments.append("-StagedRetry")
    _run_native(
        identity,
        "feature_upgrade.ps1",
        "feature retry validation",
        arguments,
        {},
    )


async def check_feature(
    client: httpx.AsyncClient,
    identity: TargetIdentity,
    offers: list[Offer],
    media: FeatureMedia,
    *,
    preview: bool = True,
) -> FeatureImage:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", media.sha256):
        raise ValueError("Supply the ISO's Microsoft-published SHA-256 digest.")
    if identity.installation_type.casefold() != "client" or identity.build < 22000:
        raise ValueError("The ISO compatibility preview requires Windows 11 client.")
    build = None
    if offers:
        offer, release = select_offer(offers, identity)
        response = await client.get(_RELEASE_HISTORY)
        response.raise_for_status()
        build = release_build(response.text, offer, release, identity)
    if await asyncio.to_thread(read_target, read_loader=False) != identity:
        raise ValueError(
            "The running Windows identity changed during the feature check."
        )
    if media.rollback:
        print("  The feature upgrade includes a wuo rollback backup.")
    else:
        print("  Add --backup-drive to create a wuo rollback backup.")
    if preview and media.preserve_boot_order:
        boot = await asyncio.to_thread(feature_boot, identity, "Preview")
        print(f"  EFI partition: {boot['esp']}")
        entries = boot["entries"]
        if isinstance(entries, list):
            print(
                "  UEFI order: " + ", ".join(str(entry["label"]) for entry in entries)
            )
        print(f"  EFI fallback: {boot['fallback_path']} ({boot['fallback_state']})")
    if build is None:
        print(
            "Checking explicitly supplied media without a Windows Update feature offer."
        )
    print("Checking the ISO and running Windows Setup compatibility scan…", flush=True)
    image = await asyncio.to_thread(
        _scan_media, identity, media.iso, media.sha256.lower(), build
    )
    print("Windows Setup confirmed compatibility with keeping apps and data.")
    if preview:
        print(
            "Feature upgrade check only. No installation or recovery job was started."
        )
    return image
