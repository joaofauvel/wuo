"""Bake a protected feature upgrade's recovery checks into independent WinRE."""

import json
from dataclasses import asdict
from hashlib import sha256
from importlib.resources import files
from re import IGNORECASE, fullmatch
from typing import TYPE_CHECKING
from uuid import UUID

from .recovery import _hook_helpers

if TYPE_CHECKING:
    from .feature_upgrade import FeatureImage
    from .hooks import Hook
    from .target import TargetIdentity


def feature_recovery_hook_digest(hooks: tuple[Hook, ...]) -> str:
    """Identify the exact ordered post actions captured on trusted media."""
    actions = [asdict(hook) for hook in hooks if hook.phase == "post"]
    return sha256(
        json.dumps(actions, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def feature_recovery_receipt(
    job: UUID | str, image: FeatureImage, hooks: tuple[Hook, ...]
) -> bytes:
    job_id = UUID(str(job))
    digest = feature_recovery_hook_digest(hooks)
    return f"v1 {job_id} {digest} {image.build}\r\n".encode("ascii")


def _volume(name: str) -> str:
    match = fullmatch(r"\\\\\?\\Volume\{([0-9a-f-]{36})\}\\", name, IGNORECASE)
    if match is None:
        raise ValueError("A Windows volume name is required for independent recovery.")
    identifier = UUID(match[1])
    if not identifier.int:
        raise ValueError("An empty volume identifier is invalid.")
    return f"\\\\?\\Volume{{{identifier}}}\\"


def _firmware_entry(name: str) -> str:
    if name.startswith("{") and name.endswith("}"):
        name = name[1:-1]
    if (
        fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", name, IGNORECASE)
        is None
    ):
        raise ValueError("An exact BCD firmware identifier is required.")
    identifier = UUID(name)
    if not identifier.int:
        raise ValueError("An empty BCD firmware identifier is invalid.")
    return f"{{{identifier}}}"


def _captured_hooks(hooks: tuple[Hook, ...]) -> str:
    lines: list[str] = []
    for hook in hooks:
        key = (
            r"%HOOK_HIVE%\ControlSet%CS%"
            if hook.scope == "control-set"
            else "%HOOK_HIVE%"
        )
        expected = hex(hook.expected) if hook.expected is not None else ""
        lines.extend(
            (
                rf'set "HOOK_KEY={key}\{hook.key}"',
                f'set "HOOK_NAME={hook.name}"',
                f'set "HOOK_NEW={hook.value:#x}"',
                f'set "HOOK_EXPECTED={expected}"',
                "call :%~1_hook || exit /b 1",
            )
        )
    return "\n".join(lines)


def render_feature_recovery(
    job: UUID | str,
    owner: TargetIdentity,
    image: FeatureImage,
    hooks: tuple[Hook, ...],
    *,
    windows_volume: str,
    efi_volume: str,
    backup_volume: str,
    recovery_entry: str,
    recovery_efi_volume: str,
    recovery_path: str,
    recovery_loader_sha256: str,
    restore_sha256: str,
    rollback_sha256: str,
    windows_entry: str = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
) -> bytes:
    """Render the per-job independent stock WinRE startup script."""
    windows, efi, backup, recovery_efi = map(
        _volume, (windows_volume, efi_volume, backup_volume, recovery_efi_volume)
    )
    if len({windows, efi, backup, recovery_efi}) != 4:
        raise ValueError(
            "The Windows, EFI, backup and recovery volumes must be distinct."
        )
    windows_entry, recovery_entry = map(
        _firmware_entry, (windows_entry, recovery_entry)
    )
    if windows_entry == recovery_entry:
        raise ValueError("Recovery and Windows must use distinct firmware entries.")
    if not fullmatch(
        r"\\EFI(?:\\[A-Za-z0-9_. -]+)+\.efi", recovery_path, IGNORECASE
    ) or {"..", "."}.intersection(recovery_path.split("\\")):
        raise ValueError("Invalid independent recovery EFI loader path.")
    if not all(
        fullmatch(r"[0-9a-fA-F]{64}", digest)
        for digest in (restore_sha256, rollback_sha256, recovery_loader_sha256)
    ):
        raise ValueError(
            "The captured rollback manifest and recovery loaders need SHA-256 digests."
        )
    if (
        not 0 < owner.build < image.build <= 0x7FFFFFFF
        or not 0 <= owner.revision <= 0xFFFFFFFF
        or not 0 <= image.revision <= 0xFFFFFFFF
        or fullmatch(r"[A-Za-z0-9]{1,80}", image.edition) is None
        or image.architecture != owner.architecture
    ):
        raise ValueError(
            "The captured source and replacement Windows builds are invalid."
        )
    post = tuple(hook for hook in hooks if hook.phase == "post")
    for hook in post:
        if (
            fullmatch(
                r"[A-Za-z0-9_. -]{1,90}(?:\\[A-Za-z0-9_. -]{1,90}){0,12}",
                hook.key,
            )
            is None
            or fullmatch(r"[A-Za-z0-9_.-]{1,90}", hook.name) is None
            or hook.scope not in {"control-set", "system"}
            or type(hook.value) is not int
            or not 0 <= hook.value <= 0xFFFFFFFF
            or hook.expected is not None
            and (type(hook.expected) is not int or not 0 <= hook.expected <= 0xFFFFFFFF)
        ):
            raise ValueError("The captured post hook cannot be represented in WinRE.")
    replacements = {
        "JOB": str(UUID(str(job))),
        "MACHINE": str(UUID(owner.machine_guid)),
        "SOURCE_BUILD": str(owner.build),
        "SOURCE_REVISION": hex(owner.revision),
        "TARGET_BUILD": str(image.build),
        "TARGET_REVISION": hex(image.revision),
        "TARGET_EDITION": image.edition,
        "WINDOWS_VOLUME": windows,
        "EFI_VOLUME": efi,
        "BACKUP_VOLUME": backup,
        "WINDOWS_ENTRY": windows_entry,
        "RECOVERY_ENTRY": recovery_entry,
        "RECOVERY_EFI_VOLUME": recovery_efi,
        "RECOVERY_PATH": recovery_path,
        "RECOVERY_LOADER_HASH": recovery_loader_sha256.lower(),
        "ROLLBACK_HASH": rollback_sha256.lower(),
        "RESTORE_HASH": restore_sha256.lower(),
        "RECEIPT": feature_recovery_receipt(job, image, hooks).decode("ascii").strip(),
        "CAPTURED_HOOKS": _captured_hooks(post),
        "HOOK_HELPERS": _hook_helpers(
            r"%TARGET%\Windows\System32\Config\SYSTEM", backup=False
        ).replace(r"%JOB%\hook-value.txt", r"%WORK%\hook-value.txt"),
    }
    template = (
        files("wuo").joinpath("feature_recovery.cmd.in").read_text(encoding="ascii")
    )
    for key, value in replacements.items():
        template = template.replace(f"@@{key}@@", value)
    return template.replace("\n", "\r\n").encode("ascii")
