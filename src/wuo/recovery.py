"""Render a bounded stock WinRE recovery job."""

import json
from importlib.resources import files
from pathlib import PureWindowsPath
from re import fullmatch
from typing import TYPE_CHECKING
from uuid import UUID

from .downloads import safe_name

if TYPE_CHECKING:
    from .bundle import BundlePlan
    from .feature_upgrade import FeatureImage
    from .hooks import Hook
    from .target import TargetIdentity


def _hook_lines(
    hooks: tuple[Hook, ...], *, revert_on_failure: bool = False, live: bool = False
) -> str:
    if not hooks:
        return "exit /b 0"
    lines = ["call :open_hook_hive || exit /b 1"]
    for operation in ("inspect", "write"):
        for index, hook in enumerate(hooks, 1):
            path = "%HOOK_HIVE%"
            if hook.scope == "control-set":
                path += r"\ControlSet%CS%"
            expected = hex(hook.expected) if hook.expected is not None else ""
            lines.extend(
                (
                    rf'set "HOOK_KEY={path}\{hook.key}"',
                    f'set "HOOK_NAME={hook.name}"',
                    f'set "HOOK_NEW={hook.value:#x}"',
                    f'set "HOOK_EXPECTED={expected}"',
                )
            )
            if revert_on_failure and operation == "write":
                lines.append(f"call :write_hook || goto revert_{index}")
            else:
                lines.append(f"call :{operation}_hook || goto hook_failed")
            if revert_on_failure and operation == "inspect":
                lines.append(f'set "ORIGINAL_{index}=%ACTUAL%"')
    if not live:
        lines.append(
            r'"%SYS%\reg.exe" unload "%HOOK_HIVE%" >>"%LOG%" 2>&1 || exit /b 1'
        )
    lines.append("exit /b 0")
    if revert_on_failure:
        for index, hook in reversed(list(enumerate(hooks, 1))):
            path = "%HOOK_HIVE%"
            if hook.scope == "control-set":
                path += r"\ControlSet%CS%"
            lines.extend(
                (
                    f":revert_{index}",
                    rf'set "HOOK_KEY={path}\{hook.key}"',
                    f'set "HOOK_NAME={hook.name}"',
                    f'set "HOOK_NEW=%ORIGINAL_{index}%"',
                    'call :write_hook || set "RESTORE_FAILED=1"',
                )
            )
        lines.extend(
            (
                r'if defined RESTORE_FAILED >>"%LOG%" echo The original hook values could not all be restored.',
                "goto hook_failed",
            )
        )
    return "\n".join(lines)


def _hook_helpers(system_hive: str | None, *, backup: bool) -> str:
    template = (
        files("wuo").joinpath("registry_hooks.cmd.in").read_text(encoding="ascii")
    )
    backup_line = (
        r'"%SYS%\reg.exe" save "%HOOK_HIVE%" "%JOB%\%PHASE%-SYSTEM.hiv"'
        r' >>"%LOG%" 2>&1 || goto hook_failed' + "\n"
        if backup
        else ""
    )
    mount = (
        rf'"%SYS%\reg.exe" load "%HOOK_HIVE%" "{system_hive}" >>"%LOG%" 2>&1 || exit /b 1'
        if system_hive is not None
        else ""
    )
    unmount = (
        r'"%SYS%\reg.exe" unload "%HOOK_HIVE%" >>"%LOG%" 2>&1'
        if system_hive is not None
        else ""
    )
    return (
        template.removesuffix("\n")
        .replace("@@MOUNT@@", mount)
        .replace("@@UNMOUNT@@", unmount)
        .replace("@@BACKUP_LINE@@", backup_line)
    )


def render_feature_precommit(
    job: str,
    owner: TargetIdentity,
    image: FeatureImage,
    hooks: tuple[Hook, ...],
    *,
    rollback: bool,
) -> str:
    """Render the Windows Setup callback that checks and edits staged NewOS."""
    if not fullmatch(r"[A-Za-z0-9]{1,80}", image.edition):
        raise ValueError("Invalid Windows Setup image edition.")
    if image.build <= owner.build or not 0 <= image.revision <= 0xFFFFFFFF:
        raise ValueError("Invalid Windows Setup target build or revision.")
    template = (
        files("wuo").joinpath("feature_precommit.cmd.in").read_text(encoding="ascii")
    )
    replacements = {
        "JOB": str(UUID(job)),
        "MACHINE": str(UUID(owner.machine_guid)),
        "SOURCE_BUILD": str(owner.build),
        "SOURCE_REVISION": hex(owner.revision),
        "TARGET_BUILD": str(image.build),
        "TARGET_REVISION": hex(image.revision),
        "TARGET_EDITION": image.edition,
        "HOOKS": _hook_lines(tuple(hook for hook in hooks if hook.phase == "post")),
        "HOOK_HELPERS": _hook_helpers(
            r"%NEWOS%\System32\Config\SYSTEM", backup=rollback
        ),
    }
    for name, value in replacements.items():
        template = template.replace(f"@@{name}@@", value)
    return template.replace("\n", "\r\n")


def render_feature_source_hooks(
    hooks: tuple[Hook, ...], *, rollback: bool, live: bool = False
) -> str:
    """Apply captured source hooks before native Setup."""
    source_hooks = tuple(hook for hook in hooks if hook.phase == "pre")
    template = (
        files("wuo").joinpath("feature_source_hooks.cmd.in").read_text(encoding="ascii")
    )
    return (
        template.replace(
            "@@CHECK_ENV@@",
            ("if /i " if live else "if /i not ")
            + '"%SystemRoot%"=="X:\\Windows" exit /b 1',
        )
        .replace("@@HIVE@@", r"HKLM\SYSTEM" if live else r"HKLM\WUO_FEATURE_SOURCE")
        .replace(
            "@@CHECK_TARGET@@",
            ""
            if live
            else r'if not exist "%TARGET%\Windows\System32\Config\SYSTEM" exit /b 1',
        )
        .replace(
            "@@HOOKS@@", _hook_lines(source_hooks, revert_on_failure=True, live=live)
        )
        .replace(
            "@@HOOK_HELPERS@@",
            _hook_helpers(
                None if live else r"%TARGET%\Windows\System32\Config\SYSTEM",
                backup=rollback,
            ),
        )
        .replace("\n", "\r\n")
    )


def render_feature_restore(
    job: str,
    owner: TargetIdentity,
    image: FeatureImage,
    receipt: bytes,
    *,
    preserve_boot_order: bool = False,
    protected: bool = False,
    hook_receipt_sha256: str = "",
) -> str:
    """Render recovery of a committed feature upgrade from its verified backup."""
    if protected and not preserve_boot_order:
        raise ValueError("Protected rollback requires the captured boot order.")
    if protected and (
        not fullmatch(r"[0-9a-f]{64}", hook_receipt_sha256)
        or not fullmatch(r"[A-Za-z0-9]{1,80}", image.edition)
    ):
        raise ValueError(
            "Protected rollback requires the captured offline hook receipt."
        )
    saved = json.loads(receipt)
    machine = str(UUID(owner.machine_guid))
    job = str(UUID(job))
    if (
        not isinstance(saved, dict)
        or saved.get("schema") != 1
        or saved.get("id") != job
        or saved.get("machine") != machine
        or saved.get("source") != f"{owner.build}.{owner.revision}"
        or not fullmatch(r"[A-Z]:", str(saved.get("original_letter")))
        or (
            owner.windows.drive
            and saved["original_letter"].casefold() != owner.windows.drive.casefold()
        )
        or not fullmatch(r"[A-Za-z0-9-]{1,63}", str(saved.get("computer")))
        or not fullmatch(
            r"[0-9]{2}/[0-9]{2}/[0-9]{4}-[0-9]{2}:[0-9]{2}", str(saved.get("catalog"))
        )
        or image.build <= owner.build
        or not isinstance(saved.get("boot_files"), list)
    ):
        raise ValueError("The feature rollback backup does not match this job.")
    volumes: dict[str, str] = {}
    for field in ("windows", "efi", "volume"):
        match = fullmatch(
            r"\\\\\?\\Volume\{([0-9a-fA-F-]{36})\}\\", str(saved.get(field))
        )
        if match is None:
            raise ValueError("Invalid feature rollback volume name.")
        volumes[field] = "\\\\?\\Volume{" + str(UUID(match[1])) + "}\\"
    if len(set(volumes.values())) != 3:
        raise ValueError(
            "The rollback backup, Windows and EFI volumes must be distinct."
        )
    checks: list[str] = []
    auxiliary: list[str] = []
    seen: set[str] = set()
    owned = "efi\\microsoft\\boot\\"
    allowed = {
        r"efi\microsoft\recovery\bcd",
        r"efi\boot\bootx64.efi",
        r"efi\boot\bootia32.efi",
        r"efi\boot\bootaa64.efi",
    }
    for entry in saved["boot_files"]:
        if not isinstance(entry, dict):
            raise ValueError("Invalid file in the feature rollback backup.")
        name, digest = entry.get("path"), entry.get("sha256")
        if (
            not isinstance(name, str)
            or not all(
                part not in {".", ".."} and fullmatch(r"[A-Za-z0-9_.{} -]+", part)
                for part in name.split("\\")
            )
            or not isinstance(digest, str)
            or not fullmatch(r"[a-f0-9]{64}", digest)
        ):
            raise ValueError("Invalid file or hash in the feature rollback backup.")
        canonical = name.casefold()
        if canonical in seen or not (
            canonical.startswith(owned) or canonical in allowed
        ):
            raise ValueError(
                "The feature rollback backup contains an unexpected EFI file."
            )
        seen.add(canonical)
        checks.append(f'call :verify_file "{name}" {digest} || exit /b 1')
        if canonical in allowed:
            parent = PureWindowsPath(name).parent
            auxiliary.extend(
                (
                    rf'if not exist "%EFI%\{parent}\" (mkdir "%EFI%\{parent}" || goto failed)',
                    rf'copy /b /y "%SNAPSHOT%\{name}" "%EFI%\{name}" >>"%LOG%" || goto failed',
                )
            )
            if canonical == r"efi\microsoft\recovery\bcd":
                auxiliary.append(
                    rf'if exist "%EFI%\{name}.LOG*" del /q "%EFI%\{name}.LOG*"'
                )
    if owned + "bcd" not in seen or owned + "bootmgfw.efi" not in seen:
        raise ValueError("The rollback backup has no verified Windows Boot Manager.")
    replacements = {
        "JOB": job,
        "MACHINE": machine,
        "SOURCE_BUILD": str(owner.build),
        "SOURCE_UBR": hex(owner.revision),
        "REPLACEMENT_CHECK": "call :check_replacement || goto wrong_windows"
        if protected
        else (
            f"call :load_identity {image.build} {hex(image.revision)} || goto wrong_windows\n"
            "call :verify_pending || goto wrong_windows"
        ),
        "WINDOWS": volumes["windows"],
        "EFI": volumes["efi"],
        "BACKUP": volumes["volume"],
        "COMPUTER": saved["computer"],
        "VERSION": saved["catalog"],
        "ORIGINAL_LETTER": saved["original_letter"],
        "BOOT_FILE_COUNT": str(sum(name.startswith(owned) for name in seen)),
        "VERIFY_FILES": "\n".join(checks),
        "RESTORE_EXTRA": "\n".join(auxiliary),
        "RESTORE_BOOT_ORDER": (
            rf'(>"%WINDOWS%\ProgramData\WinOfflineUpdate\jobs\{job}\boot-rollback.id" echo {job})'
            " || echo Boot order restoration could not be queued. Review firmware setup after restarting."
            if preserve_boot_order and not protected
            else ""
        ),
        "PRE_SWAP_FAILURE": "protected_preswap" if protected else "wrong_windows",
        "PROTECTED_REQUIREMENTS": 'if not exist "%TOOLS%fc.exe" goto invalid_catalog'
        if protected
        else "",
        "RESUME_CHECK": (
            'if exist "%SNAPSHOT%\\restore.done" goto interrupted\n'
            'if exist "%SNAPSHOT%\\restore.started" (\n'
            "    call :verify_restore_start || goto interrupted\n"
            "    goto rollback_phase_verified\n"
            ")"
        )
        if protected
        else "",
        "START_RESTORE": "call :start_restore || goto failed"
        if protected
        else (
            'if exist "%SNAPSHOT%\\restore.started" goto interrupted\n'
            f'(>"%SNAPSHOT%\\restore.started" echo {job}) || goto failed'
        ),
        "PRE_SWAP_BRANCH": (
            "goto rollback_phase_verified\n:protected_preswap\n"
            "call :check_preswap || goto wrong_windows\n"
            ":rollback_phase_verified"
            if protected
            else ""
        ),
        "PROTECTED_QUEUE": "call :queue_boot_restore || goto failed"
        if protected
        else "",
        "PROTECTED_SUBROUTINES": rf"""
:verify_restore_start
(>"%WORK%\expected-job.txt" echo {job}) || exit /b 1
"%TOOLS%fc.exe" /b "%WORK%\expected-job.txt" "%SNAPSHOT%\restore.started" >nul 2>&1 || exit /b 1
exit /b 0
:start_restore
if exist "%SNAPSHOT%\restore.started" goto verify_restore_start
(>"%SNAPSHOT%\restore.start.tmp" echo {job}) || exit /b 1
ren "%SNAPSHOT%\restore.start.tmp" restore.started || exit /b 1
goto verify_restore_start
:check_replacement
call :load_identity {image.build} {hex(image.revision)} {image.edition} && call :verify_pending && exit /b 0
set "VERIFY_ROOT=%WINDOWS%\ProgramData\WinOfflineUpdate\jobs\{job}"
call :verify_file independent-hooks.done {hook_receipt_sha256} || exit /b 1
set "VERIFY_ROOT=%WINDOWS%\Windows"
call :load_identity {image.build} any {image.edition} || exit /b 1
exit /b 0
:check_preswap
set "VERIFY_ROOT=%WINDOWS%\Windows"
call :load_identity {owner.build} {hex(owner.revision)} || exit /b 1
set "JOBROOT=%WINDOWS%\ProgramData\WinOfflineUpdate\jobs\{job}"
if not exist "%TOOLS%fc.exe" exit /b 1
(>"%WORK%\expected-job.txt" echo {job}) || exit /b 1
"%TOOLS%fc.exe" /b "%WORK%\expected-job.txt" "%JOBROOT%\claimed.id" >nul 2>&1 || exit /b 1
exit /b 0
:queue_boot_restore
set "JOBROOT=%WINDOWS%\ProgramData\WinOfflineUpdate\jobs\{job}"
if not exist "%JOBROOT%\feature_upgrade.ps1" exit /b 1
if not exist "%JOBROOT%\boot-order.json" exit /b 1
if exist "%SNAPSHOT%\recovery\ventoy-state.json" (
    copy /b /y "%SNAPSHOT%\recovery\ventoy-state.json" "%JOBROOT%\ventoy-state.json" >>"%LOG%" 2>&1 || echo The Ventoy configuration receipt is still on the backup drive.
)
if not exist "%TOOLS%fc.exe" exit /b 1
(>"%WORK%\expected-job.txt" echo {job}) || exit /b 1
copy /b /y "%WORK%\expected-job.txt" "%JOBROOT%\boot-rollback.id" >>"%LOG%" 2>&1 || exit /b 1
"%TOOLS%fc.exe" /b "%WORK%\expected-job.txt" "%JOBROOT%\boot-rollback.id" >nul 2>&1 || exit /b 1
exit /b 0
"""
        if protected
        else "",
    }
    template = (
        files("wuo").joinpath("feature_restore.cmd.in").read_text(encoding="ascii")
    )
    for name, value in replacements.items():
        template = template.replace(f"@@{name}@@", value)
    return template.replace("\n", "\r\n")


def render_runner(plan: BundlePlan) -> str:
    packages: list[str] = []
    for relative, size in plan.size.items():
        if not all(safe_name(part) for part in relative.split("/")) or size <= 0:
            raise ValueError("Unsafe package filename or size in the recovery plan.")
        filename = relative.replace("/", "\\")
        packages.extend(
            (
                rf'if not exist "%BUNDLE%{filename}" exit /b 1',
                rf'for %%F in ("%BUNDLE%{filename}") do if not "%%~zF"=="{size}" exit /b 1',
            )
        )
    expected = [
        path.split("/", 1)[1] for path in plan.size if path.startswith("packages/")
    ]
    if plan.kind == "drivers":
        packages.extend(
            (
                'set "PACKAGE_COUNT=0"',
                r'for /r "%BUNDLE%packages" %%F in (*) do set /a PACKAGE_COUNT+=1 >nul',
                f'if not "%PACKAGE_COUNT%"=="{len(expected)}" exit /b 1',
            )
        )
    else:
        allowed = " ".join(f'if /i not "%%~nxF"=="{name}"' for name in expected)
        packages.append(rf'for %%F in ("%BUNDLE%packages\*") do {allowed} exit /b 1')
        if plan.kind == "packages":
            packages.append(r'for /d %%D in ("%BUNDLE%packages\*") do exit /b 1')
    stages: list[str] = []
    for relative in plan.commands:
        if relative not in plan.size:
            raise ValueError("Servicing command has no verified package.")
        if plan.kind == "drivers" and not (
            relative.startswith("packages/") and relative.lower().endswith(".inf")
        ):
            raise ValueError("Driver servicing requires a verified INF.")
        if plan.kind == "packages" and not (
            relative.startswith("packages/")
            and len(relative.split("/")) == 2
            and relative.lower().endswith((".msu", ".cab"))
        ):
            raise ValueError("CBS servicing requires a verified MSU/CAB package.")
        filename = relative.replace("/", "\\")
        stages.extend(
            (rf'set "PACKAGE=%BUNDLE%{filename}"', "call :dism_add || exit /b 1")
        )
    state_checks: list[str] = []
    if plan.kind == "packages":
        from .bundle import _canonical_identity

        if not plan.package_identities or len(set(plan.package_identities)) != len(
            plan.package_identities
        ):
            raise ValueError("CBS servicing requires a canonical package inventory.")
        for index, identity in enumerate(plan.package_identities, 1):
            _canonical_identity(identity, plan.target.architecture)
            state_checks.extend(
                (
                    f'set "CBS_EXPECTED={identity}"',
                    rf'set "CBS_FILE=%JOB%\packages-after-{index:04}.txt"',
                    "call :verify_cbs_package || exit /b 1",
                )
            )
    state_checks.append("exit /b 0")
    template = files("wuo").joinpath("recovery.cmd.in").read_text(encoding="ascii")
    replacements = {
        "JOB": str(UUID(plan.id)),
        "MACHINE": str(UUID(plan.target.machine_guid)),
        "LOADER": "{" + str(UUID(plan.target.loader_guid)) + "}",
        "BUILD": str(plan.target.build),
        "BEFORE": hex(plan.target.revision),
        "PACKAGES": "\n".join(packages),
        "STAGES": "\n".join(stages),
        "PACKAGE_STATES": "\n".join(state_checks),
        "DISM_ADD": '/Add-Driver /Driver:"%PACKAGE%"'
        if plan.kind == "drivers"
        else '/Add-Package /PackagePath:"%PACKAGE%"',
        "PRE_HOOKS": _hook_lines(
            tuple(hook for hook in plan.hooks if hook.phase == "pre")
        ),
        "POST_HOOKS": _hook_lines(
            tuple(hook for hook in plan.hooks if hook.phase == "post")
        ),
        "HOOK_HELPERS": _hook_helpers(
            r"%TARGET%\Windows\System32\Config\SYSTEM", backup=True
        ),
    }
    for name, value in replacements.items():
        template = template.replace(f"@@{name}@@", value)
    return template.replace("\n", "\r\n")
