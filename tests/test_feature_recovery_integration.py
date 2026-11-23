import json
import os
import shutil
import subprocess
from pathlib import Path
from uuid import UUID

import pytest

from wuo import feature_upgrade
from wuo.feature_upgrade import (
    FeatureImage,
    FeatureMedia,
    feature_setup_assets,
    render_feature_safeos,
)
from wuo.hooks import Hook
from wuo.recovery import render_feature_restore
from wuo.target import TargetIdentity

JOB = UUID(int=10)
TARGET = TargetIdentity(
    "25H2", 26200, 8400, "x64", Path("C:/Windows"), str(UUID(int=11)), "", "Client"
)
IMAGE = FeatureImage(6, 26300, 9457, "Professional", "x64", "en-US")
EFI = rf"\\?\Volume{{{UUID(int=12)}}}\\"[:-1]
WINDOWS = rf"\\?\Volume{{{UUID(int=13)}}}\\"[:-1]
VENTOY_EFI = rf"\\?\Volume{{{UUID(int=16)}}}\\"[:-1]
ENTRY = f"{{{UUID(int=14)}}}"
POST = (Hook("post", r"Services\USBHUB3", "Start", 0),)
POWERSHELL = shutil.which("powershell.exe")
NATIVE = Path(__file__).parents[1] / "src/wuo/feature_upgrade.ps1"


@pytest.mark.parametrize("changed", [False, True])
def test_backup_binds_the_native_receipt_bytes(
    monkeypatch: pytest.MonkeyPatch, changed: bool
) -> None:
    metadata = {
        "schema": 1,
        "id": str(JOB),
        "machine": TARGET.machine_guid,
        "source": "26200.8400",
        "volume": rf"\\?\Volume{{{UUID(int=15)}}}\\"[:-1],
        "catalog": "11/22/2026-00:00",
        "boot_files": [{"path": r"EFI\Microsoft\Boot\BCD", "sha256": "1" * 64}],
    }
    persisted = json.dumps(
        metadata | ({"source": "26200.9000"} if changed else {}),
        separators=(",", ":"),
    ).encode("ascii")
    monkeypatch.setattr(feature_upgrade, "_run_native", lambda *_: json.dumps(metadata))

    def read_receipt(path: Path) -> bytes:
        assert path.name == "rollback.json"
        assert path.parent.name == str(JOB)
        return persisted

    monkeypatch.setattr(Path, "read_bytes", read_receipt)
    if changed:
        with pytest.raises(ValueError, match="saved feature backup receipt"):
            feature_upgrade.backup_feature(TARGET, JOB, "F:")
    else:
        receipt, _ = feature_upgrade.backup_feature(TARGET, JOB, "F:")
        assert receipt == persisted


def test_protected_feature_manifest_defers_post_writes_to_recovery() -> None:
    media = FeatureMedia(
        Path("C:/feature.iso"),
        "f" * 64,
        rollback=True,
        preserve_boot_order=True,
        recovery_drive="E:",
    )
    request, callback = feature_setup_assets(JOB, TARGET, media, IMAGE, POST)
    assert json.loads(request)["schema"] == 2
    assert b"Services\\USBHUB3" not in callback
    assert b"precommit.done" in callback


def test_protected_feature_requires_rollback_and_boot_snapshot() -> None:
    media = FeatureMedia(Path("C:/feature.iso"), "f" * 64, recovery_drive="D:")
    with pytest.raises(ValueError, match="backup and boot preservation"):
        feature_setup_assets(JOB, TARGET, media, IMAGE, POST)


def test_safeos_cannot_start_native_recovery_before_firmware_readback() -> None:
    script = render_feature_safeos(
        JOB, WINDOWS, EFI, ENTRY, r"\EFI\BOOT\BOOTX64.EFI", VENTOY_EFI
    )
    assert b"@@" not in script
    assert script.index(b"if not defined DEVICE_MATCH goto stop") < script.index(
        b"bootsequence %RECOVERY%"
    )
    assert script.index(b"call :check_order") < script.index(b"bootsequence %RECOVERY%")
    assert script.index(b"call :check_next") < script.index(b"safeos.ready")
    assert script.index(b"safeos.ready") < script.index(
        b"/wait X:\\sources\\recovery\\recenv.exe"
    )
    with pytest.raises(ValueError, match="EFI loader"):
        render_feature_safeos(JOB, WINDOWS, EFI, ENTRY, r"\EFI\..\boot.efi", VENTOY_EFI)


@pytest.fixture
def protected_restore() -> str:
    receipt = json.dumps(
        {
            "schema": 1,
            "id": str(JOB),
            "machine": TARGET.machine_guid,
            "source": "26200.8400",
            "volume": f"\\\\?\\Volume{{{UUID(int=15)}}}\\",
            "windows": WINDOWS,
            "efi": EFI,
            "original_letter": "C:",
            "catalog": "11/22/2026-00:00",
            "computer": "LAB",
            "boot_files": [
                {"path": path, "sha256": "1" * 64}
                for path in (
                    r"EFI\Microsoft\Boot\BCD",
                    r"EFI\Microsoft\Boot\bootmgfw.efi",
                )
            ],
        }
    ).encode("ascii")
    return render_feature_restore(
        str(JOB),
        TARGET,
        IMAGE,
        receipt,
        preserve_boot_order=True,
        protected=True,
        hook_receipt_sha256="2" * 64,
    )


def test_protected_restore_requires_resuming_the_captured_boot_snapshot(
    protected_restore: str,
) -> None:
    script = protected_restore
    assert "call :check_preswap || goto wrong_windows" in script
    assert script.index(
        'if not exist "%TOOLS%fc.exe" goto invalid_catalog'
    ) < script.index('if /i "%~1"=="check_backup"')
    assert script.index('"%SYS%\\wbadmin.exe" get items') < script.index(
        "restore.started"
    )
    assert script.index("call :queue_boot_restore || goto failed") < script.index(
        r'(>"%SNAPSHOT%\restore.done"'
    )
    assert r'fc.exe" /b "%WORK%\expected-job.txt"' in script
    assert script.index("call :verify_file independent-hooks.done") < script.index(
        f"call :load_identity {IMAGE.build} any {IMAGE.edition}"
    )
    assert script.index('set "TEMP_EFI="') < script.index("call :detect")


@pytest.mark.skipif(os.name != "nt", reason="Runs the generated rollback commands")
def test_protected_rollback_resumes_only_the_captured_job(
    protected_restore: str, tmp_path: Path
) -> None:
    command = tmp_path / "checkpoint.cmd"
    start = protected_restore.index("\r\n:verify_restore_start\r\n")
    end = protected_restore.index("\r\n:check_preswap\r\n", start)
    command.write_bytes(
        (
            '@echo off\r\nset "WORK=%~dp0"\r\nset "SNAPSHOT=%~dp0"\r\n'
            'set "TOOLS=%SystemRoot%\\System32\\"\r\n'
            "call :start_restore || exit /b 1\r\nexit /b 0\r\n"
            + protected_restore[start:end]
        ).encode("ascii")
    )
    checkpoint = tmp_path / "restore.started"
    for expected in (0, 0, 1):
        if expected:
            checkpoint.write_bytes(f"{UUID(int=20)}\r\n".encode("ascii"))
        result = subprocess.run(
            [os.environ["COMSPEC"], "/d", "/c", str(command)],
            capture_output=True,
            check=False,
        )
        assert result.returncode == expected, result.stdout
        marker = UUID(int=20) if expected else JOB
        assert checkpoint.read_bytes() == f"{marker}\r\n".encode("ascii")


@pytest.mark.skipif(os.name != "nt", reason="Runs the generated rollback commands")
def test_protected_rollback_preserves_ventoy_receipt(
    protected_restore: str, tmp_path: Path
) -> None:
    windows = tmp_path / "restored Windows"
    job = windows / "ProgramData" / "WinOfflineUpdate" / "jobs" / str(JOB)
    job.mkdir(parents=True)
    (job / "feature_upgrade.ps1").touch()
    (job / "boot-order.json").touch()
    snapshot = tmp_path / "backup"
    recovery = snapshot / "recovery"
    recovery.mkdir(parents=True)
    receipt = b'{\r\n  "original": null\r\n}\r\n'
    (recovery / "ventoy-state.json").write_bytes(receipt)
    start = protected_restore.index("\r\n:queue_boot_restore\r\n")
    end = protected_restore.index("\r\n:detect\r\n", start)
    command = tmp_path / "queue.cmd"
    command.write_bytes(
        (
            '@echo off\r\nset "WORK=%~dp0"\r\n'
            f'set "WINDOWS={windows}"\r\nset "SNAPSHOT={snapshot}"\r\n'
            'set "LOG=%~dp0restore.log"\r\nset "TOOLS=%SystemRoot%\\System32\\"\r\n'
            "call :queue_boot_restore || exit /b 1\r\nexit /b 0\r\n"
            + protected_restore[start:end]
        ).encode("ascii")
    )
    result = subprocess.run(
        [os.environ["COMSPEC"], "/d", "/c", str(command)],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (job / "ventoy-state.json").read_bytes() == receipt
    assert (job / "boot-rollback.id").read_bytes() == f"{JOB}\r\n".encode("ascii")


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize("case", ["safeos", "extra-loader", "wrong-ramdisk"])
def test_protected_stage_requires_a_single_verified_safeos_loader(case: str) -> None:
    assert POWERSHELL is not None
    script = r"""
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile($env:WUO_SOURCE, [ref]$null, [ref]$null)
$validation = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-NativeSafeOsQueue'
}, $false)
. ([scriptblock]::Create($validation.Extent.Text))
function Mock-WuoBCD {
    $global:LASTEXITCODE = 0
    $loader = '{11111111-1111-1111-1111-111111111111}'
    if ($args[1] -eq '{bootmgr}') {
        "bootsequence            $loader"
        if ($env:WUO_CASE -eq 'extra-loader') { '                        {33333333-3333-3333-3333-333333333333}' }
        'timeout                 0'
        return
    }
    if ($args[1] -ne $loader) { throw 'Queried the wrong Setup loader.' }
    $volume = if ($env:WUO_CASE -eq 'wrong-ramdisk') { 'D:' } else { 'C:' }
    $image = 'ramdisk=[{0}]\$WINDOWS.~BT\Sources\SafeOS\winre.wim,{{22222222-2222-2222-2222-222222222222}}' -f $volume
    "device                  $image"
    "osdevice                $image"
    'path                    \windows\system32\winload.efi'
    'winpe                   Yes'
}
$env:SystemDrive = 'C:'
Set-Alias "$env:SystemRoot\System32\bcdedit.exe" Mock-WuoBCD
$null = Get-NativeSafeOsQueue
'verified'
"""
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env=os.environ | {"WUO_SOURCE": str(NATIVE), "WUO_CASE": case},
    )
    if case == "safeos":
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "verified"
    else:
        assert result.returncode != 0
        assert "SafeOS" in result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize(
    "case", ["safeos", "idle", "foreign-loader", "different-default", "export-fails"]
)
def test_aborted_protected_setup_disarms_only_its_native_queue(
    tmp_path: Path, case: str
) -> None:
    assert POWERSHELL is not None
    script = r"""
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile($env:WUO_SOURCE, [ref]$null, [ref]$null)
foreach ($definition in $ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in 'Get-NativeSafeOsQueue', 'Clear-AbortedNativeSetupBoot'
}, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$env:SystemDrive = 'C:'
$script:queued = $env:WUO_CASE -ne 'idle'
function Mock-WuoBCD {
    $global:LASTEXITCODE = 0
    $current = '{11111111-1111-1111-1111-111111111111}'
    $loader = '{22222222-2222-2222-2222-222222222222}'
    if ($args[0] -eq '/export') {
        if ($env:WUO_CASE -eq 'export-fails') { $global:LASTEXITCODE = 1; return }
        [IO.File]::WriteAllText($args[1], 'preserved BCD')
        return
    }
    if ($args[0] -eq '/deletevalue') {
        if ($args[1] -ne '{bootmgr}' -or $args[2] -ne 'bootsequence') { throw 'Unexpected BCD write' }
        if (!(Test-Path -LiteralPath (Join-Path $env:WUO_JOB 'bcd-before-abort.bak'))) { throw 'BCD was not backed up' }
        [IO.File]::WriteAllText((Join-Path $env:WUO_JOB 'deleted.txt'), 'bootsequence')
        $script:queued = $false
        return
    }
    if ($args[0] -ne '/enum') { throw 'Unexpected BCDEdit command' }
    if ($args[1] -eq '{bootmgr}') {
        $default = if ($env:WUO_CASE -eq 'different-default') { $loader } else { $current }
        "default                 $default"
        if ($script:queued) { "bootsequence            $loader" }
        return
    }
    if ($args[1] -eq '{current}') {
        "identifier              $current"
        'device                  partition=C:'
        'osdevice                partition=C:'
        'path                    \WINDOWS\system32\winload.efi'
        return
    }
    if ($args[1] -ne $loader) { throw 'Queried the wrong Setup loader.' }
    $volume = if ($env:WUO_CASE -eq 'foreign-loader') { 'E:' } else { 'C:' }
    $image = 'ramdisk=[{0}]\$WINDOWS.~BT\Sources\SafeOS\winre.wim,{{33333333-3333-3333-3333-333333333333}}' -f $volume
    "device                  $image"
    "osdevice                $image"
    'path                    \windows\system32\winload.efi'
    'winpe                   Yes'
}
Set-Alias "$env:SystemRoot\System32\bcdedit.exe" Mock-WuoBCD
Clear-AbortedNativeSetupBoot $env:WUO_JOB
"""
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env=os.environ
        | {"WUO_SOURCE": str(NATIVE), "WUO_CASE": case, "WUO_JOB": str(tmp_path)},
    )
    if case in {"safeos", "idle"}:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
    assert (tmp_path / "deleted.txt").is_file() == (case == "safeos")
