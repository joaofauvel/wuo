import os
import subprocess
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest

from wuo.feature_recovery import feature_recovery_receipt, render_feature_recovery
from wuo.feature_upgrade import FeatureImage, render_feature_safeos
from wuo.target import TargetIdentity

JOB = UUID(int=10)
OWNER = TargetIdentity(
    "25H2", 26200, 8400, "x64", Path("C:/Windows"), str(UUID(int=11)), "", "Client"
)
IMAGE = FeatureImage(6, 26300, 9457, "Professional", "x64", "en-US")
WINDOWS = f"\\\\?\\Volume{{{UUID(int=12)}}}\\"
EFI = f"\\\\?\\Volume{{{UUID(int=13)}}}\\"
VENTOY = f"\\\\?\\Volume{{{UUID(int=14)}}}\\"
BACKUP = f"\\\\?\\Volume{{{UUID(int=15)}}}\\"
ENTRY = f"{{{UUID(int=16)}}}"
RAMDISK = r"ramdisk=[W:]\$WINDOWS.~BT\Sources\SafeOS\winre.wim,{22222222-2222-2222-2222-222222222222}"


def render_independent() -> str:
    return render_feature_recovery(
        JOB,
        OWNER,
        IMAGE,
        (),
        windows_volume=WINDOWS,
        efi_volume=EFI,
        backup_volume=BACKUP,
        recovery_entry=ENTRY,
        recovery_efi_volume=VENTOY,
        recovery_path=r"\EFI\BOOT\BOOTX64.EFI",
        recovery_loader_sha256="a" * 64,
        restore_sha256="b" * 64,
        rollback_sha256="c" * 64,
    ).decode("ascii")


def run_batch(
    tmp_path: Path, commands: str, helpers: str
) -> subprocess.CompletedProcess[str]:
    harness = tmp_path / "preflight-test.cmd"
    harness.write_bytes(
        (
            "@echo off\r\n"
            "setlocal EnableExtensions DisableDelayedExpansion\r\n"
            'set "WORK=%~dp0"\r\n'
            'set "SYS=%SystemRoot%\\System32"\r\n'
            'set "TOOLS=%SYS%\\"\r\n' + commands + "\r\n" + helpers
        ).encode("ascii")
    )
    return subprocess.run(
        [os.environ["COMSPEC"], "/d", "/c", str(harness)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


@pytest.mark.skipif(os.name != "nt", reason="Runs the generated SafeOS batch gate")
@pytest.mark.parametrize("receipt_file", ["exact", "missing", "modified", "wrong-crlf"])
def test_safeos_checks_exact_preflight_before_native_setup(
    tmp_path: Path, receipt_file: str
) -> None:
    receipt = feature_recovery_receipt(JOB, IMAGE, ())
    candidate = {
        "exact": receipt,
        "missing": None,
        "modified": receipt.replace(b"26300", b"26301"),
        "wrong-crlf": receipt[:-2] + b"\n\n",
    }[receipt_file]
    if candidate is not None:
        (tmp_path / "independent-preflight.done").write_bytes(candidate)
    safeos = render_feature_safeos(
        JOB,
        WINDOWS,
        EFI,
        ENTRY,
        r"\EFI\BOOT\BOOTX64.EFI",
        VENTOY,
        preflight_receipt=receipt.decode("ascii").strip(),
    ).decode("ascii")
    guard, label, helpers = safeos.partition("\r\n:verify_preflight_receipt\r\n")
    assert label, "SafeOS has no receipt verifier"
    assert guard.index("call :verify_preflight_receipt") < guard.index("recenv.exe")
    result = run_batch(
        tmp_path,
        'set "JOB=%~dp0"\r\ncall :verify_preflight_receipt\r\nexit /b %ERRORLEVEL%',
        label + helpers,
    )
    assert result.returncode == (0 if receipt_file == "exact" else 1), result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Runs the generated BCD field parser")
@pytest.mark.parametrize(
    "loader", ["native", "other-volume", "other-options", "not-pe"]
)
def test_independent_recovery_checks_the_queued_native_safeos_loader(
    tmp_path: Path, loader: str
) -> None:
    device = RAMDISK.replace("[W:]", "[Z:]") if loader == "other-volume" else RAMDISK
    osdevice = (
        device.replace("22222222", "33333333") if loader == "other-options" else device
    )
    (tmp_path / "bcd.txt").write_bytes(
        (
            f"device                  {device}\r\n"
            f"osdevice                {osdevice}\r\n"
            "path                    \\windows\\system32\\winload.efi\r\n"
            f"winpe                   {'No' if loader == 'not-pe' else 'Yes'}\r\n"
        ).encode("ascii")
    )
    recovery = render_independent()
    _, label, helpers = recovery.partition("\r\n:verify_safeos_loader\r\n")
    assert label, "Independent recovery has no queued SafeOS loader verifier"
    result = run_batch(
        tmp_path,
        'set "TARGET=W:"\r\n'
        'set "SAFEOS_RELATIVE=\\$WINDOWS.~BT\\Sources\\SafeOS\\winre.wim"\r\n'
        "call :verify_safeos_loader\r\nexit /b %ERRORLEVEL%",
        label + helpers,
    )
    assert result.returncode == (0 if loader == "native" else 1), result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Runs the generated SafeOS image check")
@pytest.mark.parametrize("image_state", ["staged", "changed", "missing-proof"])
def test_independent_preflight_requires_the_verified_patched_image(
    tmp_path: Path, image_state: str
) -> None:
    image = tmp_path / "target/$WINDOWS.~BT/Sources/SafeOS/winre.wim"
    image.parent.mkdir(parents=True)
    patched = b"patched native SafeOS image"
    image.write_bytes(b"stock image" if image_state == "changed" else patched)
    job = tmp_path / "job"
    job.mkdir()
    if image_state != "missing-proof":
        (job / "safeos.sha256").write_bytes(
            (sha256(patched).hexdigest() + "\r\n").encode("ascii")
        )
    _, label, helpers = render_independent().partition("\r\n:verify_staged_safeos\r\n")
    assert label
    result = run_batch(
        tmp_path,
        'set "LOG=%~dp0preflight.log"\r\n'
        'set "JOB=%~dp0job"\r\n'
        'set "TARGET=%~dp0target"\r\n'
        'set "SAFEOS_RELATIVE=\\$WINDOWS.~BT\\Sources\\SafeOS\\winre.wim"\r\n'
        "call :verify_staged_safeos\r\nexit /b %ERRORLEVEL%",
        label + helpers,
    )
    assert result.returncode == (0 if image_state == "staged" else 1), result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Runs the generated BCD rollback handoff")
@pytest.mark.parametrize(
    ("state", "removed", "released"),
    [
        ("clean", False, True),
        ("safeos", True, True),
        ("wrong-default", False, False),
        ("changed-flag", False, False),
        ("unrelated", False, False),
        ("delete-ignored", True, False),
        ("loader-changed", True, False),
    ],
)
def test_failed_preflight_only_releases_the_verified_original_loader(
    tmp_path: Path, state: str, removed: bool, released: bool
) -> None:
    original = "{11111111-1111-1111-1111-111111111111}"
    safeos = "{22222222-2222-2222-2222-222222222222}"
    (tmp_path / "original-loader.txt").write_bytes(
        (
            f"identifier {original}\r\n"
            "device partition=W:\r\n"
            "osdevice partition=W:\r\n"
            "path \\windows\\system32\\winload.efi\r\n"
            "systemroot \\Windows\r\n"
        ).encode("ascii")
    )
    fake_bcd = (
        "@echo off\r\n"
        'if "%~3"=="/deletevalue" goto removed\r\n'
        'if "%~4"=="{bootmgr}" goto manager\r\n'
        f'if "%~4"=="{original}" goto normal\r\n'
        f'if "%~4"=="{safeos}" goto setup\r\n'
        "exit /b 1\r\n"
        ":manager\r\n"
        f'if "{state}"=="wrong-default" (echo default {safeos}) else echo default {original}\r\n'
        f'if "{state}"=="clean" exit /b 0\r\n'
        f'if exist "%~dp0removed" if not "{state}"=="delete-ignored" exit /b 0\r\n'
        f"echo bootsequence {safeos}\r\n"
        "exit /b 0\r\n"
        ":normal\r\n"
        f"echo identifier {original}\r\n"
        f'if "{state}"=="loader-changed" if exist "%~dp0removed" goto changed\r\n'
        "echo device partition=W:\r\n"
        "echo osdevice partition=W:\r\n"
        "echo path \\windows\\system32\\winload.efi\r\n"
        "echo systemroot \\Windows\r\n"
        f'if "{state}"=="changed-flag" echo testsigning Yes\r\n'
        "exit /b 0\r\n"
        ":changed\r\n"
        "echo device partition=Z:\r\n"
        "exit /b 0\r\n"
        ":setup\r\n"
        f'if "{state}"=="unrelated" exit /b 1\r\n'
        f"echo identifier {safeos}\r\n"
        f"echo device {RAMDISK}\r\n"
        f"echo osdevice {RAMDISK}\r\n"
        "echo path \\windows\\system32\\winload.efi\r\n"
        "echo winpe Yes\r\n"
        "exit /b 0\r\n"
        ":removed\r\n"
        'type nul >"%~dp0removed"\r\n'
        "exit /b 0\r\n"
    )
    (tmp_path / "bcdedit.cmd").write_bytes(fake_bcd.encode("ascii"))
    _, label, helpers = render_independent().partition("\r\n:read_boot_manager\r\n")
    assert label
    result = run_batch(
        tmp_path,
        'set "LOG=%~dp0abort.log"\r\n'
        'set "BCD=%~dp0fake.bcd"\r\n'
        'set "TARGET=W:"\r\n'
        'set "SAFEOS_RELATIVE=\\$WINDOWS.~BT\\Sources\\SafeOS\\winre.wim"\r\n'
        f'set "ORIGINAL_LOADER={original}"\r\n'
        "call :clear_safeos_queue\r\nexit /b %ERRORLEVEL%",
        (label + helpers).replace(r'"%SYS%\bcdedit.exe"', r'call "%WORK%bcdedit.cmd"'),
    )
    assert (tmp_path / "removed").is_file() == removed, result.stdout + result.stderr
    assert result.returncode == (0 if released else 1), result.stdout + result.stderr
