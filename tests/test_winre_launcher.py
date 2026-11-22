import hashlib
import os
import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest

TEMPLATE = Path(__file__).parents[1] / "src/wuo/winre_launcher.cmd.in"
MACHINE = "11111111-aaaa-1111-1111-111111111111"
JOB = "22222222-bbbb-2222-2222-222222222222"
WINDOWS = "\\\\?\\Volume{33333333-3333-3333-3333-333333333333}\\"
EFI = "\\\\?\\Volume{44444444-4444-4444-4444-444444444444}\\"


class LauncherLab(NamedTuple):
    root: Path
    script: Path
    cmd: Path

    @property
    def trace(self) -> list[str]:
        return (self.root / "trace.txt").read_text().splitlines()

    @property
    def bundle(self) -> Path:
        return self.root / "menu/bundles" / JOB

    @property
    def job(self) -> Path:
        return self.root / "jobs" / JOB

    def anchor_inventory(self) -> None:
        digest = hashlib.sha256((self.bundle / "hashes.txt").read_bytes()).hexdigest()
        (self.job / "hashes.sha256").write_text(digest + "\n", encoding="ascii")

    def run(self, **settings: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.cmd, "/d", "/c", r".\launcher.cmd"],
            cwd=self.script.parent,
            env={**os.environ, "WUO_TEST_ROOT": str(self.root), **settings},
            input="",
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )


def test_feature_job_authorizes_once_and_restarts(launcher: LauncherLab) -> None:
    feature = launcher.job
    (feature / "feature.ready").write_bytes(f"{JOB}\r\n".encode("ascii"))
    (feature / "feature.json").write_text("{}", encoding="ascii")
    staged = launcher.root / "NewOS/Windows/System32/Config/SYSTEM"
    staged.parent.mkdir(parents=True)
    staged.touch()

    assert launcher.run().returncode == 0
    assert (feature / "authorized.id").read_bytes() == f"{JOB}\r\n".encode("ascii")
    assert "Reboot" in launcher.trace
    assert not (feature / "claimed.id").exists()

    assert launcher.run().returncode != 0
    assert launcher.trace.count("Reboot") == 1


@pytest.mark.parametrize("backup", ["available", "offline", "missing-recipe"])
def test_feature_requires_rollback_backup_before_authorization(
    launcher: LauncherLab, backup: str
) -> None:
    marker = f"{JOB}\r\n".encode("ascii")
    (launcher.job / "feature.ready").write_bytes(marker)
    (launcher.job / "rollback.required").write_bytes(marker)
    (launcher.job / "rollback.json").write_bytes(b"{}")
    (launcher.job / "feature.json").write_text("{}", encoding="ascii")
    staged = launcher.root / "NewOS/Windows/System32/Config/SYSTEM"
    staged.parent.mkdir(parents=True)
    staged.touch()
    for name in ("restore", "source-hooks"):
        if name == "restore" and backup == "missing-recipe":
            continue
        script = launcher.job / f"{name}.cmd"
        tail = (
            "exit /b %WUO_TEST_BACKUP_FAILURE%\n"
            if name == "restore"
            else "exit /b 0\n"
        )
        script.write_text(
            f'@echo off\n>>"%WUO_TEST_ROOT%\\trace.txt" echo {name} %~1\n{tail}',
            encoding="ascii",
        )
        digest = hashlib.sha256(script.read_bytes()).hexdigest()
        (launcher.job / f"{name}.sha256").write_bytes(f"{digest}\r\n".encode("ascii"))

    result = launcher.run(WUO_TEST_BACKUP_FAILURE="1" if backup == "offline" else "0")
    ready = backup == "available"
    assert (result.returncode == 0) is ready
    assert (launcher.job / "authorized.id").is_file() is ready
    assert ("Reboot" in launcher.trace) is ready
    assert any(line.startswith("source-hooks ") for line in launcher.trace) is ready
    assert ("restore check_backup" in launcher.trace) is (backup != "missing-recipe")
    if ready:
        assert launcher.trace.index("restore check_backup") < launcher.trace.index(
            "source-hooks Z:"
        )
    else:
        assert "rollback backup" in result.stdout.lower()


@pytest.mark.parametrize("approved", [False, True])
def test_feature_rollback_checks_the_recipe_before_asking_for_approval(
    launcher: LauncherLab, approved: bool
) -> None:
    marker = f"{JOB}\r\n".encode("ascii")
    (launcher.job / "feature.ready").write_bytes(marker)
    (launcher.job / "claimed.id").write_bytes(marker)
    restore = launcher.job / "restore.cmd"
    restore.write_text(
        '@echo off\n>>"%WUO_TEST_ROOT%\\trace.txt" echo rollback %~1\nexit /b 0\n',
        encoding="ascii",
    )
    digest = hashlib.sha256(restore.read_bytes()).hexdigest()
    (launcher.job / "restore.sha256").write_bytes(f"{digest}\r\n".encode("ascii"))

    result = launcher.run(WUO_TEST_ROLLBACK_CHOICE="1" if approved else "2")
    assert "rollback check" in launcher.trace
    assert ("rollback apply" in launcher.trace) is approved
    assert ("Reboot" in launcher.trace) is approved
    assert (result.returncode == 0) is approved


@pytest.fixture
def launcher(tmp_path: Path) -> LauncherLab:
    if os.name != "nt":
        pytest.skip("Runs Windows CMD")
    windows = Path(os.environ["SYSTEMROOT"])
    system = windows / "System32"
    tool = tmp_path / "tools"
    tool.mkdir()
    lab = LauncherLab(tmp_path, tool / "launcher.cmd", system / "cmd.exe")
    substitutions = {
        "@@WINDOWS_VOLUME@@": WINDOWS,
        "@@EFI_VOLUME@@": EFI,
        "@@MACHINE_GUID@@": MACHINE,
        r'if /i not "%SystemRoot%"=="X:\Windows"': (
            f'if /i not "%SystemRoot%"=="{windows}"'
        ),
        r'"%SYS%\mountvol.exe"': r'call "%~dp0mountvol.cmd"',
        r'"%SYS%\wpeutil.exe"': r'call "%~dp0wpeutil.cmd"',
        r'"%~dp0choice.exe"': r'call "%~dp0choice.cmd"',
        r"%SYS%\..\Temp\WUO-": r"%WUO_TEST_ROOT%\WUO-",
        r"%TARGET%\ProgramData\WinOfflineUpdate": r"%WUO_TEST_ROOT%",
        r"%TARGET%\ProgramData": r"%WUO_TEST_ROOT%",
        r"%TARGET%\$WINDOWS.~BT\NewOS\Windows": r"%WUO_TEST_ROOT%\NewOS\Windows",
        r'"%~dp0findstr.exe"': f'"{system / "findstr.exe"}"',
        r'"%~dp0certutil.exe"': f'"{system / "certutil.exe"}"',
    }
    script = TEMPLATE.read_text(encoding="ascii")
    for old, new in substitutions.items():
        assert old in script
        script = script.replace(old, new)
    lab.script.write_text(script, encoding="ascii")
    (tool / "mountvol.cmd").write_text(
        r"""@echo off
setlocal
set "LETTER=%~1"
set "LETTER=%LETTER:~0,1%"
set "MAPPING=%WUO_TEST_ROOT%\mount-%LETTER%.txt"
if /i "%~2"=="/L" (
    if not exist "%MAPPING%" exit /b 1
    type "%MAPPING%"
    exit /b
)
if /i "%~2"=="/D" (
    >>"%WUO_TEST_ROOT%\trace.txt" echo unmount %LETTER%
    del "%MAPPING%"
    exit /b
)
if "%WUO_TEST_BLOCK_MOUNT%"=="%~2" exit /b 1
if exist "%MAPPING%" exit /b 1
>"%MAPPING%" echo %~2
>>"%WUO_TEST_ROOT%\trace.txt" echo mount %LETTER% %~2
exit /b 0
""",
        encoding="ascii",
    )
    (tool / "wpeutil.cmd").write_text(
        '@echo off\n>>"%WUO_TEST_ROOT%\\trace.txt" echo %~1\nexit /b 0\n',
        encoding="ascii",
    )
    (tool / "choice.cmd").write_text(
        "@echo off\nexit /b %WUO_TEST_ROLLBACK_CHOICE%\n", encoding="ascii"
    )
    lab.job.mkdir(parents=True)
    (lab.job / "target.id").write_bytes(f"{JOB}\r\n".encode())
    (lab.bundle / "packages").mkdir(parents=True)
    (lab.root / "trace.txt").touch()
    (lab.root / "menu/installed.id").write_bytes(f"{MACHINE}\n".encode())
    (lab.root / "menu/pending.id").write_bytes(f"{JOB}\r\n".encode())
    (lab.bundle / "recovery.cmd").write_text(
        f"""@echo off
>>"%WUO_TEST_ROOT%\\trace.txt" echo %~1 %~2 %~3
if "%WUO_TEST_FAIL%"=="check" exit /b 1
if /i "%~1"=="check" exit /b 0
mkdir "%WUO_TEST_ROOT%\\jobs\\{JOB}\\apply.started"
if "%WUO_TEST_FAIL%"=="apply" exit /b 1
>"%WUO_TEST_ROOT%\\jobs\\{JOB}\\state.ready" echo {JOB}
exit /b 0
""",
        encoding="ascii",
    )
    (lab.bundle / "plan.json").write_text("{}", encoding="ascii")
    plan_digest = hashlib.sha256((lab.bundle / "plan.json").read_bytes()).hexdigest()
    (lab.job / "plan.sha256").write_text(plan_digest + "\n", encoding="ascii")
    (lab.bundle / "packages/Driver~ 1.inf").write_bytes(b"test INF")
    files = [p for p in lab.bundle.rglob("*") if p.is_file()]
    (lab.bundle / "hashes.txt").write_bytes(
        "".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()} "
            f"{p.relative_to(lab.bundle).as_posix()}\r\n"
            for p in files
        ).encode("ascii")
    )
    lab.anchor_inventory()
    return lab


def test_launcher_checks_applies_and_reboots_with_identified_mounts(
    launcher: LauncherLab,
) -> None:
    result = launcher.run()
    assert result.returncode == 0, result.stdout + result.stderr
    first, second, check, apply, remove_second, remove_first, reboot = launcher.trace
    win_letter, efi_letter = first.split()[1], second.split()[1]
    assert win_letter != efi_letter
    assert first == f"mount {win_letter} {WINDOWS}"
    assert second == f"mount {efi_letter} {EFI}"
    assert check == f"check {win_letter}: {efi_letter}:"
    assert apply == f"apply {win_letter}: {efi_letter}:"
    assert remove_second == f"unmount {efi_letter}"
    assert remove_first == f"unmount {win_letter}"
    assert reboot.lower() == "reboot"


def test_launcher_reuses_existing_mounts(launcher: LauncherLab) -> None:
    (launcher.root / "mount-S.txt").write_text(WINDOWS + "\n", encoding="ascii")
    (launcher.root / "mount-W.txt").write_text(EFI + "\n", encoding="ascii")
    result = launcher.run(WUO_TEST_FAIL="check")
    assert result.returncode != 0
    assert launcher.trace == ["check S: W:"]


def test_launcher_cleans_windows_mount_when_efi_cannot_mount(
    launcher: LauncherLab,
) -> None:
    result = launcher.run(WUO_TEST_BLOCK_MOUNT=EFI)
    assert result.returncode != 0
    mount, cleanup = launcher.trace
    assert mount.endswith(WINDOWS)
    assert cleanup == f"unmount {mount.split()[1]}"


@pytest.mark.parametrize(
    "damage",
    [
        "pending-extras",
        "pending-injection",
        "installed-extras",
        "started",
        "ready",
        "hash-mismatch",
        "hash-omission",
        "hash-duplicate",
        "hash-traversal",
        "hash-injection",
    ],
)
def test_launcher_refuses_damaged_job_before_running_bundle(
    launcher: LauncherLab, damage: str
) -> None:
    manifest = launcher.bundle / "hashes.txt"
    entries = manifest.read_bytes().splitlines(keepends=True)
    if damage == "pending-extras":
        (launcher.root / "menu/pending.id").write_bytes(f"{JOB}\nx".encode())
    elif damage == "pending-injection":
        (launcher.root / "menu/pending.id").write_bytes(b'"&echo BAD&rem \n')
    elif damage == "installed-extras":
        (launcher.root / "menu/installed.id").write_bytes(f"{MACHINE}\nx".encode())
    elif damage == "started":
        (launcher.job / "apply.started").mkdir()
    elif damage == "ready":
        (launcher.job / "state.ready").touch()
    elif damage == "hash-mismatch":
        (launcher.bundle / "packages/Driver~ 1.inf").write_bytes(b"not INF!")
    elif damage == "hash-omission":
        manifest.write_bytes(b"".join(e for e in entries if b"packages/" not in e))
    elif damage == "hash-duplicate":
        manifest.write_bytes(b"".join([*entries, entries[0]]))
    elif damage == "hash-traversal":
        manifest.write_bytes(b"".join([*entries, b"1" * 64 + b" ../target.cmd\r\n"]))
    elif damage == "hash-injection":
        manifest.write_bytes(b"".join([*entries, b"1" * 64 + b' x"&echo BAD&rem \r\n']))
    if damage.startswith("hash-"):
        launcher.anchor_inventory()
    result = launcher.run()
    assert result.returncode != 0, result.stdout + result.stderr
    assert not any(
        item.startswith(("check", "apply", "reboot")) for item in launcher.trace
    )
    assert "BAD" not in result.stdout


def test_launcher_refuses_runner_and_inventory_replacement(
    launcher: LauncherLab,
) -> None:
    runner = launcher.bundle / "recovery.cmd"
    original = hashlib.sha256(runner.read_bytes()).hexdigest().encode("ascii")
    runner.write_bytes(runner.read_bytes() + b"rem changed runner\r\n")
    replacement = hashlib.sha256(runner.read_bytes()).hexdigest().encode("ascii")
    inventory = launcher.bundle / "hashes.txt"
    inventory.write_bytes(inventory.read_bytes().replace(original, replacement))

    result = launcher.run()

    assert result.returncode != 0, result.stdout + result.stderr
    assert not any(
        step.lower().startswith(("check", "apply", "reboot")) for step in launcher.trace
    )


def test_launcher_leaves_failed_apply_for_review_without_reboot(
    launcher: LauncherLab,
) -> None:
    result = launcher.run(WUO_TEST_FAIL="apply")
    assert result.returncode != 0
    assert (launcher.job / "apply.started").is_dir()
    assert len([item for item in launcher.trace if item.startswith("apply ")]) == 1
    assert all(item.lower() != "reboot" for item in launcher.trace)
    assert launcher.run().returncode != 0
    assert len([item for item in launcher.trace if item.startswith("apply ")]) == 1
