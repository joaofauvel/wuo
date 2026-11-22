import os
import shutil
import subprocess
from pathlib import Path

import pytest

POWERSHELL = shutil.which("powershell.exe")
SCRIPT = Path(__file__).parents[1] / "src/wuo/feature_safeos.ps1"
BOOT_SCRIPT = SCRIPT.with_name("feature_boot.ps1")
STOCK = b"[LaunchApp]\r\nAppPath=X:\\sources\\recovery\\recenv.exe\r\n"
WRAPPED = (
    b"[LaunchApps]\r\n"
    b"%SYSTEMROOT%\\System32\\cmd.exe, /d /c X:\\Windows\\System32\\wuo-safeos.cmd\r\n"
)


def _run_powershell(
    command: str, **paths: Path | str
) -> subprocess.CompletedProcess[str]:
    assert POWERSHELL is not None
    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$ErrorActionPreference = 'Stop'; . $env:WUO_SCRIPT; " + command,
        ],
        env=os.environ
        | {"WUO_SCRIPT": str(SCRIPT)}
        | {f"WUO_{name.upper()}": str(path) for name, path in paths.items()},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize(
    "case", ["stock", "other-shell", "no-recovery", "collision", "wim", "junction"]
)
def test_safeos_wrapper_requires_unmodified_native_shell(
    tmp_path: Path, case: str
) -> None:
    mount = tmp_path / "Mounted"
    system = mount / "Windows" / "System32"
    system.mkdir(parents=True)
    native_recovery = mount / "sources" / "recovery" / "recenv.exe"
    native_recovery.parent.mkdir(parents=True)
    if case != "no-recovery":
        native_recovery.touch()
    launcher = system / "winpeshl.ini"
    original = STOCK if case != "other-shell" else STOCK + b"AppPath=missing.exe\r\n"
    launcher.write_bytes(original)
    destination = system / "wuo-safeos.cmd"
    if case == "collision":
        destination.write_bytes(b"existing")
    wrapper = tmp_path / "candidate.cmd"
    wrapper.write_bytes(b"@echo off\r\n")
    harness = r"""
function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force)
    $item = Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
    if ($env:WUO_CASE -in 'wim', 'junction' -and $item.Name -ieq 'recenv.exe') {
        return [pscustomobject]@{
            PSIsContainer = $false
            Attributes = [IO.FileAttributes]::Archive -bor [IO.FileAttributes]::ReparsePoint
        }
    }
    return $item
}
function Mock-SafeOsFsutil {
    if ($args[0] -ne 'reparsepoint' -or $args[1] -ne 'query' -or $args[2] -notlike '*\recenv.exe') {
        throw 'Unexpected reparse point query.'
    }
    $global:LASTEXITCODE = 0
    $tag = if ($env:WUO_CASE -eq 'wim') { '0x80000008' } else { '0xa0000003' }
    "Reparse Tag Value : $tag"
}
Set-Alias "$env:SystemRoot\System32\fsutil.exe" Mock-SafeOsFsutil
Install-WuoSafeOsWrapper $env:WUO_MOUNT $env:WUO_WRAPPER
"""
    result = _run_powershell(
        harness,
        mount=mount,
        wrapper=wrapper,
        case=case,
    )
    if case in {"stock", "wim"}:
        assert result.returncode == 0, result.stderr
        assert launcher.read_bytes() == WRAPPED
        assert destination.read_bytes() == wrapper.read_bytes()
    else:
        assert result.returncode != 0
        assert "Cannot wrap the native SafeOS shell" in result.stderr
        assert launcher.read_bytes() == original
        if case == "collision":
            assert destination.read_bytes() == b"existing"
        else:
            assert not destination.exists()


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize(
    "case", ["commit", "dism-fails", "source-changed", "collision"]
)
def test_native_wim_is_untouched_until_verified_replacement(
    tmp_path: Path, case: str
) -> None:
    native = tmp_path / "winre.wim"
    native.write_bytes(b"stock WIM")
    job = tmp_path / "job"
    job.mkdir()
    staged = job / "safeos-staged.wim"
    if case == "collision":
        staged.write_bytes(b"existing")
    wrapper = tmp_path / "wrapper.cmd"
    wrapper.write_bytes(b"@echo off\r\n")
    stock = tmp_path / "winpeshl.ini"
    stock.write_bytes(STOCK)
    harness = r"""
. $env:WUO_BOOT_SCRIPT
function Invoke-WuoSafeOsDism([string[]]$Options, [string]$LogPath) {
    $native = [IO.File]::ReadAllText($env:WUO_NATIVE)
    if ($native -ne 'stock WIM') { throw 'Original WIM was changed too early.' }
    $mount = (($Options | Where-Object { $_ -like '/MountDir:*' }) -replace '^/MountDir:', '')
    if ($Options[0] -eq '/Mount-Image') {
        if ($Options -notcontains "/ImageFile:$env:WUO_STAGED") { throw 'DISM must mount a copy.' }
        $system = Join-Path $mount 'Windows\System32'
        $recovery = Join-Path $mount 'sources\recovery'
        $null = [IO.Directory]::CreateDirectory($system)
        $null = [IO.Directory]::CreateDirectory($recovery)
        [IO.File]::Copy($env:WUO_STOCK, (Join-Path $system 'winpeshl.ini'))
        [IO.File]::WriteAllText((Join-Path $recovery 'recenv.exe'), 'fixture')
        return
    }
    if ($Options -contains '/Discard') {
        [IO.File]::WriteAllText($LogPath, 'discarded')
        return
    }
    if ($env:WUO_CASE -eq 'dism-fails') { throw 'DISM refused the commit.' }
    if (!(Test-Path -LiteralPath (Join-Path $mount 'Windows\System32\wuo-safeos.cmd'))) {
        throw 'The commit must include the verified wrapper.'
    }
    [IO.File]::WriteAllText($env:WUO_STAGED, 'patched WIM')
    if ($env:WUO_CASE -eq 'source-changed') {
        [IO.File]::WriteAllText($env:WUO_NATIVE, 'changed by Setup')
    }
}
Install-WuoSafeOsImage $env:WUO_NATIVE $env:WUO_JOB $env:WUO_WRAPPER
"""
    result = _run_powershell(
        harness,
        boot_script=BOOT_SCRIPT,
        native=native,
        job=job,
        staged=staged,
        wrapper=wrapper,
        stock=stock,
        case=case,
    )
    original = job / "safeos-original.wim"
    if case == "commit":
        assert result.returncode == 0, result.stderr
        assert native.read_bytes() == b"patched WIM"
        assert original.read_bytes() == b"stock WIM"
        assert not staged.exists()
        return

    assert result.returncode != 0
    assert not original.exists()
    if case == "source-changed":
        assert "The native SafeOS image changed" in result.stderr
        assert native.read_bytes() == b"changed by Setup"
    else:
        assert native.read_bytes() == b"stock WIM"
    if case == "dism-fails":
        assert "DISM refused the commit." in result.stderr
        assert (job / "dism.log").read_text() == "discarded"
    if case == "collision":
        assert "SafeOS staging path already exists" in result.stderr
        assert staged.read_bytes() == b"existing"
