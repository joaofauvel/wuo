import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

POWERSHELL = shutil.which("powershell.exe")
SCRIPT = Path(__file__).parents[1] / "src/wuo/feature_upgrade.ps1"


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is required")
@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("ready", ""),
        ("no-backup", "requires its verified rollback backup"),
        ("authorized", "already authorized"),
        ("setup", "Windows Setup is still running or staged"),
        ("running-task", "expected LocalSystem startup task"),
        ("different-account", "expected LocalSystem startup task"),
        ("bad-trigger", "expected LocalSystem startup task"),
        ("truncated-arguments", "expected LocalSystem startup task"),
        ("staged-ready", ""),
        ("staged-no-marker", "prepared.id"),
        ("staged-no-hive", "staged-SYSTEM"),
        ("staged-busy", "Windows Setup is still running or staged"),
    ],
)
def test_native_feature_retry_requires_its_ready_startup_task_and_backup(
    tmp_path: Path, case: str, error: str
) -> None:
    assert POWERSHELL is not None
    job = "b3bfc366-b2de-466a-9ba6-baa460c10775"
    state = tmp_path / "protected job"
    state.mkdir()
    (state / "feature_upgrade.ps1").touch()
    (state / "rollback.required").write_bytes(f"{job}\r\n".encode("ascii"))
    if case == "authorized":
        (state / "authorized.id").touch()
    if case.startswith("staged-"):
        attempt = state / "retry-active"
        attempt.mkdir()
        if case != "staged-no-marker":
            (attempt / "prepared.id").write_bytes(f"{job}\r\n".encode("ascii"))
        if case != "staged-no-hive":
            (state / "staged-SYSTEM").touch()
    harness = tmp_path / "retry_guard.ps1"
    harness.write_text(
        r"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:WUO_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw $errors[0] }
foreach ($name in 'CheckRetryJob', 'StagedRetry', 'RetryPrepareJob') {
    if ($ast.ParamBlock.Parameters.Name.VariablePath.UserPath -notcontains $name) {
        throw "Missing retry parameter: $name"
    }
}
foreach ($function in $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in 'Assert-FeatureRetry', 'Assert-PlainPath', 'Assert-JobMarker'
}, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}

function Assert-SourceMachine { return }
function Assert-WindowsReady {
    if ($env:WUO_CASE -like 'staged-*') { throw 'A prepared upgrade can leave SetupProgress present' }
    if ($env:WUO_FEATURE_SOURCE -ne '26200.9457') { throw 'Source build was not checked' }
}
function Assert-ProtectedJobDirectory { param($Path) Assert-PlainPath $Path -Directory }
function Get-ItemProperty {
    param($Path)
    if ($Path -ne 'HKLM:\SYSTEM\Setup') { throw 'Unexpected registry check' }
    @{SystemSetupInProgress=[int]($env:WUO_CASE -eq 'staged-busy')}
}
function Assert-BootPreservationAssets { $script:bootChecked = $true }
function Assert-FeatureBackupAvailable { $script:backupChecked = $true }
function Get-Process {
    param($Name, $ErrorAction)
    if ($env:WUO_CASE -eq 'setup') { [pscustomobject]@{Name='setuphost'} }
}
function Get-ScheduledTask {
    param($TaskName, $TaskPath)
    if ($TaskName -ne "wuo-feature-$env:WUO_JOB" -or $TaskPath -ne '\') {
        throw 'Unexpected task lookup'
    }
    $state = if ($env:WUO_CASE -eq 'running-task') { 'Running' } else { 'Ready' }
    $account = if ($env:WUO_CASE -eq 'different-account') { 'Administrator' } else { 'SYSTEM' }
    $trigger = if ($env:WUO_CASE -eq 'bad-trigger') { 'MSFT_TaskLogonTrigger' } else { 'MSFT_TaskBootTrigger' }
    $id = if ($env:WUO_CASE -eq 'truncated-arguments') { $env:WUO_JOB.Substring(0, 31) } else { $env:WUO_JOB }
    $runner = Join-Path $env:WUO_STATE 'feature_upgrade.ps1'
    [pscustomobject]@{
        State=$state
        Principal=@{UserId=$account}
        Triggers=@(@{Enabled=$true; CimClass=@{CimClassName=$trigger}})
        Actions=@(@{
            Execute="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            Arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`" -FinalizeJob $id"
        })
    }
}
Assert-FeatureRetry $env:WUO_STATE $env:WUO_JOB @{
    source='26200.9457'; rollback=($env:WUO_CASE -ne 'no-backup'); boot_preservation=@{enabled=$true}
} (Join-Path $env:WUO_STATE 'staged-SYSTEM') -Staged:($env:WUO_CASE -like 'staged-*')
if (!$script:bootChecked -or !$script:backupChecked) { throw 'Existing recovery assets were not checked' }
""",
        encoding="ascii",
    )
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            harness,
        ],
        env={
            **os.environ,
            "WUO_SCRIPT": str(SCRIPT),
            "WUO_STATE": str(state),
            "WUO_JOB": job,
            "WUO_CASE": case,
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert (result.returncode != 0) is bool(error), result.stderr
    assert error in result.stderr
    assert not result.stdout


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is required")
@pytest.mark.parametrize(
    "modified", [None, "job-runner", "portable-runner", "portable-digest"]
)
def test_native_feature_retry_verifies_its_portable_restore_launcher(
    tmp_path: Path, modified: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert POWERSHELL is not None
    monkeypatch.delenv("PSMODULEPATH", raising=False)
    job = "b3bfc366-b2de-466a-9ba6-baa460c10775"
    machine = "19063d8b-088e-437f-9d70-cc52fcefa470"
    volume = r"\\?\Volume{11111111-2222-3333-4444-555555555555}" + "\\"
    state = tmp_path / "job"
    state.mkdir()
    portable = tmp_path / "WUO-Rollback" / job / "recovery"
    portable.mkdir(parents=True)
    runner = b"@echo off\r\nexit /b 0\r\n"
    digest = f"{hashlib.sha256(runner).hexdigest()}\r\n".encode("ascii")
    for location in state, portable:
        (location / "restore.cmd").write_bytes(runner)
        (location / "restore.sha256").write_bytes(digest)
    for tool in "certutil.exe", "findstr.exe":
        (portable / tool).touch()
    (state / "rollback.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "id": job,
                "machine": machine,
                "source": "26200.9457",
                "computer": os.environ["COMPUTERNAME"],
                "catalog": "11/20/2026-12:43",
                "volume": volume,
            }
        ),
        encoding="ascii",
    )
    overrides = {
        "job-runner": state / "restore.cmd",
        "portable-runner": portable / "restore.cmd",
        "portable-digest": portable / "restore.sha256",
    }
    if modified:
        overrides[modified].write_bytes(b"modified")
    harness = tmp_path / "verify_restore.ps1"
    harness.write_text(
        r"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:WUO_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw $errors[0] }
foreach ($function in $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in 'Assert-FeatureBackupAvailable', 'Assert-PlainPath'
}, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
$letter = 90..68 | ForEach-Object { [string][char]$_ } |
    Where-Object { !(Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) } |
    Select-Object -First 1
New-PSDrive -Name $letter -PSProvider FileSystem -Root $env:WUO_FIXTURE | Out-Null
function Get-Partition { [pscustomobject]@{AccessPaths=@($env:WUO_VOLUME); DriveLetter=$letter} }
function Mock-Catalog {
    if ($args[0] -ne 'get' -or $args[1] -ne 'items') { throw 'Unexpected backup operation' }
    $global:LASTEXITCODE = 0
}
Set-Alias "$env:SystemRoot\System32\wbadmin.exe" Mock-Catalog
Assert-FeatureBackupAvailable $env:WUO_STATE $env:WUO_JOB @{machine=$env:WUO_MACHINE; source='26200.9457'} -VerifyArtifacts
""",
        encoding="ascii",
    )
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            harness,
        ],
        env={
            **os.environ,
            "WUO_SCRIPT": str(SCRIPT),
            "WUO_FIXTURE": str(tmp_path),
            "WUO_STATE": str(state),
            "WUO_JOB": job,
            "WUO_MACHINE": machine,
            "WUO_VOLUME": volume,
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert (result.returncode == 0) is (modified is None), result.stderr
    if modified:
        assert "The rollback launcher or its checksum changed" in result.stderr
