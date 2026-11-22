import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

POWERSHELL = shutil.which("powershell.exe")
SCRIPT = Path(__file__).resolve().parents[1] / "src" / "wuo" / "feature_boot.ps1"
pytestmark = pytest.mark.skipif(
    POWERSHELL is None, reason="Windows PowerShell required"
)

HARNESS = r"""
$ErrorActionPreference = 'Stop'
. $env:WUO_BOOT_SCRIPT

$fixture = Get-Content -LiteralPath $env:WUO_BOOT_FIXTURE -Raw | ConvertFrom-Json
$job = Join-Path $env:WUO_BOOT_ROOT 'job'
$esp = Join-Path $env:WUO_BOOT_ROOT 'esp'
$fallback = Join-Path $esp 'EFI\Boot\bootx64.efi'
$bootmgr = Join-Path $esp 'EFI\Microsoft\Boot\bootmgfw.efi'
$null = New-Item -ItemType Directory -Path $job, (Split-Path $fallback), (Split-Path $bootmgr) -Force
$knownLoader = [Text.Encoding]::ASCII.GetBytes('Verified Windows loader')
$originalLoader = [byte[]]::new(160)
$originalLoader[0] = 0x4D; $originalLoader[1] = 0x5A
$originalLoader[60] = 64
$originalLoader[64] = 0x50; $originalLoader[65] = 0x45
$originalLoader[68] = 0x64; $originalLoader[69] = 0x86
$originalLoader[84] = 72
$originalLoader[88] = 0xB; $originalLoader[89] = 2
$originalLoader[156] = 10
if ($fixture.invalid_original) { $originalLoader = [Text.Encoding]::ASCII.GetBytes('Invalid image') }
if (!$fixture.absent_fallback) { [IO.File]::WriteAllBytes($fallback, $originalLoader) }
[IO.File]::WriteAllBytes($bootmgr, $knownLoader)
$state = $fixture.original
$partition = '58aef694-4e98-4aeb-9ee6-00edcb120827'
$firmwareWrites = [Collections.Generic.List[string]]::new()
$fileWrites = [Collections.Generic.List[string]]::new()

function Get-WuoEsp { return @{ id = $script:partition; root = "$script:esp\" } }
function Get-WuoFallbackPath { return 'EFI\Boot\bootx64.efi' }
function Assert-WuoProtectedJob([string]$Path) {}
function Get-WuoWindowsBootHash {
    (Get-FileHash -LiteralPath $bootmgr -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Test-WuoWindowsBootMetadata([string]$Path) { return [bool]$fixture.original_windows }
function Get-WuoFirmwareVariable([string]$Name) {
    if ($Name -ceq 'BootOrder') {
        $bytes = [Collections.Generic.List[byte]]::new()
        foreach ($number in $script:state.order) {
            $bytes.AddRange([BitConverter]::GetBytes([uint16]$number))
        }
        return @{ bytes = $bytes.ToArray(); attributes = 7 }
    }
    if ($Name -notmatch '^Boot[0-9A-F]{4}$') { throw "Unexpected variable read: $Name" }
    $lookup = [int]('0x' + $Name.Substring(4))
    $entry = $script:state.entries.PSObject.Properties[[string]$lookup]
    if ($null -eq $entry) { throw "Missing test boot entry: $Name" }
    $description = [Text.Encoding]::Unicode.GetBytes("Entry $lookup`0")
    $data = [Text.Encoding]::ASCII.GetBytes([string]$entry.Value)
    $bytes = [byte[]](@(1, 0, 0, 0, 4, 0) + $description + @(127, 255, 4, 0) + $data)
    return @{ bytes = $bytes; attributes = 7 }
}
function Set-WuoBootOrder([byte[]]$Bytes, [uint32]$Attributes) {
    if ($Attributes -ne 7) { throw 'The original variable attributes were not preserved.' }
    $ids = for ($offset = 0; $offset -lt $Bytes.Length; $offset += 2) {
        [BitConverter]::ToUInt16($Bytes, $offset)
    }
    $firmwareWrites.Add(($ids -join ','))
    if (!$fixture.firmware_write_ignored) { $script:state.order = @($ids) }
}
function Move-WuoFile([string]$Source, [string]$Destination) {
    if ($Destination -eq $script:fallback) {
        $fileWrites.Add('fallback')
        if ($fixture.file_write_failure) { throw 'Mocked FAT replacement failure.' }
    }
    if ($fixture.native_result_move -and $Destination -ne $script:fallback) {
        Initialize-WuoBootNative
        [WuoBootNative]::ReplaceFile($Source, $Destination)
        return
    }
    if ([IO.File]::Exists($Destination)) { [IO.File]::Delete($Destination) }
    [IO.File]::Move($Source, $Destination)
}

$preview = Invoke-WuoBootPreservation -Mode Preview
$previewArtifacts = @(Get-ChildItem -LiteralPath $job -Force).Count
$previewFirmwareWrites = $firmwareWrites.Count
$previewFileWrites = $fileWrites.Count
$snapshot = Invoke-WuoBootPreservation -Mode Capture -JobPath $job
$state = $fixture.current
if ($fixture.changed_partition) { $partition = 'facb7bf7-4739-4b46-933d-b18d71a3dfaa' }
if ($fixture.destination_order_result_directory) {
    $null = New-Item -ItemType Directory -Path (Join-Path $job 'boot-order-result.json')
}
if ($fixture.replacement -eq 'windows') { [IO.File]::WriteAllBytes($fallback, $knownLoader) }
if ($fixture.replacement -eq 'unknown') { [IO.File]::WriteAllText($fallback, 'Unrecognized loader') }
$restoreError = $null
$result = $null
try { $result = Invoke-WuoBootPreservation -Mode Restore -JobPath $job }
catch { $restoreError = $_.Exception.Message }
$retry = $null
if ($fixture.retry_restore) { $retry = Invoke-WuoBootPreservation -Mode Restore -JobPath $job }
$resultPath = Join-Path $job 'boot-order-result.json'
$fallbackContents = if ([IO.File]::Exists($fallback)) {
    $data = [IO.File]::ReadAllBytes($fallback)
    if ([Convert]::ToBase64String($data) -ceq [Convert]::ToBase64String($originalLoader)) { 'Original loader' }
    else { [Text.Encoding]::ASCII.GetString($data) }
}
$resultContents = if ([IO.File]::Exists($resultPath)) {
    Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
}
$report = @{
    preview = $preview
    preview_artifacts = $previewArtifacts
    preview_firmware_writes = $previewFirmwareWrites
    preview_file_writes = $previewFileWrites
    snapshot = $snapshot
    captured_fallback = [IO.File]::Exists((Join-Path $job 'boot-fallback.efi'))
    result = $result
    retry = $retry
    restore_error = $restoreError
    firmware_writes = @($firmwareWrites.ToArray())
    file_writes = @($fileWrites.ToArray())
    fallback_bytes = $fallbackContents
    disk_result = $resultContents
}
$report | ConvertTo-Json -Depth 10 -Compress
"""


def exercise(
    tmp_path: Path, *, capture_failure: bool = False, **overrides: object
) -> dict[str, Any]:
    assert POWERSHELL is not None
    state = {
        "original": {"order": [1, 2], "entries": {"1": "Limine", "2": "Windows"}},
        "current": {
            "order": [3, 2, 1, 4],
            "entries": {"1": "Limine", "2": "Windows", "3": "New 1", "4": "New 2"},
        },
        "replacement": "windows",
        **overrides,
    }
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps(state), encoding="ascii")
    harness = tmp_path / "test.ps1"
    harness.write_text(HARNESS, encoding="ascii")
    env = {
        key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"
    }
    env.update(
        WUO_BOOT_SCRIPT=str(SCRIPT),
        WUO_BOOT_FIXTURE=str(fixture),
        WUO_BOOT_ROOT=str(tmp_path),
    )
    run = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness),
        ],
        env=env,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    if capture_failure:
        assert run.returncode != 0
        return {"stderr": run.stderr}
    assert run.returncode == 0, run.stderr
    report: dict[str, Any] = json.loads(run.stdout)
    return report


def test_preview_is_read_only_and_restore_retains_new_entries(tmp_path: Path) -> None:
    result = exercise(tmp_path, native_result_move=True)
    assert result["preview_artifacts"] == 0
    assert result["preview_firmware_writes"] == 0
    assert result["preview_file_writes"] == 0
    assert [entry["id"] for entry in result["preview"]["entries"]] == [
        "Boot0001",
        "Boot0002",
    ]
    assert result["preview"] == result["snapshot"]
    assert result["firmware_writes"] == ["1,2,3,4"]
    assert result["file_writes"] == ["fallback"]
    assert result["fallback_bytes"] == "Original loader"
    assert result["result"]["order"] == "restored"
    assert result["result"]["fallback"] == "restored"
    assert result["result"] == result["disk_result"]


@pytest.mark.parametrize(
    "current",
    [
        {"order": [2], "entries": {"2": "Windows"}},
        {"order": [2, 3, 4], "entries": {"2": "Windows", "3": "Limine", "4": "Limine"}},
        {
            "order": [1, 2, 3],
            "entries": {"1": "Changed", "2": "Windows", "3": "New"},
        },
    ],
)
def test_rejects_missing_ambiguous_or_repointed_entries(
    tmp_path: Path, current: dict[str, object]
) -> None:
    result = exercise(tmp_path, current=current)
    assert result["firmware_writes"] == []
    assert result["result"]["order"] == "blocked"


def test_matches_renumbered_entry_to_the_same_loader(tmp_path: Path) -> None:
    result = exercise(
        tmp_path,
        current={
            "order": [8, 2, 6],
            "entries": {"2": "Windows", "6": "Limine", "8": "New"},
        },
    )
    assert result["firmware_writes"] == ["6,2,8"]
    assert result["result"]["order"] == "restored"


def test_restores_verified_entry_removed_from_order_but_still_present(
    tmp_path: Path,
) -> None:
    result = exercise(
        tmp_path,
        current={
            "order": [2, 8],
            "entries": {"1": "Limine", "2": "Windows", "8": "New"},
        },
    )
    assert result["firmware_writes"] == ["1,2,8"]
    assert result["result"]["order"] == "restored"


def test_retains_reused_number_when_the_original_loader_has_moved(
    tmp_path: Path,
) -> None:
    result = exercise(
        tmp_path,
        current={
            "order": [1, 2, 8, 6],
            "entries": {"1": "Reused", "2": "Windows", "6": "Limine", "8": "New"},
        },
    )
    assert result["firmware_writes"] == ["6,2,1,8"]
    assert result["result"]["order"] == "restored"


def test_retry_verifies_changes_without_rewriting_firmware_or_efi(
    tmp_path: Path,
) -> None:
    result = exercise(tmp_path, native_result_move=True, retry_restore=True)
    assert result["firmware_writes"] == ["1,2,3,4"]
    assert result["file_writes"] == ["fallback"]
    assert result["retry"]["order"] == "unchanged"
    assert result["retry"]["fallback"] == "unchanged"
    assert result["retry"] == result["disk_result"]


@pytest.mark.parametrize(
    ("replacement", "expected_status", "retained_bytes"),
    [
        ("none", "unchanged", "Original loader"),
        ("unknown", "skipped", "Unrecognized loader"),
    ],
)
def test_restore_leaves_unchanged_or_unrecognized_fallbacks(
    tmp_path: Path, replacement: str, expected_status: str, retained_bytes: str
) -> None:
    result = exercise(tmp_path, replacement=replacement)
    assert result["file_writes"] == []
    assert result["fallback_bytes"] == retained_bytes
    assert result["result"]["fallback"] == expected_status
    if replacement == "unknown":
        assert result["firmware_writes"] == []
        assert result["result"]["order"] == "blocked"


def test_absent_original_does_not_remove_windows_fallback(tmp_path: Path) -> None:
    result = exercise(tmp_path, absent_fallback=True)
    assert result["preview"]["fallback_state"] == "absent"
    assert result["captured_fallback"] is False
    assert result["file_writes"] == []
    assert result["fallback_bytes"] == "Verified Windows loader"
    assert result["result"]["fallback"] == "absent"


def test_original_windows_loader_is_not_preserved_over_setup(tmp_path: Path) -> None:
    result = exercise(tmp_path, original_windows=True)
    assert result["preview"]["fallback_state"] == "windows"
    assert result["captured_fallback"] is False
    assert result["file_writes"] == []
    assert result["fallback_bytes"] == "Verified Windows loader"


def test_invalid_original_fallback_stops_before_a_snapshot(tmp_path: Path) -> None:
    result = exercise(tmp_path, invalid_original=True, capture_failure=True)
    assert (
        "The original EFI fallback is not a native EFI application" in result["stderr"]
    )
    assert list((tmp_path / "job").iterdir()) == []


@pytest.mark.parametrize("file_write_failure", [False, True])
def test_failures_keep_the_snapshot_and_report_the_unverified_restoration(
    tmp_path: Path,
    file_write_failure: bool,
) -> None:
    result = exercise(
        tmp_path, firmware_write_ignored=True, file_write_failure=file_write_failure
    )
    assert result["result"]["order"] == ("blocked" if file_write_failure else "failed")
    assert result["result"]["fallback"] == (
        "failed" if file_write_failure else "restored"
    )
    assert result["captured_fallback"] is True
    assert result["fallback_bytes"] == (
        "Verified Windows loader" if file_write_failure else "Original loader"
    )


@pytest.mark.parametrize(
    "unsafe", ["changed_partition", "destination_order_result_directory"]
)
def test_rejects_unsafe_result_destination_or_efi_identity(
    tmp_path: Path, unsafe: str
) -> None:
    result = exercise(tmp_path, **{unsafe: True})
    assert result["restore_error"]
    assert result["firmware_writes"] == []
    assert result["file_writes"] == []
