import base64
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path
from uuid import UUID

import pytest

POWERSHELL = shutil.which("powershell.exe")
SCRIPT = Path(__file__).parents[1] / "src/wuo/feature_boot.ps1"
PARTITION = UUID("19a976bd-3c7e-4c4c-befb-8dfcfa65a22e")
LOADER = r"\EFI\BOOT\BOOTX64.EFI"


def _powershell(command: str, **fixture: str) -> subprocess.CompletedProcess[str]:
    assert POWERSHELL is not None
    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ". $env:WUO_SCRIPT; " + command,
        ],
        env=os.environ | {"WUO_SCRIPT": str(SCRIPT)} | fixture,
        capture_output=True,
        check=False,
        text=True,
        timeout=20,
    )


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
def test_ventoy_partition_uses_pinned_volume_name_on_selected_usb_disk() -> None:
    result = _powershell(
        r"""
$ventoy = '\\?\Volume{19a976bd-3c7e-4c4c-befb-8dfcfa65a22e}\'
$other = '\\?\Volume{19a976bd-3c7e-4c4c-befb-8dfcfa65a22f}\'
function Get-Volume([string]$FileSystemLabel) {
    if ($FileSystemLabel -ne 'VTOYEFI') { throw 'Use an exact volume label query.' }
    @{ Path = $ventoy; FileSystem = 'FAT' }
    @{ Path = $other; FileSystem = 'FAT32' }
}
$data = @{ DiskNumber = 3; PartitionNumber = 1 }
$parts = @(
    $data,
    @{ DiskNumber = 3; PartitionNumber = 2; Guid = '{19a976bd-3c7e-4c4c-befb-8dfcfa65a22e}'; AccessPaths = @('I:\', $ventoy) },
    @{ DiskNumber = 4; PartitionNumber = 2; Guid = '{19a976bd-3c7e-4c4c-befb-8dfcfa65a22f}'; AccessPaths = @('J:\', $other) }
)
(Find-WuoVentoyPartition $parts $data).Guid
"""
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"{{{PARTITION}}}"


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize(
    "case", ["valid", "inactive", "mbr", "wrong-path", "trailing-node", "truncated"]
)
def test_recovery_efi_identity_is_read_from_load_option(case: str) -> None:
    name = (LOADER if case != "wrong-path" else "\\EFI\\..\\loader.efi") + "\0"
    name_bytes = name.encode("utf-16-le")
    disk_node = struct.pack(
        "<BBHIQQ16sBB",
        4,
        1,
        42,
        2,
        2048,
        65536,
        PARTITION.bytes_le,
        2,
        1 if case == "mbr" else 2,
    )
    nodes = (
        disk_node
        + struct.pack("<BBH", 4, 4, 4 + len(name_bytes))
        + name_bytes
        + b"\x7f\xff\x04\x00"
    )
    if case == "trailing-node":
        nodes += b"\x7f\xff\x04\x00"
    bits = 0 if case == "inactive" else 1
    data = struct.pack("<IH", bits, len(nodes)) + "Ventoy\0".encode("utf-16-le") + nodes
    if case == "truncated":
        data = data[:-1]
    result = _powershell(
        r"""
function Get-WuoFirmwareVariable([string]$Name) {
    if ($Name -cne 'Boot1234') { throw "Unexpected UEFI read: $Name" }
    return @{ bytes = [Convert]::FromBase64String($env:WUO_ENTRY); attributes = 7 }
}
Get-WuoBootEntry 'Boot1234' -IncludeDevice | ConvertTo-Json -Compress
""",
        WUO_ENTRY=base64.b64encode(data).decode("ascii"),
    )
    if case == "truncated":
        assert result.returncode != 0
        assert "Malformed UEFI entry" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        response = json.loads(result.stdout)
        expected = (
            {"partition": str(PARTITION), "loader": LOADER} if case == "valid" else None
        )
        assert response["device"] == expected


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize("case", ["empty", "set", "invalid"])
def test_only_absent_bootnext_is_accepted_for_capture(case: str) -> None:
    result = _powershell(
        r"""
function Get-WuoFirmwareVariable([string]$Name, [switch]$AllowMissing) {
    if ($Name -cne 'BootNext' -or !$AllowMissing) { throw 'Unexpected variable read.' }
    if ($env:WUO_CASE -eq 'empty') { return }
    if ($env:WUO_CASE -eq 'invalid') { return @{ bytes = [byte[]]@(8); attributes = 7 } }
    return @{ bytes = [BitConverter]::GetBytes([uint16]0x22); attributes = 7 }
}
Assert-WuoRecoveryBootNextIdle
'ready'
""",
        WUO_CASE=case,
    )
    if case == "empty":
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "ready"
    else:
        assert result.returncode != 0
        assert "BootNext" in result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize("case", ["one", "canonical", "ambiguous"])
def test_recovery_selects_the_registered_windows_boot_manager(case: str) -> None:
    result = _powershell(
        r"""
$esp = '11111111-1111-1111-1111-111111111111'
$dev = @{ partition = $esp; loader = '\EFI\Microsoft\Boot\bootmgfw.efi' }
$bare = @{ id = 'Boot9101'; identity = 'bare'; device = $dev; windows_registration = $false }
$entries = @($bare)
if ($env:WUO_CASE -ne 'one') {
    $entries += @{
        id = 'Boot0008'; identity = 'registered'; device = $dev
        windows_registration = $env:WUO_CASE -eq 'canonical'
    }
}
(Select-WuoWindowsBootEntry $entries $esp).id
""",
        WUO_CASE=case,
    )
    if case == "ambiguous":
        assert result.returncode != 0
        assert "Windows Boot Manager" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == ("Boot9101" if case == "one" else "Boot0008")


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize(
    ("mode", "case"),
    [
        ("Arm", "good"),
        ("Arm", "unrelated"),
        ("Arm", "stale-id"),
        ("Arm", "ignored"),
        ("Release", "good"),
        ("Release", "unrelated"),
        ("Release", "missing"),
    ],
)
def test_one_time_boot_never_overwrites_an_unowned_selection(
    mode: str, case: str
) -> None:
    result = _powershell(
        r"""
$selected = @{ id = 'Boot0022'; identity = 'captured-fingerprint' }
$next = if ($env:WUO_CASE -eq 'unrelated') { 'Boot0001' }
        elseif ($env:WUO_MODE -eq 'Release' -and $env:WUO_CASE -ne 'missing') { 'Boot0022' }
$script:writes = @()
function Get-WuoRecoveryBootNext { return $script:next }
function Get-WuoBootEntry([string]$Id) {
    if ($Id -ne 'Boot0022') { throw 'Unexpected firmware entry.' }
    if ($env:WUO_CASE -eq 'stale-id') { return @{ identity = 'different-fingerprint' } }
    return $selected
}
function Set-WuoRecoveryBootNext([string]$Id) {
    $script:writes += $Id
    if ($env:WUO_CASE -ne 'ignored') { $script:next = $Id }
}
$failure = $null
try { Set-WuoProtectedSetupBoot $selected $env:WUO_MODE }
catch { $failure = $_.Exception.Message }
@{ failure = $failure; writes = $writes; next = $next } | ConvertTo-Json -Compress
""",
        WUO_MODE=mode,
        WUO_CASE=case,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    if case == "good":
        expected = "Boot0022" if mode == "Arm" else ""
        assert report == {"failure": None, "writes": [expected], "next": expected}
    else:
        assert "UEFI" in report["failure"]
        assert report["writes"] == (["Boot0022"] if case == "ignored" else [])


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize("case", ["match", "different-device", "different-path", "two"])
def test_bcd_recovery_entry_matches_device_and_path(case: str) -> None:
    identifier = "{af0db5c9-21b2-4f91-97f5-93b39849289f}"
    device = r"\Device\HarddiskVolume9"
    records = [
        "",
        "Firmware Application (101fffff)",
        "--------------------------------",
        f"identifier              {identifier}",
        f"device                  partition={device}",
        f"path                    {LOADER}",
        "description             Same label",
    ]
    if case == "different-device":
        records[4] = r"device                  partition=\Device\HarddiskVolume10"
    if case == "different-path":
        records[5] = r"path                    \EFI\other\other.efi"
    if case == "two":
        records = records + [
            line.replace(identifier, "{b60918ec-0cfe-4c55-8e1c-fdb352742fd3}")
            for line in records
        ]
    result = _powershell(
        r"""
Find-WuoRecoveryBcdId ($env:WUO_FIRMWARE -split '\n') @($env:WUO_DEVICE, 'F:') $env:WUO_LOADER
""",
        WUO_FIRMWARE="\n".join(records),
        WUO_DEVICE=device,
        WUO_LOADER=LOADER,
    )
    if case == "match":
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == identifier
    else:
        assert result.returncode != 0
        assert "unique recovery boot application" in result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="requires Windows PowerShell")
@pytest.mark.parametrize("case", ["verified", "ignored-order", "changed-entry"])
def test_recovery_order_is_persistent_before_safeos_is_released(case: str) -> None:
    result = _powershell(
        r"""
$recovery = @{ id = 'Boot0022'; identity = 'recovery' }
$windows = @{ id = 'Boot0005'; identity = 'windows' }
$script:entries = @($windows, $recovery, @{ id = 'Boot0001'; identity = 'limine' })
$script:next = 'Boot0022'
$script:writes = @()
function Get-WuoBootEntry([string]$Id) {
    if ($Id -eq 'Boot0005' -and $env:WUO_CASE -eq 'changed-entry') {
        return @{ id = $Id; identity = 'different entry' }
    }
    return $script:entries | Where-Object { $_.id -eq $Id }
}
function Get-WuoBootState { return @{ entries = $script:entries; attributes = 7 } }
function Get-WuoRecoveryBootNext { return $script:next }
function Set-WuoBootOrder([byte[]]$Bytes, [uint32]$Attributes) {
    $newOrder = @(for ($i = 0; $i -lt $Bytes.Length; $i += 2) {
        'Boot{0:X4}' -f [BitConverter]::ToUInt16($Bytes, $i)
    })
    $script:writes += ($newOrder -join ',')
    if ($env:WUO_CASE -ne 'ignored-order') {
        $script:entries = @($newOrder | ForEach-Object { Get-WuoBootEntry $_ })
    }
}
function Set-WuoRecoveryBootNext([string]$Id) { $script:next = $Id; $script:writes += $Id }
$failure = $null
try {
    Set-WuoProtectedRecoveryOrder $recovery
    Start-WuoSafeOsBoot $recovery $windows
}
catch { $failure = $_.Exception.Message }
@{ next = $next; writes = $writes; failure = $failure } | ConvertTo-Json -Compress
""",
        WUO_CASE=case,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    if case == "verified":
        assert report == {
            "next": "Boot0005",
            "writes": ["Boot0022,Boot0005,Boot0001", "Boot0005"],
            "failure": None,
        }
    else:
        assert report["next"] == "Boot0022"
        assert "UEFI" in report["failure"]
        assert "Boot0005" not in report["writes"]
