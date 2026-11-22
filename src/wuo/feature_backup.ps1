[CmdletBinding()]
param(
    [Parameter(Mandatory)][Guid]$Job,
    [Parameter(Mandatory)][Guid]$Machine,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]+\.[0-9]+$')][string]$SourceBuild,
    [Parameter(Mandatory)][ValidatePattern('^[A-Z]:$')][string]$BackupDrive
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$system32 = Join-Path $env:SystemRoot 'System32'
$drive = $env:SystemDrive
$volumeName = '^\\\\\?\\Volume\{[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}\\$'

function Get-VolumeName($Partition) {
    $paths = @($Partition.AccessPaths | Where-Object { $_ -match $volumeName })
    if ($paths.Count -ne 1) { throw 'Could not verify a unique volume name.' }
    return $paths[0]
}

function Invoke-Native([string]$Name, [string[]]$Arguments) {
    $result = & (Join-Path $system32 $Name) @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Name returned $LASTEXITCODE. $($result -join ' ')"
    }
    return ($result -join "`n")
}

$versionKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Create the feature rollback backup from an administrator terminal.'
}
$machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
if ($Machine -ne [Guid]$machineGuid -or "$($versionKey.CurrentBuildNumber).$($versionKey.UBR)" -ne $SourceBuild) {
    throw 'The running Windows installation differs from the feature upgrade plan.'
}
if ((Test-Path -LiteralPath (Join-Path "$drive\" '$WINDOWS.~BT\NewOS\Windows\System32\Config\SYSTEM')) -or
    (Get-ItemProperty 'HKLM:\SYSTEM\Setup').SystemSetupInProgress) {
    throw 'Create the rollback backup before staging Windows Setup.'
}
$windows = Get-Partition -DriveLetter $drive[0]
$efi = @(Get-Partition | Where-Object { $_.IsSystem -and $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' })
$backup = Get-Partition -DriveLetter $BackupDrive[0]
$target = Get-Volume -DriveLetter $BackupDrive[0]
if ($efi.Count -ne 1 -or $backup.DiskNumber -in $windows.DiskNumber, $efi[0].DiskNumber -or
    $target.FileSystem -ne 'NTFS' -or $target.HealthStatus -ne 'Healthy') {
    throw 'Use a healthy NTFS backup volume on a disk separate from Windows and EFI.'
}
$windowsId = Get-VolumeName $windows
$efiId = Get-VolumeName $efi[0]
$backupId = Get-VolumeName $backup
$source = Get-Volume -DriveLetter $drive[0]
if ($target.SizeRemaining -lt ($source.Size - $source.SizeRemaining + 1GB)) {
    throw 'The rollback volume does not have enough free space to back up Windows and EFI.'
}
if (Test-Path -LiteralPath (Join-Path "$BackupDrive\" 'WindowsImageBackup')) {
    throw 'Select a backup volume without an existing Windows Image Backup catalog.'
}

$base = Join-Path "$BackupDrive\" 'WUO-Rollback'
$out = Join-Path $base $Job.ToString('D')
if ((Test-Path -LiteralPath $base) -and
    ((Get-Item -LiteralPath $base -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The rollback directory must be local to the selected backup volume.'
}
if (Test-Path -LiteralPath $out) { throw 'A rollback backup already exists for this job.' }
$null = New-Item -Path $out -ItemType Directory -Force
$bootCopy = Join-Path $out 'EFI\Microsoft\Boot'
$attached = $false
$efiDrive = $null
try {
    if ($efi[0].DriveLetter -match '^[A-Z]$') {
        $efiDrive = "$($efi[0].DriveLetter):"
    } else {
        foreach ($letter in [char[]]'ZYXWVUTSRQPONMLKJIHGFED') {
            if (Get-PSDrive -Name $letter -ErrorAction SilentlyContinue) { continue }
            $efiDrive = "${letter}:"
            $null = Invoke-Native 'mountvol.exe' @("$efiDrive\", $efiId)
            $attached = $true
            break
        }
    }
    if (!$efiDrive -or (Invoke-Native 'mountvol.exe' @("$efiDrive\", '/L')).Trim() -ine $efiId) {
        throw 'Could not verify a drive letter for the active EFI system partition.'
    }
    $boot = Join-Path "$efiDrive\" 'EFI\Microsoft\Boot'
    if (!(Test-Path -LiteralPath (Join-Path $boot 'BCD') -PathType Leaf)) {
        throw 'The selected EFI partition has no Windows Boot Manager store.'
    }
    $robocopy = Join-Path $system32 'robocopy.exe'
    & $robocopy $boot $bootCopy /E /COPY:DAT /DCOPY:DAT /R:0 /W:0 /XJ /XF BCD 'BCD.LOG*' *> (Join-Path $out 'efi-backup.log')
    if ($LASTEXITCODE -ge 8) { throw 'The Windows EFI backup failed.' }
    $bcdCopy = Join-Path $bootCopy 'BCD'
    $null = Invoke-Native 'bcdedit.exe' @('/export', $bcdCopy)
    $validationCopy = Join-Path $out 'validation.bcd'
    [IO.File]::Copy($bcdCopy, $validationCopy, $false)
    $live = Invoke-Native 'bcdedit.exe' @('/enum', '{bootmgr}', '/v')
    $savedStore = Invoke-Native 'bcdedit.exe' @('/store', $validationCopy, '/enum', '{bootmgr}', '/v')
    if ($live -cne $savedStore) { throw 'The saved BCD does not match the active Windows Boot Manager.' }
    $inventory = @(foreach ($file in Get-ChildItem -LiteralPath $boot -File -Force -Recurse) {
        if ($file.Name -match '^BCD(?:\.LOG.*)?$') { continue }
        $relative = $file.FullName.Substring($boot.Length + 1)
        $digest = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $saved = Join-Path $bootCopy $relative
        if (!(Test-Path -LiteralPath $saved -PathType Leaf) -or
            (Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash -cne $digest) {
            throw 'The saved Windows EFI file differs from the original.'
        }
        @{ path = "EFI\Microsoft\Boot\$relative"; sha256 = $digest.ToLowerInvariant() }
    })
    $inventory += @{
        path = 'EFI\Microsoft\Boot\BCD'; sha256 = (Get-FileHash -LiteralPath $bcdCopy -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $auxiliary = @(
        'EFI\Microsoft\Recovery\BCD',
        'EFI\Boot\bootx64.efi', 'EFI\Boot\bootaa64.efi', 'EFI\Boot\bootia32.efi'
    )
    foreach ($relative in $auxiliary) {
        $file = Join-Path "$efiDrive\" $relative
        if (!(Test-Path -LiteralPath $file -PathType Leaf)) { continue }
        $saved = Join-Path $out $relative
        $null = [IO.Directory]::CreateDirectory((Split-Path -Parent $saved))
        [IO.File]::Copy($file, $saved, $false)
        $digest = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        if ((Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash -cne $digest) {
            throw "The saved EFI file differs from the original: $relative"
        }
        $inventory += @{ path = $relative; sha256 = $digest.ToLowerInvariant() }
    }
    Invoke-Native 'bcdedit.exe' @('/enum', 'firmware', '/v') |
        Set-Content -LiteralPath (Join-Path $out 'firmware.log') -Encoding Ascii
} finally {
    if ($attached -and (Invoke-Native 'mountvol.exe' @("$efiDrive\", '/L')).Trim() -ieq $efiId) {
        $null = Invoke-Native 'mountvol.exe' @("$efiDrive\", '/D')
    }
}

$tool = Join-Path $system32 'wbadmin.exe'
& $tool start backup "-backupTarget:$BackupDrive" "-include:$drive" -vssCopy -quiet *> (Join-Path $out 'windows-backup.log')
if ($LASTEXITCODE -ne 0) { throw "Windows Backup failed with exit $LASTEXITCODE." }
$catalog = Invoke-Native 'wbadmin.exe' @('get', 'versions', "-backupTarget:$BackupDrive", "-machine:$env:COMPUTERNAME")
$catalog | Set-Content -LiteralPath (Join-Path $out 'catalog.log') -Encoding Ascii
$matches = [regex]::Matches($catalog, '(?m):\s*(\d{2}/\d{2}/\d{4}-\d{2}:\d{2})[ \t]*$')
if ($matches.Count -ne 1) { throw 'Could not identify a single Windows rollback backup.' }
$backupVersion = $matches[0].Groups[1].Value
$items = Invoke-Native 'wbadmin.exe' @('get', 'items', "-version:$backupVersion", "-backupTarget:$BackupDrive", "-machine:$env:COMPUTERNAME")
$items | Set-Content -LiteralPath (Join-Path $out 'items.log') -Encoding Ascii
if ($items -notmatch [regex]::Escape($drive)) { throw 'The Windows volume was not found in the verified backup catalog.' }
$report = @{
    schema = 1; id = $Job.ToString('D'); machine = $Machine.ToString('D'); source = $SourceBuild
    volume = $backupId; windows = $windowsId; efi = $efiId; original_letter = $drive
    catalog = $backupVersion; computer = $env:COMPUTERNAME; boot_files = $inventory
} | ConvertTo-Json -Depth 5 -Compress
[IO.File]::WriteAllText((Join-Path $out 'rollback.json'), $report, [Text.UTF8Encoding]::new($false))
$report
