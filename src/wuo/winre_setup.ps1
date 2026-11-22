[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('install', 'uninstall')]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [string]$Root,
    [Parameter(Mandatory = $true)]
    [guid]$MachineGuid,
    [string]$Launcher,
    [string]$Profile,
    [string]$HookMetadata
)

$ErrorActionPreference = 'Stop'
$administrators = 'S-1-5-32-544'
$system = 'S-1-5-18'
$trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$toolPath = 'WUO\cmd.exe'
$toolArguments = '/d /c X:\Sources\Recovery\Tools\WUO\launcher.cmd'
$toolName = 'wuo'
$legacyToolName = 'Windows Offline Update'
$toolDescription = 'Apply a staged update job'
$utf8 = [Text.UTF8Encoding]::new($false)
$ascii = [Text.Encoding]::ASCII
$volumePattern = '^\\\\\?\\Volume\{[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}\\$'

function Test-PlainPath([string]$Path, [switch]$Directory, [switch]$AllowImageBacking) {
    try {
        $attributes = [IO.File]::GetAttributes($Path)
    } catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] {
        return $false
    }
    if ([bool]($attributes -band [IO.FileAttributes]::Directory) -ne $Directory.IsPresent) {
        throw "Unexpected file type at $Path."
    }
    if ($attributes -band [IO.FileAttributes]::ReparsePoint) {
        # WIM Mount and Windows Overlay tags back file contents with image
        # data. Directory mounts and symbolic links use different tags.
        if ($AllowImageBacking -and !$Directory -and
            (Invoke-SystemTool 'fsutil.exe' @('reparsepoint', 'query', $Path)) -match '\b0x800000(?:08|17)\b') {
            return $true
        }
        throw "Unexpected file type or reparse point at $Path."
    }
    return $true
}

function Get-TrustedAcl([string]$Path, [switch]$SystemDirectory) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $system, $administrators -and (!$SystemDirectory -or $owner -ne $trustedInstaller)) {
        throw "$Path has an untrusted owner."
    }
    return $acl
}

function Assert-ProtectedPath([string]$Path) {
    $acl = Get-TrustedAcl $Path
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if (!$rules.Count -or @($rules | Where-Object {
        $_.AccessControlType -ne 'Allow' -or $_.IdentityReference.Value -notin $system, $administrators
    }).Count) {
        throw "$Path must only grant access to SYSTEM and Administrators."
    }
}

function Protect-Directory([string]$Path, $Security) {
    $acl = Get-TrustedAcl $Path
    $access = [Security.AccessControl.AccessControlSections]::Access
    $acl.SetSecurityDescriptorSddlForm($Security.GetSecurityDescriptorSddlForm($access), $access)
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-ProtectedPath $Path
}

function Initialize-MenuRoot([string]$Path, [string]$WindowsDrive, [string]$Action) {
    $programData = Join-Path $WindowsDrive 'ProgramData'
    $base = Join-Path $programData 'WinOfflineUpdate'
    if ($Path -ine (Join-Path $base 'menu')) {
        throw 'The WinRE configuration must be on the active Windows drive in ProgramData\WinOfflineUpdate\menu.'
    }
    foreach ($parent in $WindowsDrive, $programData) {
        if (!(Test-PlainPath $parent -Directory)) { throw "$parent is missing." }
        $acl = Get-TrustedAcl $parent -SystemDirectory
        # Standard ProgramData allows creating directories. It must not allow
        # replacing an administrator-owned child or changing its own DACL.
        $unsafe = [Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership'
        if (@($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Value -notin $system, $administrators, $trustedInstaller -and
            !($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($_.FileSystemRights -band $unsafe)
        }).Count) {
            throw "$parent permits untrusted changes to the installation path."
        }
    }

    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new($administrators))
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in $system, $administrators) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
            'ContainerInherit, ObjectInherit', 'None', 'Allow'
        )
        $security.AddAccessRule($rule)
    }

    $hasBase = Test-PlainPath $base -Directory
    if ($hasBase) {
        $null = Get-TrustedAcl $base
        $hasMenu = Test-PlainPath $Path -Directory
        if ($hasMenu) { Assert-ProtectedPath $Path }
    } else {
        $hasMenu = $false
    }
    if (!$hasMenu -and $Action -eq 'uninstall') {
        throw 'The Windows Offline Update recovery menu is not installed.'
    }
    if (!$hasBase) {
        $null = [IO.Directory]::CreateDirectory($base, $security)
    }
    if (!(Test-PlainPath $base -Directory)) { throw "$base is missing." }
    Protect-Directory $base $security

    $jobs = Join-Path $base 'jobs'
    if (!(Test-PlainPath $jobs -Directory) -and $Action -eq 'install') {
        $null = [IO.Directory]::CreateDirectory($jobs, $security)
    }
    if (Test-PlainPath $jobs -Directory) { Protect-Directory $jobs $security }

    if (!$hasMenu) {
        $null = [IO.Directory]::CreateDirectory($Path, $security)
    }
    if (!(Test-PlainPath $Path -Directory)) { throw "$Path is missing." }
    Assert-ProtectedPath $Path
}

function Invoke-SystemTool([string]$Exe, [string[]]$Arguments) {
    $output = & (Join-Path $system32 $Exe) @Arguments
    $status = $LASTEXITCODE
    if ($status -ne 0) {
        throw "$Exe $($Arguments[0]) returned $status. $($output -join ' ')"
    }
    return ($output -join [Environment]::NewLine)
}

function Get-UniqueVolume($Partitions, [string]$Purpose) {
    if (@($Partitions).Count -ne 1) { throw "Could not find a unique $Purpose partition." }
    $volumes = @($Partitions.AccessPaths | Where-Object { $_ -match $volumePattern })
    if ($volumes.Count -ne 1) { throw "Could not find a unique $Purpose volume name." }
    return $volumes[0]
}

function Read-RecoveryRegistration {
    $info = Invoke-SystemTool 'reagentc.exe' @('/info')
    $xml = [xml][IO.File]::ReadAllText($agentConfig)
    $enabled = $xml.WindowsRE.InstallState.state
    $oemTool = $xml.WindowsRE.OemTool.state
    if ($enabled -notin '0', '1' -or $oemTool -notin '0', '1') {
        throw 'WinRE registration state could not be verified.'
    }
    if ($enabled -eq '0') { return @{ Enabled = $false; OemTool = ($oemTool -eq '1') } }

    $location = $xml.WindowsRE.WinreLocation.path
    $locations = @([regex]::Matches($info, '(?im)\\\\\?\\GLOBALROOT\\device\\harddisk(?<disk>\d+)\\partition(?<partition>\d+)(?<path>\\[^\r\n]+)') |
        Where-Object { $_.Groups['path'].Value.TrimEnd().TrimEnd('\') -ieq $location.TrimEnd('\') })
    $bcd = [guid]::Empty
    if ($locations.Count -ne 1 -or ![guid]::TryParse($xml.WindowsRE.WinreBCD.id, [ref]$bcd) -or $bcd -eq [guid]::Empty) {
        throw 'The active WinRE image location or boot entry could not be verified.'
    }
    $directory = $locations[0].Value.TrimEnd().TrimEnd('\')
    return @{
        Enabled = $true
        OemTool = ($oemTool -eq '1')
        Directory = $directory
        RelativePath = $location.Trim('\')
        Disk = [int]$locations[0].Groups['disk'].Value
        Partition = [int]$locations[0].Groups['partition'].Value
        Wim = "$directory\Winre.wim"
        Bcd = $bcd
    }
}

function Close-RecoveryVolume($Volume) {
    if ($Volume -and $Volume.Temporary -and
        (Invoke-SystemTool 'mountvol.exe' @($Volume.Drive, '/L')).Trim() -ieq $Volume.Name) {
        $null = Invoke-SystemTool 'mountvol.exe' @($Volume.Drive, '/D')
    }
}

function Open-RecoveryVolume($Registration) {
    $partition = @(Get-Partition -DiskNumber $Registration.Disk -PartitionNumber $Registration.Partition)
    $name = Get-UniqueVolume $partition 'WinRE'
    $drives = @($partition.AccessPaths | Where-Object { $_ -match '^[a-z]:\\$' })
    if ($drives.Count -gt 1) { throw 'The WinRE partition has multiple drive letters.' }
    $volume = @{ Name = $name; Drive = $drives[0]; Temporary = $false }
    if (!$volume.Drive) {
        $used = @([IO.DriveInfo]::GetDrives() | ForEach-Object Name) +
            @(Get-PSDrive -PSProvider FileSystem | ForEach-Object Root)
        $drive = @(90..68 | Where-Object { $_ -ne 88 } |
            ForEach-Object { ([string][char]$_) + ':\' } |
            Where-Object { $_ -notin $used } | Select-Object -First 1)
        if (!$drive.Count) { throw 'No drive letter is available for the WinRE partition.' }
        $volume.Drive = $drive[0]
        $null = Invoke-SystemTool 'mountvol.exe' @($volume.Drive, $volume.Name)
        $volume.Temporary = $true
    }
    try {
        if ((Invoke-SystemTool 'mountvol.exe' @($volume.Drive, '/L')).Trim() -ine $volume.Name) {
            throw 'The original WinRE volume could not be verified.'
        }
        $directory = $volume.Drive
        foreach ($component in $Registration.RelativePath.Split('\')) {
            if (!$component -or $component -in '.', '..' -or $component -match '[:?*]') {
                throw 'The original WinRE directory is not a volume-relative path.'
            }
            $directory = [IO.Path]::Combine($directory, $component)
            if (!(Test-PlainPath $directory -Directory)) { throw "$directory is missing." }
        }
        $volume.Directory = $directory
        return $volume
    } catch {
        Close-RecoveryVolume $volume
        throw
    }
}

function Get-WimHash([string]$Path) {
    if (!(Test-PlainPath $Path)) { throw "The registered image $Path is missing." }
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($algorithm.ComputeHash($stream))
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Copy-WinreImage([string]$Source, [string]$Destination) {
    if (!(Test-PlainPath $Source)) { throw "The registered image $Source is missing." }
    [IO.File]::Copy($Source, $Destination)
    [IO.File]::SetAttributes($Destination, [IO.FileAttributes]::Normal)
}

function Replace-WinreImage([string]$Source, $Volume, [string[]]$KnownHashes) {
    $state = [xml][IO.File]::ReadAllText($agentConfig)
    if ($state.WindowsRE.InstallState.state -ne '0' -or
        (Invoke-SystemTool 'mountvol.exe' @($Volume.Drive, '/L')).Trim() -ine $Volume.Name) {
        throw 'The original WinRE volume must be verified and WinRE must be disabled before replacing the image.'
    }
    $directory = $Volume.Directory
    if (!(Test-PlainPath $Directory -Directory)) {
        $null = [IO.Directory]::CreateDirectory($Directory)
    }
    $wim = [IO.Path]::Combine($Directory, 'Winre.wim')
    $temporary = [IO.Path]::Combine($Directory, ('wuo-' + [guid]::NewGuid().ToString('N') + '.wim'))
    try {
        if (Test-PlainPath $wim) {
            if ((Get-WimHash $wim) -cnotin $KnownHashes) {
                throw 'A different WinRE image appeared in the original recovery directory.'
            }
            # WinRE is disabled and the original image was backed up. Free
            # its previous space on recovery partitions sized for one WIM.
            [IO.File]::SetAttributes($wim, [IO.FileAttributes]::Normal)
            [IO.File]::Delete($wim)
        }
        Copy-WinreImage $Source $temporary
        [IO.File]::Move($temporary, $wim)
    } finally {
        if ([IO.File]::Exists($temporary)) {
            [IO.File]::Delete($temporary)
        }
    }
}

function Copy-RecoveryCommand([string]$Source, [string]$Name, [string]$Destination) {
    $executable = Join-Path $Source $Name
    if (!(Test-PlainPath $executable -AllowImageBacking)) { throw "$executable is missing." }
    [IO.File]::WriteAllBytes((Join-Path $Destination $Name), [IO.File]::ReadAllBytes($executable))
    $locales = Get-ChildItem -LiteralPath $Source -Directory | Where-Object {
        $_.Name -match '^[a-z]{2,3}(?:-[a-z0-9]{2,8})+$'
    }
    foreach ($locale in $locales) {
        $resource = Join-Path $locale.FullName "$Name.mui"
        # WinRE can store its system resources in WOF-backed files.
        if (Test-PlainPath $resource -AllowImageBacking) {
            $destinationLocale = Join-Path $Destination $locale.Name
            $null = [IO.Directory]::CreateDirectory($destinationLocale)
            [IO.File]::WriteAllBytes(
                (Join-Path $destinationLocale "$Name.mui"), [IO.File]::ReadAllBytes($resource)
            )
        }
    }
}

function Edit-RecoveryTools(
    [string]$Mount, [string]$HostSystem32, [string]$Action, [string]$MachineGuid, [string]$LauncherText,
    [switch]$AllowMissing
) {
    $tools = $Mount
    foreach ($component in 'Sources', 'Recovery', 'Tools') {
        $tools = Join-Path $tools $component
        if (!(Test-PlainPath $tools -Directory)) {
            if ($AllowMissing) { return $false }
            if ($Action -eq 'uninstall') { throw 'The custom recovery tool directory is missing.' }
            $null = [IO.Directory]::CreateDirectory($tools)
        }
    }
    $config = Join-Path $tools 'WinREConfig.xml'
    $payload = Join-Path $tools 'WUO'
    $owner = Join-Path $payload 'owner.id'
    $hasConfig = Test-PlainPath $config -AllowImageBacking
    $hasPayload = Test-PlainPath $payload -Directory
    $expected = "<Recovery><RecoveryTools><RelativeFilePath>$toolPath</RelativeFilePath>" +
        "<CommandLineParam>$toolArguments</CommandLineParam></RecoveryTools></Recovery>"

    if ($Action -eq 'uninstall') {
        if ($AllowMissing -and !$hasConfig -and !$hasPayload) { return $false }
        if (!$hasConfig -or !$hasPayload -or !(Test-PlainPath $owner -AllowImageBacking) -or
            [IO.File]::ReadAllText($owner).Trim() -ine $MachineGuid -or
            ([xml][IO.File]::ReadAllText($config)).DocumentElement.OuterXml -cne $expected) {
            throw 'The custom recovery tool is missing or belongs to another installation.'
        }
        # A serviced WIM can contain other tools. Only remove our own files.
        foreach ($name in 'launcher.cmd', 'owner.id', 'cmd.exe', 'certutil.exe', 'findstr.exe', 'fc.exe', 'choice.exe') {
            $file = Join-Path $payload $name
            if (Test-PlainPath $file -AllowImageBacking) { [IO.File]::Delete($file) }
        }
        foreach ($locale in Get-ChildItem -LiteralPath $payload -Directory) {
            if ($locale.Name -notmatch '^[a-z]{2,3}(?:-[a-z0-9]{2,8})+$') { continue }
            $null = Test-PlainPath $locale.FullName -Directory
            foreach ($name in 'cmd.exe.mui', 'certutil.exe.mui', 'findstr.exe.mui', 'fc.exe.mui', 'choice.exe.mui') {
                $file = Join-Path $locale.FullName $name
                if (Test-PlainPath $file -AllowImageBacking) { [IO.File]::Delete($file) }
            }
            if (!(Get-ChildItem -LiteralPath $locale.FullName -Force)) {
                [IO.Directory]::Delete($locale.FullName)
            }
        }
        if (!(Get-ChildItem -LiteralPath $payload -Force)) { [IO.Directory]::Delete($payload) }
        [IO.File]::Delete($config)
        return $true
    }

    if ($hasConfig -or $hasPayload) { throw 'WinRE already contains a custom recovery tool.' }
    $null = [IO.Directory]::CreateDirectory($payload)
    Copy-RecoveryCommand (Join-Path $Mount 'Windows\System32') 'cmd.exe' $payload
    Copy-RecoveryCommand $HostSystem32 'certutil.exe' $payload
    Copy-RecoveryCommand $HostSystem32 'findstr.exe' $payload
    Copy-RecoveryCommand $HostSystem32 'fc.exe' $payload
    Copy-RecoveryCommand $HostSystem32 'choice.exe' $payload
    [IO.File]::WriteAllText((Join-Path $payload 'launcher.cmd'), $LauncherText, $ascii)
    [IO.File]::WriteAllText($owner, ($MachineGuid + [Environment]::NewLine), $ascii)
    [IO.File]::WriteAllText($config, ('<?xml version="1.0" encoding="utf-8"?>' + $expected), $utf8)
    return $true
}

function New-BootShellConfig([string]$Path, [string]$MountedImage) {
    $payload = Join-Path $MountedImage 'Sources\Recovery\Tools\WUO'
    $locales = @('en-US') + @(Get-ChildItem -LiteralPath $payload -Directory | ForEach-Object Name)
    $xml = '<?xml version="1.0" encoding="utf-8"?><BootShell>'
    foreach ($locale in ($locales | Sort-Object -Unique)) {
        $xml += "<WinRETool locale=""$($locale.ToLowerInvariant())""><Name>$toolName</Name>" +
            "<Description>$toolDescription</Description></WinRETool>"
    }
    [IO.File]::WriteAllText($Path, ($xml + '</BootShell>'), $utf8)
}

function Get-BootShellFiles([string]$RecoveryDirectory) {
    @((Join-Path $system32 'Recovery\ReCustomization.xml'), "$RecoveryDirectory\ReCustomization.xml") |
        Where-Object { Test-PlainPath $_ }
}

function Assert-OwnedBootShell([string]$Path) {
    $xml = [xml][IO.File]::ReadAllText($Path)
    $labels = @($xml.SelectNodes('/BootShell/WinRETool'))
    if (!$labels.Count -or @($labels | Where-Object {
        $_.Name -cnotin $toolName, $legacyToolName -or $_.Description -cne $toolDescription
    }).Count) {
        throw 'The registered custom recovery tool label belongs to another tool.'
    }
}

function Save-ExistingBootShell($Registration, [string]$Destination) {
    $paths = @(Get-BootShellFiles $Registration.Directory)
    if (!$Registration.OemTool -and $paths.Count) {
        throw 'WinRE has an existing custom recovery tool label.'
    }
    if ($Registration.OemTool -and !$paths.Count) {
        throw 'The registered wuo recovery tool label could not be found.'
    }
    foreach ($path in $paths) { Assert-OwnedBootShell $path }
    if ($paths.Count) { [IO.File]::Copy($paths[0], $Destination) }
}

function Clear-OwnedBootShell([string]$RecoveryDirectory, [string]$Workspace) {
    $xml = [xml]::new()
    $xml.PreserveWhitespace = $true
    $xml.XmlResolver = $null
    $xml.Load($agentConfig)
    $oem = $xml.WindowsRE.OemTool
    if ($xml.WindowsRE.InstallState.state -ne '0' -or $oem.state -notin '0', '1') {
        throw 'WinRE must be disabled before removing the owned recovery menu registration.'
    }
    $paths = @(Get-BootShellFiles $RecoveryDirectory)
    foreach ($path in $paths) { Assert-OwnedBootShell $path }
    foreach ($path in $paths) { [IO.File]::Delete($path) }
    if ($oem.state -eq '1') {
        # REAgentC registers OEM tools but does not provide a removal command.
        # Reset only the owned OEM flag while Windows RE is disabled.
        $oem.SetAttribute('state', '0')
        $staged = Join-Path $Workspace 'ReAgent-cleared.xml'
        $xml.Save($staged)
        [IO.File]::Replace($staged, $agentConfig, (Join-Path $Workspace 'ReAgent-before-clear.xml'))
    }
}

function Set-RecoveryRegistration(
    [string]$ImageDirectory, [string]$BootShell, [string]$WimHash, $Original, [string]$Workspace
) {
    if (!$BootShell) { Clear-OwnedBootShell $Original.Directory $Workspace }
    $null = Invoke-SystemTool 'reagentc.exe' @('/setreimage', '/path', $ImageDirectory)
    $null = Invoke-SystemTool 'reagentc.exe' @('/enable')
    if ($BootShell) {
        $null = Invoke-SystemTool 'reagentc.exe' @('/setbootshelllink', '/configfile', $BootShell)
    }
    $current = Read-RecoveryRegistration
    if (!$current.Enabled -or $current.Directory -ine $Original.Directory -or $current.OemTool -ne [bool]$BootShell -or
        (Get-WimHash $current.Wim) -cne $WimHash) {
        throw 'The enabled WinRE image and custom tool registration could not be verified.'
    }
}

function Restore-RecoveryRegistration(
    [string]$Backup, [string]$OriginalHash, [string]$OriginalBootShell, $Original,
    $Volume, [string]$CandidateHash
) {
    $current = Read-RecoveryRegistration
    if ($current.Enabled) {
        $currentHash = Get-WimHash $current.Wim
        if ($current.Directory -ieq $Original.Directory -and $current.OemTool -eq $Original.OemTool -and
            $currentHash -ceq $OriginalHash) {
            return
        }
        if ($currentHash -cnotin $OriginalHash, $CandidateHash) {
            throw 'A different WinRE location is active. Restore the original image from the backup.'
        }
        $null = Invoke-SystemTool 'reagentc.exe' @('/disable')
    }
    Replace-WinreImage $Backup $Volume @($OriginalHash, $CandidateHash)
    Set-RecoveryRegistration $Volume.Directory $OriginalBootShell $OriginalHash $Original ([IO.Path]::GetDirectoryName($Backup))
}

try {
    if ($HookMetadata -and !$Profile) { throw 'Hook metadata requires a profile.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run the recovery menu setup from an elevated Windows terminal.'
    }
    $windows = [Environment]::GetFolderPath('Windows')
    $windowsDrive = [IO.Path]::GetPathRoot($windows)
    $system32 = Join-Path $windows 'System32'
    $agentConfig = Join-Path $system32 'Recovery\ReAgent.xml'
    $liveMachineGuid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    if ($MachineGuid -eq [guid]::Empty -or $MachineGuid -ne [guid]$liveMachineGuid) {
        throw 'The requested machine identity does not match the active Windows installation.'
    }
    $machine = $MachineGuid.ToString('D')

    $launcherText = $null
    if ($Action -eq 'install') {
        if (!$Launcher) { throw 'An installed recovery launcher template is required.' }
        $os = Get-UniqueVolume @(Get-Partition -DriveLetter $windowsDrive[0]) 'Windows'
        $efi = Get-UniqueVolume @(Get-Partition | Where-Object {
            $_.IsSystem -and $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        }) 'active GPT EFI'
        if ($os -ieq $efi) { throw 'The Windows and EFI volumes must be distinct.' }
        $launcherText = [IO.File]::ReadAllText($Launcher)
        foreach ($placeholder in '@@WINDOWS_VOLUME@@', '@@EFI_VOLUME@@', '@@MACHINE_GUID@@') {
            if (!$launcherText.Contains($placeholder)) { throw "The launcher is missing $placeholder." }
        }
        $launcherText = $launcherText.Replace('@@WINDOWS_VOLUME@@', $os).Replace('@@EFI_VOLUME@@', $efi).
            Replace('@@MACHINE_GUID@@', $machine)
        if ($launcherText -match '@@[A-Z0-9_]+@@|[^\x00-\x7f]') {
            throw 'The launcher template contains an unknown placeholder or non-ASCII text.'
        }
        $launcherText = $launcherText -replace '\r?\n', [Environment]::NewLine
    }

    $Root = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    Initialize-MenuRoot $Root $windowsDrive $Action
    $lockPath = Join-Path $Root 'setup.lock'
    if (Test-PlainPath $lockPath) { Assert-ProtectedPath $lockPath }
    $lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
    try {
        $marker = Join-Path $Root 'installed.id'
        $savedProfile = Join-Path $Root 'profile.toml'
        $savedHookMetadata = Join-Path $Root 'hooks.json'
        $savedSelection = Join-Path $Root 'selection.json'
        $hasMarker = Test-PlainPath $marker
        $hasProfile = Test-PlainPath $savedProfile
        $hasHookMetadata = Test-PlainPath $savedHookMetadata
        $hasSelection = Test-PlainPath $savedSelection
        if ($hasMarker) { Assert-ProtectedPath $marker }
        if ($hasProfile) { Assert-ProtectedPath $savedProfile }
        if ($hasHookMetadata) { Assert-ProtectedPath $savedHookMetadata }
        if ($hasSelection) { Assert-ProtectedPath $savedSelection }
        if ($Action -eq 'install' -and ($hasMarker -or $hasProfile -or $hasHookMetadata -or $hasSelection)) {
            throw 'The recovery menu configuration already exists. Remove the existing installation before setting up again.'
        }
        if ($Action -eq 'uninstall' -and (!$hasMarker -or [IO.File]::ReadAllText($marker).Trim() -ine $machine)) {
            throw 'No wuo recovery menu is installed for this Windows installation.'
        }

        $original = Read-RecoveryRegistration
        if (!$original.Enabled) { throw 'Enable Windows Recovery Environment before changing its recovery menu.' }
        if ($Action -eq 'install' -and $original.OemTool) {
            throw 'WinRE already has a registered custom recovery tool.'
        }
        $work = Join-Path $Root ('winre-' + [guid]::NewGuid().ToString('N'))
        $image = Join-Path $work 'candidate'
        $mount = Join-Path $work 'mount'
        $null = [IO.Directory]::CreateDirectory($image)
        $null = [IO.Directory]::CreateDirectory($mount)
        $backup = Join-Path $work 'original.wim'
        $candidate = Join-Path $image 'Winre.wim'
        $label = Join-Path $work 'BootShell.xml'
        $oldLabel = Join-Path $work 'original-bootshell.xml'
        $stagedMarker = Join-Path $work 'installed.id'
        $stagedProfile = Join-Path $work 'profile.toml'
        $stagedHookMetadata = Join-Path $work 'hooks.json'
        $stagedSelection = Join-Path $work 'selection.json'
        $keepWork = $false
        $volume = $null
        try {
            Save-ExistingBootShell $original $oldLabel
            if ($Action -eq 'install') {
                [IO.File]::WriteAllText($stagedMarker, ($machine + [Environment]::NewLine), $ascii)
                if ($Profile) { [IO.File]::WriteAllBytes($stagedProfile, [IO.File]::ReadAllBytes($Profile)) }
                if ($HookMetadata) { [IO.File]::WriteAllBytes($stagedHookMetadata, [IO.File]::ReadAllBytes($HookMetadata)) }
            }
            Copy-WinreImage $original.Wim $backup
            $originalHash = Get-WimHash $backup
            Copy-WinreImage $backup $candidate

            $mounted = $false
            try {
                $null = Invoke-SystemTool 'dism.exe' @('/English', '/Mount-Image', "/ImageFile:$candidate", '/Index:1', "/MountDir:$mount")
                $mounted = $true
                $changed = Edit-RecoveryTools $mount $system32 $Action $machine $launcherText -AllowMissing:(
                    $Action -eq 'uninstall' -and !$original.OemTool
                )
                if ($Action -eq 'install') { New-BootShellConfig $label $mount }
                $mode = if ($changed) { '/Commit' } else { '/Discard' }
                $null = Invoke-SystemTool 'dism.exe' @('/English', '/Unmount-Image', "/MountDir:$mount", $mode)
                $mounted = $false
            } finally {
                if ($mounted) {
                    try {
                        $null = Invoke-SystemTool 'dism.exe' @('/English', '/Unmount-Image', "/MountDir:$mount", '/Discard')
                    } catch {
                        $keepWork = $true
                        Write-Warning "DISM could not discard the mount at $mount. $_"
                    }
                }
            }

            $candidateHash = Get-WimHash $candidate
            $current = Read-RecoveryRegistration
            if (!$current.Enabled -or $current.Directory -ine $original.Directory -or
                $current.Bcd -ne $original.Bcd -or $current.OemTool -ne $original.OemTool -or
                (Get-WimHash $current.Wim) -cne $originalHash) {
                throw 'WinRE changed while the image was being prepared. Retry the operation.'
            }
            $newLabel = if ($Action -eq 'install') { $label } else { '' }
            $restoreLabel = if ($original.OemTool) { $oldLabel } else { '' }
            if ($changed) { $volume = Open-RecoveryVolume $original }
            $markerMoved = $false
            $profileMoved = $false
            $hookMetadataMoved = $false
            $selectionMoved = $false
            # Keep the original image if the process is interrupted while
            # Windows RE is being replaced or restored.
            $keepWork = $true
            try {
                if ($changed) {
                    $null = Invoke-SystemTool 'reagentc.exe' @('/disable')
                    Replace-WinreImage $candidate $volume @($originalHash)
                    Set-RecoveryRegistration $volume.Directory $newLabel $candidateHash $original $work
                }
                if ($Action -eq 'install') {
                    if ($Profile) {
                        [IO.File]::Move($stagedProfile, $savedProfile)
                        $profileMoved = $true
                    }
                    if ($HookMetadata) {
                        [IO.File]::Move($stagedHookMetadata, $savedHookMetadata)
                        $hookMetadataMoved = $true
                    }
                    [IO.File]::Move($stagedMarker, $marker)
                    $markerMoved = $true
                } else {
                    if ($hasProfile) {
                        [IO.File]::Move($savedProfile, $stagedProfile)
                        $profileMoved = $true
                    }
                    if ($hasHookMetadata) {
                        [IO.File]::Move($savedHookMetadata, $stagedHookMetadata)
                        $hookMetadataMoved = $true
                    }
                    if ($hasSelection) {
                        [IO.File]::Move($savedSelection, $stagedSelection)
                        $selectionMoved = $true
                    }
                    [IO.File]::Move($marker, $stagedMarker)
                    $markerMoved = $true
                }
                $keepWork = $false
            } catch {
                $failure = $_
                try {
                    if ($changed) {
                        Restore-RecoveryRegistration $backup $originalHash $restoreLabel $original $volume $candidateHash
                    }
                    if ($Action -eq 'install') {
                        if ($markerMoved) { [IO.File]::Move($marker, $stagedMarker) }
                        if ($hookMetadataMoved) { [IO.File]::Move($savedHookMetadata, $stagedHookMetadata) }
                        if ($profileMoved) { [IO.File]::Move($savedProfile, $stagedProfile) }
                    } else {
                        if ($markerMoved) { [IO.File]::Move($stagedMarker, $marker) }
                        if ($selectionMoved) { [IO.File]::Move($stagedSelection, $savedSelection) }
                        if ($hookMetadataMoved) { [IO.File]::Move($stagedHookMetadata, $savedHookMetadata) }
                        if ($profileMoved) { [IO.File]::Move($stagedProfile, $savedProfile) }
                    }
                    $keepWork = $false
                } catch {
                    throw "WinRE change failed. $failure Rollback also failed. $_ The original image is backed up at $backup."
                }
                throw "WinRE change failed and the previous registration was restored. $failure"
            }
        } finally {
            try { Close-RecoveryVolume $volume }
            catch { Write-Warning "Could not remove the temporary WinRE drive letter. $_" }
            if (!$keepWork) {
                try {
                    $agentFiles = @((Join-Path $work 'ReAgent-cleared.xml'), (Join-Path $work 'ReAgent-before-clear.xml'))
                    foreach ($file in @($backup, $candidate, $label, $oldLabel, $stagedMarker, $stagedProfile, $stagedHookMetadata, $stagedSelection) + $agentFiles) {
                        if (Test-PlainPath $file) {
                            [IO.File]::SetAttributes($file, [IO.FileAttributes]::Normal)
                            [IO.File]::Delete($file)
                        }
                    }
                    foreach ($directory in $mount, $image, $work) {
                        if ([IO.Directory]::Exists($directory) -and !(Get-ChildItem -LiteralPath $directory -Force)) {
                            [IO.Directory]::Delete($directory)
                        }
                    }
                } catch {
                    Write-Warning "Could not clean WinRE working files under $work. $_"
                }
            }
        }
    } finally {
        $lock.Dispose()
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
