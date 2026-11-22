function New-WuoFeatureIso([string]$Root, [string]$BootImage, [string]$Output) {
    # IMAPI generates an El Torito catalog from the signed Microsoft EFI image.
    $stream = New-Object -ComObject ADODB.Stream
    $stream.Type = 1
    $stream.Open()
    try {
        $stream.LoadFromFile($BootImage)
        $boot = New-Object -ComObject IMAPI2FS.BootOptions
        $boot.AssignBootImage($stream)
        $boot.PlatformId = 0xef
        $boot.Emulation = 0
        $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
        $image.FileSystemsToCreate = 7
        $image.VolumeName = 'WUO_RECOVERY'
        $image.FreeMediaBlocks = 0
        $image.WorkingDirectory = Split-Path -Parent $Output
        $image.BootImageOptions = $boot
        $image.Root.AddTree($Root, $false)
        $result = $image.CreateResultImage()
        if (!('WuoFeatureIsoFile' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class WuoFeatureIsoFile {
    public static void Write(object source, string path, long count) {
        IStream stream = (IStream)source;
        byte[] buffer = new byte[1024 * 1024];
        IntPtr read = Marshal.AllocCoTaskMem(sizeof(int));
        try {
            using (FileStream file = File.Open(path, FileMode.CreateNew, FileAccess.Write)) {
                while (count > 0) {
                    int requested = (int)Math.Min(count, buffer.Length);
                    stream.Read(buffer, requested, read);
                    int length = Marshal.ReadInt32(read);
                    if (length <= 0 || length > requested)
                        throw new IOException("IMAPI returned a truncated or invalid ISO stream.");
                    file.Write(buffer, 0, length);
                    count -= length;
                }
            }
        } finally {
            Marshal.FreeCoTaskMem(read);
        }
    }
}
'@
        }
        [WuoFeatureIsoFile]::Write($result.ImageStream, $Output, ([long]$result.TotalBlocks * $result.BlockSize))
    } finally {
        $stream.Close()
    }
}

function Export-WuoFeatureWimAssets(
    [string]$Image, [int]$Index, [string]$Work, [hashtable]$Required, [hashtable]$Optional
) {
    if (!('WuoFeatureWim' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class WuoFeatureWim {
    private sealed class WimHandle : SafeHandleZeroOrMinusOneIsInvalid {
        public WimHandle() : base(true) {}
        protected override bool ReleaseHandle() { return WIMCloseHandle(handle); }
    }

    [DllImport("wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern WimHandle WIMCreateFile(string file, uint access, uint disposition,
        uint flags, uint compression, out uint result);
    [DllImport("wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern bool WIMSetTemporaryPath(WimHandle wim, string path);
    [DllImport("wimgapi.dll", SetLastError = true)]
    private static extern WimHandle WIMLoadImage(WimHandle wim, uint index);
    [DllImport("wimgapi.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern bool WIMExtractImagePath(WimHandle image, string path, string destination, uint flags);
    [DllImport("wimgapi.dll")]
    private static extern bool WIMCloseHandle(IntPtr handle);

    public static void Extract(string file, uint index, string work, string[] sources,
        string[] destinations, int required) {
        uint disposition;
        using (WimHandle wim = WIMCreateFile(file, 0x80000000, 3, 0, 0, out disposition)) {
            if (wim.IsInvalid || !WIMSetTemporaryPath(wim, work))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            using (WimHandle image = WIMLoadImage(wim, index)) {
                if (image.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                for (int i = 0; i < sources.Length; i++) {
                    if (File.Exists(destinations[i]) || Directory.Exists(destinations[i]))
                        throw new IOException("The image extraction destination already exists.");
                    if (WIMExtractImagePath(image, sources[i], destinations[i], 0)) continue;
                    int error = Marshal.GetLastWin32Error();
                    if (i >= required && (error == 2 || error == 3)) continue;
                    throw new IOException("Could not extract " + sources[i] + " from the selected Windows image.",
                        new Win32Exception(error));
                }
            }
        }
    }
}
'@
    }
    $sources = @($Required.Keys) + @($Optional.Keys)
    $destinations = foreach ($path in $sources) {
        if ($Required.ContainsKey($path)) { $Required[$path] } else { $Optional[$path] }
    }
    [WuoFeatureWim]::Extract($Image, $Index, $Work, [string[]]$sources, [string[]]$destinations, $Required.Count)
}

function Invoke-WuoFeatureMediaDism([string[]]$Options) {
    $command = Join-Path $env:SystemRoot 'System32\dism.exe'
    & $command /English @Options
    if ($LASTEXITCODE -ne 0) {
        throw ('DISM {0} failed with exit code {1}.' -f $Options[0], $LASTEXITCODE)
    }
}

function Use-WuoFeatureMediaImage(
    [string]$Image, [int]$Index, [string]$Mount, [scriptblock]$Operation,
    [switch]$Write
) {
    $options = @('/Mount-Image', "/ImageFile:$Image", "/Index:$Index", "/MountDir:$Mount", '/CheckIntegrity')
    if (!$Write) { $options += '/ReadOnly' }
    Invoke-WuoFeatureMediaDism $options
    $mounted = $true
    try {
        & $Operation $Mount
        if ($Write) {
            Invoke-WuoFeatureMediaDism @('/Unmount-Image', "/MountDir:$Mount", '/Commit', '/CheckIntegrity')
            $mounted = $false
        }
    } finally {
        if ($mounted) {
            Invoke-WuoFeatureMediaDism @('/Unmount-Image', "/MountDir:$Mount", '/Discard')
        }
    }
}

function Install-WuoFeatureMediaLauncher([string]$Mount, [string]$Payload) {
    $system = Join-Path $Mount 'Windows\System32'
    $launcher = Join-Path $system 'winpeshl.ini'
    $expected = @('[LaunchApp]', 'AppPath=X:\sources\recovery\recenv.exe')
    $stock = [IO.File]::ReadAllText($launcher).Trim() -split '\r?\n'
    if ($stock.Count -ne 2 -or $stock[0] -ne $expected[0] -or $stock[1] -ne $expected[1]) {
        throw 'The Windows RE image uses an unsupported startup shell.'
    }
    foreach ($name in 'cmd.exe', 'wpeinit.exe', 'wpeutil.exe', 'reg.exe', 'mountvol.exe',
                      'bcdedit.exe', 'wbadmin.exe', 'robocopy.exe') {
        if (![IO.File]::Exists((Join-Path $system $name))) {
            throw "The stock Windows RE image is missing $name."
        }
    }
    $directory = Join-Path $system 'WUO'
    if (Test-Path -LiteralPath $directory) { throw 'The Windows RE image already contains a WUO directory.' }
    Copy-Item -LiteralPath $Payload -Destination $directory -Recurse
    [IO.File]::WriteAllLines($launcher, @(
        '[LaunchApps]',
        '%SYSTEMROOT%\System32\cmd.exe, /d /k X:\Windows\System32\WUO\boot.cmd'
    ), [Text.Encoding]::ASCII)
}

function New-WuoFeatureRecoveryMedia([string]$Iso, [string]$ExpectedHash, [int]$Index, [string]$Work) {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Build feature recovery media from an elevated Windows terminal.'
    }
    $sourceDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Iso))
    $workDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Work))
    if ($sourceDrive.DriveType -eq [IO.DriveType]::Network -or
        $workDrive.DriveType -eq [IO.DriveType]::Network -or $workDrive.DriveFormat -ne 'NTFS') {
        throw 'Use a local Windows ISO and a local NTFS build directory.'
    }
    $imageFile = [IO.File]::Open($Iso, 'Open', 'Read', 'Read')
    $mountedHere = $false
    try {
        if ((Get-FileHash -InputStream $imageFile -Algorithm SHA256).Hash -ne $ExpectedHash) {
            throw 'The Microsoft Windows ISO does not match the expected SHA-256 digest.'
        }
        $disk = Get-DiskImage -ImagePath $Iso -StorageType ISO
        if (!$disk.Attached) {
            $disk = Mount-DiskImage -ImagePath $Iso -StorageType ISO -Access ReadOnly -PassThru
            $mountedHere = $true
        }
        $volumes = @($disk | Get-Volume | Where-Object DriveLetter)
        if ($volumes.Count -ne 1 -or $volumes[0].DriveLetter -notmatch '^[A-Z]$') {
            throw 'Could not identify a single drive letter for the Windows ISO.'
        }
        $root = "$($volumes[0].DriveLetter):\"
        $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $root 'setup.exe')
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.SubjectName.Decode('UseNewLines') -notmatch '(?im)^O=Microsoft Corporation\s*$') {
            throw 'Windows Setup does not have a valid Microsoft Corporation signature.'
        }
        $media = Join-Path $Work 'media'
        $payload = Join-Path $Work 'assets'
        $mount = Join-Path $Work 'mount'
        $sources = Join-Path $media 'sources'
        foreach ($directory in $media, $sources, $mount) {
            $null = [IO.Directory]::CreateDirectory($directory)
        }
        foreach ($name in 'boot', 'efi', 'bootmgr', 'bootmgr.efi') {
            Copy-Item -LiteralPath (Join-Path $root $name) -Destination $media -Recurse
        }

        $install = Join-Path $root 'sources\install.wim'
        $esd = Join-Path $root 'sources\install.esd'
        if ([IO.File]::Exists($esd) -and ![IO.File]::Exists($install)) {
            $install = Join-Path $Work 'install.wim'
            Invoke-WuoFeatureMediaDism @('/Export-Image', "/SourceImageFile:$esd", "/SourceIndex:$Index",
                                       "/DestinationImageFile:$install", '/Compress:fast', '/CheckIntegrity')
            $Index = 1
        }
        $info = Get-WindowsImage -ImagePath $install -Index $Index
        if ($info.Architecture -ne 9 -or $info.InstallationType -ne 'Client' -or
            $info.Languages[$info.DefaultLanguageIndex] -ne 'en-US') {
            throw 'The selected Windows recovery source must be an x64 English-US client image.'
        }
        $winre = Join-Path $sources 'boot.wim'
        $resources = Join-Path $payload 'en-US'
        $null = [IO.Directory]::CreateDirectory($resources)
        $required = @{ '\Windows\System32\Recovery\Winre.wim' = $winre }
        $optional = @{}
        foreach ($tool in 'certutil.exe', 'fc.exe', 'findstr.exe') {
            $required["\Windows\System32\$tool"] = Join-Path $payload $tool
            $optional["\Windows\System32\en-US\$tool.mui"] = Join-Path $resources "$tool.mui"
        }
        Export-WuoFeatureWimAssets $install $Index $Work $required $optional
        [IO.File]::SetAttributes($winre, [IO.FileAttributes]::Normal)
        [IO.File]::WriteAllLines((Join-Path $payload 'boot.cmd'), @(
            '@echo off',
            'wpeinit',
            'if errorlevel 1 (',
            '    echo Windows RE initialization failed.',
            '    exit /b 1',
            ')',
            'call "%~dp0start.cmd"',
            'exit /b %errorlevel%'
        ), [Text.Encoding]::ASCII)
        Use-WuoFeatureMediaImage $winre 1 $mount -Write -Operation {
            param([string]$Mounted)
            Install-WuoFeatureMediaLauncher $Mounted $payload
        }
        Use-WuoFeatureMediaImage $winre 1 $mount {
            param([string]$Mounted)
            $launcher = Join-Path $Mounted 'Windows\System32\winpeshl.ini'
            if ([IO.File]::ReadAllText($launcher).Trim() -cne
                "[LaunchApps]" + [Environment]::NewLine +
                '%SYSTEMROOT%\System32\cmd.exe, /d /k X:\Windows\System32\WUO\boot.cmd') {
                throw 'The committed Windows RE startup shell could not be verified.'
            }
            foreach ($asset in Get-ChildItem -LiteralPath $payload -File -Recurse) {
                $relative = $asset.FullName.Substring($payload.Length + 1)
                $embedded = Join-Path $Mounted "Windows\System32\WUO\$relative"
                if ((Get-FileHash -LiteralPath $embedded).Hash -ne (Get-FileHash -LiteralPath $asset.FullName).Hash) {
                    throw "The committed Windows RE asset could not be verified: $($asset.Name)"
                }
            }
        }
        New-WuoFeatureIso $media (Join-Path $media 'efi\microsoft\boot\efisys_noprompt.bin') (Join-Path $Work 'recovery.iso')
    } finally {
        try {
            if ($mountedHere) { $null = Dismount-DiskImage -ImagePath $Iso -StorageType ISO }
        } finally {
            $imageFile.Dispose()
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    New-WuoFeatureRecoveryMedia $env:WUO_RECOVERY_MEDIA_SOURCE $env:WUO_RECOVERY_MEDIA_SHA256 $env:WUO_RECOVERY_MEDIA_INDEX $PWD.Path
}
