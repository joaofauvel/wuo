function Test-WuoSafeOsWimProjection([string]$Path) {
    $details = @(& "$env:SystemRoot\System32\fsutil.exe" reparsepoint query $Path)
    # The WIM Mount filter projects regular image files with IO_REPARSE_TAG_WIM.
    return ($LASTEXITCODE -eq 0 -and $details.Count -gt 0 -and $details[0] -match ':\s*0x80000008\s*$')
}

function Install-WuoSafeOsWrapper([string]$Mount, [string]$Wrapper) {
    $system = Join-Path $Mount 'Windows\System32'
    $launcher = Join-Path $system 'winpeshl.ini'
    $native = Join-Path $Mount 'sources\recovery\recenv.exe'
    $destination = Join-Path $system 'wuo-safeos.cmd'
    $errorPrefix = 'Cannot wrap the native SafeOS shell'
    foreach ($directory in @($Mount, (Split-Path -Parent $system), $system,
                            (Join-Path $Mount 'sources'), (Split-Path -Parent $native))) {
        $item = Get-Item -LiteralPath $directory -Force -ErrorAction SilentlyContinue
        if (!$item -or !$item.PSIsContainer -or $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
            throw "$errorPrefix because an image directory is missing or redirects elsewhere."
        }
    }
    foreach ($file in $launcher, $native, $Wrapper) {
        $item = Get-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        if (!$item -or $item.PSIsContainer) {
            throw "$errorPrefix because a required file is missing: $file"
        }
        if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -and
            ($file -eq $Wrapper -or !(Test-WuoSafeOsWimProjection $file))) {
            throw "$errorPrefix because a required file has an unsupported reparse point: $file"
        }
    }
    $stockShell = [IO.File]::ReadAllText($launcher).Trim() -split '\r?\n'
    if ($stockShell.Count -ne 2 -or $stockShell[0] -ne '[LaunchApp]' -or
        $stockShell[1] -ne 'AppPath=X:\sources\recovery\recenv.exe') {
        throw "$errorPrefix because the Windows Setup launcher differs from the supported layout."
    }
    if (Get-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue) {
        throw "$errorPrefix because the wrapper destination is already occupied."
    }
    [IO.File]::Copy($Wrapper, $destination, $false)
    [IO.File]::WriteAllLines($launcher, @(
        '[LaunchApps]',
        '%SYSTEMROOT%\System32\cmd.exe, /d /c X:\Windows\System32\wuo-safeos.cmd'
    ), [Text.Encoding]::ASCII)
}

function Invoke-WuoSafeOsDism([string[]]$Options, [string]$LogPath) {
    & "$env:SystemRoot\System32\dism.exe" @Options *>> $LogPath
    if ($LASTEXITCODE -ne 0) {
        throw ('DISM {0} failed with exit code {1}. See {2}.' -f $Options[0], $LASTEXITCODE, $LogPath)
    }
}

function Install-WuoSafeOsImage([string]$NativeWim, [string]$Job, [string]$Wrapper) {
    # The caller holds the protected job and has verified the native Setup boot entry.
    $staged = Join-Path $Job 'safeos-staged.wim'
    $original = Join-Path $Job 'safeos-original.wim'
    $mount = Join-Path $Job 'safeos-mount'
    $log = Join-Path $Job 'dism.log'
    foreach ($path in $staged, $original, $mount, $log) {
        if ((Get-WuoPathKind $path) -ne 'absent') { throw "SafeOS staging path already exists: $path" }
    }
    if ((Get-WuoPathKind $NativeWim) -ne 'file') { throw 'The native SafeOS image is missing.' }
    $stockHash = Get-WuoFileHash $NativeWim
    [IO.File]::Copy($NativeWim, $staged, $false)
    if ((Get-WuoFileHash $staged) -cne $stockHash) {
        throw 'The native SafeOS image changed while being copied.'
    }
    [IO.File]::SetAttributes($staged, [IO.FileAttributes]::Normal)
    $null = [IO.Directory]::CreateDirectory($mount)
    try {
        Invoke-WuoSafeOsDism @('/Mount-Image', "/ImageFile:$staged", '/Index:1', "/MountDir:$mount", '/CheckIntegrity') $log
        Install-WuoSafeOsWrapper $mount $Wrapper
        Invoke-WuoSafeOsDism @('/Unmount-Image', "/MountDir:$mount", '/Commit', '/CheckIntegrity') $log
    } catch {
        $failure = $_
        try { Invoke-WuoSafeOsDism @('/Unmount-Image', "/MountDir:$mount", '/Discard') $log }
        catch { Write-Warning "Could not discard the staged SafeOS mount. See $log." }
        throw $failure
    }
    $stagedHash = Get-WuoFileHash $staged
    if ($stagedHash -ceq $stockHash) { throw 'DISM did not save the modified SafeOS image.' }
    if ((Get-WuoPathKind $NativeWim) -ne 'file' -or (Get-WuoFileHash $NativeWim) -cne $stockHash) {
        throw 'The native SafeOS image changed before replacement.'
    }
    [IO.File]::Replace($staged, $NativeWim, $original)
    if ((Get-WuoFileHash $NativeWim) -cne $stagedHash -or (Get-WuoFileHash $original) -cne $stockHash) {
        throw 'SafeOS image replacement failed hash verification.'
    }
    return $stagedHash
}
