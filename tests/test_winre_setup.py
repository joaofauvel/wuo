import os
import subprocess
from pathlib import Path
from xml.etree import ElementTree

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Requires Windows PowerShell")

SCRIPT = Path(__file__).parents[1] / "src" / "wuo" / "winre_setup.ps1"
MACHINE = "12345678-1234-1234-1234-123456789abc"


def run_setup_helper(
    command: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    # Load the helper definitions without running the installer.
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            """
$ErrorActionPreference = 'Stop'
$tokens = $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:WUO_SETUP_TEST_SCRIPT, [ref]$tokens, [ref]$errors
)
if ($errors.Count) { throw ($errors -join [Environment]::NewLine) }
foreach ($statement in $ast.EndBlock.Statements) {
    if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
        $statement -is [System.Management.Automation.Language.AssignmentStatementAst]) {
        . ([scriptblock]::Create($statement.Extent.Text))
    }
}
"""
            + command,
        ],
        env={
            **os.environ,
            "WUO_SETUP_TEST_SCRIPT": str(SCRIPT),
            **environment,
        },
        check=False,
        capture_output=True,
        text=True,
    )


def edit_tools(
    image: Path, host: Path, action: str, *, allow_missing: bool = False
) -> subprocess.CompletedProcess[str]:
    return run_setup_helper(
        """
Edit-RecoveryTools -Mount $env:WUO_SETUP_TEST_IMAGE -HostSystem32 $env:WUO_SETUP_TEST_HOST `
    -Action $env:WUO_SETUP_TEST_ACTION -MachineGuid $env:WUO_SETUP_TEST_MACHINE `
    -LauncherText "@echo off`r`n" -AllowMissing:($env:WUO_SETUP_ALLOW_MISSING -eq '1')
""",
        {
            "WUO_SETUP_TEST_IMAGE": str(image),
            "WUO_SETUP_TEST_HOST": str(host),
            "WUO_SETUP_TEST_ACTION": action,
            "WUO_SETUP_TEST_MACHINE": MACHINE,
            "WUO_SETUP_ALLOW_MISSING": str(int(allow_missing)),
        },
    )


def test_install_and_remove_tool_preserves_other_recovery_files(tmp_path: Path) -> None:
    image = tmp_path / "WinRE"
    system32 = image / "Windows/System32"
    host = tmp_path / "Windows/System32"
    tools = image / "Sources/Recovery/Tools"
    tools.mkdir(parents=True)
    (tools / "vendor-notes.txt").write_text("keep", encoding="ascii")
    (system32 / "en-US").mkdir(parents=True)
    (host / "de-DE").mkdir(parents=True)
    (system32 / "cmd.exe").write_bytes(b"recovery cmd")
    (system32 / "en-US/cmd.exe.mui").write_bytes(b"recovery cmd resources")
    (host / "certutil.exe").write_bytes(b"installed certutil")
    (host / "findstr.exe").write_bytes(b"installed findstr")
    (host / "fc.exe").write_bytes(b"installed fc")
    (host / "choice.exe").write_bytes(b"installed choice")
    (host / "de-DE/findstr.exe.mui").write_bytes(b"installed findstr resources")

    install = edit_tools(image, host, "install")
    assert install.returncode == 0, install.stdout + install.stderr
    config = ElementTree.parse(tools / "WinREConfig.xml")
    assert config.findtext("./RecoveryTools/RelativeFilePath") == r"WUO\cmd.exe"
    assert config.findtext("./RecoveryTools/CommandLineParam") == (
        r"/d /c X:\Sources\Recovery\Tools\WUO\launcher.cmd"
    )
    payload = tools / "WUO"
    assert (payload / "owner.id").read_text(encoding="ascii").strip() == MACHINE
    assert (payload / "launcher.cmd").read_bytes() == b"@echo off\r\n"
    assert (payload / "cmd.exe").read_bytes() == b"recovery cmd"
    assert (payload / "en-US/cmd.exe.mui").read_bytes() == b"recovery cmd resources"
    assert (payload / "certutil.exe").read_bytes() == b"installed certutil"
    assert (payload / "findstr.exe").read_bytes() == b"installed findstr"
    assert (payload / "fc.exe").read_bytes() == b"installed fc"
    assert (payload / "choice.exe").read_bytes() == b"installed choice"
    assert (
        payload / "de-DE/findstr.exe.mui"
    ).read_bytes() == b"installed findstr resources"

    remove = edit_tools(image, host, "uninstall")
    assert remove.returncode == 0, remove.stdout + remove.stderr
    assert not payload.exists()
    assert not (tools / "WinREConfig.xml").exists()
    assert (tools / "vendor-notes.txt").read_text(encoding="ascii") == "keep"


@pytest.mark.parametrize(
    ("action", "allow_missing"),
    [("install", False), ("uninstall", False), ("uninstall", True)],
)
def test_foreign_recovery_tool_is_left_untouched(
    tmp_path: Path, action: str, allow_missing: bool
) -> None:
    tools = tmp_path / "WinRE/Sources/Recovery/Tools"
    tools.mkdir(parents=True)
    config = tools / "WinREConfig.xml"
    original = (
        b"<Recovery><RecoveryTools><RelativeFilePath>OEM.exe</RelativeFilePath>"
        b"</RecoveryTools></Recovery>"
    )
    config.write_bytes(original)
    result = edit_tools(
        tmp_path / "WinRE", tmp_path / "Host", action, allow_missing=allow_missing
    )
    assert result.returncode != 0
    assert "custom recovery tool" in result.stdout + result.stderr
    assert config.read_bytes() == original


def test_serviced_image_without_any_registered_tool_is_left_as_is(
    tmp_path: Path,
) -> None:
    tools = tmp_path / "WinRE/Sources/Recovery/Tools"
    tools.mkdir(parents=True)
    (tools / "vendor-notes.txt").write_text("keep", encoding="ascii")

    remove = edit_tools(
        tmp_path / "WinRE", tmp_path / "Host", "uninstall", allow_missing=True
    )
    assert remove.returncode == 0, remove.stdout + remove.stderr
    assert remove.stdout.strip() == "False"
    assert sorted(path.name for path in tools.iterdir()) == ["vendor-notes.txt"]


@pytest.mark.parametrize("label", ["Windows Offline Update", "wuo"])
def test_clear_owned_shell_label_preserves_other_recovery_settings(
    tmp_path: Path,
    label: str,
) -> None:
    windows = tmp_path / "Windows"
    recovery = windows / "System32/Recovery"
    recovery.mkdir(parents=True)
    active = tmp_path / "active"
    active.mkdir()
    agent = recovery / "ReAgent.xml"
    agent.write_text(
        '<WindowsRE version="2.0"><InstallState state="0"/><OemTool state="1"/>'
        '<WinreLocation path="original"/></WindowsRE>',
        encoding="ascii",
    )
    for path in (active, recovery):
        (path / "ReCustomization.xml").write_text(
            f'<BootShell><WinRETool locale="en-us"><Name>{label}</Name>'
            "<Description>Apply a staged update job</Description></WinRETool></BootShell>",
            encoding="ascii",
        )
    result = run_setup_helper(
        r"""
$system32 = Join-Path $env:WUO_SETUP_TEST_WINDOWS 'System32'
$agentConfig = Join-Path $system32 'Recovery\ReAgent.xml'
Clear-OwnedBootShell -RecoveryDirectory $env:WUO_SETUP_TEST_ACTIVE -Workspace $env:WUO_SETUP_TEST_WORK
""",
        {
            "WUO_SETUP_TEST_WINDOWS": str(windows),
            "WUO_SETUP_TEST_ACTIVE": str(active),
            "WUO_SETUP_TEST_WORK": str(tmp_path),
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (active / "ReCustomization.xml").exists()
    assert not (recovery / "ReCustomization.xml").exists()
    state = ElementTree.parse(agent)
    oem = state.find("./OemTool")
    location = state.find("./WinreLocation")
    assert oem is not None and oem.get("state") == "0"
    assert location is not None and location.get("path") == "original"


def run_configuration_transaction(
    root: Path,
    work: Path,
    action: str,
    *,
    snapshot: bool = False,
    hook_metadata: bool = True,
) -> subprocess.CompletedProcess[str]:
    # Execute the installer's real file/registration transaction, substituting
    # only the recovery OS operations. File moves and rollback use real files.
    return run_setup_helper(
        r"""
$Action = $env:WUO_SETUP_TEST_ACTION
$Root = $env:WUO_SETUP_TEST_ROOT
$work = $env:WUO_SETUP_TEST_WORK
$Profile = Join-Path $work 'source.toml'
$HookMetadata = if ($env:WUO_SETUP_TEST_METADATA -eq '1') { Join-Path $work 'source.json' } else { $null }
$machine = $env:WUO_SETUP_TEST_MACHINE
$marker = Join-Path $Root 'installed.id'
$savedProfile = Join-Path $Root 'profile.toml'
$savedHookMetadata = Join-Path $Root 'hooks.json'
$savedSelection = Join-Path $Root 'selection.json'
$stagedMarker = Join-Path $work 'installed.id'
$stagedProfile = Join-Path $work 'profile.toml'
$stagedHookMetadata = Join-Path $work 'hooks.json'
$stagedSelection = Join-Path $work 'selection.json'
if ($env:WUO_SETUP_TEST_SNAPSHOT -eq '1') {
    $stage = @($ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text.Contains('[IO.File]::WriteAllText($stagedMarker')
    }, $true))
    if ($stage.Count -ne 1) { throw 'Cannot locate configuration staging.' }
    . ([scriptblock]::Create($stage[0].Extent.Text))
    # Sources may disappear or change once the immutable snapshot is staged.
    [IO.File]::Delete($Profile)
    if ($HookMetadata) { [IO.File]::WriteAllText($HookMetadata, 'changed after staging') }
}
$hasProfile = [IO.File]::Exists($savedProfile)
$hasHookMetadata = [IO.File]::Exists($savedHookMetadata)
$hasSelection = [IO.File]::Exists($savedSelection)
$markerMoved = $profileMoved = $hookMetadataMoved = $selectionMoved = $false
$changed = $true
$volume = @{ Directory = 'fixture' }
function Invoke-SystemTool { }
function Replace-WinreImage { }
function Set-RecoveryRegistration { }
function Restore-RecoveryRegistration {
    [IO.File]::WriteAllText((Join-Path $work 'registration-restored'), 'restored')
}
$transaction = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.TryStatementAst] -and
    @($node.CatchClauses | Where-Object {
        $_.Body.Extent.Text.Contains('WinRE change failed and the previous registration was restored.')
    }).Count
}, $true))
if ($transaction.Count -ne 1) { throw 'Cannot locate configuration transaction.' }
. ([scriptblock]::Create($transaction[0].Extent.Text))
""",
        {
            "WUO_SETUP_TEST_ACTION": action,
            "WUO_SETUP_TEST_ROOT": str(root),
            "WUO_SETUP_TEST_WORK": str(work),
            "WUO_SETUP_TEST_MACHINE": MACHINE,
            "WUO_SETUP_TEST_SNAPSHOT": str(int(snapshot)),
            "WUO_SETUP_TEST_METADATA": str(int(hook_metadata)),
        },
    )


@pytest.mark.parametrize("hook_metadata", [False, True])
def test_install_commits_exact_staged_configuration(
    tmp_path: Path, hook_metadata: bool
) -> None:
    root, work = tmp_path / "menu", tmp_path / "work"
    root.mkdir()
    work.mkdir()
    profile = b'[[hooks]]\r\nphase = "pre"\r\n'
    metadata = b'{"schema_version":1, "profiles":[]}\r\n'
    (work / "source.toml").write_bytes(profile)
    (work / "source.json").write_bytes(metadata)
    result = run_configuration_transaction(
        root, work, "install", snapshot=True, hook_metadata=hook_metadata
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / "profile.toml").read_bytes() == profile
    if hook_metadata:
        assert (root / "hooks.json").read_bytes() == metadata
    else:
        assert not (root / "hooks.json").exists()
    assert (root / "installed.id").read_text(encoding="ascii").strip() == MACHINE
    assert not (work / "registration-restored").exists()


@pytest.mark.parametrize("blocked", ["hooks.json", "installed.id"])
def test_failed_install_restores_registration_and_staged_configuration(
    tmp_path: Path, blocked: str
) -> None:
    root, work = tmp_path / "menu", tmp_path / "work"
    root.mkdir()
    work.mkdir()
    contents = {
        "profile.toml": b"profile",
        "hooks.json": b"metadata",
        "installed.id": b"id",
    }
    for name, content in contents.items():
        (work / name).write_bytes(content)
    (root / blocked).mkdir()
    result = run_configuration_transaction(root, work, "install")
    assert result.returncode != 0
    assert "previous registration was restored" in result.stdout + result.stderr
    assert (work / "registration-restored").read_text() == "restored"
    assert sorted(path.name for path in root.iterdir()) == [blocked]
    for name, content in contents.items():
        assert (work / name).read_bytes() == content


@pytest.mark.parametrize("fail_marker", [False, True])
def test_uninstall_moves_or_restores_hook_metadata_and_selection_pointer(
    tmp_path: Path, fail_marker: bool
) -> None:
    root, work = tmp_path / "menu", tmp_path / "work"
    root.mkdir()
    work.mkdir()
    contents = {
        "profile.toml": b"profile",
        "hooks.json": b"metadata",
        "selection.json": b'{"profile":"selected-generation"}',
        "installed.id": MACHINE.encode("ascii"),
    }
    for name, content in contents.items():
        (root / name).write_bytes(content)
    generation = root / "selections/selected-generation"
    generation.mkdir(parents=True)
    (generation / "profile.toml").write_bytes(b"keep generation")
    jobs = root.parent / "jobs"
    jobs.mkdir()
    (jobs / "job.json").write_bytes(b"keep job")
    if fail_marker:
        (work / "installed.id").write_bytes(b"blocked")
    result = run_configuration_transaction(root, work, "uninstall")
    if fail_marker:
        assert result.returncode != 0
        assert "previous registration was restored" in result.stdout + result.stderr
        assert (work / "registration-restored").read_text() == "restored"
        for name, content in contents.items():
            assert (root / name).read_bytes() == content
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        for name, content in contents.items():
            assert not (root / name).exists()
            assert (work / name).read_bytes() == content
    assert (generation / "profile.toml").read_bytes() == b"keep generation"
    assert (jobs / "job.json").read_bytes() == b"keep job"


def test_hook_metadata_requires_profile_before_any_os_changes(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-Action",
            "install",
            "-Root",
            str(tmp_path / "menu"),
            "-MachineGuid",
            MACHINE,
            "-HookMetadata",
            str(tmp_path / "hooks.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Hook metadata requires a profile" in result.stdout + result.stderr
    assert not (tmp_path / "menu").exists()


@pytest.mark.parametrize("filename", ["hooks.json", "selection.json"])
@pytest.mark.parametrize("unsafe_acl", [False, True])
def test_install_rejects_stale_metadata_and_pointer_before_recovery_changes(
    tmp_path: Path, filename: str, unsafe_acl: bool
) -> None:
    saved = tmp_path / filename
    saved.write_bytes(b"preserve existing configuration")
    result = run_setup_helper(
        r"""
$Root = $env:WUO_SETUP_TEST_ROOT
$Action = 'install'
function Assert-ProtectedPath([string]$Path) {
    if ($env:WUO_SETUP_TEST_UNSAFE_ACL -eq '1') { throw 'Unsafe saved configuration' }
}
# Run only the locked preflight. Registration, mounting and servicing are never
# reached; the real plain-path checks and stale-file conditions run unchanged.
$locked = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.TryStatementAst] -and
    $null -ne $node.Finally -and $node.Finally.Extent.Text.Contains('$lock.Dispose()')
}, $true))
if ($locked.Count -ne 1) { throw 'Cannot locate locked setup preflight.' }
foreach ($statement in $locked[0].Body.Statements) {
    if ($statement.Extent.Text.StartsWith('$original =')) { break }
    . ([scriptblock]::Create($statement.Extent.Text))
}
""",
        {
            "WUO_SETUP_TEST_ROOT": str(tmp_path),
            "WUO_SETUP_TEST_UNSAFE_ACL": str(int(unsafe_acl)),
        },
    )
    assert result.returncode != 0
    expected = (
        "Unsafe saved configuration" if unsafe_acl else "configuration already exists"
    )
    assert expected in result.stdout + result.stderr
    assert saved.read_bytes() == b"preserve existing configuration"
