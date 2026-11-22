import argparse
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from uuid import UUID

import pytest
from httpx import AsyncClient

from wuo import cli, update
from wuo import feature_upgrade as feature
from wuo.hooks import Hook
from wuo.models import Update, UpdateFile
from wuo.recovery import render_feature_precommit, render_feature_source_hooks
from wuo.target import TargetIdentity
from wuo.update import Offer
from wuo.winre_menu import Menu

TARGET = TargetIdentity(
    "25H2", 26200, 9457, "x64", Path("C:/Windows"), "machine", "", "Client"
)
OFFER = Offer(str(UUID(int=1)), "Windows 11, version 26H2", "features", revision=4)
POWERSHELL = shutil.which("powershell.exe")
SCRIPT = Path(__file__).parents[1] / "src/wuo/feature_upgrade.ps1"


def test_feature_precommit_renders_only_replacement_hooks() -> None:
    owner = replace(TARGET, machine_guid=str(UUID(int=5)))
    image = feature.FeatureImage(6, 26300, 9457, "Professional", "x64", "en-US")
    job = str(UUID(int=8))
    script = render_feature_precommit(
        job,
        owner,
        image,
        (
            Hook("pre", r"Services\OldOnly", "Start", 0),
            Hook("post", r"Services\UASPStor", "Start", 0, expected=3),
        ),
        rollback=False,
    )
    assert "@@" not in script
    assert "OldOnly" not in script
    assert job in script
    assert rf"%SYSTEMDRIVE%\ProgramData\WinOfflineUpdate\jobs\{job}" in script
    assert r"%SYSTEMDRIVE%\$WINDOWS.~BT\NewOS\Windows" in script
    assert r"Services\UASPStor" in script
    assert 'set "HOOK_EXPECTED=0x3"' in script
    assert r"X:\Windows\System32\reg.exe" not in script
    assert 'reg.exe" save' not in script
    assert script.index("call :apply_hooks") < script.index('" precommit.done')


def test_feature_source_hooks_capture_values_before_writing_and_can_revert() -> None:
    script = render_feature_source_hooks(
        (
            Hook("pre", r"Services\First", "Start", 0),
            Hook("pre", r"Services\Second", "Start", 0),
            Hook("post", r"Services\ReplacementOnly", "Start", 0),
        ),
        rollback=False,
    )
    assert "ReplacementOnly" not in script
    assert 'reg.exe" save' not in script
    assert script.index('set "ORIGINAL_2=%ACTUAL%"') < script.index("call :write_hook")
    assert script.index(":revert_2\r\n") < script.index(":revert_1\r\n")


def test_feature_asset_request_pins_callback_and_verified_media() -> None:
    owner = replace(TARGET, machine_guid=str(UUID(int=5)))
    image = feature.FeatureImage(6, 26300, 9457, "Professional", "x64", "en-US")
    media = feature.FeatureMedia(Path("D:/Windows 11.iso"), "AB" * 32)
    job = UUID(int=9)
    request, callback = feature.feature_setup_assets(job, owner, media, image, ())
    manifest = json.loads(request)
    assert manifest["source"] == "26200.9457"
    assert manifest["image"]["index"] == image.index
    assert manifest["id"] == str(job)
    assert manifest["iso"] == str(media.iso)
    assert manifest["sha256"] == "ab" * 32
    assert manifest["callback_sha256"] == hashlib.sha256(callback).hexdigest()
    assert manifest["rollback"] is False


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is required")
@pytest.mark.parametrize("backup", ["missing", "wrong-volume", "bad-catalog", "ready"])
def test_native_resume_validates_the_selected_backup_catalog(
    tmp_path: Path, backup: str
) -> None:
    assert POWERSHELL is not None
    volume = r"\\?\Volume{11111111-2222-3333-4444-555555555555}" + "\\"
    job = str(UUID(int=9))
    machine = str(UUID(int=10))
    (tmp_path / "rollback.json").write_text(
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
    portable = tmp_path / "WUO-Rollback" / job / "recovery"
    portable.mkdir(parents=True)
    for tool in ("restore.cmd", "certutil.exe", "findstr.exe"):
        (portable / tool).touch()
    harness = tmp_path / "backup.ps1"
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
        $node.Name -in 'Assert-PlainPath', 'Assert-FeatureBackupAvailable'
}, $false)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
$letter = 90..68 | ForEach-Object { [string][char]$_ } |
    Where-Object { !(Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) } |
    Select-Object -First 1
New-PSDrive -Name $letter -PSProvider FileSystem -Root $env:WUO_FIXTURE | Out-Null
function Get-Partition {
    if ($env:WUO_BACKUP_CASE -eq 'missing') { return }
    $volume = if ($env:WUO_BACKUP_CASE -eq 'wrong-volume') { 'another-volume' } else { $env:WUO_BACKUP_VOLUME }
    [pscustomobject]@{AccessPaths=@($volume); DriveLetter=$letter}
}
function Mock-BackupCatalog {
    if ($args.Count -ne 5 -or $args[0] -ne 'get' -or $args[1] -ne 'items' -or
        $args[2] -ne '-version:11/20/2026-12:43' -or $args[3] -ne ('-backupTarget:{0}:' -f $letter) -or
        $args[4] -ne "-machine:$env:COMPUTERNAME") { throw 'Wrong backup lookup.' }
    'Catalog checked'
    Set-Content -LiteralPath $env:WUO_CALLS -Value 'catalog'
    $global:LASTEXITCODE = [int]($env:WUO_BACKUP_CASE -eq 'bad-catalog')
}
Set-Alias "$env:SystemRoot\System32\wbadmin.exe" Mock-BackupCatalog
Assert-FeatureBackupAvailable $env:WUO_FIXTURE $env:WUO_JOB @{machine=$env:WUO_MACHINE; source='26200.9457'}
""",
        encoding="ascii",
    )
    calls = tmp_path / "calls.txt"
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
            "WUO_BACKUP_CASE": backup,
            "WUO_BACKUP_VOLUME": volume,
            "WUO_JOB": job,
            "WUO_MACHINE": machine,
            "WUO_CALLS": str(calls),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert (result.returncode == 0) is (backup == "ready"), result.stderr
    assert calls.exists() is (backup in {"bad-catalog", "ready"}), result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is required")
@pytest.mark.parametrize("change", ["none", "snapshot", "helper", "unknown"])
def test_native_resume_binds_the_boot_preservation_assets(
    tmp_path: Path, change: str
) -> None:
    assert POWERSHELL is not None
    digests = {}
    for name in ("feature_boot.ps1", "boot-order.json"):
        (tmp_path / name).write_bytes(b"fixture")
        digests[name] = hashlib.sha256(b"fixture").hexdigest()
    if change in {"snapshot", "helper"}:
        name = "boot-order.json" if change == "snapshot" else "feature_boot.ps1"
        (tmp_path / name).write_bytes(b"changed")
    elif change == "unknown":
        digests["unrelated"] = "a" * 64
    (tmp_path / "request.json").write_text(
        json.dumps({"boot_preservation": digests}), encoding="ascii"
    )
    harness = tmp_path / "validate.ps1"
    harness.write_text(
        r"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:WUO_SCRIPT, [ref]$null, [ref]$null)
foreach ($definition in $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in 'Assert-PlainPath', 'Assert-BootPreservationAssets'
}, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$request = Get-Content -LiteralPath (Join-Path $env:WUO_FIXTURE 'request.json') -Raw | ConvertFrom-Json
Assert-BootPreservationAssets $env:WUO_FIXTURE $request
""",
        encoding="ascii",
    )
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-File", harness],
        env={
            **{k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"},
            "WUO_SCRIPT": str(SCRIPT),
            "WUO_FIXTURE": str(tmp_path),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert (result.returncode == 0) is (change == "none"), result.stderr
    if change != "none":
        assert "boot preservation asset" in result.stderr


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is required")
@pytest.mark.parametrize(
    ("phase", "current_build", "restores"),
    [
        ("success", "26300", True),
        ("success", "26200", False),
        ("failure", "26200", True),
        ("failure", "26300", False),
        ("rollback", "26200", True),
    ],
)
def test_native_boot_restoration_requires_a_verified_terminal_build(
    tmp_path: Path, phase: str, current_build: str, restores: bool
) -> None:
    assert POWERSHELL is not None
    job_id = str(UUID(int=18))
    job = tmp_path / "jobs" / job_id
    job.mkdir(parents=True)
    (tmp_path / "menu").mkdir()
    (job / "precommit.done").write_bytes(f"{job_id}\r\n".encode("ascii"))
    (job / "boot-order-result.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "order": "blocked",
                "fallback": "skipped",
            }
        ),
        encoding="ascii",
    )
    (job / "feature_boot.ps1").write_text(
        r"""
param($Mode, $JobPath)
if ($Mode -ne 'Restore') { throw 'Unexpected boot preservation mode.' }
[IO.File]::WriteAllText((Join-Path $JobPath 'boot-order-result.json'), '{"schema":1,"order":"restored","fallback":"restored"}')
""",
        encoding="ascii",
    )
    harness = tmp_path / "completion.ps1"
    harness.write_text(
        r"""
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile($env:WUO_SCRIPT, [ref]$null, [ref]$null)
foreach ($definition in $ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -in 'Assert-PlainPath', 'Assert-JobMarker', 'Complete-FeatureBoot'
}, $false)) { . ([scriptblock]::Create($definition.Extent.Text)) }
function Assert-ProtectedJobDirectory($Path) { Assert-PlainPath $Path -Directory }
function Assert-BootPreservationAssets($Job, $Request) {}
function Get-ItemProperty($Path, $Name) {
    if ($Name -eq 'MachineGuid') { return @{MachineGuid='known-machine'} }
    return @{CurrentBuildNumber=$env:WUO_TEST_BUILD; UBR=9457; EditionID='Core'}
}
$request = @{
    machine='known-machine'; source='26200.9457'; boot_preservation=$true;
    image=@{build=26300; revision=9457; edition='Core'}
}
Complete-FeatureBoot $env:WUO_FIXTURE $env:WUO_JOB_ID $request $env:WUO_COMPLETION
""",
        encoding="ascii",
    )
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-File", harness],
        env={
            **{k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"},
            "WUO_SCRIPT": str(SCRIPT),
            "WUO_FIXTURE": str(job),
            "WUO_JOB_ID": job_id,
            "WUO_TEST_BUILD": current_build,
            "WUO_COMPLETION": phase,
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads((job / "boot-order-result.json").read_bytes())
    assert report["order"] == ("restored" if restores else "failed")
    assert (job / "boot-completion.phase").exists() is restores
    assert (tmp_path / "menu" / "boot-order-last.id").read_text().strip() == job_id


def test_only_one_new_full_feature_offer_is_eligible() -> None:
    irrelevant = [
        replace(OFFER, title="Windows 11, version 25H2"),
        replace(OFFER, title="Windows 11, version 26H2 (KB1234567)"),
        replace(OFFER, category="monthly"),
        replace(OFFER, revision=None),
        replace(OFFER, title="Windows 11, version 26H2 or 27H2"),
    ]
    assert feature.select_offer([*irrelevant, OFFER], TARGET) == (OFFER, "26H2")
    with pytest.raises(ValueError, match="No eligible"):
        feature.select_offer(irrelevant, TARGET)
    with pytest.raises(ValueError, match="Multiple"):
        feature.select_offer([OFFER, replace(OFFER, id=str(UUID(int=2)))], TARGET)


def test_plain_feature_title_can_refer_to_an_enablement_kb() -> None:
    raw = json.dumps(
        {
            "status": 2,
            "updates": [
                {
                    "id": OFFER.id,
                    "title": OFFER.title,
                    "type": 1,
                    "revision": 4,
                    "kb_articles": ["5121794", "KB5121794", ""],
                }
            ],
        }
    )
    offers, issue = update.parse_offers(raw)
    assert issue is None
    assert offers[0].kb_articles == ("KB5121794",)
    assert feature.offered_release(offers[0], TARGET) is None


def test_wua_enablement_offer_can_use_the_plain_upgrades_title() -> None:
    raw = json.dumps(
        {
            "status": 2,
            "updates": [
                {
                    "id": "aa272a56-7dbf-4349-b410-10ae6defc750",
                    "title": "Windows 11, version 26H2",
                    "type": 1,
                    "revision": 1,
                    "kb_articles": ["5132061"],
                    "categories": ["3689bdc8-b205-4af4-8d4a-a63924c5e9d5"],
                }
            ],
        }
    )
    offers, issue = update.parse_offers(raw)
    assert issue is None
    # This offer's actual WUA plan contains an enablement CAB and no Setup media.
    assert feature.offered_release(offers[0], TARGET) is None
    assert (
        feature.offered_release(
            replace(offers[0], title="Windows 11, version 26H2 enablement package"),
            TARGET,
        )
        is None
    )


def test_iso_preview_preserves_a_feature_offer_with_a_standalone_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    identity = replace(TARGET, windows=tmp_path / "Windows")
    previews = []
    monkeypatch.setattr(update, "scan_offers", lambda _: ([OFFER], None))

    async def package(
        _: AsyncClient, offer: Offer, installed: TargetIdentity
    ) -> Update:
        assert offer == OFFER
        assert installed == identity
        return Update(
            offer.id,
            offer.title,
            architecture="x64",
            files=(
                UpdateFile(
                    "enablement.cab",
                    "https://download.windowsupdate.com/enablement.cab",
                    sha256="a" * 64,
                ),
            ),
        )

    async def check(
        _: AsyncClient,
        installed: TargetIdentity,
        offers: list[Offer],
        media: feature.FeatureMedia,
        *,
        preview: bool,
    ) -> feature.FeatureImage:
        assert preview
        assert installed == identity
        # A separate ISO preview is allowed, but the CBS offer is not a Setup candidate.
        assert not offers
        previews.append(media.iso)
        return feature.FeatureImage(6, 26300, 9457, "Professional", "x64", "en-US")

    monkeypatch.setattr(update, "_package", package)
    monkeypatch.setattr(feature, "check_feature", check)

    async def run() -> int:
        async with AsyncClient() as client:
            return await update.run_update(
                client,
                identity,
                tmp_path,
                dry_run=True,
                feature_media=feature.FeatureMedia(Path("windows.iso"), "a" * 64),
            )

    assert asyncio.run(run()) == 0
    assert "Would download enablement.cab" in capsys.readouterr().out
    assert previews == [Path("windows.iso")]


def test_published_build_must_be_unique_and_match_explicit_offer_build() -> None:
    history = "<p><strong>Version 26H2 (OS build 26300)</strong></p>"
    assert feature.release_build(history * 2, OFFER, "26H2", TARGET) == 26300
    with pytest.raises(ValueError, match="confirm"):
        feature.release_build(
            history + history.replace("26300", "26301"), OFFER, "26H2", TARGET
        )
    with pytest.raises(ValueError, match="different"):
        feature.release_build(
            history, replace(OFFER, title=OFFER.title + " (26350.1000)"), "26H2", TARGET
        )


@pytest.mark.parametrize(
    ("code", "message"),
    [(0, "0x00000000"), (0xC1900204, "keep apps and data"), (0xC190020E, "space")],
)
def test_only_setup_scan_success_is_accepted(code: int, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        feature.require_scan_success(code)
    feature.require_scan_success(0xC1900210 - 2**32)


@pytest.mark.parametrize("backup_drive", [None, "E:"])
def test_cli_accepts_the_optional_rollback_drive_in_a_preview(
    backup_drive: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run(args: argparse.Namespace) -> int:
        assert args.dry_run
        assert args.backup_drive == backup_drive
        return 0

    monkeypatch.setattr(cli, "_run", run)
    assert (
        cli.main(
            [
                "update",
                "--dry-run",
                "--feature-iso",
                "windows.iso",
                "--iso-sha256",
                "a" * 64,
                "--accept-setup-eula",
                *(["--backup-drive", backup_drive] if backup_drive else []),
            ]
        )
        == 0
    )
    assert cli.main(["update", "--no-rollback"]) == 2
    assert cli.main(["update", "--backup-drive", "E:"]) == 2
    assert cli.main(["update", "--dry-run", "--feature-iso", "windows.iso"]) == 2


def test_feature_apply_accepts_an_opt_in_backup_destination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not feature.FeatureMedia(Path("windows.iso"), "a" * 64).rollback

    drives: list[str | None] = []

    async def accept(args: argparse.Namespace) -> int:
        assert not args.dry_run
        drives.append(args.backup_drive)
        return 0

    monkeypatch.setattr(cli, "_run", accept)
    command = [
        "update",
        "--feature-iso",
        "windows.iso",
        "--iso-sha256",
        "a" * 64,
        "--accept-setup-eula",
    ]
    assert cli.main(command) == 0
    assert cli.main([*command, "--backup-drive", "E:"]) == 0
    assert cli.main([*command, "--no-rollback"]) == 0
    assert cli.main([*command, "--backup-drive", "E:", "--no-rollback"]) == 2
    assert drives == [None, "E:", None]


def test_feature_apply_accepts_boot_preservation_without_backup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def accept(args: argparse.Namespace) -> int:
        assert args.preserve_boot_order is True
        assert args.backup_drive is None
        return 0

    monkeypatch.setattr(cli, "_run", accept)
    assert (
        cli.main(
            [
                "update",
                "--feature-iso",
                "windows.iso",
                "--iso-sha256",
                "a" * 64,
                "--accept-setup-eula",
                "--preserve-boot-order",
            ]
        )
        == 0
    )


@pytest.mark.parametrize(
    ("requested_drive", "interactive", "answer", "staged"),
    [
        ("E:", False, "no", True),
        (None, True, " Yes ", True),
        (None, True, "", False),
        (None, True, "no", False),
        (None, True, None, False),
        (None, False, "yes", False),
    ],
)
def test_update_confirms_unbacked_feature_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    requested_drive: str | None,
    interactive: bool,
    answer: str | None,
    staged: bool,
) -> None:
    identity = replace(
        TARGET, windows=tmp_path / "Windows", machine_guid=str(UUID(int=5))
    )
    menu = Menu(identity)
    menu.root.mkdir(parents=True)
    (menu.root / "installed.id").write_text(identity.machine_guid, encoding="ascii")
    image = feature.FeatureImage(6, 26300, 9457, "Professional", "x64", "en-US")
    events: list[str] = []

    async def scan(
        _client: AsyncClient,
        _identity: TargetIdentity,
        _output: Path,
        *,
        prepared: update.PreparedUpdates,
        **_options: object,
    ) -> int:
        prepared.feature = image
        return 0

    def stage(
        _menu: Menu,
        media: feature.FeatureMedia,
        verified: feature.FeatureImage,
        profile: Path | None,
        *,
        backup_drive: str | None,
    ) -> Path:
        assert media.rollback is (requested_drive is not None)
        assert media.iso == Path("windows.iso")
        assert verified == image and profile is None and backup_drive == requested_drive
        events.append("stage")
        return tmp_path

    def confirm(question: str) -> str:
        assert "backup" in question and "[y/N]" in question
        events.append("confirm")
        if answer is None:
            raise EOFError
        return answer

    monkeypatch.setattr(cli.target, "read_target", lambda **_: identity)
    monkeypatch.setattr(cli, "run_update", scan)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: interactive)
    monkeypatch.setattr("builtins.input", confirm)
    monkeypatch.setattr(Menu, "resume", lambda *_, **__: True)
    monkeypatch.setattr(Menu, "check_windows", lambda _: True)
    monkeypatch.setattr(Menu, "stage_feature", stage)
    monkeypatch.setattr(Menu, "offer_restart", lambda _: events.append("restart"))
    assert cli.main(
        [
            "update",
            "--feature-iso",
            "windows.iso",
            "--iso-sha256",
            "a" * 64,
            "--accept-setup-eula",
            *(["--backup-drive", requested_drive] if requested_drive else []),
        ]
    ) == (0 if staged else 1)
    expected = ["confirm"] if requested_drive is None and interactive else []
    if staged:
        expected += ["stage", "restart"]
    assert events == expected
    assert ("unbootable" in capsys.readouterr().err) is (requested_drive is None)


@pytest.mark.parametrize("scan_error", [False, True])
def test_explicit_iso_preview_without_a_wua_offer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scan_error: bool
) -> None:
    identity = replace(
        TARGET, windows=tmp_path / "Windows", machine_guid=str(UUID(int=5))
    )
    calls = []

    def scan(installed: TargetIdentity) -> tuple[list[Offer], None]:
        assert installed == identity
        if scan_error:
            raise OSError("WUA unavailable")
        return [], None

    def check_native(
        installed: TargetIdentity, iso: Path, digest: str, build: int | None
    ) -> None:
        assert installed == identity
        calls.append((iso, digest, build))

    def refuse(*args: object, **kwargs: object) -> None:
        pytest.fail("Feature preview attempted to stage or restart Windows")

    monkeypatch.setattr("wuo.target.read_target", lambda *, read_loader: identity)
    monkeypatch.setattr(feature, "read_target", lambda *, read_loader: identity)
    monkeypatch.setattr("wuo.update.scan_offers", scan)
    monkeypatch.setattr(feature, "_scan_media", check_native)
    monkeypatch.setattr(Menu, "resume", refuse)
    monkeypatch.setattr(Menu, "publish", refuse)
    monkeypatch.setattr(Menu, "stage_feature", refuse)
    arguments = [
        "update",
        "--dry-run",
        "--only",
        "features",
        "--feature-iso",
        "windows.iso",
        "--iso-sha256",
        "a" * 64,
        "--accept-setup-eula",
    ]
    assert cli.main(arguments) == 0
    assert calls == [(Path("windows.iso"), "a" * 64, None)]

    menu = Menu(identity)
    menu.root.mkdir(parents=True)
    (menu.root / "installed.id").write_text(identity.machine_guid, encoding="ascii")
    (menu.root / "pending.id").write_text(str(UUID(int=6)), encoding="ascii")
    assert cli.main(arguments) == 1
    assert len(calls) == 1


def test_preview_isolated_from_staging_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = replace(
        TARGET, windows=tmp_path / "Windows", machine_guid=str(UUID(int=5))
    )
    calls = []
    processed = []
    scans = []
    driver = Offer(str(UUID(int=7)), "Driver offer", "drivers")
    enablement = replace(OFFER, id=str(UUID(int=8)), title=OFFER.title + " (KB1234567)")

    def refuse(*args: object, **kwargs: object) -> None:
        pytest.fail("Feature preview attempted to stage or restart Windows")

    async def check(
        client: AsyncClient,
        installed: TargetIdentity,
        offers: list[Offer],
        media: feature.FeatureMedia,
        *,
        preview: bool,
    ) -> feature.FeatureImage:
        assert preview
        assert installed == identity
        assert offers == [OFFER]
        calls.append((media.iso, media.sha256, media.rollback))
        return feature.FeatureImage(6, 26300, 9457, "Professional", "x64", "en-US")

    def scan(installed: TargetIdentity) -> tuple[list[Offer], None]:
        assert installed == identity
        scans.append(installed)
        return [OFFER, driver, enablement], None

    async def process(
        _client: object,
        _installed: object,
        _output: object,
        offer: Offer,
        **options: object,
    ) -> bool:
        assert options["dry_run"] is True
        candidates = options["setup_candidates"]
        if offer == OFFER and isinstance(candidates, list):
            candidates.append(offer)
            return True
        processed.append(offer)
        return True

    monkeypatch.setattr("wuo.target.read_target", lambda *, read_loader: identity)
    monkeypatch.setattr("wuo.update.scan_offers", scan)
    monkeypatch.setattr("wuo.update._process_offer", process)
    monkeypatch.setattr(Menu, "resume", refuse)
    monkeypatch.setattr(Menu, "publish", refuse)
    monkeypatch.setattr(feature, "check_feature", check)
    assert cli.main(["update"]) == 1
    assert processed == [OFFER, driver, enablement]
    assert scans == [identity]
    assert not calls
    processed.clear()
    scans.clear()
    arguments = [
        "update",
        "--dry-run",
        "--feature-iso",
        "windows.iso",
        "--iso-sha256",
        "a" * 64,
        "--accept-setup-eula",
        "--no-rollback",
    ]
    assert cli.main(arguments) == 0
    assert calls == [(Path("windows.iso"), "a" * 64, False)]
    assert scans == [identity]
    assert processed == [driver, enablement]

    assert cli.main([*arguments, "--only", "drivers"]) == 0
    assert processed == [driver, enablement, driver]
    assert len(calls) == 1
    assert cli.main([*arguments, "--only", "features"]) == 0
    assert processed == [driver, enablement, driver, enablement]
    assert len(calls) == 2

    menu = Menu(identity)
    menu.root.mkdir(parents=True)
    (menu.root / "installed.id").write_text(identity.machine_guid, encoding="ascii")
    (menu.root / "pending.id").write_text(str(UUID(int=6)), encoding="ascii")
    assert cli.main(arguments) == 1
    assert len(calls) == 2
    (menu.root / "pending.id").unlink()
    (menu.root / "windows-request.json").write_text("{}", encoding="ascii")
    assert cli.main(arguments) == 1
    assert len(calls) == 2


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is required")
def test_scan_media_uses_native_modules_with_inherited_module_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    custom_modules = tmp_path / "PowerShell" / "Modules"
    custom_modules.mkdir(parents=True)
    monkeypatch.setenv("PSMODULEPATH", str(custom_modules))
    monkeypatch.setattr(feature, "files", lambda _: tmp_path)
    (tmp_path / "feature_upgrade.ps1").write_text(
        """
$ErrorActionPreference = 'Stop'
$hash = Get-FileHash -LiteralPath $env:WUO_FEATURE_ISO -Algorithm SHA256
if ($hash.Hash -ne $env:WUO_FEATURE_SHA256) { throw 'Expected SHA-256 mismatch' }
Get-Command Get-AuthenticodeSignature, Get-DiskImage, Get-WindowsImage | Out-Null
@{
    setup_code = -1047526896
    index = 1
    edition = 'Core'
    architecture = $env:WUO_FEATURE_ARCH
    language = 'en-US'
    build = 26300
    revision = 9457
} | ConvertTo-Json -Compress
""",
        encoding="ascii",
    )
    iso = tmp_path / "fixture.iso"
    iso.write_bytes(b"fixture")
    identity = replace(TARGET, windows=Path(os.environ["SYSTEMROOT"]))
    image = feature._scan_media(
        identity, iso, hashlib.sha256(b"fixture").hexdigest(), None
    )
    assert image == feature.FeatureImage(
        index=1,
        build=26300,
        revision=9457,
        edition="Core",
        architecture="x64",
        language="en-US",
    )
    assert os.environ["PSMODULEPATH"] == str(custom_modules)


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is required")
def test_prepare_media_passes_the_verified_image_to_the_native_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(feature, "files", lambda _: tmp_path)
    (tmp_path / "feature_upgrade.ps1").write_text(
        """
param([switch]$Prepare)
$ErrorActionPreference = 'Stop'
if (!$Prepare) { throw 'Expected deferred preparation' }
@{
    setup_code = 0
    index = [int]$env:WUO_FEATURE_INDEX
    edition = $env:WUO_FEATURE_EDITION
    architecture = $env:WUO_FEATURE_ARCH
    language = $env:WUO_FEATURE_LANGUAGE
    build = [int]$env:WUO_FEATURE_BUILD
    revision = [int]$env:WUO_FEATURE_REVISION
} | ConvertTo-Json -Compress
""",
        encoding="ascii",
    )
    iso = tmp_path / "fixture.iso"
    iso.write_bytes(b"fixture")
    identity = replace(TARGET, windows=Path(os.environ["SYSTEMROOT"]))
    selected = feature.FeatureImage(6, 26300, 9457, "Professional", "x64", "en-US")
    media = feature.FeatureMedia(iso, hashlib.sha256(b"fixture").hexdigest())
    assert feature.prepare_media(identity, media, selected) == selected


HARNESS = r"""
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility
$letter = 90..68 | ForEach-Object { [string][char]$_ } |
    Where-Object { !(Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) } |
    Select-Object -First 1
New-PSDrive -Name $letter -PSProvider FileSystem -Root $env:WUO_FIXTURE | Out-Null
function Get-ItemProperty {
    param($Path, $Name, $ErrorAction)
    if ($Path -like '*CurrentVersion') { return @{CurrentBuildNumber=26200; UBR=9457} }
    if ($Name -eq 'SetupProgress') {
        if ($env:WUO_TEST_SETUP_BUSY -eq '1') { return @{SetupProgress=0} }
        return
    }
    return @{SystemSetupInProgress=0}
}
function New-Object { param($ComObject) @{RebootRequired=$false} }
function Test-Path {
    param($Path, $LiteralPath, $PathType)
    if ($Path -like 'HKLM:*') { return $false }
    if ($LiteralPath -like '*NewOS\Windows\System32\Config\SYSTEM') {
        return $script:setupPrepared -and $env:WUO_TEST_STAGE_READY -eq '1'
    }
    Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType
}
function Get-DiskImage { param($ImagePath, $StorageType) @{Attached=$false} }
function Mount-DiskImage {
    param($ImagePath, $StorageType, $Access, [switch]$PassThru)
    if ($StorageType -ne 'ISO' -or $Access -ne 'ReadOnly') { throw 'Wrong access' }
    Add-Content $env:WUO_CALLS mount
    @{Attached=$true}
}
function Dismount-DiskImage {
    param($ImagePath, $StorageType)
    Add-Content $env:WUO_CALLS dismount
    [pscustomobject]@{ImagePath=$ImagePath; Attached=$false}
}
function Get-Volume { [pscustomobject]@{DriveLetter=$letter} }
function Get-AuthenticodeSignature {
    param($LiteralPath)
    $name = [Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=Microsoft Windows, O=Microsoft Corporation')
    $signer = [pscustomobject]@{ SubjectName=$name }
    @{Status='Valid'; SignerCertificate=$signer}
}
function Get-WindowsEdition { param([switch]$Online) @{Edition='Professional'} }
function Mock-Dism {
    $global:LASTEXITCODE = 0
    'Default system UI language : en-US'
}
Set-Alias "$env:SystemRoot\System32\dism.exe" Mock-Dism
function Mock-BcdEdit {
    $global:LASTEXITCODE = 0
    if ($script:setupPrepared -and $env:WUO_TEST_BOOT_CHANGED -eq '1') {
        return 'bootmgr after shutdown'
    }
    'bootmgr before shutdown'
}
Set-Alias "$env:SystemRoot\System32\bcdedit.exe" Mock-BcdEdit
function Get-WindowsImage {
    param($ImagePath, $Index)
    if ($Index -eq 0) { return @{ImageIndex=6} }
    return @{
        ImageIndex=6; MajorVersion=10; MinorVersion=0; Build=[int]$env:WUO_TEST_IMAGE_BUILD; SPBuild=9457
        InstallationType='Client'; Architecture=9; EditionId='Professional'
        DefaultLanguageIndex=0; Languages=@('en-US')
    }
}
function Start-Process {
    param($FilePath, $WorkingDirectory, [switch]$Wait, [switch]$PassThru, $ArgumentList)
    if ($FilePath -ne "${letter}:\setup.exe" -or !$Wait -or !$PassThru) { throw 'Wrong Setup invocation' }
    Add-Content $env:WUO_CALLS ($ArgumentList -join ' ')
    if ($env:WUO_TEST_PREPARE -eq '1') {
        $script:setupPrepared = $true
        return @{ExitCode=0}
    }
    return @{ExitCode=-1047526896}
}
if ($env:WUO_TEST_PREPARE -eq '1') { & $env:WUO_SCRIPT -Prepare }
else { & $env:WUO_SCRIPT }
"""


@pytest.fixture
def native_setup_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # Match the native module environment used by the production launcher.
    monkeypatch.delenv("PSMODULEPATH", raising=False)
    harness = tmp_path / "harness.ps1"
    harness.write_text(HARNESS, encoding="utf-8")
    return harness


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is required")
@pytest.mark.parametrize(
    ("index", "stage_ready", "boot_changed"),
    [(6, True, False), (1, True, False), (6, False, False), (6, True, True)],
)
def test_native_prepare_rechecks_image_and_deferred_state(
    tmp_path: Path,
    native_setup_harness: Path,
    index: int,
    stage_ready: bool,
    boot_changed: bool,
) -> None:
    assert POWERSHELL is not None
    media = tmp_path / "media"
    (media / "sources").mkdir(parents=True)
    (media / "sources/install.wim").touch()
    iso = tmp_path / "fixture.iso"
    iso.write_bytes(b"fixture")
    calls = tmp_path / "calls.txt"
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            native_setup_harness,
        ],
        env={
            **os.environ,
            "WUO_SCRIPT": str(SCRIPT),
            "WUO_FIXTURE": str(media),
            "WUO_CALLS": str(calls),
            "WUO_FEATURE_ISO": str(iso),
            "WUO_FEATURE_SHA256": hashlib.sha256(b"fixture").hexdigest(),
            "WUO_FEATURE_SOURCE": "26200.9457",
            "WUO_FEATURE_BUILD": "26300",
            "WUO_FEATURE_ARCH": "x64",
            "WUO_FEATURE_INDEX": str(index),
            "WUO_FEATURE_EDITION": "Professional",
            "WUO_FEATURE_LANGUAGE": "en-US",
            "WUO_FEATURE_REVISION": "9457",
            "WUO_TEST_PREPARE": "1",
            "WUO_TEST_STAGE_READY": str(int(stage_ready)),
            "WUO_TEST_BOOT_CHANGED": str(int(boot_changed)),
            "WUO_TEST_IMAGE_BUILD": "26300",
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    arguments = "/Auto Upgrade /Quiet /SkipFinalize /DynamicUpdate Disable /EULA Accept /ImageIndex 6"
    expected = ["mount", arguments, "dismount"] if index == 6 else ["mount", "dismount"]
    assert calls.is_file(), result.stderr
    assert calls.read_text().splitlines() == expected, result.stderr
    if index == 6 and stage_ready and not boot_changed:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["setup_code"] == 0
    else:
        assert result.returncode != 0


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell is required")
@pytest.mark.parametrize(
    (
        "arch",
        "valid_hash",
        "setup_busy",
        "expected_build",
        "image_build",
        "expected_calls",
    ),
    [
        ("x64", True, False, "26300", 26300, ["mount", "scan", "dismount"]),
        ("x64", True, False, "", 26300, ["mount", "scan", "dismount"]),
        ("x64", True, False, "", 26200, ["mount", "dismount"]),
        ("x64", True, False, "", 26100, ["mount", "dismount"]),
        ("x64", True, False, "26300", 26400, ["mount", "dismount"]),
        ("arm64", True, False, "26300", 26300, ["mount", "dismount"]),
        ("x64", False, False, "26300", 26300, []),
        ("x64", True, True, "26300", 26300, []),
    ],
)
def test_native_check_validates_media_and_only_invokes_scan(
    tmp_path: Path,
    native_setup_harness: Path,
    arch: str,
    valid_hash: bool,
    setup_busy: bool,
    expected_build: str,
    image_build: int,
    expected_calls: list[str],
) -> None:
    assert POWERSHELL is not None
    fixture = tmp_path / "media"
    (fixture / "sources").mkdir(parents=True)
    (fixture / "sources/install.wim").touch()
    iso = tmp_path / "fixture.iso"
    iso.write_bytes(b"fixture")
    calls = tmp_path / "calls.txt"
    result = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            native_setup_harness,
        ],
        env={
            **os.environ,
            "WUO_SCRIPT": str(SCRIPT),
            "WUO_FIXTURE": str(fixture),
            "WUO_CALLS": str(calls),
            "WUO_FEATURE_ISO": str(iso),
            "WUO_FEATURE_SHA256": hashlib.sha256(b"fixture").hexdigest()
            if valid_hash
            else "0" * 64,
            "WUO_FEATURE_SOURCE": "26200.9457",
            "WUO_FEATURE_BUILD": expected_build,
            "WUO_FEATURE_ARCH": arch,
            "WUO_TEST_SETUP_BUSY": str(int(setup_busy)),
            "WUO_TEST_IMAGE_BUILD": str(image_build),
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    setup = "/Auto Upgrade /Quiet /Compat ScanOnly /DynamicUpdate Disable /EULA Accept /ImageIndex 6"
    expected = [setup if call == "scan" else call for call in expected_calls]
    assert (calls.read_text().splitlines() if calls.exists() else []) == expected, (
        result.stderr
    )
    if "scan" in expected_calls:
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        feature.require_scan_success(report["setup_code"])
        assert report["build"] == image_build
    else:
        assert result.returncode != 0
        expected_error = (
            "pending Windows"
            if setup_busy
            else ("one Windows" if valid_hash else "differs from")
        )
        assert expected_error in result.stderr
