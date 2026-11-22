import argparse
import asyncio
import json
import os
import subprocess
from pathlib import Path
from uuid import uuid4
from xml.etree import ElementTree

import httpx
import pytest

from wuo import cli
from wuo.downloads import package_hashes
from wuo.target import TargetIdentity

JOB = "a1bad4cd-52c8-4e0b-bc75-dc24c29e4155"
OWNER = "9e1379fb-31bc-4c97-b14a-52aed0371c44"
LOADER = "32df251e-0f11-4e78-8559-23308eb4e23c"


@pytest.fixture(autouse=True)
def no_host_restart_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wuo.windows_updates.current_reboot_required", lambda _: False)


def test_main_help_shows_the_routine_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["--help"]) == 0
    help_text = capsys.readouterr().out
    for command in ("setup", "update", "status", "search", "download"):
        assert command in help_text
    assert "prepare-drivers" not in help_text
    assert cli.main(["prepare-drivers", "--help"]) == 0


def test_feature_task_keeps_the_full_id_and_escapes_the_script_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wuo import winre_menu

    windows = tmp_path / "Windows"
    menu = winre_menu.Menu(
        TargetIdentity("25H2", 26200, 9974, "x64", windows, OWNER, LOADER)
    )
    script = tmp_path / "upgrade & recovery" / "feature_upgrade.ps1"
    script.parent.mkdir()
    task_files: list[Path] = []

    def register(command: list[str | Path]) -> str:
        assert command[:-1] == [
            windows / "System32/schtasks.exe",
            "/Create",
            "/TN",
            f"wuo-feature-{JOB}",
            "/XML",
        ]
        task_file = Path(command[-1])
        assert task_file.is_relative_to(script.parent)
        task_files.append(task_file)
        definition = ElementTree.parse(task_file).getroot()
        assert definition.find("{*}Triggers/{*}BootTrigger") is not None
        assert definition.findtext("{*}Principals/{*}Principal/{*}UserId") == "S-1-5-18"
        assert definition.findtext("{*}Actions/{*}Exec/{*}Command") == str(
            windows / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        assert definition.findtext("{*}Actions/{*}Exec/{*}Arguments") == (
            f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script}" -FinalizeJob {JOB}'
        )
        return ""

    monkeypatch.setattr(winre_menu, "_run", register)
    menu._register_feature_task(JOB, script)
    assert len(task_files) == 1
    assert not task_files[0].exists()


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted",
    reason="requires the disposable Windows CI runner's elevated Task Scheduler",
)
def test_windows_scheduler_stores_the_full_feature_task_command(tmp_path: Path) -> None:
    from wuo.winre_menu import Menu

    windows = Path(os.environ["SYSTEMROOT"])
    menu = Menu(TargetIdentity("25H2", 26200, 9974, "x64", windows, OWNER, LOADER))
    script = tmp_path / "upgrade & recovery" / "feature_upgrade.ps1"
    script.parent.mkdir()
    script.write_text("exit 0\n", encoding="ascii")
    job = str(uuid4())
    task = f"wuo-feature-{job}"
    scheduler = windows / "System32/schtasks.exe"
    menu._register_feature_task(job, script)
    try:
        exported = subprocess.check_output(
            [scheduler, "/Query", "/TN", task, "/XML"], text=True
        )
        definition = ElementTree.fromstring(exported)
        assert definition.find("{*}Triggers/{*}BootTrigger") is not None
        assert definition.findtext("{*}Principals/{*}Principal/{*}UserId") == "S-1-5-18"
        assert Path(definition.findtext("{*}Actions/{*}Exec/{*}Command", "")) == (
            windows / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        arguments = definition.findtext("{*}Actions/{*}Exec/{*}Arguments")
        assert arguments == (
            f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script}" -FinalizeJob {job}'
        )
    finally:
        subprocess.run([scheduler, "/Delete", "/TN", task, "/F"], check=True)


@pytest.mark.parametrize("backup_fails", [False, True])
@pytest.mark.parametrize(
    ("preserve_boot", "protected"), [(False, False), (True, False), (True, True)]
)
def test_feature_is_published_only_after_backup_and_deferred_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backup_fails: bool,
    preserve_boot: bool,
    protected: bool,
) -> None:
    from wuo import feature_upgrade
    from wuo.winre_menu import Menu, _require_captured_feature_hook_support

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    menu = Menu(identity)
    menu.root.mkdir(parents=True)
    menu.job_state(JOB).parent.mkdir()
    (menu.root / "installed.id").write_text(f"{OWNER}\n", encoding="ascii")
    (menu.root / "feature-menu.version").write_bytes(
        b"3\r\n" if protected else b"2\r\n"
    )
    iso = tmp_path / "Windows.iso"
    iso.touch()
    media = feature_upgrade.FeatureMedia(
        iso,
        "ab" * 32,
        rollback=True,
        preserve_boot_order=preserve_boot,
        recovery_drive="F:" if protected else None,
    )
    image = feature_upgrade.FeatureImage(1, 26300, 9500, "Core", "x64", "en-US")
    events: list[str] = []
    backup_root = tmp_path / "backup"
    system32 = identity.windows / "System32"
    system32.mkdir(parents=True)
    for name in ("certutil.exe", "findstr.exe", "fc.exe"):
        (system32 / name).write_bytes(name.encode("ascii"))

    def capture(_target: object, mode: str, job: Path) -> dict[str, object]:
        assert mode == "Capture"
        events.append("capture")
        (job / "boot-order.json").write_text('{"schema": 1}', encoding="ascii")
        (job / "boot-fallback.efi").write_bytes(b"original fallback")
        return {"schema": 1}

    def backup(_target: object, job: object, _drive: object) -> tuple[bytes, Path]:
        events.append("backup")
        if backup_fails:
            raise ValueError("backup failed")
        receipt = json.dumps(
            {
                "schema": 1,
                "id": str(job),
                "machine": OWNER,
                "source": "26200.9974",
                "original_letter": identity.windows.drive or "C:",
                "computer": "test-pc",
                "catalog": "11/20/2026-14:39",
                "windows": "\\\\?\\Volume{11111111-1111-1111-1111-111111111111}\\",
                "efi": "\\\\?\\Volume{22222222-2222-2222-2222-222222222222}\\",
                "volume": "\\\\?\\Volume{33333333-3333-3333-3333-333333333333}\\",
                "boot_files": [
                    {"path": r"EFI\Microsoft\Boot\BCD", "sha256": "ab" * 32},
                    {"path": r"EFI\Microsoft\Boot\bootmgfw.efi", "sha256": "cd" * 32},
                ],
            }
        ).encode("ascii")
        snapshot = backup_root / str(job)
        snapshot.mkdir(parents=True)
        (snapshot / "rollback.json").write_bytes(receipt)
        return receipt, snapshot

    def prepare(*_args: object) -> None:
        assert not protected
        assert not (menu.root / "pending.id").exists()
        assert not list(menu.job_state(JOB).parent.glob("*/feature.ready"))
        (portable,) = backup_root.glob("*/recovery")
        job = menu.job_state(portable.parent.name)
        assert (portable / "restore.cmd").read_bytes() == (
            job / "restore.cmd"
        ).read_bytes()
        for name in ("certutil.exe", "findstr.exe", "fc.exe"):
            assert (portable / name).read_bytes() == (system32 / name).read_bytes()
        if preserve_boot:
            request = json.loads((job / "feature.json").read_bytes())
            assert (
                request["boot_preservation"]["boot-order.json"]
                == package_hashes(job / "boot-order.json")[0]
            )
            assert (portable / "boot-fallback.efi").read_bytes() == b"original fallback"
            callbacks = system32 / "update" / "runonce" / job.name
            assert "-Outcome success" in (callbacks / "success.cmd").read_text()
            assert "-Outcome failure" in (callbacks / "failure.cmd").read_text()
            assert "boot-rollback.id" in (job / "restore.cmd").read_text()
        events.append("prepare")

    def select(_target: object, drive: str, backup: str) -> dict[str, object]:
        assert drive == "F:" and backup == "E:"
        events.append("identify")
        return {"id": "Boot0001"}

    def prepare_recovery(
        _target: object,
        _media: object,
        _image: object,
        job: Path,
        _hooks: object,
        selection: dict[str, object],
        receipt: bytes,
    ) -> dict[str, object]:
        assert protected and selection["id"] == "Boot0001"
        assert not (menu.root / "pending.id").exists()
        assert not (job / "feature.ready").exists()
        assert not (system32 / "update" / "runonce" / job.name).exists()
        assert receipt == (job / "rollback.json").read_bytes()
        assert (backup_root / job.name / "recovery" / "restore.cmd").is_file()
        events.append("prepare-recovery")
        return {"receipt": f"v1 {job.name} {'f' * 64} 26300"}

    def schedule(_job: str, continuation: Path) -> None:
        assert continuation.is_file()
        assert not (menu.root / "pending.id").exists()
        events.append("schedule")

    monkeypatch.setattr("wuo.target.read_target", lambda: identity)
    monkeypatch.setattr("wuo.winre_menu._run", lambda _: "")
    monkeypatch.setattr(feature_upgrade, "backup_feature", backup)
    monkeypatch.setattr(feature_upgrade, "prepare_media", prepare)
    monkeypatch.setattr(feature_upgrade, "feature_boot", capture, raising=False)
    monkeypatch.setattr(feature_upgrade, "feature_recovery_selection", select)
    monkeypatch.setattr(
        feature_upgrade, "prepare_independent_recovery", prepare_recovery
    )
    monkeypatch.setattr(menu, "_register_feature_task", schedule)
    capture_events = (["identify"] if protected else []) + (
        ["capture", "schedule"] if preserve_boot else []
    )
    if backup_fails:
        with pytest.raises(ValueError, match="backup failed"):
            menu.stage_feature(media, image, None, backup_drive="E:")
        assert events == [*capture_events, "backup"]
        assert not (menu.root / "pending.id").exists()
    else:
        job = menu.stage_feature(media, image, None, backup_drive="E:")
        assert events == [
            *capture_events,
            "backup",
            "prepare-recovery" if protected else "prepare",
            *([] if preserve_boot else ["schedule"]),
        ]
        marker = f"{job.name}\r\n".encode("ascii")
        assert (job / "feature.ready").read_bytes() == marker
        assert (job / "rollback.required").read_bytes() == marker
        assert (menu.root / "pending.id").read_bytes() == marker
        assert (job / "restore.sha256").read_text().strip() == package_hashes(
            job / "restore.cmd"
        )[0]
        if protected:
            assert (job / "feature.protected").read_bytes() == marker
            request = json.loads((job / "feature.json").read_bytes())
            assert request["schema"] == 2
            proof = job / "independent-preflight.done"
            with pytest.raises(
                ValueError, match="Ventoy drive and wait for its preflight"
            ):
                _require_captured_feature_hook_support(job)
            proof.write_bytes(f"{request['recovery']['receipt']}\r\n".encode("ascii"))
            _require_captured_feature_hook_support(job)


@pytest.mark.parametrize(
    ("scope", "key", "name", "value"),
    [
        ("control-set", r"Services\Usb4HostRouter", "Start", 0),
        ("system", r"ControlSet001\Services\Usb4HostRouter", "Start", 0),
        ("control-set", r"Services\stornvme\StartOverride", "0", 0),
        ("system", r"Software\WUO", "Enabled", 1),
    ],
)
def test_full_iso_feature_stage_refuses_post_hooks_before_changing_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    key: str,
    name: str,
    value: int,
) -> None:
    from wuo import feature_upgrade
    from wuo.winre_menu import Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    menu = Menu(identity)
    menu.root.mkdir(parents=True)
    (menu.root / "installed.id").write_text(f"{OWNER}\n", encoding="ascii")
    (menu.root / "feature-menu.version").write_bytes(b"2\r\n")
    menu.job_state(JOB).parent.mkdir()
    profile = tmp_path / "external.toml"
    profile.write_text(
        f"[[hooks]]\nphase = 'post'\nscope = '{scope}'\nkey = '{key}'\nname = '{name}'\nvalue = {value}\n",
        encoding="ascii",
    )
    iso = tmp_path / "Windows.iso"
    iso.touch()
    media = feature_upgrade.FeatureMedia(
        iso, "ab" * 32, rollback=True, preserve_boot_order=True
    )
    image = feature_upgrade.FeatureImage(1, 26300, 9457, "Core", "x64", "en-US")
    monkeypatch.setattr(menu, "_require_windows_complete_locked", lambda: None)
    monkeypatch.setattr("wuo.target.read_target", lambda: identity)
    monkeypatch.setattr(
        "wuo.winre_menu._run", lambda _: pytest.fail("Changed feature job state")
    )

    with pytest.raises(ValueError, match="after SafeOS"):
        menu.stage_feature(media, image, profile, backup_drive="F:")

    assert not (menu.root / "pending.id").exists()
    assert not any(menu.root.parent.glob("jobs/*"))


def test_resume_requires_boot_preservation_in_the_captured_feature_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from wuo import windows_updates
    from wuo.winre_menu import Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    menu = Menu(identity)
    state = menu.job_state(JOB)
    state.mkdir(parents=True)
    menu.root.mkdir(parents=True)
    (menu.root / "installed.id").write_text(f"{OWNER}\n", encoding="ascii")
    for marker in (menu.root / "pending.id", state / "feature.ready"):
        marker.write_text(f"{JOB}\n", encoding="ascii")
    request = {"id": JOB, "machine": OWNER, "source": "26200.9974"}
    (state / "feature.json").write_text(json.dumps(request), encoding="ascii")
    monkeypatch.setattr(menu, "offer_restart", lambda: pytest.fail("Offered old job"))

    with pytest.raises(ValueError, match="staged without boot preservation"):
        menu.resume(require_boot_preservation=True)

    (state / "profile.toml").write_text(
        "[[hooks]]\nphase = 'post'\nkey = 'Services\\AnotherDriver\\StartOverride'\nname = '0'\nvalue = 0\n",
        encoding="ascii",
    )
    with pytest.raises(ValueError, match="after SafeOS"):
        menu.resume()
    assert (menu.root / "pending.id").read_text().strip() == JOB
    capsys.readouterr()
    menu.status()
    output = capsys.readouterr().out
    assert "Full ISO feature upgrades with post hooks are blocked" in output
    assert "Run wuo update to enter recovery" not in output

    (state / "authorized.id").write_text(f"{JOB}\n", encoding="ascii")
    (state / "backup-check.log").touch()
    menu.status()
    output = capsys.readouterr().out
    assert "The saved startup task can still resume it" in output
    assert "Reconnect the backup drive and restart" not in output

    monkeypatch.setattr(
        windows_updates,
        "verify",
        lambda *_: windows_updates.WindowsResult(False, True, (), state / "journal"),
    )
    with pytest.raises(ValueError, match="after SafeOS"):
        menu.resume()
    assert "Restart Windows to finish the Windows phase" not in capsys.readouterr().out

    (state / "profile.toml").unlink()
    (state / "hooks.json").write_text("{}", encoding="ascii")
    with pytest.raises(ValueError, match="captured feature hook profile is missing"):
        menu.resume()


def test_feature_cli_blocks_post_hooks_before_offer_to_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from wuo.feature_upgrade import FeatureImage
    from wuo.update import PreparedUpdates
    from wuo.winre_menu import Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    menu = Menu(identity)
    menu.root.mkdir(parents=True)
    profile = tmp_path / "profile.toml"
    profile.write_text(
        "[[hooks]]\nphase = 'post'\nkey = 'Control'\nname = 'BootDriverFlags'\nvalue = 28\n",
        encoding="ascii",
    )
    args = argparse.Namespace(
        feature_iso=tmp_path / "Windows.iso",
        iso_sha256="ab" * 32,
        backup_drive=None,
        dry_run=False,
        only=["features"],
        driver_cache=True,
        extractor=None,
    )

    async def scan(*_: object, prepared: PreparedUpdates, **__: object) -> int:
        prepared.feature = FeatureImage(1, 26300, 9457, "Core", "x64", "en-US")
        return 0

    monkeypatch.setattr(cli, "run_update", scan)
    monkeypatch.setattr(Menu, "check_windows", lambda _: True)
    monkeypatch.setattr("wuo.target.read_target", lambda: identity)
    monkeypatch.setattr(
        cli, "_confirm_feature_without_backup", lambda: pytest.fail("Offered staging")
    )

    async def run() -> int:
        async with httpx.AsyncClient() as client:
            return await cli._stage_update(
                client, args, identity, menu, True, tmp_path, profile
            )

    with pytest.raises(ValueError, match="after SafeOS"):
        asyncio.run(run())
    assert "Preparing Windows Setup" not in capsys.readouterr().out


def test_feature_verification_waits_for_boot_preservation_receipt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from wuo.winre_menu import Menu

    identity = TargetIdentity(
        "26H2", 26300, 9500, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    menu = Menu(identity)
    state = menu.job_state(JOB)
    state.mkdir(parents=True)
    (state / "feature.ready").write_text(f"{JOB}\n", encoding="ascii")
    (state / "precommit.done").write_text(f"{JOB}\n", encoding="ascii")
    (state / "feature.json").write_text(
        json.dumps(
            {
                "id": JOB,
                "machine": OWNER,
                "source": "26200.9974",
                "image": {"build": 26300, "revision": 9500, "architecture": "x64"},
                "boot_preservation": {"boot-order.json": "ab" * 32},
            }
        ),
        encoding="ascii",
    )

    assert not menu._verify_feature(JOB, state)
    assert "Boot preservation result is pending" in capsys.readouterr().out
    (state / "boot-order-result.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "order": "blocked",
                "order_detail": "Original entry was changed.",
                "fallback": "restored",
                "fallback_detail": "Original fallback was verified.",
            }
        ),
        encoding="ascii",
    )

    assert menu._verify_feature(JOB, state)
    output = capsys.readouterr().out
    assert "Original entry was changed." in output
    assert "Original fallback was verified." in output


@pytest.mark.parametrize("corrupt", [False, True])
def test_only_a_complete_verified_bundle_is_published(
    tmp_path: Path, corrupt: bool
) -> None:
    from wuo.winre_menu import MENU_PATH, Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    root = tmp_path / MENU_PATH
    root.mkdir(parents=True)
    (root / "installed.id").write_text(f"{OWNER}\n", encoding="ascii")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    runner = bundle / "recovery.cmd"
    runner.write_bytes(b"@echo off\r\n")
    inventory = {"recovery.cmd": package_hashes(runner)[0]}
    plan = bundle / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "id": JOB,
                "target": {
                    "machine_guid": OWNER,
                    "loader_guid": LOADER,
                    "release": "25H2",
                    "build": 26200,
                    "revision": 9974,
                    "architecture": "x64",
                },
                "paths": inventory,
            }
        ),
        encoding="ascii",
    )
    state = root.parent / "jobs" / JOB
    state.mkdir(parents=True)
    (state / "target.id").write_text(f"{JOB}\n", encoding="ascii")
    (state / "plan.sha256").write_text(package_hashes(plan)[0] + "\n", encoding="ascii")

    menu = Menu(identity)
    if corrupt:
        runner.write_bytes(b"wrong")
        with pytest.raises(ValueError, match="digest mismatch"):
            menu.publish(bundle)
        assert not (root / "pending.id").exists()
    else:
        destination = menu.publish(bundle)
        assert (root / "pending.id").read_text(encoding="ascii") == f"{JOB}\n"
        assert (destination / "hashes.txt").read_text(
            encoding="ascii"
        ).splitlines() == [
            f"{package_hashes(plan)[0]} plan.json",
            f"{inventory['recovery.cmd']} recovery.cmd",
        ]
        assert (state / "hashes.sha256").read_text(
            encoding="ascii"
        ).strip() == package_hashes(destination / "hashes.txt")[0]
        with pytest.raises(ValueError, match="already staged"):
            menu.publish(bundle)
        menu.discard()
        assert not (root / "pending.id").exists()
        assert destination.is_dir()


def test_status_leaves_an_interrupted_job_pending(tmp_path: Path) -> None:
    from wuo.winre_menu import MENU_PATH, Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    root = tmp_path / MENU_PATH
    root.mkdir(parents=True)
    (root / "installed.id").write_text(f"{OWNER}\n", encoding="ascii")
    pending = root / "pending.id"
    pending.write_text(f"{JOB}\n", encoding="ascii")
    menu = Menu(identity)
    state = menu.job_state(JOB)
    (state / "apply.started").mkdir(parents=True)

    with pytest.raises(ValueError, match="servicing was interrupted"):
        menu.status()
    assert pending.read_text(encoding="ascii") == f"{JOB}\n"


def test_setup_can_replace_or_disable_saved_hooks_without_reinstalling_winre(
    tmp_path: Path,
) -> None:
    from wuo.hook_selection import read_selection
    from wuo.winre_menu import MENU_PATH, Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    root = tmp_path / MENU_PATH
    root.mkdir(parents=True)
    (root / "installed.id").write_text(f"{OWNER}\n", encoding="ascii")
    source = tmp_path / "usb4.toml"
    source.write_text(
        "[[hooks]]\nphase = 'post'\nkey = 'Services\\UASPStor'\nname = 'Start'\nvalue = 0\n",
        encoding="ascii",
    )
    menu = Menu(identity)
    menu.configure("install", source)
    saved = menu.profile
    assert saved is not None and saved != source
    original = read_selection(saved)
    assert original.origins[0].location == str(source.resolve())
    source.write_text(source.read_text().replace("value = 0", "value = 1"))
    assert read_selection(menu.profile).hooks == original.hooks
    menu.configure("install", source)
    assert read_selection(menu.profile).hooks[0].value == 1
    assert read_selection(saved).hooks[0].value == 0
    menu.configure("install")
    assert menu.profile is None


def test_setup_displays_pending_hooks_when_saved_selection_is_disabled(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from wuo.winre_menu import MENU_PATH, Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    root = tmp_path / MENU_PATH
    root.mkdir(parents=True)
    (root / "installed.id").write_text(f"{OWNER}\n", encoding="ascii")
    (root / "pending.id").write_text(f"{JOB}\n", encoding="ascii")
    pending = root / "bundles" / JOB
    pending.mkdir(parents=True)
    (pending / "hooks.toml").write_text(
        "[[hooks]]\nphase = 'post'\nkey = 'Services\\UASPStor'\nname = 'Start'\nvalue = 0\n",
        encoding="ascii",
    )
    (pending / "plan.json").write_text('{"hooks": [{}]}', encoding="ascii")
    menu = Menu(identity)
    menu.configure("install")
    menu.describe_hooks()
    output = capsys.readouterr().out
    assert "Hooks: none." in output
    assert f"Pending job {JOB}" in output
    assert "UASPStor" in output


def test_pending_job_cannot_restart_with_conflicting_hook_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wuo.winre_menu import MENU_PATH, Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    root = tmp_path / MENU_PATH
    root.mkdir(parents=True)
    (root / "installed.id").write_text(f"{OWNER}\n", encoding="ascii")
    (root / "pending.id").write_text(f"{JOB}\n", encoding="ascii")
    menu = Menu(identity)
    called = []
    monkeypatch.setattr(menu, "offer_restart", lambda: called.append(True))
    with pytest.raises(ValueError, match="pending job has captured hooks"):
        menu.resume(allow_restart=False)
    assert called == []
    assert (root / "pending.id").is_file()


def test_stale_menu_cannot_publish_across_new_native_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wuo import windows_updates
    from wuo.winre_menu import MENU_PATH, Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    root = tmp_path / MENU_PATH
    root.mkdir(parents=True)
    (root / "installed.id").write_text(OWNER, encoding="ascii")
    state = {"incomplete": False}

    def verify(*_: object) -> windows_updates.WindowsResult | None:
        if state["incomplete"]:
            return windows_updates.WindowsResult(
                False, False, (), root / "windows-updates.json"
            )
        return None

    monkeypatch.setattr(windows_updates, "verify", verify)
    stale = Menu(identity)
    assert stale.resume()
    state["incomplete"] = True  # Another scanner finished its native phase later.
    assert stale.windows_incomplete is False
    with pytest.raises(ValueError, match="Windows.*incomplete|Windows phase"):
        stale.publish(tmp_path / "not-yet-read")
    assert not (root / "pending.id").exists()


def test_restart_rechecks_native_phase_after_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wuo import windows_updates, winre_menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    menu = winre_menu.Menu(identity)
    menu.root.mkdir(parents=True)
    (menu.root / "installed.id").write_text(OWNER, encoding="ascii")
    (menu.root / "pending.id").write_text(JOB, encoding="ascii")
    state = {"incomplete": False}

    def verify(*_: object) -> windows_updates.WindowsResult | None:
        return (
            windows_updates.WindowsResult(
                False, True, (), menu.root / "windows-updates.json"
            )
            if state["incomplete"]
            else None
        )

    def consent(_: str) -> str:
        state["incomplete"] = True
        return "yes"

    monkeypatch.setattr(windows_updates, "verify", verify)
    monkeypatch.setattr(winre_menu.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", consent)
    monkeypatch.setattr(
        winre_menu, "_run", lambda *_: pytest.fail("The stale restart must not run.")
    )
    with pytest.raises(ValueError, match="Windows.*incomplete|Windows phase"):
        menu.offer_restart()


def test_incomplete_native_phase_does_not_offer_existing_recovery_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wuo import windows_updates
    from wuo.winre_menu import Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    menu = Menu(identity)
    menu.root.mkdir(parents=True)
    (menu.root / "installed.id").write_text(OWNER, encoding="ascii")
    (menu.root / "pending.id").write_text(JOB, encoding="ascii")
    monkeypatch.setattr(
        windows_updates,
        "verify",
        lambda *_: windows_updates.WindowsResult(
            False, False, (), menu.root / "windows-updates.json"
        ),
    )
    monkeypatch.setattr(
        menu,
        "offer_restart",
        lambda: pytest.fail("Resolve the native phase before a recovery restart."),
    )
    assert menu.resume() is False
    assert menu.windows_incomplete


def test_pending_native_hooks_remain_visible_after_future_selection_is_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from wuo import windows_hooks, windows_updates
    from wuo.hook_selection import resolve_selection
    from wuo.winre_menu import Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    menu = Menu(identity)
    menu.root.mkdir(parents=True)
    (menu.root / "installed.id").write_text(OWNER, encoding="ascii")
    (menu.root / "selection.json").write_text('{"profile": null}', encoding="ascii")
    selected = resolve_selection(("official/usb4",), None, tmp_path / "selected")
    monkeypatch.setattr(windows_hooks, "_backup", lambda *_: None)
    monkeypatch.setattr(windows_hooks, "apply", lambda *_: None)
    job_id = "55555555-5555-5555-5555-555555555555"
    with windows_hooks.capture(
        selected.path, menu.root, OWNER, identity.windows, job_id=job_id
    ):
        pass
    (menu.root / windows_updates.JOURNAL).write_text(
        json.dumps({"hooks_job_id": job_id, "phase_complete": False}), encoding="ascii"
    )
    menu.describe_hooks()
    output = capsys.readouterr().out
    assert "Saved hooks for future jobs" in output and "Hooks: none." in output
    assert "Pending Windows phase uses these captured hooks" in output
    assert "official/usb4" in output and "UASPStor" in output


def test_unfinished_native_phase_rejects_new_hook_flags_before_rescan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wuo import windows_updates
    from wuo.winre_menu import Menu

    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", OWNER, LOADER
    )
    menu = Menu(identity)
    menu.root.mkdir(parents=True)
    (menu.root / "installed.id").write_text(OWNER, encoding="ascii")
    monkeypatch.setattr(
        windows_updates,
        "verify",
        lambda *_: windows_updates.WindowsResult(
            False, False, (), menu.root / windows_updates.JOURNAL
        ),
    )
    with pytest.raises(ValueError, match="captured hooks"):
        menu.resume(allow_restart=False)
