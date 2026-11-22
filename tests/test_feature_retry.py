import json
from hashlib import sha256
from pathlib import Path

import pytest

from wuo import feature_upgrade
from wuo.target import TargetIdentity
from wuo.winre_menu import Menu

JOB = "85bbe1a6-db82-45a4-8e9e-90c5b012fc3e"
OLD = "13d67809-d177-4c69-9c3a-a4871d5228af"
OWNER = "9e1379fb-31bc-4c97-b14a-52aed0371c44"
LOADER = "32df251e-0f11-4e78-8559-23308eb4e23c"


@pytest.fixture
def retry_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Menu, Path]:
    windows = tmp_path / "Windows"
    (tmp_path / "Windows.iso").touch()
    menu = Menu(TargetIdentity("25H2", 26200, 9974, "x64", windows, OWNER, LOADER))
    menu.root.mkdir(parents=True)
    for name, value in {
        "installed.id": OWNER,
        "pending.id": JOB,
        f"pending.{OLD}.abandoned.id": OLD,
    }.items():
        (menu.root / name).write_bytes(f"{value}\r\n".encode())
    callbacks = windows / "System32/update/runonce"
    for job_id in (JOB, OLD):
        directory = menu.job_state(job_id)
        directory.mkdir(parents=True)
        (directory / "feature.ready").write_bytes(f"{job_id}\r\n".encode())
        callback = callbacks / job_id / "precommit.cmd"
        callback.parent.mkdir(parents=True)
        callback.write_bytes(job_id.encode())
        request = {
            "id": job_id,
            "machine": OWNER,
            "schema": 1,
            "source": "26200.9974",
            "rollback": True,
            "boot_preservation": {"boot-order.json": "ab" * 32},
            "iso": str(tmp_path / "Windows.iso"),
            "sha256": "ab" * 32,
            "image": {
                "index": 1,
                "build": 26300,
                "revision": 9457,
                "edition": "Core",
                "architecture": "x64",
                "language": "en-US",
            },
            "callback_sha256": sha256(job_id.encode()).hexdigest(),
        }
        (directory / "feature.json").write_text(json.dumps(request), encoding="ascii")
    state = menu.job_state(JOB)
    (state / "claimed.id").write_bytes(f"{JOB}\r\n".encode())
    (state / "finalize.result").write_bytes(b"0xC19001E3\r\n")
    (state / "boot-completion.phase").write_bytes(b"failure\r\n")
    (state / "boot-order-result.json").write_text(
        '{"schema":1,"order":"unchanged","fallback":"restored"}', encoding="ascii"
    )
    (state / "rollback.json").write_text("Keep this backup receipt.", encoding="ascii")
    monkeypatch.setattr(menu, "_require_windows_complete_locked", lambda: None)
    monkeypatch.setattr("wuo.winre_menu._run", lambda command: "")
    return menu, callbacks


def _prepared(state: Path, image, retry_job: str):
    assert retry_job == JOB
    (state / "retry-active/prepared.id").write_bytes(f"{JOB}\r\n".encode())
    return image


@pytest.mark.parametrize("dry_run", [False, True])
def test_retry_refuses_captured_post_hooks_before_touching_backup_or_callbacks(
    retry_job: tuple[Menu, Path], monkeypatch: pytest.MonkeyPatch, dry_run: bool
) -> None:
    menu, callbacks = retry_job
    state = menu.job_state(JOB)
    (state / "profile.toml").write_text(
        "[[hooks]]\nphase = 'post'\nkey = 'Control'\nname = 'BootDriverFlags'\nvalue = 28\n",
        encoding="ascii",
    )
    monkeypatch.setattr(
        feature_upgrade,
        "check_feature_retry",
        lambda *args, **kwargs: pytest.fail("Started native retry validation"),
    )
    with pytest.raises(ValueError, match="after SafeOS"):
        menu.retry_feature(dry_run=dry_run)

    assert (state / "rollback.json").is_file()
    assert (state / "claimed.id").is_file()
    assert (callbacks / OLD / "precommit.cmd").is_file()


@pytest.mark.parametrize("dry_run", [False, True])
def test_retry_keeps_the_same_backup_and_moves_only_archived_callbacks(
    retry_job: tuple[Menu, Path], monkeypatch: pytest.MonkeyPatch, dry_run: bool
) -> None:
    menu, callbacks = retry_job
    state = menu.job_state(JOB)
    events: list[str] = []
    monkeypatch.setattr(
        feature_upgrade,
        "check_feature_retry",
        lambda identity, job, *, staged: events.append(job),
        raising=False,
    )

    def prepare(identity, media, image, *, retry_job):
        assert not (callbacks / OLD).exists()
        assert (callbacks / JOB / "precommit.cmd").is_file()
        assert (state / "claimed.id").is_file()
        assert media.rollback and media.preserve_boot_order
        events.append("prepare")
        return _prepared(state, image, retry_job)

    monkeypatch.setattr(feature_upgrade, "prepare_media", prepare)
    menu.retry_feature(dry_run=dry_run)
    assert (menu.root / "pending.id").read_text().strip() == JOB
    assert (state / "rollback.json").read_text() == "Keep this backup receipt."
    assert events == ([JOB] if dry_run else [JOB, "prepare"])
    assert (callbacks / OLD).exists() == dry_run
    assert (state / "claimed.id").exists() == dry_run
    assert (state / "boot-completion.phase").exists() == dry_run
    if not dry_run:
        assert (
            menu.job_state(OLD) / "archived-setup-callbacks/precommit.cmd"
        ).is_file()
        assert len(list(state.glob("retry-*/finalize.result"))) == 1


def test_native_validation_failure_leaves_callbacks_and_claim_in_place(
    retry_job: tuple[Menu, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    menu, callbacks = retry_job

    def unavailable(*args, **kwargs):
        raise ValueError("The rollback drive is unavailable.")

    monkeypatch.setattr(feature_upgrade, "check_feature_retry", unavailable)
    with pytest.raises(ValueError, match="rollback drive is unavailable"):
        menu.retry_feature(dry_run=False)
    assert (callbacks / OLD / "precommit.cmd").is_file()
    assert (menu.job_state(JOB) / "claimed.id").is_file()


def test_failed_preparation_can_be_retried_with_archived_callbacks(
    retry_job: tuple[Menu, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    menu, callbacks = retry_job
    state = menu.job_state(JOB)
    monkeypatch.setattr(
        feature_upgrade, "check_feature_retry", lambda *args, **kwargs: None
    )

    def failed_prepare(*args, **kwargs):
        raise ValueError("Windows Setup failed to prepare the ISO.")

    monkeypatch.setattr(feature_upgrade, "prepare_media", failed_prepare)
    with pytest.raises(ValueError, match="failed to prepare the ISO"):
        menu.retry_feature(dry_run=False)
    assert (state / "claimed.id").is_file()
    assert (state / "finalize.result").read_text().strip() == "0xC19001E3"
    assert not (callbacks / OLD).exists()
    monkeypatch.setattr(
        feature_upgrade,
        "prepare_media",
        lambda identity, media, image, *, retry_job: _prepared(state, image, retry_job),
    )
    menu.retry_feature(dry_run=False)
    assert not (state / "claimed.id").exists()
    assert (state / "rollback.json").is_file()


def test_retry_refuses_a_changed_archived_callback(
    retry_job: tuple[Menu, Path],
) -> None:
    menu, callbacks = retry_job
    (callbacks / OLD / "precommit.cmd").write_bytes(b"other callback")
    with pytest.raises(ValueError, match="Setup callback changed"):
        menu.retry_feature(dry_run=False)
    assert (callbacks / OLD).is_dir()
    assert (menu.job_state(JOB) / "claimed.id").is_file()


def test_retry_refuses_after_the_current_job_started_its_precommit_hook(
    retry_job: tuple[Menu, Path],
) -> None:
    menu, callbacks = retry_job
    (menu.job_state(JOB) / "precommit.expected").write_bytes(f"{JOB}\r\n".encode())
    with pytest.raises(ValueError, match="cannot be retried"):
        menu.retry_feature(dry_run=False)
    assert (callbacks / OLD).is_dir()


def test_can_finish_a_verified_stage_after_interrupted_record_cleanup(
    retry_job: tuple[Menu, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    menu, _ = retry_job
    state = menu.job_state(JOB)
    calls: list[bool | str] = []
    monkeypatch.setattr(
        feature_upgrade,
        "check_feature_retry",
        lambda identity, job, *, staged: calls.append(staged),
    )

    def prepare(identity, media, image, *, retry_job):
        calls.append("prepare")
        return _prepared(state, image, retry_job)

    monkeypatch.setattr(feature_upgrade, "prepare_media", prepare)
    unlink = Path.unlink

    def interrupt(path: Path, *, missing_ok: bool = False) -> None:
        if path == state / "boot-order-result.json":
            raise OSError("interrupted cleanup")
        unlink(path, missing_ok=missing_ok)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", interrupt)
        with pytest.raises(OSError, match="interrupted cleanup"):
            menu.retry_feature(dry_run=False)
    assert (state / "claimed.id").is_file()
    assert not (state / "boot-completion.phase").exists()
    menu.retry_feature(dry_run=False)
    assert calls == [False, "prepare", True]
    assert not (state / "claimed.id").exists()
