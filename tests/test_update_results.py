import argparse
import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import httpx
import pytest

from wuo import cli, update, windows_updates
from wuo.models import Update, UpdateFile
from wuo.target import TargetIdentity
from wuo.winre_menu import Menu


@pytest.fixture(autouse=True)
def no_host_restart_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(windows_updates, "current_reboot_required", lambda _: False)


def test_download_only_updates_are_recorded_separately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", "machine", ""
    )
    offer = update.Offer(
        "a32ca1d0-ddd4-486b-b708-d941db4f1165",
        "Windows Security platform 10.0.29680.1000",
        "security-platform",
    )
    package = Update(
        offer.id,
        offer.title,
        architecture="x64",
        kb="KB5007651",
        files=(
            UpdateFile(
                "securityhealthsetup.exe",
                "https://download.windowsupdate.com/securityhealthsetup.exe",
            ),
        ),
        route="Run the Microsoft installer in Windows.",
    )
    monkeypatch.setattr(update, "scan_offers", lambda _: ([offer], None))

    async def resolve(*_: object) -> Update:
        return package

    monkeypatch.setattr(update, "_package", resolve)
    prepared = update.PreparedUpdates(tmp_path / "prepared")

    async def run() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, content=b"payload")
            )
        ) as client:
            return await update.run_update(
                client, identity, tmp_path / "downloads", prepared=prepared
            )

    assert asyncio.run(run()) == 0
    assert not prepared.drivers and not prepared.monthly
    assert len(prepared.manual) == 1
    item = prepared.manual[0]
    assert item.category == "security-platform" and item.title == offer.title
    assert item.directory == tmp_path / "downloads" / offer.id
    output = capsys.readouterr().out
    assert "Downloaded only" in output and "requires installation" in output


def test_update_does_not_report_a_download_only_run_as_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    identity = TargetIdentity(
        "25H2", 26200, 9974, "x64", tmp_path / "Windows", "machine", ""
    )
    args = argparse.Namespace(
        only=[], dry_run=False, driver_cache=True, extractor="7z.exe"
    )
    menu = SimpleNamespace(root=tmp_path, check_windows=lambda: True)

    async def scan(*_: object, **options: object) -> int:
        prepared = options["prepared"]
        assert isinstance(prepared, update.PreparedUpdates)
        prepared.manual.append(
            update.ManualUpdate(
                "security-platform",
                "Windows Security platform",
                tmp_path / "download",
                "Run the installer in Windows.",
            )
        )
        return 0

    monkeypatch.setattr(cli, "run_update", scan)

    async def run() -> int:
        async with httpx.AsyncClient() as client:
            return await cli._stage_update(
                client,
                args,
                identity,
                cast(Menu, menu),
                True,
                tmp_path / "downloads",
                None,
            )

    assert asyncio.run(run()) == 1
    output = capsys.readouterr().out
    assert "1 update(s) still require installation" in output


def test_native_security_offer_is_queued_without_catalog_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = TargetIdentity("25H2", 26200, 9974, "x64", tmp_path, "machine", "")
    offer = update.Offer(
        "a32ca1d0-ddd4-486b-b708-d941db4f1165",
        "Windows Security platform KB5007651",
        "security-platform",
        revision=200,
    )
    monkeypatch.setattr(update, "scan_offers", lambda _: ([offer], None))

    async def forbidden(*_: object) -> Update:
        pytest.fail("The exact native offer must not depend on a Catalog lookup.")

    monkeypatch.setattr(update, "_package", forbidden)
    prepared = update.PreparedUpdates(tmp_path / "prepared")

    async def run() -> int:
        async with httpx.AsyncClient() as client:
            return await update.run_update(
                client, identity, tmp_path, prepared=prepared
            )

    assert asyncio.run(run()) == 0
    assert prepared.security == [offer]
    assert not prepared.manual


@pytest.mark.parametrize("no_hooks", [False, True])
def test_windows_restart_barrier_prevents_recovery_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_hooks: bool
) -> None:
    identity = TargetIdentity("25H2", 26200, 9974, "x64", tmp_path, "machine", "")
    offer = update.Offer(
        "a32ca1d0-ddd4-486b-b708-d941db4f1165",
        "KB5007651",
        "security-platform",
        revision=200,
    )
    args = argparse.Namespace(
        only=[], dry_run=False, driver_cache=True, extractor="7z.exe", no_hooks=no_hooks
    )

    class FakeMenu:
        root = tmp_path

        def install_windows(
            self,
            offers: list[update.Offer],
            profile: Path | None,
            *,
            hooks_explicit: bool = False,
        ) -> windows_updates.WindowsResult:
            assert offers == [offer] and profile is None and hooks_explicit is no_hooks
            return windows_updates.WindowsResult(False, True, (), tmp_path / "journal")

        def publish(self, _: Path) -> None:
            pytest.fail("Recovery must not run across an unfinished Windows phase.")

    async def scan(*_: object, **options: object) -> int:
        prepared = options["prepared"]
        assert isinstance(prepared, update.PreparedUpdates)
        prepared.security.append(offer)
        prepared.monthly.append(tmp_path / "package")
        return 0

    monkeypatch.setattr(cli, "run_update", scan)

    async def run() -> int:
        async with httpx.AsyncClient() as client:
            return await cli._stage_update(
                client, args, identity, cast(Menu, FakeMenu()), True, tmp_path, None
            )

    assert asyncio.run(run()) == 1


def test_previous_incomplete_windows_phase_blocks_driver_only_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = TargetIdentity("25H2", 26200, 9974, "x64", tmp_path, "machine", "")
    args = argparse.Namespace(
        only=["drivers"], dry_run=False, driver_cache=True, extractor="7z.exe"
    )
    menu = SimpleNamespace(
        root=tmp_path, windows_incomplete=True, check_windows=lambda: False
    )

    async def scan(*_: object, **options: object) -> int:
        prepared = options["prepared"]
        assert isinstance(prepared, update.PreparedUpdates)
        prepared.drivers.append(tmp_path / "driver")
        return 0

    monkeypatch.setattr(cli, "run_update", scan)

    async def run() -> int:
        async with httpx.AsyncClient() as client:
            return await cli._stage_update(
                client, args, identity, cast(Menu, menu), True, tmp_path, None
            )

    assert asyncio.run(run()) == 1


def test_packages_are_staged_before_drivers_without_category_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    identity = TargetIdentity("25H2", 26200, 9974, "x64", tmp_path, "machine", "")
    args = argparse.Namespace(
        only=[], dry_run=False, driver_cache=True, extractor="7z.exe"
    )
    published: list[Path] = []
    menu = SimpleNamespace(
        root=tmp_path,
        publish=published.append,
        offer_restart=lambda: None,
        check_windows=lambda: True,
    )

    async def scan(*_: object, **options: object) -> int:
        prepared = options["prepared"]
        assert isinstance(prepared, update.PreparedUpdates)
        prepared.monthly.extend([tmp_path / "first", tmp_path / "second"])
        prepared.drivers.append(tmp_path / "driver")
        return 0

    monkeypatch.setattr(cli, "run_update", scan)
    monkeypatch.setattr(cli.target, "read_target", lambda: identity)
    monkeypatch.setattr(cli, "Menu", lambda _: menu)

    async def run() -> int:
        async with httpx.AsyncClient() as client:
            return await cli._stage_update(
                client, args, identity, cast(Menu, menu), True, tmp_path, None
            )

    assert asyncio.run(run()) == 0
    assert published == [tmp_path / "first"]
    assert "run wuo update again" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("manual", "dry_run", "expected"),
    [(False, False, 1), (True, False, 0), (False, True, 0)],
)
def test_unconfigured_plain_update_requires_setup_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    manual: bool,
    dry_run: bool,
    expected: int,
) -> None:
    identity = TargetIdentity("25H2", 26200, 9974, "x64", tmp_path, "machine", "")
    args = argparse.Namespace(
        only=[], dry_run=dry_run, manual=manual, driver_cache=True, extractor="7z.exe"
    )
    calls = []

    async def scan(*_: object, **options: object) -> int:
        calls.append((options["prepared"], options["dry_run"]))
        return 0

    monkeypatch.setattr(cli, "run_update", scan)

    async def run() -> int:
        async with httpx.AsyncClient() as client:
            return await cli._stage_update(
                client,
                args,
                identity,
                cast(Menu, SimpleNamespace(root=tmp_path)),
                False,
                tmp_path,
                None,
            )

    assert asyncio.run(run()) == expected
    if not manual and not dry_run:
        assert len(calls) == 1 and isinstance(calls[0][0], update.PreparedUpdates)
        assert calls[0][1] is True and "wuo setup" in capsys.readouterr().out
    elif manual:
        assert calls == [(None, dry_run)]
    else:
        assert len(calls) == 1 and isinstance(calls[0][0], update.PreparedUpdates)
        assert calls[0][1] is True


def test_repeat_native_restart_returns_incomplete_exit_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = TargetIdentity("25H2", 26200, 9974, "x64", tmp_path, "machine", "")
    args = argparse.Namespace(
        manual=False,
        output=tmp_path,
        dry_run=False,
        hook=[],
        profile=None,
        no_hooks=False,
    )
    menu = SimpleNamespace(
        installed=True, windows_incomplete=True, resume=lambda **_: False
    )
    monkeypatch.setattr(cli.target, "read_target", lambda **_: identity)
    monkeypatch.setattr(cli, "Menu", lambda _: menu)

    async def run() -> int:
        async with httpx.AsyncClient() as client:
            return await cli._update(client, args)

    assert asyncio.run(run()) == 1
