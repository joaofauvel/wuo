import hashlib
import os
import struct
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(os.name != "nt", reason="Uses Windows path semantics")
def test_build_publishes_only_the_generated_iso(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wuo import feature_media

    source = tmp_path / "Microsoft ISO.iso"
    source.write_bytes(b"trusted source")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "Feature Recovery.iso"
    expected_image = b"built recovery media"
    assets = {"start.cmd": b"@echo off\r\n", "job.json": b"{}"}

    def run(command: list[str | Path], *, env: dict[str, str], cwd: Path) -> str:
        assert "-File" in command
        assert env["WUO_RECOVERY_MEDIA_SHA256"] == source_hash
        assert env["WUO_RECOVERY_MEDIA_SOURCE"] == str(source)
        assert env["WUO_RECOVERY_MEDIA_INDEX"] == "6"
        assert {
            path.name: path.read_bytes() for path in (cwd / "assets").iterdir()
        } == assets
        assert not output.exists()
        (cwd / "recovery.iso").write_bytes(expected_image)
        return ""

    monkeypatch.setattr(feature_media, "_run", run)
    assert (
        feature_media.build_recovery_iso(source, source_hash, output, assets, index=6)
        == hashlib.sha256(expected_image).hexdigest()
    )
    assert output.read_bytes() == expected_image
    assert source.read_bytes() == b"trusted source"
    assert not list(tmp_path.glob("wuo-feature-media-*"))


@pytest.mark.skipif(os.name != "nt", reason="Uses Windows no-overwrite rename")
def test_does_not_replace_an_iso_published_by_another_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wuo import feature_media

    source = tmp_path / "Windows.iso"
    source.write_bytes(b"source")
    output = tmp_path / "recovery.iso"

    def run(command: list[str | Path], *, env: dict[str, str], cwd: Path) -> str:
        (cwd / "recovery.iso").write_bytes(b"new image")
        output.write_bytes(b"existing image")
        return ""

    monkeypatch.setattr(feature_media, "_run", run)
    with pytest.raises(ValueError, match="Recovery media build stopped"):
        feature_media.build_recovery_iso(
            source, "a" * 64, output, {"start.cmd": b"rem starter"}
        )
    assert output.read_bytes() == b"existing image"


@pytest.mark.skipif(os.name != "nt", reason="Uses Windows path semantics")
@pytest.mark.parametrize(
    "unexpected", ["../replace.cmd", "START.CMD", "boot.cmd", "certutil.exe", "NUL.cmd"]
)
def test_rejects_unsafe_or_reserved_baked_paths(
    tmp_path: Path, unexpected: str
) -> None:
    from wuo.feature_media import build_recovery_iso

    source = tmp_path / "verified.iso"
    source.write_bytes(b"source")
    with pytest.raises(ValueError, match="recovery asset"):
        build_recovery_iso(
            source,
            hashlib.sha256(source.read_bytes()).hexdigest(),
            tmp_path / "new.iso",
            {"start.cmd": b"rem starter", unexpected: b"rem unexpected"},
        )
    assert len(list(tmp_path.iterdir())) == 1


def _powershell(tmp_path: Path, command: str) -> None:
    media_script = Path(__file__).resolve().parents[1] / "src/wuo/feature_media.ps1"
    result = subprocess.run(
        [
            Path(os.environ["SYSTEMROOT"])
            / "System32/WindowsPowerShell/v1.0/powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$ErrorActionPreference='Stop'; . $env:WUO_TEST_SCRIPT; " + command,
        ],
        env={**os.environ, "WUO_TEST_SCRIPT": str(media_script)},
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows PowerShell")
@pytest.mark.parametrize("stock", [True, False])
def test_shell_only_changes_a_supported_windows_re_image(
    tmp_path: Path, stock: bool
) -> None:
    system = tmp_path / "image/Windows/System32"
    system.mkdir(parents=True)
    launcher = system / "winpeshl.ini"
    original = (
        b"[LaunchApp]\r\nAppPath=X:\\sources\\recovery\\recenv.exe\r\n"
        if stock
        else b"[LaunchApp]\r\nAppPath=X:\\unexpected.exe\r\n"
    )
    launcher.write_bytes(original)
    for name in (
        "cmd.exe",
        "wpeinit.exe",
        "wpeutil.exe",
        "reg.exe",
        "mountvol.exe",
        "bcdedit.exe",
        "wbadmin.exe",
        "robocopy.exe",
    ):
        (system / name).touch()
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "start.cmd").write_bytes(b"rem baked entry\r\n")
    install = (
        "Install-WuoFeatureMediaLauncher (Join-Path $pwd 'image') "
        "(Join-Path $pwd 'assets')"
    )
    if stock:
        _powershell(tmp_path, install)
        assert launcher.read_bytes() == (
            b"[LaunchApps]\r\n"
            b"%SYSTEMROOT%\\System32\\cmd.exe, /d /k X:\\Windows\\System32\\WUO\\boot.cmd\r\n"
        )
        assert (system / "WUO/start.cmd").read_bytes() == b"rem baked entry\r\n"
    else:
        _powershell(
            tmp_path,
            f"try {{ {install}; throw 'unsafe success' }} "
            "catch { if ($_ -notmatch 'unsupported startup shell') { throw } }; exit 0",
        )
        assert launcher.read_bytes() == original
        assert not (system / "WUO").exists()


@pytest.mark.skipif(os.name != "nt", reason="Requires Windows PowerShell and IMAPI")
def test_native_iso_writer_embeds_no_emulation_efi_image(tmp_path: Path) -> None:
    content = tmp_path / "source files"
    content.mkdir()
    sources = content / "sources"
    sources.mkdir()
    (sources / "boot.wim").write_bytes(b"fixture")
    boot_image = b"EFI boot image fixture".ljust(1440 * 1024, b"\0")
    (content / "efi.bin").write_bytes(boot_image)
    _powershell(
        tmp_path,
        "New-WuoFeatureIso (Join-Path $pwd 'source files') "
        "(Join-Path $pwd 'source files/efi.bin') (Join-Path $pwd 'fixture.iso')",
    )

    sector_size = 2048
    image = (tmp_path / "fixture.iso").read_bytes()
    descriptor = next(
        image[offset : offset + sector_size]
        for offset in range(16 * sector_size, 32 * sector_size, sector_size)
        if image[offset : offset + 7] == b"\x00CD001\x01"
    )
    assert descriptor[7:39].rstrip(b"\0 ") == b"EL TORITO SPECIFICATION"
    catalog_sector = struct.unpack_from("<I", descriptor, 71)[0]
    catalog = image[catalog_sector * sector_size : (catalog_sector + 1) * sector_size]
    assert catalog[:2] == b"\x01\xef"
    assert catalog[30:34] == b"\x55\xaa\x88\x00"
    boot_sector = struct.unpack_from("<I", catalog, 40)[0]
    assert (
        image[boot_sector * sector_size : boot_sector * sector_size + len(boot_image)]
        == boot_image
    )
