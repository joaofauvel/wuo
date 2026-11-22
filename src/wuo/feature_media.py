"""Build independent recovery media for a protected Windows feature upgrade."""

import hashlib
import os
import re
import shutil
import tempfile
from collections.abc import Mapping
from importlib.resources import as_file, files
from pathlib import Path

from .downloads import safe_name
from .winpe import _run

_RESERVED = {"boot.cmd", "certutil.exe", "fc.exe", "findstr.exe"}


def build_recovery_iso(
    source_iso: Path,
    source_sha256: str,
    output: Path,
    assets: Mapping[str, bytes],
    *,
    index: int = 1,
) -> str:
    """Embed job files alongside WinRE tools and return the new ISO digest.

    Supply a Microsoft installation ISO and its published digest. The selected
    install image must provide x64 English-US Windows RE. Build on a local NTFS
    volume from an elevated process. The media runs start.cmd in a console after
    Windows PE initializes. The script and its assets share one WIM directory.
    """
    if os.name != "nt":
        raise ValueError("Building feature recovery media requires Windows.")
    source_iso = source_iso.resolve(strict=True)
    if (
        not re.fullmatch(r"[A-Za-z]:", source_iso.drive)
        or source_iso.suffix.casefold() != ".iso"
        or not source_iso.is_file()
        or not re.fullmatch(r"[0-9a-fA-F]{64}", source_sha256)
    ):
        raise ValueError("Supply a local Windows ISO and its Microsoft SHA-256 digest.")
    if not 1 <= index <= 2_147_483_647:
        raise ValueError("Supply a positive Windows installation image index.")
    output = output.resolve()
    if (
        not re.fullmatch(r"[A-Za-z]:", output.drive)
        or output.suffix.casefold() != ".iso"
        or output.exists()
    ):
        raise ValueError("Choose a new .iso file on a local NTFS volume.")
    names = set(_RESERVED)
    for name in assets:
        canonical = name.casefold()
        if (not safe_name(name) and name != "manifest.json") or canonical in names:
            raise ValueError(f"Invalid or duplicate recovery asset name: {name!r}.")
        names.add(canonical)
    if not assets.get("start.cmd"):
        raise ValueError("Supply a start.cmd recovery asset.")

    output.parent.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="wuo-feature-media-", dir=output.parent))
    staged = workspace / "recovery.iso"
    try:
        payload = workspace / "assets"
        payload.mkdir()
        for name, content in assets.items():
            (payload / name).write_bytes(content)
        system = Path(os.environ["SYSTEMROOT"])
        native = system / "Sysnative"
        if not native.is_dir():
            native = system / "System32"
        powershell = native / "WindowsPowerShell/v1.0/powershell.exe"
        env = {
            **{
                name: value
                for name, value in os.environ.items()
                if name.upper() != "PSMODULEPATH"
            },
            "WUO_RECOVERY_MEDIA_SOURCE": str(source_iso),
            "WUO_RECOVERY_MEDIA_SHA256": source_sha256.lower(),
            "WUO_RECOVERY_MEDIA_INDEX": str(index),
        }
        with as_file(files("wuo").joinpath("feature_media.ps1")) as builder:
            _run(
                [
                    powershell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    builder,
                ],
                env=env,
                cwd=workspace,
            )
        if not staged.is_file() or staged.stat().st_size == 0:
            raise ValueError("The recovery media build did not produce an ISO.")
        with staged.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        staged.rename(output)
    except (OSError, ValueError, KeyboardInterrupt) as error:
        raise ValueError(
            f"Recovery media build stopped. Working files are at {workspace}. {error}"
        ) from error

    shutil.rmtree(workspace, ignore_errors=True)
    return digest
