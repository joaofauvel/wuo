"""Temporarily select protected feature recovery media on a Ventoy data volume."""

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import UUID

_DIGEST = re.compile(r"[a-f0-9]{64}")
_BOOT_PLUGINS = (
    "image_list",
    "image_blacklist",
    "password",
    "auto_install",
    "auto_memdisk",
    "injection",
    "conf_replace",
)
_MAX_CONFIG = 1024 * 1024


@dataclass(frozen=True, slots=True)
class _Receipt:
    original: bytes | None
    had_directory: bool
    iso_sha256: str
    config_sha256: str


def _kind(path: Path) -> Literal["file", "directory", "absent"]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "absent"
    if not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        if stat.S_ISREG(info.st_mode):
            return "file"
        if stat.S_ISDIR(info.st_mode):
            return "directory"
    raise ValueError(f"Unexpected filesystem entry in Ventoy recovery staging: {path}")


def _paths(volume: Path, job: UUID, state: Path) -> tuple[Path, Path, Path]:
    if _kind(volume) != "directory" or state.resolve().is_relative_to(volume.resolve()):
        raise ValueError(
            "Use the Ventoy data volume and a separate protected job path."
        )
    config = volume / "ventoy" / "ventoy.json"
    if _kind(config.parent) == "file":
        raise ValueError("The Ventoy configuration directory is unavailable.")
    return config, volume / f"WUO-Recovery-{job}.iso", volume / ".wuo-recovery.lock"


def _read(path: Path, limit: int = _MAX_CONFIG) -> bytes | None:
    kind = _kind(path)
    if kind == "absent":
        return None
    if kind != "file":
        raise ValueError(f"Expected a regular Ventoy recovery file: {path}")
    with path.open("rb") as stream:
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise ValueError(f"Ventoy recovery file is too large: {path}")
    return result


def _json_object(content: bytes) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("Duplicate Ventoy configuration keys.")
        return result

    try:
        value: object = json.loads(content.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, RecursionError) as error:
        raise ValueError(
            "Ventoy configuration or job state contains invalid JSON."
        ) from error
    if not isinstance(value, dict):
        raise ValueError("Expected a Ventoy configuration object.")
    return value


def _configuration(original: bytes | None, iso: Path) -> bytes:
    config = {} if original is None else _json_object(original)
    for plugin in _BOOT_PLUGINS:
        if config.get(f"{plugin}_uefi", config.get(plugin)):
            raise ValueError(
                f"Ventoy {plugin} settings conflict with automatic recovery."
            )

    settings: dict[str, str] = {}
    control = config.get("control_uefi", config.get("control", []))
    if not isinstance(control, list):
        raise ValueError("Ventoy control settings must be an array.")
    for setting in control:
        if not isinstance(setting, dict) or len(setting) != 1:
            raise ValueError("Expected individual Ventoy control settings.")
        name, value = next(iter(setting.items()))
        if not isinstance(name, str) or not isinstance(value, str) or name in settings:
            raise ValueError("Ventoy control settings must be unique text values.")
        settings[name] = value
    if (
        settings.get("VTOY_DEFAULT_SEARCH_ROOT", "/") != "/"
        or settings.get("VTOY_FILE_FLT_ISO", "0") != "0"
    ):
        raise ValueError(
            "Ventoy search or ISO filtering would hide the recovery image."
        )
    settings.update(
        {
            "VTOY_DEFAULT_IMAGE": f"/{iso.name}",
            "VTOY_MENU_TIMEOUT": "5",
            "VTOY_SECONDARY_BOOT_MENU": "0",
        }
    )
    config["control_uefi"] = [{name: value} for name, value in settings.items()]
    return _json_bytes(config)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _digest(path: Path) -> str:
    if _kind(path) != "file":
        raise ValueError(f"Expected a regular recovery ISO: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _atomic_file(
    path: Path,
    content: Path | bytes,
    *,
    replace: bool = False,
    sha256: str | None = None,
) -> None:
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=".wuo-", suffix=".tmp", delete=False
    ) as stream:
        temporary = Path(stream.name)
        try:
            if isinstance(content, bytes):
                stream.write(content)
            else:
                with content.open("rb") as source:
                    shutil.copyfileobj(source, stream, length=1024 * 1024)
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            if sha256 is not None and _digest(temporary) != sha256:
                raise ValueError("The Ventoy ISO copy failed SHA-256 verification.")
            if replace:
                temporary.replace(path)
            elif os.name == "nt":
                temporary.rename(path)
            else:
                os.link(temporary, path)
        finally:
            stream.close()
            temporary.unlink(missing_ok=True)


def _read_receipt(state: Path, job: UUID) -> _Receipt | None:
    content = _read(state, 2 * _MAX_CONFIG)
    if content is None:
        return None
    data = _json_object(content)
    original = data.get("original")
    directory = data.get("had_directory")
    iso_sha256 = data.get("iso_sha256")
    config_sha256 = data.get("config_sha256")
    if (
        data.get("schema") != 1
        or data.get("job") != str(job)
        or not isinstance(directory, bool)
        or not isinstance(iso_sha256, str)
        or not _DIGEST.fullmatch(iso_sha256)
        or not isinstance(config_sha256, str)
        or not _DIGEST.fullmatch(config_sha256)
        or (original is not None and (not directory or not isinstance(original, str)))
    ):
        raise ValueError("The Ventoy recovery state does not match this job.")
    original_bytes = (
        None if original is None else base64.b64decode(original, validate=True)
    )
    return _Receipt(original_bytes, directory, iso_sha256, config_sha256)


def deploy_recovery_iso(
    volume: Path, source: Path, sha256: str, job: UUID, state: Path
) -> Path:
    """Copy the ISO to an identified Ventoy volume and select it on x64 UEFI."""
    config, iso, owner = _paths(volume, job, state)
    sha256 = sha256.lower()
    if not _DIGEST.fullmatch(sha256) or _digest(source) != sha256:
        raise ValueError("The source recovery ISO failed SHA-256 verification.")
    marker = f"{job}\n".encode("ascii")
    receipt = _read_receipt(state, job)
    if receipt is not None:
        current = _read(config)
        if (
            receipt.iso_sha256 == sha256
            and _read(owner, 128) == marker
            and current is not None
            and hashlib.sha256(current).hexdigest() == receipt.config_sha256
            and _kind(iso) == "file"
            and _digest(iso) == sha256
        ):
            return iso
        restore_recovery_media(volume, job, state)
    if _kind(owner) != "absent":
        raise ValueError("Ventoy is already reserved for a recovery job.")
    if _kind(iso) != "absent":
        raise ValueError("The Ventoy recovery ISO path is already occupied.")
    original = _read(config)
    had_directory = _kind(config.parent) == "directory"
    staging = _configuration(original, iso)
    _atomic_file(
        state,
        _json_bytes(
            {
                "schema": 1,
                "job": str(job),
                "original": (
                    None
                    if original is None
                    else base64.b64encode(original).decode("ascii")
                ),
                "had_directory": had_directory,
                "iso_sha256": sha256,
                "config_sha256": hashlib.sha256(staging).hexdigest(),
            }
        ),
    )
    acquired = False
    try:
        _atomic_file(owner, marker)
        acquired = True
        if _read(config) != original:
            raise ValueError("The Ventoy configuration changed during deployment.")
        _atomic_file(iso, source, sha256=sha256)
        if _digest(iso) != sha256:
            raise ValueError("The published Ventoy ISO failed SHA-256 verification.")
        config.parent.mkdir(exist_ok=True)
        if _kind(config.parent) != "directory" or _read(config) != original:
            raise ValueError("The Ventoy configuration changed during deployment.")
        _atomic_file(config, staging, replace=original is not None)
        if _read(config) != staging:
            raise ValueError("The published Ventoy configuration failed readback.")
    except (OSError, ValueError, KeyboardInterrupt) as error:
        try:
            if acquired:
                restore_recovery_media(volume, job, state)
            else:
                state.unlink()
        except (OSError, ValueError) as cleanup:
            error.add_note(f"Ventoy recovery cleanup stopped: {cleanup}")
        raise
    return iso


def restore_recovery_media(volume: Path, job: UUID, state: Path) -> None:
    """Restore the prior Ventoy config and remove the ISO owned by this job."""
    receipt = _read_receipt(state, job)
    if receipt is None:
        return
    config, iso, owner = _paths(volume, job, state)
    current = _read(config)
    marker = _read(owner, 128)
    if marker is None and current == receipt.original and _kind(iso) == "absent":
        state.unlink()
        return
    if marker != f"{job}\n".encode("ascii"):
        raise ValueError("This Ventoy volume does not hold the matching recovery job.")
    if current != receipt.original:
        if (
            current is None
            or hashlib.sha256(current).hexdigest() != receipt.config_sha256
        ):
            raise ValueError(
                "The Ventoy configuration changed after recovery was staged."
            )
        if receipt.original is None:
            config.unlink()
        else:
            _atomic_file(config, receipt.original, replace=True)
        if _read(config) != receipt.original:
            raise ValueError("The restored Ventoy configuration failed readback.")
    if _kind(iso) != "absent":
        if _digest(iso) != receipt.iso_sha256:
            raise ValueError("The Ventoy recovery ISO changed after it was staged.")
        iso.unlink()
    if (
        not receipt.had_directory
        and _kind(config.parent) == "directory"
        and not any(config.parent.iterdir())
    ):
        config.parent.rmdir()
    owner.unlink()
    state.unlink()
