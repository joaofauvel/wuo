"""Install exact Windows security offers and retain restart/verification state."""

import json
import os
import re
import shutil
import subprocess
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from . import windows_hooks
from .downloads import atomic_json, package_hashes
from .target import TargetIdentity, read_target
from .update import Offer

_ORDER = {"KB4052623": 0, "KB5007651": 1, "KB2267602": 2}
_KB = re.compile(r"\bKB\d{6,8}\b", re.I)
JOURNAL = "windows-updates.json"


def _kb(offer: Offer) -> str:
    matches: set[str] = {value.upper() for value in _KB.findall(offer.title)}
    if len(matches) != 1 or not matches <= _ORDER.keys():
        raise ValueError(
            "The offer has no supported Windows security installation route."
        )
    return matches.pop()


def eligible(offer: Offer) -> bool:
    try:
        kb = _kb(offer)
        UUID(offer.id)
    except ValueError, AttributeError:
        return False
    return (
        type(offer.revision) is int
        and offer.revision > 0
        and offer.category == ("security-platform" if kb == "KB5007651" else "defender")
    )


def ordered(offers: list[Offer]) -> list[Offer]:
    if not all(eligible(item) for item in offers):
        raise ValueError(
            "A Windows security offer has an invalid identity or category."
        )
    identities = [(item.id, item.revision) for item in offers]
    if len(identities) != len(set(identities)):
        raise ValueError("Duplicate Windows security offer.")
    return sorted(offers, key=lambda item: (_ORDER[_kb(item)], item.id))


@dataclass(frozen=True)
class WindowsResult:
    complete: bool
    reboot_required: bool
    updates: tuple[dict[str, Any], ...]
    journal: Path


def read_result(
    path: Path, target: TargetIdentity, request: dict[str, Any]
) -> WindowsResult:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if (
            data["schema_version"] != 1
            or data["request_id"] != request["request_id"]
            or data["target"]["machine_guid"].casefold()
            != target.machine_guid.casefold()
            or type(data["reboot_required"]) is not bool
            or not isinstance(data["boot_id"], str)
            or not isinstance(data["updates"], list)
            or data.get("hooks_job_id") != request.get("hooks_job_id")
            or data["target"] != request["target"]
        ):
            raise ValueError("The Windows update journal does not match this request.")
        expected = {(item["id"], item["revision"]) for item in request["updates"]}
        actual = {(item["id"], item["revision"]) for item in data["updates"]}
        if actual != expected or len(data["updates"]) != len(expected):
            raise ValueError(
                "The Windows update journal does not cover every requested update."
            )
        for item in data["updates"]:
            if (
                item["state"]
                not in {
                    "pending",
                    "downloading",
                    "installing",
                    "installed",
                    "failed",
                    "unavailable",
                    "reboot-required",
                }
                or type(item["verified"]) is not bool
                or type(item["reboot_required"]) is not bool
                or (item["verified"] and item["state"] != "installed")
                or (item["verified"] and item.get("installed_proof") is not True)
                or (item["reboot_required"] and not data["reboot_required"])
            ):
                raise ValueError("Invalid Windows update result.")
    except (KeyError, TypeError, AttributeError, UnicodeError) as error:
        raise ValueError(f"Invalid Windows update journal at {path}.") from error
    complete = not data["reboot_required"] and all(
        item["verified"] for item in data["updates"]
    )
    return WindowsResult(
        complete, data["reboot_required"], tuple(data["updates"]), path
    )


def current_reboot_required(target: TargetIdentity) -> bool:
    """Read current WUA state without reopening a completed update identity."""
    try:
        process = subprocess.run(
            [
                target.windows / "System32/WindowsPowerShell/v1.0/powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference='Stop'; (New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired | ConvertTo-Json -Compress",
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(
            "Could not read the current Windows restart requirement."
        ) from error
    try:
        value = json.loads(process.stdout)
    except (ValueError, TypeError) as error:
        raise ValueError(
            "Could not read the current Windows restart requirement."
        ) from error
    if process.returncode or type(value) is not bool:
        raise ValueError(
            "Could not read the current Windows restart requirement: "
            + process.stderr.strip()
        )
    return value


def _record_completion(journal: Path, data: dict[str, Any]) -> None:
    staged = journal.with_name(f".{journal.name}.{uuid4()}.terminal")
    try:
        atomic_json(staged, {**data, "phase_complete": True})
        receipts = journal.parent / "windows-completions"
        receipts.mkdir(exist_ok=True)
        atomic_json(
            receipts / f"{UUID(data['request_id'])}.json",
            {
                "schema_version": 1,
                "request_id": data["request_id"],
                "hooks_job_id": data.get("hooks_job_id"),
                "journal_sha256": package_hashes(staged)[0],
            },
        )
        staged.replace(journal)
    finally:
        staged.unlink(missing_ok=True)


def _verify_completion(journal: Path, data: dict[str, Any]) -> None:
    receipt = (
        journal.parent / "windows-completions" / f"{UUID(data['request_id'])}.json"
    )
    try:
        record = json.loads(receipt.read_text(encoding="utf-8"))
        if (
            record.get("schema_version") != 1
            or record.get("request_id") != data["request_id"]
            or record.get("hooks_job_id") != data.get("hooks_job_id")
            or record.get("journal_sha256") != package_hashes(journal)[0]
        ):
            raise ValueError(
                "The terminal Windows completion receipt does not match its journal."
            )
    except (OSError, TypeError, AttributeError) as error:
        raise ValueError(
            "The terminal Windows completion receipt is missing or invalid."
        ) from error


def _invoke(
    request: dict[str, Any],
    target: TargetIdentity,
    root: Path,
    *,
    profile: Path | None = None,
) -> WindowsResult:
    request = {**request, "schema_version": 1, "request_id": str(uuid4())}
    if request["mode"] == "install":
        request["hooks_job_id"] = request["request_id"]
        current = read_target(read_loader=False)
        if _target(current) != _target(target) or current.windows != target.windows:
            raise ValueError(
                "The running Windows identity changed before installation. Run a fresh update scan."
            )
    request_path = root / "windows-request.json"
    journal = root / JOURNAL
    if journal.exists():
        history = root / "windows-history"
        history.mkdir(exist_ok=True)
        shutil.copyfile(journal, history / f"{uuid4()}.json")
    atomic_json(request_path, request)
    powershell = target.windows / "System32/WindowsPowerShell/v1.0/powershell.exe"
    with ExitStack() as context:
        script = context.enter_context(
            as_file(files("wuo").joinpath("windows_updates.ps1"))
        )
        if request["mode"] == "install":
            context.enter_context(
                windows_hooks.capture(
                    profile,
                    root,
                    target.machine_guid,
                    target.windows,
                    job_id=request["hooks_job_id"],
                )
            )
        with subprocess.Popen(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script,
                "-Request",
                request_path,
                "-Journal",
                journal,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        ) as process:
            while True:
                try:
                    _, stderr = process.communicate(timeout=30)
                    break
                except subprocess.TimeoutExpired:
                    print(
                        "Windows Update is still running; waiting for its result before applying post hooks.",
                        flush=True,
                    )
                except KeyboardInterrupt:
                    print(
                        "Waiting for Windows Update to finish safely before exiting.",
                        flush=True,
                    )
            returncode = process.returncode
    try:
        result = read_result(journal, target, request)
    except (OSError, ValueError) as error:
        detail = stderr.strip() or str(error)
        raise ValueError(
            f"Could not verify Windows update results: {detail}"
        ) from error
    windows_hooks.verify(root, target.machine_guid, job_id=request.get("hooks_job_id"))
    if returncode and result.complete:
        raise ValueError(
            f"The Windows installer exited with {returncode}: {stderr.strip()}"
        )
    if returncode and stderr.strip():
        print(f"Windows installer exited with {returncode}: {stderr.strip()}")
    if result.complete:
        data = json.loads(journal.read_text(encoding="utf-8-sig"))
        _record_completion(journal, data)
    describe(result)
    return result


def install(
    offers: list[Offer],
    target: TargetIdentity,
    root: Path,
    *,
    profile: Path | None = None,
    hooks_explicit: bool = False,
) -> WindowsResult:
    selected = ordered(offers)
    if not selected:
        raise ValueError("No Windows security updates were selected.")
    previous = verify(target, root)
    deferred = False
    if previous is not None and not previous.complete:
        if previous.reboot_required:
            raise ValueError(
                "Restart Windows to finish the previous Windows phase before installing more updates."
            )
        if hooks_explicit:
            raise ValueError(
                "The unfinished Windows phase has captured hooks. Finish it with a plain wuo update before selecting --hook, --profile, or --no-hooks for a new phase."
            )
        unresolved = {
            (str(UUID(item["id"])), item["revision"])
            for item in previous.updates
            if not item["verified"]
        }
        requested = {(str(UUID(item.id)), item.revision) for item in selected}
        if not unresolved <= requested:
            raise ValueError(
                "The previous Windows phase has unresolved exact update revisions outside this scan. Run wuo status and retry all unresolved updates without --only; unavailable revisions require explicit installation evidence before continuing. The previous journal was retained."
            )
        captured = json.loads(previous.journal.read_text(encoding="utf-8-sig")).get(
            "hooks_job_id"
        )
        if not isinstance(captured, str):
            raise ValueError(
                "The unfinished Windows phase has no captured hook identity. Review its journal before retrying."
            )
        profile = windows_hooks.captured_profile(root, target.machine_guid, captured)
        selected = ordered(
            [
                Offer(
                    str(UUID(row["id"])),
                    row["title"],
                    row["category"],
                    revision=row["revision"],
                )
                for row in previous.updates
                if not row["verified"]
            ]
        )
        deferred = bool(requested - unresolved)
        from .hook_selection import describe_selection, read_selection

        print(
            "Retrying the previous exact Windows updates with their original captured hooks."
        )
        describe_selection(read_selection(profile), check_freshness=False)
    records = [
        {
            "id": str(UUID(offer.id)),
            "revision": offer.revision,
            "kb": _kb(offer),
            "title": offer.title,
            "category": offer.category,
        }
        for offer in selected
    ]
    print("Windows installation order")
    for item in records:
        print(f"  {item['kb']}: {item['title']}")
    result = _invoke(
        {"mode": "install", "target": _target(target), "updates": records},
        target,
        root,
        profile=profile,
    )
    if deferred and result.complete:
        print(
            "The previous Windows phase is complete. New security offers were deferred; run wuo update again before recovery servicing."
        )
        return WindowsResult(
            False, result.reboot_required, result.updates, result.journal
        )
    return result


def require_completed_phase(target: TargetIdentity, root: Path) -> None:
    """Inspect a saved Windows phase without updating its request or journal."""
    request_path = root / "windows-request.json"
    journal = root / JOURNAL
    if not request_path.exists() and not journal.exists():
        return
    message = "Resolve the previous Windows update phase with wuo status first."
    try:
        request = json.loads(request_path.read_text(encoding="utf-8-sig"))
        saved = json.loads(journal.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as error:
        raise ValueError(message) from error
    if (
        not isinstance(saved, dict)
        or saved.get("phase_complete") is not True
        or not read_result(journal, target, request).complete
    ):
        raise ValueError(message)
    _verify_completion(journal, saved)


def verify(target: TargetIdentity, root: Path) -> WindowsResult | None:
    journal = root / JOURNAL
    if not journal.is_file():
        windows_hooks.verify(root, target.machine_guid)
        if current_reboot_required(target):
            return WindowsResult(False, True, (), journal)
        return None
    data = json.loads(journal.read_text(encoding="utf-8-sig"))
    if (
        data.get("target", {}).get("machine_guid", "").casefold()
        != target.machine_guid.casefold()
    ):
        raise ValueError("The Windows update journal belongs to another installation.")
    recorded_target = data["target"]
    if (
        recorded_target.get("architecture") != target.architecture
        or type(recorded_target.get("build")) is not int
        or type(recorded_target.get("revision")) is not int
        or (target.build, target.revision)
        < (recorded_target["build"], recorded_target["revision"])
    ):
        raise ValueError(
            "The Windows journal belongs to a different architecture or newer baseline."
        )
    stored = read_result(journal, target, data)
    terminal = data.get("phase_complete") is True
    if terminal and not stored.complete:
        raise ValueError("The completed Windows journal contains incomplete results.")
    if terminal:
        _verify_completion(journal, data)
    windows_hooks.verify(root, target.machine_guid, check_values=not terminal)
    windows_hooks.verify(
        root,
        target.machine_guid,
        job_id=data.get("hooks_job_id"),
        check_values=not terminal,
    )
    if terminal:
        if current_reboot_required(target):
            return WindowsResult(False, True, stored.updates, journal)
        return stored
    return _invoke(
        {
            "mode": "verify",
            "target": data["target"],
            "updates": data["updates"],
            "previous_boot_id": data["boot_id"],
            "previous_reboot_required": data["reboot_required"],
            "hooks_job_id": data.get("hooks_job_id"),
        },
        target,
        root,
    )


def _target(target: TargetIdentity) -> dict[str, str | int]:
    return {
        key: value
        for key, value in asdict(target).items()
        if key in {"machine_guid", "build", "revision", "architecture"}
    }


def describe(result: WindowsResult) -> None:
    for record in result.updates:
        label = "verified" if record["verified"] else record["state"]
        print(f"  Windows update {label}: {record['title']}")
        if record.get("error"):
            print(f"    {record['error']}")
    if result.reboot_required:
        print("Restart Windows to finish this phase, then run wuo update again.")
    elif not result.complete:
        print(f"Windows updates remain incomplete. Results: {result.journal}")
