"""Stage and inspect a job for the locally installed WinRE menu."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from importlib.resources import as_file, files
from pathlib import Path
from stat import FILE_ATTRIBUTE_REPARSE_POINT
from uuid import UUID, uuid4
from xml.sax.saxutils import escape

from . import bundle
from .downloads import package_hashes
from .hooks import require_full_upgrade_hook_support
from .target import TargetIdentity
lazy from . import windows_updates
lazy from .feature_upgrade import FeatureImage, FeatureMedia
lazy from .hook_registry import HookRegistry
lazy from .hook_selection import describe_selection, read_selection, resolve_selection
lazy from .update import Offer

MENU_PATH = bundle.JOBS_PATH.parent / "menu"
_FEATURE_MENU = "feature-menu.version"
_FEATURE_MENU_VERSION = b"2\r\n"
_FEATURE_FAILURE_RECORDS = (
    "boot-completion.phase",
    "boot-order-result.json",
    "finalize.result",
)


def _id(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("Invalid WinRE job or installation ID.")
    return value


def _read_id(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except PermissionError:
        raise ValueError(
            "Open an administrator terminal to use the WinRE menu."
        ) from None
    return _id(value.removesuffix("\n"))


def _check_callback(path: Path, digest: str) -> None:
    for entry in (path.parent, path):
        attributes = getattr(entry.lstat(), "st_file_attributes", 0)
        if entry.is_symlink() or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError(f"Unexpected filesystem link in Setup callbacks: {entry}")
    if not path.is_file() or package_hashes(path)[0] != digest:
        raise ValueError(f"The feature Setup callback changed: {path}")


def _run(command: list[str | Path]) -> str:
    result = subprocess.run(
        command, capture_output=True, text=True, errors="replace", check=False
    )
    if result.returncode:
        raise ValueError(
            result.stderr.strip()
            or result.stdout.strip()
            or f"{Path(command[0]).name} exited with {result.returncode}."
        )
    return result.stdout


class Menu:
    def __init__(self, target: TargetIdentity) -> None:
        self.target = target
        self.root = target.windows.parent / MENU_PATH
        self.windows_incomplete = False

    @property
    def installed(self) -> bool:
        marker = _read_id(self.root / "installed.id")
        if marker is None:
            return False
        if marker != self.target.machine_guid:
            raise ValueError("The WinRE menu belongs to another Windows installation.")
        return True

    @property
    def profile(self) -> Path | None:
        selected = self.root / "selection.json"
        if selected.is_file():
            record = json.loads(selected.read_text(encoding="ascii"))
            if not isinstance(record, dict) or record.keys() != {"profile"}:
                raise ValueError("Invalid saved hook selection.")
            profile = record["profile"]
            if profile is None:
                return None
            if not isinstance(profile, str):
                raise ValueError("Invalid saved hook profile.")
            version = _id(profile)
            path = self.root / "selections" / version / "profile.toml"
            if path.resolve() != path or not path.is_file():
                raise ValueError("The saved hook profile is missing or unsafe.")
            return path
        path = self.root / "profile.toml"
        return path if path.is_file() else None

    @contextmanager
    def _lock(self) -> Iterator[None]:
        if not self.installed:
            raise ValueError("Run wuo setup first.")
        with (self.root / "update.lock").open("a+b") as lock:
            if os.name == "nt":
                import msvcrt

                lock.seek(0)
                try:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise ValueError(
                        "Another wuo process is changing the pending job."
                    ) from None
            yield

    def job_state(self, job_id: str) -> Path:
        return self.target.windows.parent / bundle.JOBS_PATH / job_id

    def _pending_id(self) -> str | None:
        return _read_id(self.root / "pending.id")

    def _windows_complete_locked(self) -> bool:
        result = windows_updates.verify(self.target, self.root)
        self.windows_incomplete = result is not None and not result.complete
        return not self.windows_incomplete

    def _require_windows_complete_locked(self) -> None:
        if not self._windows_complete_locked():
            raise ValueError(
                "The Windows phase is incomplete. Run wuo status and resolve it before publishing or restarting recovery."
            )

    def check_windows(self) -> bool:
        with self._lock():
            return self._windows_complete_locked()

    @contextmanager
    def feature_preview(self) -> Iterator[None]:
        if not self.installed:
            yield
            return
        with self._lock():
            if self._pending_id() is not None:
                raise ValueError(
                    "Resolve the pending recovery job with wuo status first."
                )
            windows_updates.require_completed_phase(self.target, self.root)
            yield

    def stage_feature(
        self,
        media: FeatureMedia,
        image: FeatureImage,
        profile: Path | None,
        *,
        backup_drive: str | None,
    ) -> Path:
        """Prepare a single feature job and publish it to the installed WinRE menu."""
        from dataclasses import replace

        from .feature_upgrade import (
            backup_feature,
            feature_boot,
            feature_setup_assets,
            prepare_media,
        )
        from .recovery import render_feature_restore, render_feature_source_hooks
        from .target import read_target

        if media.rollback and backup_drive is None:
            raise ValueError("Select a separate rollback drive before preparing Setup.")
        with self._lock():
            self._require_windows_complete_locked()
            if self._pending_id() is not None:
                raise ValueError("An update is already staged. Run wuo status.")
            capability = self.root / _FEATURE_MENU
            if (
                not capability.is_file()
                or capability.read_bytes() != _FEATURE_MENU_VERSION
            ):
                raise ValueError(
                    "Refresh the recovery menu with wuo remove and wuo setup before preparing a feature upgrade."
                )
            selected = read_selection(profile)
            require_full_upgrade_hook_support(selected.hooks)
            if read_target() != self.target:
                raise ValueError(
                    "The running Windows identity changed before preparation."
                )
            media = replace(media, iso=media.iso.resolve(strict=True))
            job_id = uuid4()
            job = self.job_state(str(job_id))
            callback_dir = self.target.windows / "System32/update/runonce" / str(job_id)
            request, callback = feature_setup_assets(
                job_id, self.target, media, image, selected.hooks
            )
            job.mkdir()
            _run(
                [
                    self.target.windows / "System32/icacls.exe",
                    job,
                    "/setowner",
                    "*S-1-5-32-544",
                ]
            )
            if profile is not None:
                snapshot = job / "profile.toml"
                metadata = profile.with_name("hooks.json")
                if metadata.is_file():
                    shutil.copyfile(profile, snapshot)
                    shutil.copyfile(metadata, snapshot.with_name("hooks.json"))
                else:
                    resolve_selection((), profile, job)
                captured = read_selection(snapshot)
                if (captured.hooks, captured.origins) != (
                    selected.hooks,
                    selected.origins,
                ):
                    raise ValueError("The hook selection changed during preparation.")
            continuation = job / "feature_upgrade.ps1"
            continuation.write_bytes(
                files("wuo").joinpath("feature_upgrade.ps1").read_bytes()
            )
            boot_assets: tuple[Path, ...] = ()
            if media.preserve_boot_order:
                feature_boot(self.target, "Capture", job)
                helper = job / "feature_boot.ps1"
                helper.write_bytes(files("wuo").joinpath(helper.name).read_bytes())
                boot_assets = (helper, job / "boot-order.json")
                if (job / "boot-fallback.efi").is_file():
                    boot_assets = (*boot_assets, job / "boot-fallback.efi")
                manifest = json.loads(request)
                manifest["boot_preservation"] = {
                    asset.name: package_hashes(asset)[0] for asset in boot_assets
                }
                request = json.dumps(manifest, sort_keys=True).encode("ascii")
            (job / "feature.json").write_bytes(request)
            if media.preserve_boot_order:
                # A volume rollback must restore the task as well as the snapshot.
                self._register_feature_task(str(job_id), continuation)
            marker = f"{job_id}\r\n".encode("ascii")
            if any(hook.phase == "pre" for hook in selected.hooks):
                pre_hooks = job / "source-hooks.cmd"
                pre_hooks.write_bytes(
                    render_feature_source_hooks(
                        selected.hooks, rollback=media.rollback
                    ).encode("ascii")
                )
                (job / "source-hooks.sha256").write_bytes(
                    f"{package_hashes(pre_hooks)[0]}\r\n".encode("ascii")
                )
            if media.rollback and backup_drive is not None:
                receipt, snapshot = backup_feature(self.target, job_id, backup_drive)
                runner = job / "restore.cmd"
                runner.write_bytes(
                    render_feature_restore(
                        str(job_id),
                        self.target,
                        image,
                        receipt,
                        preserve_boot_order=media.preserve_boot_order,
                    ).encode("ascii")
                )
                (job / "rollback.json").write_bytes(receipt)
                (job / "restore.sha256").write_bytes(
                    f"{package_hashes(runner)[0]}\r\n".encode("ascii")
                )
                self._export_feature_restore(snapshot, job, boot_assets=boot_assets)
                (job / "rollback.required").write_bytes(marker)
            callback_dir.mkdir(parents=True)
            (callback_dir / "precommit.cmd").write_bytes(callback)
            if boot_assets:
                for outcome in ("success", "failure"):
                    (callback_dir / f"{outcome}.cmd").write_bytes(
                        (
                            '@echo off\r\nsetlocal\r\nset "PSModulePath="\r\n'
                            '"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
                            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "
                            f'"%SystemDrive%\\ProgramData\\WinOfflineUpdate\\jobs\\{job_id}\\feature_upgrade.ps1" '
                            f"-CompleteJob {job_id} -Outcome {outcome}\r\nexit /b 0\r\n"
                        ).encode("ascii")
                    )
            prepare_media(self.target, media, image)
            if not media.preserve_boot_order:
                self._register_feature_task(str(job_id), continuation)
            (job / "target.id").write_bytes(marker)
            (job / "feature.ready").write_bytes(marker)
            pending = job / "pending.id"
            pending.write_bytes(marker)
            os.replace(pending, self.root / "pending.id")
            return job

    def _export_feature_restore(
        self, snapshot: Path, job: Path, *, boot_assets: tuple[Path, ...] = ()
    ) -> None:
        for path in (snapshot.parent, snapshot, snapshot / "rollback.json"):
            if (
                getattr(path.lstat(), "st_file_attributes", 0)
                & FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise ValueError(
                    f"The feature rollback path is a reparse point. {path}"
                )
        if json.loads((snapshot / "rollback.json").read_bytes()) != json.loads(
            (job / "rollback.json").read_bytes()
        ):
            raise ValueError(
                "The backup drive's rollback receipt changed during preparation."
            )
        system32 = self.target.windows / "System32"
        sources = (
            job / "restore.cmd",
            job / "restore.sha256",
            system32 / "certutil.exe",
            system32 / "findstr.exe",
            *(asset for asset in boot_assets if asset.name != "feature_boot.ps1"),
        )
        with tempfile.TemporaryDirectory(dir=snapshot) as work:
            draft = Path(work) / "recovery"
            draft.mkdir()
            for source in sources:
                shutil.copyfile(source, draft / source.name)
            draft.rename(snapshot / "recovery")

    def _register_feature_task(self, job: str, continuation: Path) -> None:
        system32 = self.target.windows / "System32"
        powershell = system32 / "WindowsPowerShell/v1.0/powershell.exe"
        arguments = subprocess.list2cmdline(
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(continuation),
                "-FinalizeJob",
                job,
            ]
        )
        # /TR can truncate the combined command line, including the job ID.
        definition = f"""\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger /></Triggers>
  <Principals><Principal id="System"><UserId>S-1-5-18</UserId></Principal></Principals>
  <Actions Context="System">
    <Exec>
      <Command>{escape(str(powershell))}</Command>
      <Arguments>{escape(arguments)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""
        with tempfile.TemporaryDirectory(
            prefix="task-", dir=continuation.parent
        ) as directory:
            task_file = Path(directory) / "task.xml"
            task_file.write_text(definition, encoding="utf-16")
            _run(
                [
                    system32 / "schtasks.exe",
                    "/Create",
                    "/TN",
                    f"wuo-feature-{job}",
                    "/XML",
                    task_file,
                ]
            )

    def publish(self, source: Path) -> Path:
        with self._lock():
            self._require_windows_complete_locked()
            if self._pending_id() is not None:
                raise ValueError("An update is already staged. Run wuo status.")
            plan_bytes = (source / "plan.json").read_bytes()
            bundle.verify(source)
            plan = json.loads(plan_bytes)
            job_id = _id(plan["id"])
            if any(
                plan["target"].get(key) != getattr(self.target, key)
                for key in (
                    "machine_guid",
                    "loader_guid",
                    "release",
                    "build",
                    "revision",
                    "architecture",
                )
            ):
                raise ValueError(
                    "The bundle belongs to a different Windows installation or baseline."
                )
            job = self.job_state(job_id)
            if (job / "apply.started").exists() or (job / "state.ready").exists():
                raise ValueError("This servicing job has already started.")
            if _read_id(job / "target.id") != job_id:
                raise ValueError("The bundle has no matching Windows target marker.")

            bundles = self.root / "bundles"
            bundles.mkdir(exist_ok=True)
            destination = bundles / job_id
            with tempfile.TemporaryDirectory(dir=bundles, prefix="stage-") as temporary:
                draft = Path(temporary) / "bundle"
                draft.mkdir()
                (draft / "plan.json").write_bytes(plan_bytes)
                plan_digest = package_hashes(draft / "plan.json")[0]
                if (job / "plan.sha256").read_text(
                    encoding="ascii"
                ).strip() != plan_digest:
                    raise ValueError(
                        "The bundle plan has changed since it was prepared."
                    )
                inventory = plan["paths"]
                if (
                    not {"recovery.cmd"} <= inventory.keys()
                    or {"plan.json", "hashes.txt"} & inventory.keys()
                ):
                    raise ValueError("Invalid recovery bundle inventory.")
                for relative in inventory:
                    copy = draft / relative
                    copy.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source / relative, copy)
                bundle.verify(draft)
                hashes = {**inventory, "plan.json": plan_digest}
                (draft / "hashes.txt").write_bytes(
                    "".join(
                        f"{digest} {relative}\r\n"
                        for relative, digest in sorted(hashes.items())
                    ).encode("ascii")
                )
                pending = Path(temporary) / "pending.id"
                pending.write_bytes(f"{job_id}\r\n".encode("ascii"))
                anchor = Path(temporary) / "hashes.sha256"
                anchor.write_bytes(
                    f"{package_hashes(draft / 'hashes.txt')[0]}\r\n".encode("ascii")
                )
                draft.rename(destination)
                os.replace(anchor, job / "hashes.sha256")
                os.replace(pending, self.root / "pending.id")
            return destination

    def _verify_completed(self, job_id: str) -> bool:
        state = self.job_state(job_id)
        if (state / "feature.ready").exists():
            return self._verify_feature(job_id, state)
        marker = _read_id(state / "state.ready")
        if marker is None:
            return False
        if marker != job_id:
            raise ValueError(
                f"The servicing marker does not match. See {state / 'recovery.log'}."
            )
        prepared = self.root / "bundles" / job_id
        bundle.verify(prepared, post_boot=True)
        plan = json.loads((prepared / "plan.json").read_text(encoding="utf-8"))
        kind = "Driver" if plan.get("kind") == "drivers" else "Windows package"
        print(f"{kind} recovery job verified. Log: {state / 'recovery.log'}")
        return True

    def _verify_feature(self, job_id: str, state: Path) -> bool:
        if _read_id(state / "feature.ready") != job_id:
            raise ValueError("The pending feature upgrade marker is invalid.")
        request = json.loads((state / "feature.json").read_bytes())
        if (
            not isinstance(request, dict)
            or request.get("id") != job_id
            or request.get("machine") != self.target.machine_guid
        ):
            raise ValueError(
                "The pending feature upgrade belongs to another installation."
            )
        if request["source"] == f"{self.target.build}.{self.target.revision}":
            return False
        image = request["image"]
        if (
            self.target.build != image["build"]
            or self.target.revision < image["revision"]
            or self.target.architecture != image["architecture"]
            or _read_id(state / "precommit.done") != job_id
        ):
            raise ValueError(
                f"The installed feature upgrade could not be verified. Review {state}."
            )
        profile = state / "profile.toml"
        hooks = read_selection(profile if profile.is_file() else None).hooks
        if hooks:
            import winreg

            for hook in hooks:
                if hook.phase != "post":
                    continue
                prefix = (
                    r"SYSTEM\CurrentControlSet"
                    if hook.scope == "control-set"
                    else "SYSTEM"
                )
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, f"{prefix}\\{hook.key}"
                ) as key:
                    value, kind = winreg.QueryValueEx(key, hook.name)
                if kind != winreg.REG_DWORD or value != hook.value:
                    raise ValueError(
                        f"The installed hook {hook.key} / {hook.name} does not match. Review {state}."
                    )
        if request.get("boot_preservation") and not self._describe_boot_result(state):
            print(f"Boot preservation result is pending. Job: {state}")
            return False
        print(
            f"Feature upgrade verified on build {self.target.build}.{self.target.revision}. Log: {state / 'precommit.log'}"
        )
        return True

    @staticmethod
    def _describe_boot_result(state: Path) -> bool:
        path = state / "boot-order-result.json"
        try:
            report = json.loads(path.read_bytes())
        except FileNotFoundError:
            return False
        if (
            not isinstance(report, dict)
            or report.get("schema") != 1
            or any(
                not isinstance(report.get(key), str)
                for key in ("order", "order_detail", "fallback", "fallback_detail")
            )
        ):
            raise ValueError(f"Invalid boot preservation result. Review {path}.")
        print(f"UEFI boot order {report['order']}. {report['order_detail']}")
        print(f"EFI fallback {report['fallback']}. {report['fallback_detail']}")
        return True

    def status(self) -> None:
        if not self.installed:
            print("WinRE menu is not installed. Run wuo setup.")
            return
        self.describe_hooks()
        with self._lock():
            windows_updates.verify(self.target, self.root)
            job_id = self._pending_id()
            if job_id is None:
                if latest := _read_id(self.root / "boot-order-last.id"):
                    self._describe_boot_result(self.job_state(latest))
                print("No update staged.")
                return
            if self._verify_completed(job_id):
                (self.root / "pending.id").unlink()
                return
            state = self.job_state(job_id)
            if (state / "feature.ready").is_file():
                boot_reported = self._describe_boot_result(state)
                if _read_id(state / "precommit.failed") == job_id:
                    print(
                        f"Setup stopped at the precommit check. The original Windows is active. Log: {state / 'precommit.log'}"
                    )
                elif boot_reported and (state / "boot-completion.phase").is_file():
                    phase = (
                        (state / "boot-completion.phase")
                        .read_text(encoding="ascii")
                        .strip()
                    )
                    if phase == "failure":
                        print(
                            f"Windows Setup stopped before completing the feature upgrade. Review {state}."
                        )
                        print(
                            "Check whether you can reuse the backup with wuo retry-feature --dry-run."
                        )
                    else:
                        print(
                            f"Windows Setup completed its feature job. Review {state}."
                        )
                elif (state / "claimed.id").is_file():
                    print(
                        f"Windows Setup started the feature upgrade. Review {state / 'precommit.log'}."
                    )
                elif (state / "authorized.id").is_file():
                    backup_check = state / "backup-check.log"
                    if backup_check.is_file():
                        print(
                            "Windows paused Setup because it could not verify the rollback backup. "
                            f"Reconnect the backup drive and restart Windows. See {backup_check}."
                        )
                    else:
                        print(
                            "WinRE authorized the feature upgrade. Windows will resume the staged job."
                        )
                else:
                    print("Feature upgrade staged. Run wuo update to enter recovery.")
                return
            if (state / "apply.started").exists():
                raise ValueError(
                    f"Offline servicing was interrupted. See {state / 'recovery.log'}."
                )
            print("Update staged. Run wuo update to enter recovery.")

    def retry_feature(self, *, dry_run: bool) -> None:
        from .feature_upgrade import (
            FeatureImage,
            FeatureMedia,
            check_feature_retry,
            prepare_media,
        )

        with self._lock():
            self._require_windows_complete_locked()
            job = self._pending_id()
            if job is None:
                raise ValueError("There is no pending feature upgrade to retry.")
            state = self.job_state(job)
            if (
                _read_id(state / "feature.ready") != job
                or _read_id(state / "claimed.id") != job
            ):
                raise ValueError(
                    "Retry requires a feature job that started in Windows."
                )
            if any(
                (state / name).exists()
                for name in (
                    "authorized.id",
                    "precommit.expected",
                    "precommit.done",
                    "precommit.failed",
                    "boot-rollback.id",
                )
            ):
                raise ValueError(
                    "The feature job reached a phase that cannot be retried here."
                )
            if (state / "source-hooks.cmd").exists():
                raise ValueError(
                    "This retry supports jobs with post-update hooks only."
                )
            profile = state / "profile.toml"
            require_full_upgrade_hook_support(
                read_selection(profile if profile.is_file() else None).hooks
            )
            attempt = state / "retry-active"
            if attempt.resolve() != attempt or (
                attempt.exists() and not attempt.is_dir()
            ):
                raise ValueError("The active retry history is not a plain directory.")
            interrupted = attempt.is_dir() and _read_id(attempt / "claimed.id") is None
            records = attempt if interrupted else state
            prepared = _read_id(attempt / "prepared.id") if interrupted else None
            if prepared is not None and prepared != job:
                raise ValueError("The retry preparation marker belongs to another job.")
            if (records / "finalize.result").read_text(
                encoding="ascii"
            ).strip() != "0xC19001E3":
                raise ValueError(
                    "Retry requires a Windows Setup precommit failure (0xC19001E3)."
                )
            if (records / "boot-completion.phase").read_text(
                encoding="ascii"
            ).strip() != "failure":
                raise ValueError("The feature job has no completed failure phase.")
            report = json.loads((records / "boot-order-result.json").read_bytes())
            if (
                not isinstance(report, dict)
                or report.get("schema") != 1
                or report.get("order") not in ("restored", "unchanged")
                or report.get("fallback") not in ("restored", "unchanged", "absent")
            ):
                raise ValueError(
                    "Resolve the UEFI boot order and EFI fallback result before retrying."
                )

            request = json.loads((state / "feature.json").read_bytes())
            if (
                not isinstance(request, dict)
                or request.get("rollback") is not True
                or not request.get("boot_preservation")
            ):
                raise ValueError(
                    "Retry requires the existing rollback backup and boot preservation snapshot."
                )
            iso = Path(request["iso"])
            if not iso.is_file():
                raise ValueError(f"Reconnect the original installation ISO at {iso}.")
            callbacks = self.target.windows / "System32/update/runonce"
            if callbacks.resolve() != callbacks:
                raise ValueError(
                    "The Windows Setup callback directory resolves through a filesystem link."
                )
            _check_callback(
                callbacks / job / "precommit.cmd", request["callback_sha256"]
            )
            abandoned = self._abandoned_feature_callbacks(callbacks, job)
            check_feature_retry(self.target, job, staged=prepared is not None)
            print(f"Feature job {job} can reuse its verified rollback backup.")
            if dry_run:
                for path, _ in abandoned:
                    print(f"Would archive the abandoned Setup callback at {path}.")
                return

            image = FeatureImage(**request["image"])
            media = FeatureMedia(
                iso,
                request["sha256"],
                rollback=True,
                preserve_boot_order=True,
            )
            for path, archive in abandoned:
                path.rename(archive)
                print(f"Archived the abandoned Setup callbacks at {archive}.")
            if attempt.is_dir() and not interrupted:
                attempt.rename(state / f"retry-{uuid4()}")
            if not attempt.is_dir():
                with tempfile.TemporaryDirectory(
                    prefix="retry-records-", dir=state
                ) as directory:
                    temporary = Path(directory)
                    _run(
                        [
                            self.target.windows / "System32/icacls.exe",
                            temporary,
                            "/setowner",
                            "*S-1-5-32-544",
                        ]
                    )
                    for name in _FEATURE_FAILURE_RECORDS:
                        shutil.copyfile(state / name, temporary / name)
                    temporary.rename(attempt)
            if prepared is None:
                prepare_media(self.target, media, image, retry_job=job)
                if _read_id(attempt / "prepared.id") != job:
                    raise ValueError(
                        "Windows Setup did not record a verified retry stage."
                    )
            for name in _FEATURE_FAILURE_RECORDS:
                (state / name).unlink(missing_ok=True)
            # Clearing the claim enables WinRE again, so do it only after preparation and record cleanup.
            (state / "claimed.id").rename(attempt / "claimed.id")
            try:
                attempt.rename(state / f"retry-{uuid4()}")
            except OSError:
                print(f"The retry history remains at {attempt}.")
        print(
            "Feature upgrade staged with the existing rollback backup. Run wuo update to enter recovery."
        )

    def _abandoned_feature_callbacks(
        self, callbacks: Path, job: str
    ) -> list[tuple[Path, Path]]:
        archives: list[tuple[Path, Path]] = []
        for marker in sorted(self.root.glob("pending.*.abandoned.id")):
            old = _id(
                marker.name.removeprefix("pending.").removesuffix(".abandoned.id")
            )
            path = callbacks / old
            if not path.exists() and not path.is_symlink():
                continue
            if old == job or _read_id(marker) != old:
                raise ValueError(f"Invalid abandoned feature marker: {marker}")
            old_state = self.job_state(old)
            if (
                old_state.resolve() != old_state
                or _read_id(old_state / "feature.ready") != old
            ):
                raise ValueError(
                    f"The abandoned feature job could not be verified: {old_state}"
                )
            if any(
                (old_state / name).exists() for name in ("authorized.id", "claimed.id")
            ):
                raise ValueError(
                    f"The abandoned feature job has already advanced: {old_state}"
                )
            request = json.loads((old_state / "feature.json").read_bytes())
            if (
                request.get("id") != old
                or request.get("machine") != self.target.machine_guid
            ):
                raise ValueError(
                    f"The abandoned feature request differs from its marker: {old_state}"
                )
            _check_callback(path / "precommit.cmd", request["callback_sha256"])
            if any(
                entry.name not in ("precommit.cmd", "success.cmd", "failure.cmd")
                or not entry.is_file()
                or entry.is_symlink()
                for entry in path.iterdir()
            ):
                raise ValueError(
                    f"Unrecognized files in the abandoned Setup callbacks: {path}"
                )
            archive = old_state / "archived-setup-callbacks"
            if archive.exists() or archive.is_symlink():
                raise ValueError(
                    f"The abandoned Setup callback archive already exists: {archive}"
                )
            archives.append((path, archive))
        return archives

    def discard(self) -> None:
        with self._lock():
            job_id = self._pending_id()
            if (
                job_id is not None
                and (self.job_state(job_id) / "feature.ready").is_file()
            ):
                raise ValueError(
                    "The feature upgrade has native Setup state. Review wuo status before clearing it."
                )
            (self.root / "pending.id").unlink(missing_ok=True)
        print("Pending job cleared. Its files and logs are retained.")

    def resume(
        self, *, allow_restart: bool = True, require_boot_preservation: bool = False
    ) -> bool:
        with self._lock():
            self.describe_pending_hooks()
            windows_result = windows_updates.verify(self.target, self.root)
            self.windows_incomplete = (
                windows_result is not None and not windows_result.complete
            )
            if self.windows_incomplete and not allow_restart:
                raise ValueError(
                    "The unfinished Windows phase has captured hooks. Finish it with a plain wuo update before selecting hooks for a new phase."
                )
            if windows_result is not None and windows_result.reboot_required:
                print("Restart Windows to finish the Windows phase before continuing.")
                return False
            job_id = self._pending_id()
            if job_id is None:
                return True
            if self.windows_incomplete:
                print(
                    "The Windows phase is incomplete. Resolve it before restarting the staged recovery job."
                )
                return False
            self.describe_hooks()
            if self._verify_completed(job_id):
                (self.root / "pending.id").unlink()
                return True
            state = self.job_state(job_id)
            if (state / "feature.ready").is_file():
                if require_boot_preservation:
                    request = json.loads((state / "feature.json").read_bytes())
                    if not request.get("boot_preservation"):
                        raise ValueError(
                            "This feature upgrade was staged without boot preservation. "
                            "Keep the staged job and its backup. Run wuo status to review it."
                        )
                if any(
                    (state / name).is_file() for name in ("authorized.id", "claimed.id")
                ):
                    print(
                        "The feature upgrade has already been authorized. Run wuo status."
                    )
                    return False
                profile = state / "profile.toml"
                require_full_upgrade_hook_support(
                    read_selection(profile if profile.is_file() else None).hooks
                )
            if (state / "apply.started").exists():
                raise ValueError(
                    f"Offline servicing was interrupted. See {state / 'recovery.log'}."
                )
        print("An update is already staged.")
        if not allow_restart:
            raise ValueError(
                "The pending job has captured hooks. Finish it or run wuo status --discard before selecting hooks for a new job."
            )
        self.offer_restart()
        return False

    def install_windows(
        self, offers: list[Offer], profile: Path | None, *, hooks_explicit: bool = False
    ) -> windows_updates.WindowsResult:
        with self._lock():
            if self._pending_id() is not None:
                raise ValueError(
                    "Finish the pending recovery job before installing Windows security updates."
                )
            result = windows_updates.install(
                offers,
                self.target,
                self.root,
                profile=profile,
                hooks_explicit=hooks_explicit,
            )
            self.windows_incomplete = not result.complete
            return result

    def describe_hooks(self, registry: HookRegistry | None = None) -> None:
        if not self.installed:
            print("Saved hooks: none. WinRE menu is not installed.")
            return
        registry = registry or HookRegistry()
        print("Saved hooks for future jobs")
        describe_selection(read_selection(self.profile), registry)
        self.describe_pending_hooks(registry)

    def describe_pending_hooks(self, registry: HookRegistry | None = None) -> None:
        native_journal = self.root / windows_updates.JOURNAL
        if native_journal.is_file():
            native = json.loads(native_journal.read_text(encoding="utf-8-sig"))
            if native.get("phase_complete") is True:
                print("Previous Windows security phase: completed.")
            else:
                captured = native.get("hooks_job_id")
                print("Pending Windows phase uses these captured hooks")
                if captured:
                    job = self.root / "windows-hook-jobs" / _id(captured)
                    captured_profile = job / "hooks.toml"
                    receipt = json.loads(
                        (job / "windows-hooks.json").read_text(encoding="utf-8")
                    )
                    if (
                        receipt.get("profile_sha256") is not None
                        and not captured_profile.is_file()
                    ):
                        raise ValueError(
                            "The captured Windows hook profile is missing."
                        )
                    describe_selection(
                        read_selection(
                            captured_profile if captured_profile.is_file() else None
                        ),
                        registry,
                    )
                else:
                    print(
                        "  Captured hook selection is unavailable. Review the native phase journal."
                    )
        job_id = self._pending_id()
        if job_id is not None:
            state = self.job_state(job_id)
            if (state / "feature.ready").is_file():
                feature_profile = state / "profile.toml"
                print(f"Pending feature job {job_id} uses these captured hooks")
                describe_selection(
                    read_selection(
                        feature_profile if feature_profile.is_file() else None
                    ),
                    registry,
                )
                return
            pending = self.root / "bundles" / job_id
            if not (pending / "plan.json").is_file():
                print(f"Pending job {job_id}: hook selection unavailable.")
                return
            plan = json.loads((pending / "plan.json").read_text(encoding="utf-8"))
            profile = pending / "hooks.toml" if plan.get("hooks") else None
            print(f"Pending job {job_id} uses these captured hooks")
            describe_selection(read_selection(profile), registry)

    def offer_restart(self) -> None:
        with self._lock():
            self._require_windows_complete_locked()
            pending = self._pending_id()
        print(
            "In recovery, select Troubleshoot > wuo (Windows Offline Update on older installations)."
        )
        if not sys.stdin.isatty():
            print("Run wuo update in an administrator terminal when ready to restart.")
            return
        if input("Restart into Windows Recovery now? [y/N] ").strip().lower() in {
            "y",
            "yes",
        }:
            with self._lock():
                self._require_windows_complete_locked()
                if pending is None or self._pending_id() != pending:
                    raise ValueError("The staged update changed. Run wuo status.")
                from xml.etree import ElementTree

                registration = self.target.windows / "System32/Recovery/ReAgent.xml"
                try:
                    settings = ElementTree.parse(registration)
                except (OSError, ElementTree.ParseError) as error:
                    raise ValueError(
                        "Could not read the Windows recovery registration."
                    ) from error
                if any(
                    settings.find(f"{name}[@state='1']") is None
                    for name in ("InstallState", "OemTool")
                ):
                    raise ValueError(
                        "The WinRE menu is no longer registered. Run wuo status to review the staged job."
                    )
                system32 = self.target.windows / "System32"
                _run([system32 / "reagentc.exe", "/boottore"])
                _run([system32 / "shutdown.exe", "/r", "/t", "0"])

    def remove(self) -> None:
        if not self.installed:
            print("WinRE menu is not installed.")
            return
        with self._lock():
            job_id = self._pending_id()
            if job_id is not None:
                if not self._verify_completed(job_id):
                    raise ValueError(
                        "Finish or clear the staged job before removing the menu."
                    )
                (self.root / "pending.id").unlink()
            self.configure("uninstall")

    def configure(self, action: str, profile: Path | None = None) -> None:
        selected = read_selection(profile)
        if action == "install" and self.installed:
            with self._lock():
                self._save_selection(selected.path)
            print("Saved hooks for future update jobs.")
            return
        resources = files("wuo")
        with ExitStack() as workspace:
            script = workspace.enter_context(
                as_file(resources.joinpath("winre_setup.ps1"))
            )
            launcher = workspace.enter_context(
                as_file(resources.joinpath("winre_launcher.cmd.in"))
            )
            command: list[str | Path] = [
                self.target.windows / "System32/WindowsPowerShell/v1.0/powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script,
                "-Action",
                action,
                "-Root",
                self.root,
                "-Launcher",
                launcher,
                "-MachineGuid",
                self.target.machine_guid,
            ]
            if profile is not None:
                folder = workspace.enter_context(
                    tempfile.TemporaryDirectory(prefix="wuo-profile-")
                )
                snapshot = Path(folder) / "profile.toml"
                metadata = profile.with_name("hooks.json")
                if metadata.is_file():
                    shutil.copyfile(profile, snapshot)
                    shutil.copyfile(metadata, snapshot.with_name("hooks.json"))
                else:
                    resolve_selection((), profile, Path(folder))
                read_selection(snapshot)
                command.extend(("-Profile", snapshot))
                command.extend(("-HookMetadata", snapshot.with_name("hooks.json")))
            output = _run(command)
        capability = self.root / _FEATURE_MENU
        if action == "install":
            capability.write_bytes(_FEATURE_MENU_VERSION)
        else:
            capability.unlink(missing_ok=True)
        if output.strip():
            print(output.strip())

    def _save_selection(self, profile: Path | None) -> None:
        from .downloads import atomic_json

        if profile is None:
            atomic_json(self.root / "selection.json", {"profile": None})
            return
        # Keep a complete snapshot behind one atomic pointer so readers see one generation.
        selected = read_selection(profile)
        generations = self.root / "selections"
        generations.mkdir(exist_ok=True)
        version = str(uuid4())
        destination = generations / version
        with tempfile.TemporaryDirectory(dir=generations, prefix="save-") as temporary:
            draft = Path(temporary) / "selection"
            draft.mkdir()
            metadata = profile.with_name("hooks.json")
            if metadata.is_file():
                shutil.copyfile(profile, draft / "profile.toml")
                shutil.copyfile(metadata, draft / "hooks.json")
            else:
                resolve_selection((), profile, draft)
            check = read_selection(draft / "profile.toml")
            if check.hooks != selected.hooks or check.origins != selected.origins:
                raise ValueError("Hook selection changed while saving.")
            draft.rename(destination)
            atomic_json(self.root / "selection.json", {"profile": version})
