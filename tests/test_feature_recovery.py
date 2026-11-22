import os
import subprocess
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest

from wuo import feature_recovery
from wuo.feature_upgrade import FeatureImage
from wuo.hooks import Hook
from wuo.target import TargetIdentity

JOB = UUID("ae77eb85-2b95-4a3b-8d5d-5e85957de875")
OWNER = TargetIdentity(
    "25H2",
    26200,
    1150,
    "x64",
    Path("C:/Windows"),
    "0c16a147-692c-4baa-b662-00ac8474a832",
    "45c38955-e46d-4c8f-84f3-ad5470156b28",
)
IMAGE = FeatureImage(1, 26300, 100, "Professional", "x64", "en-US")
POST = Hook("post", r"Services\UASPStor", "Start", 0, 3)
PRE = Hook("pre", r"Services\USBXHCI", "Start", 0)
EFI = "\\\\?\\Volume{3b6bc5c8-7453-47c1-8d1f-6dc638249a63}\\"
BACKUP = "\\\\?\\Volume{c5db069b-a210-42b1-894d-f84a7fb58225}\\"
WINDOWS = "\\\\?\\Volume{229b445e-753d-457f-8e58-ee57d38a314a}\\"
RECOVERY_EFI = "\\\\?\\Volume{229b445e-753d-457f-8e58-ee57d38a314b}\\"
RECOVERY = "{136e30a3-68e4-4180-84c2-70a3a5c23fb1}"


def render(**overrides: str) -> bytes:
    settings = {
        "windows_volume": WINDOWS,
        "efi_volume": EFI,
        "backup_volume": BACKUP,
        "recovery_entry": RECOVERY,
        "recovery_efi_volume": RECOVERY_EFI,
        "recovery_path": r"\EFI\BOOT\BOOTX64.EFI",
        "recovery_loader_sha256": "e" * 64,
        "restore_sha256": "b" * 64,
        "rollback_sha256": "a" * 64,
    }
    return feature_recovery.render_feature_recovery(
        JOB, OWNER, IMAGE, (PRE, POST), **(settings | overrides)
    )


def test_hook_digest_binds_post_value_and_expected_value() -> None:
    digest = feature_recovery.feature_recovery_hook_digest((PRE, POST))
    assert digest == feature_recovery.feature_recovery_hook_digest((POST,))
    assert digest != feature_recovery.feature_recovery_hook_digest(
        (Hook("post", POST.key, POST.name, 0, 2),)
    )
    assert digest != feature_recovery.feature_recovery_hook_digest(
        (Hook("post", POST.key, POST.name, 1, 3),)
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"efi_volume": "C:"},
        {"efi_volume": WINDOWS},
        {"backup_volume": EFI},
        {"recovery_efi_volume": EFI},
        {"recovery_entry": "Windows Boot Manager"},
        {"recovery_entry": RECOVERY[:-1]},
        {"recovery_path": r"\EFI\..\bootx64.efi"},
        {"windows_entry": RECOVERY},
        {"restore_sha256": "f" * 63},
        {"rollback_sha256": "a" * 64 + "\r\necho invalid"},
    ],
)
def test_recovery_refuses_unbound_boot_and_backup_inputs(
    overrides: dict[str, str],
) -> None:
    with pytest.raises(ValueError):
        render(**overrides)


def test_runner_is_bound_to_the_job_and_captured_post_hooks() -> None:
    script = render().decode("ascii")
    receipt = feature_recovery.feature_recovery_receipt(JOB, IMAGE, (PRE, POST))
    assert str(JOB) in script
    assert receipt.decode("ascii").strip() in script
    assert OWNER.machine_guid in script
    assert RECOVERY in script
    assert EFI in script and BACKUP in script
    assert "Services\\UASPStor" in script
    assert "Services\\USBXHCI" not in script
    assert "@@" not in script
    assert "\n" not in script.replace("\r\n", "")


def test_all_hooks_are_read_back_again_after_the_last_write() -> None:
    script = render().decode("ascii")
    commands = script.split("\r\n:apply_hooks", 1)[1].split("\r\n:captured_hooks", 1)[0]
    assert commands.index("call :captured_hooks write") < commands.index(
        "call :captured_hooks verify"
    )
    assert commands.index("call :captured_hooks verify") < commands.index(" unload ")


def _run_cmd_fixture(
    directory: Path, commands: str, helpers: str
) -> subprocess.CompletedProcess[str]:
    harness = directory / "verify.cmd"
    harness.write_bytes(
        (
            "@echo off\r\n"
            "setlocal EnableExtensions DisableDelayedExpansion\r\n"
            'set "WORK=%~dp0"\r\n'
            'set "TOOLS=%SystemRoot%\\System32\\"\r\n'
            + commands
            + "\r\n"
            + helpers
            + "\r\n"
        ).encode("ascii")
    )
    return subprocess.run(
        [os.environ["COMSPEC"], "/d", "/c", str(harness)],
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(os.name != "nt", reason="Runs the generated CMD parser")
@pytest.mark.parametrize(
    ("manager_fields", "expected"),
    [
        (
            f"bootsequence            {RECOVERY}\r\n"
            f"displayorder            {RECOVERY}\r\n"
            "                        {45c38955-e46d-4c8f-84f3-ad5470156b28}\r\n",
            RECOVERY,
        ),
        (
            f"displayorder            {RECOVERY}\r\n"
            "                        {45c38955-e46d-4c8f-84f3-ad5470156b28}\r\n",
            "",
        ),
        (
            f"bootsequence            {RECOVERY}\r\n"
            "                        {45c38955-e46d-4c8f-84f3-ad5470156b28}\r\n",
            None,
        ),
        (f"bootsequence            {RECOVERY} unexpected\r\n", None),
        (
            f"bootsequence            {RECOVERY}\r\n"
            f"bootsequence            {RECOVERY}\r\n",
            None,
        ),
    ],
)
def test_cmd_rejects_uncertain_boot_sequence(
    tmp_path: Path, manager_fields: str, expected: str | None
) -> None:
    # Run the built batch labels over captured-style output without touching BCD.
    (tmp_path / "bcd.txt").write_bytes(manager_fields.encode("ascii"))
    script = render().decode("ascii")
    helpers = script.split("\r\n:bcd_field", 1)[1].split("\r\n:record_receipt", 1)[0]
    result = _run_cmd_fixture(
        tmp_path,
        "call :read_sequence || exit /b 1\r\necho([%SEQUENCE%]\r\nexit /b 0",
        ":bcd_field" + helpers,
    )
    if expected is None:
        assert result.returncode == 1
    else:
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == f"[{expected}]"


@pytest.mark.skipif(os.name != "nt", reason="Runs the generated CMD device checks")
@pytest.mark.parametrize("actual_drive", ["Y:", "Z:"])
def test_cmd_preserves_the_equals_sign_in_partition_arguments(
    tmp_path: Path, actual_drive: str
) -> None:
    (tmp_path / "bcd.txt").write_bytes(
        f"device                  partition={actual_drive}\r\n"
        f"osdevice                partition={actual_drive}\r\n".encode("ascii")
    )
    script = render().decode("ascii")
    checks = [
        line
        for line in script.splitlines()
        if line.startswith(("call :bcd_value device", "call :bcd_value osdevice"))
    ]
    assert len(checks) == 4
    helpers = script.split("\r\n:bcd_field", 1)[1].split("\r\n:read_sequence", 1)[0]
    result = _run_cmd_fixture(
        tmp_path,
        "\r\n".join(
            [
                'set "RECOVERY_EFI=Y:"',
                'set "EFI=Y:"',
                'set "TARGET=Y:"',
                *checks,
                "exit /b 0",
            ]
        ),
        ":bcd_field" + helpers,
    )
    assert result.returncode == (0 if actual_drive == "Y:" else 1), result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Runs the generated CMD receipt writer")
@pytest.mark.parametrize("corrupt", [False, True])
def test_cmd_receipt_can_be_retried_without_overwriting_existing_evidence(
    tmp_path: Path, corrupt: bool
) -> None:
    receipt = b"v1 ae77eb85-2b95-4a3b-8d5d-5e85957de875 captured-digest 26300\r\n"
    (tmp_path / "receipt.txt").write_bytes(receipt)
    durable = tmp_path / "state" / "independent-hooks.done"
    durable.parent.mkdir()
    bad_receipt = receipt.removesuffix(b"\r\n")
    if corrupt:
        durable.write_bytes(bad_receipt)
    script = render().decode("ascii")
    helpers = script.split("\r\n:record_receipt", 1)[1].split("\r\n:apply_hooks", 1)[0]
    commands = (
        f'set "RECEIPT_HASH={sha256(receipt).hexdigest()}"\r\n'
        r'call :record_receipt "%~dp0state\independent-hooks.done" || exit /b 1'
        "\r\n"
        r'call :record_receipt "%~dp0state\independent-hooks.done" || exit /b 2'
        "\r\nexit /b 0"
    )
    result = _run_cmd_fixture(tmp_path, commands, ":record_receipt" + helpers)
    assert result.returncode == int(corrupt), result.stderr
    assert durable.read_bytes() == (bad_receipt if corrupt else receipt)
    assert list(durable.parent.iterdir()) == [durable]
