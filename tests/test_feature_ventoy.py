import hashlib
import json
from pathlib import Path
from uuid import UUID

import pytest

from wuo import feature_ventoy

JOB = UUID("11111111-1111-1111-1111-111111111111")


@pytest.fixture
def media(tmp_path: Path) -> tuple[Path, Path, str, Path]:
    volume = tmp_path / "ventoy volume"
    volume.mkdir()
    source = tmp_path / "source.iso"
    source.write_bytes(b"test ISO")
    state = tmp_path / "protected job" / "ventoy-state.json"
    state.parent.mkdir()
    return volume, source, hashlib.sha256(source.read_bytes()).hexdigest(), state


@pytest.mark.parametrize("existing", [True, False])
def test_deploy_and_restore_only_job_files(
    media: tuple[Path, Path, str, Path], existing: bool
) -> None:
    volume, source, sha256, state = media
    original = (
        b'{\r\n  "control": [{"VTOY_MENU_LANGUAGE":"en_US"}],\r\n'
        b'  "control_uefi": [{"VTOY_MENU_TIMEOUT":"30"}]\r\n}\r\n'
    )
    config = volume / "ventoy/ventoy.json"
    if existing:
        config.parent.mkdir()
        config.write_bytes(original)
    other = volume / "other.iso"
    other.write_bytes(b"other image")
    iso = feature_ventoy.deploy_recovery_iso(volume, source, sha256, JOB, state)
    assert iso.name == f"WUO-Recovery-{JOB}.iso"
    assert iso.read_bytes() == source.read_bytes()
    assert state.is_file()
    staged = json.loads(config.read_bytes())
    assert {
        key: value for item in staged["control_uefi"] for key, value in item.items()
    } == {
        "VTOY_DEFAULT_IMAGE": f"/{iso.name}",
        "VTOY_MENU_TIMEOUT": "5",
        "VTOY_SECONDARY_BOOT_MENU": "0",
    }
    if existing:
        assert staged["control"] == [{"VTOY_MENU_LANGUAGE": "en_US"}]
    assert feature_ventoy.deploy_recovery_iso(volume, source, sha256, JOB, state) == iso
    feature_ventoy.restore_recovery_media(volume, JOB, state)
    assert not iso.exists()
    assert not state.exists()
    assert other.read_bytes() == b"other image"
    if existing:
        assert config.read_bytes() == original
    else:
        assert not config.parent.exists()
    feature_ventoy.restore_recovery_media(volume, JOB, state)


@pytest.mark.parametrize(
    "config_bytes",
    [
        b'{"control": [{"VTOY_DEFAULT_SEARCH_ROOT": "/ISO"}]}',
        b'{"image_list_uefi": ["/other.iso"]}',
        b'{"control": [{}, {}]}',
        b'{"control": [], "control": []}',
    ],
)
def test_conflicting_or_malformed_configuration_preserves_media(
    media: tuple[Path, Path, str, Path], config_bytes: bytes
) -> None:
    volume, source, sha256, state = media
    config = volume / "ventoy/ventoy.json"
    config.parent.mkdir()
    config.write_bytes(config_bytes)
    with pytest.raises(ValueError, match="Ventoy"):
        feature_ventoy.deploy_recovery_iso(volume, source, sha256, JOB, state)
    assert config.read_bytes() == config_bytes
    assert not state.exists()
    assert list(volume.iterdir()) == [config.parent]


def test_restore_preserves_a_config_changed_after_deployment(
    media: tuple[Path, Path, str, Path],
) -> None:
    volume, source, sha256, state = media
    iso = feature_ventoy.deploy_recovery_iso(volume, source, sha256, JOB, state)
    config = volume / "ventoy/ventoy.json"
    config.write_bytes(b'{"control":[]}\n')
    with pytest.raises(ValueError, match="configuration changed"):
        feature_ventoy.restore_recovery_media(volume, JOB, state)
    assert config.read_bytes() == b'{"control":[]}\n'
    assert iso.is_file()
    assert state.is_file()


def test_a_copy_with_an_incorrect_digest_leaves_media_unmodified(
    media: tuple[Path, Path, str, Path],
) -> None:
    volume, source, _, state = media
    with pytest.raises(ValueError, match="SHA-256"):
        feature_ventoy.deploy_recovery_iso(volume, source, "a" * 64, JOB, state)
    assert not state.exists()
    assert not list(volume.iterdir())


def test_cannot_deploy_a_second_job_to_the_same_ventoy_configuration(
    media: tuple[Path, Path, str, Path],
) -> None:
    volume, source, sha256, state = media
    iso = feature_ventoy.deploy_recovery_iso(volume, source, sha256, JOB, state)
    other_state = state.with_name("other-state.json")
    other_job = UUID("22222222-2222-2222-2222-222222222222")
    config = volume / "ventoy/ventoy.json"
    contents = config.read_bytes()
    with pytest.raises(ValueError, match="already.*recovery job"):
        feature_ventoy.deploy_recovery_iso(
            volume, source, sha256, other_job, other_state
        )
    assert config.read_bytes() == contents
    assert iso.is_file()
    assert not other_state.exists()
