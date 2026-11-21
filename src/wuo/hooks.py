"""Validated local registry hook profiles."""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast


@dataclass(frozen=True, slots=True)
class Hook:
    phase: Literal["pre", "post"]
    key: str
    name: str
    value: int
    expected: int | None = None
    scope: Literal["control-set", "system"] = "control-set"


def require_full_upgrade_hook_support(hooks: tuple[Hook, ...]) -> None:
    for hook in hooks:
        service_path = (
            r"Services\\[^\\]+"
            if hook.scope == "control-set"
            else r"ControlSet[0-9]{3}\\Services\\[^\\]+"
        )
        if (
            hook.phase == "post"
            and hook.value == 0
            and hook.name.casefold() == "start"
            and re.fullmatch(service_path, hook.key, re.I)
        ):
            raise ValueError(
                "Full ISO feature upgrades with boot-start driver hooks are blocked. "
                "These settings need verification after SafeOS and before Windows boots."
            )


def load_profile(path: Path) -> tuple[Hook, ...]:
    with path.open("rb") as stream:
        profile = tomllib.load(stream)
    if set(profile) != {"hooks"} or not isinstance(profile["hooks"], list):
        raise ValueError("A hook profile must contain a list of [[hooks]] entries.")
    hooks = []
    targets = set()
    for record in profile["hooks"]:
        if not isinstance(record, dict) or set(record) - {
            "phase",
            "key",
            "name",
            "value",
            "expected",
            "scope",
        }:
            raise ValueError("Unknown registry hook fields.")
        phase = record.get("phase")
        scope = record.get("scope", "control-set")
        key = record.get("key")
        name = record.get("name")
        value = record.get("value")
        expected = record.get("expected")
        if phase not in ("pre", "post") or scope not in ("control-set", "system"):
            raise ValueError("Registry hook has an invalid phase or scope.")
        if (
            not isinstance(key, str)
            or re.fullmatch(
                r"[A-Za-z0-9_. -]{1,90}(?:\\[A-Za-z0-9_. -]{1,90}){0,12}", key
            )
            is None
        ):
            raise ValueError("Invalid registry key in hook profile.")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,90}", name) is None
        ):
            raise ValueError("Invalid registry value name in hook profile.")
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(
                "A registry DWORD must be an integer between 0 and 4294967295."
            )
        if expected is not None and (
            type(expected) is not int or not 0 <= expected <= 0xFFFFFFFF
        ):
            raise ValueError(
                "An expected registry DWORD must be between 0 and 4294967295."
            )
        identity = (phase, scope, key.casefold(), name.casefold())
        if identity in targets:
            raise ValueError(
                "A registry hook specifies the same value twice in one phase."
            )
        targets.add(identity)
        hooks.append(
            Hook(
                cast(Literal["pre", "post"], phase),
                key,
                name,
                value,
                expected,
                cast(Literal["control-set", "system"], scope),
            )
        )
    return tuple(hooks)
