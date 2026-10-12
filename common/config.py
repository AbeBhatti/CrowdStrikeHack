"""Load YAML config and project paths."""

from __future__ import annotations

import random
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import yaml

_ROOT = Path(__file__).resolve().parent.parent


def project_root() -> Path:
    return _ROOT


def _load_yaml(name: str) -> dict[str, Any]:
    path = _ROOT / "config" / name
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Config {name} must be a mapping")
    return data


@lru_cache(maxsize=1)
def get_thresholds() -> dict[str, Any]:
    return _load_yaml("thresholds.yaml")


@lru_cache(maxsize=1)
def get_host_roles() -> dict[str, Any]:
    return _load_yaml("host_roles.yaml")


@lru_cache(maxsize=1)
def get_playbooks() -> dict[str, Any]:
    return _load_yaml("playbooks.yaml")


@lru_cache(maxsize=1)
def get_attack_mapping() -> dict[str, Any]:
    return _load_yaml("attack_mapping.yaml")


@lru_cache(maxsize=1)
def get_decoys_config() -> dict[str, Any]:
    return _load_yaml("decoys.yaml")


@lru_cache(maxsize=1)
def get_oncall_config() -> dict[str, Any]:
    return _load_yaml("oncall.yaml")


def set_global_seed(seed: int | None = None) -> int:
    thr = get_thresholds()
    value = int(seed if seed is not None else thr.get("random_seed", 42))
    random.seed(value)
    np.random.seed(value)
    return value


TRAINING_SCENARIOS: tuple[str, ...] = (
    "fox",
    "harrison",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
)
HELD_OUT_SCENARIOS: tuple[str, ...] = ("russellmitchell", "santos")
ALL_SCENARIOS: tuple[str, ...] = TRAINING_SCENARIOS + HELD_OUT_SCENARIOS

STAGES: tuple[str, ...] = (
    "recon",
    "web_scan",
    "webshell",
    "cracking",
    "reverse_shell",
    "privilege_escalation",
    "service_stop",
    "exfil",
    "none",
)

TIME_LABEL_TO_STAGE: dict[str, str] = {
    "false_positive": "none",
    "network_scans": "recon",
    "service_scans": "recon",
    "dirb": "web_scan",
    "wpscan": "web_scan",
    "webshell": "webshell",
    "cracking": "cracking",
    "reverse_shell": "reverse_shell",
    "privilege_escalation": "privilege_escalation",
    "service_stop": "service_stop",
    "dnsteal": "exfil",
}

EVENT_LABEL_TO_STAGE: dict[str, str] = {
    "-": "",
    "dirb": "web_scan",
    "dnsteal": "exfil",
    "wpscan": "web_scan",
    "service_scan": "recon",
    "escalated_sudo_command": "privilege_escalation",
    "attacker_change_user": "privilege_escalation",
    "webshell_cmd": "webshell",
}

CRITICAL_STAGES: tuple[str, ...] = (
    "webshell",
    "reverse_shell",
    "privilege_escalation",
    "exfil",
)
