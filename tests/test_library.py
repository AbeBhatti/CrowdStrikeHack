"""Defense library: no held-out contamination; shared rules exist after learning."""

from __future__ import annotations

from pathlib import Path

import pytest

from common.config import HELD_OUT_SCENARIOS
from library.store import DefenseLibrary


def test_rejects_held_out_origin(tmp_path: Path) -> None:
    lib = DefenseLibrary(tmp_path / "lib.sqlite")
    with pytest.raises(AssertionError, match="held-out"):
        lib.add_rule(
            {"stage_detected": "exfil", "name": "x"},
            origin_company="russellmitchell",
            validation={"companies": ["fox"]},
            shared=False,
        )


def test_rejects_held_out_validation(tmp_path: Path) -> None:
    lib = DefenseLibrary(tmp_path / "lib.sqlite")
    with pytest.raises(AssertionError, match="held-out"):
        lib.add_rule(
            {"stage_detected": "exfil", "name": "x"},
            origin_company="fox",
            validation={"companies": ["santos"]},
            shared=True,
        )


def test_shared_rule_roundtrip(tmp_path: Path) -> None:
    lib = DefenseLibrary(tmp_path / "lib.sqlite")
    lib.add_rule(
        {"stage_detected": "webshell", "name": "w"},
        origin_company="fox",
        validation={"companies": ["fox", "harrison", "shaw", "wilson"], "fp_per_day": 0.1},
        shared=True,
    )
    lib.assert_no_held_out_contamination()
    rules = lib.shared_rules()
    assert rules and rules[0]["origin_company"] == "fox"
    assert not set(HELD_OUT_SCENARIOS) & {rules[0]["origin_company"]}
