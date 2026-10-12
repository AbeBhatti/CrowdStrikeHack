"""Smoke tests for environment helpers and text hygiene."""

from __future__ import annotations

from common.config import ALL_SCENARIOS, HELD_OUT_SCENARIOS, TRAINING_SCENARIOS, set_global_seed
from common.hosts import host_to_role
from common.stages import resolve_stage
from common.text import contains_forbidden_chars, strip_forbidden_chars


def test_scenario_split_is_fixed() -> None:
    assert set(ALL_SCENARIOS) == set(TRAINING_SCENARIOS) | set(HELD_OUT_SCENARIOS)
    assert set(TRAINING_SCENARIOS).isdisjoint(HELD_OUT_SCENARIOS)
    assert HELD_OUT_SCENARIOS == ("russellmitchell", "santos")
    assert len(TRAINING_SCENARIOS) == 6


def test_seed_is_deterministic() -> None:
    assert set_global_seed() == 42


def test_host_role_normalization() -> None:
    assert host_to_role("mail") == "mail"
    assert host_to_role("webserver") == "webserver"
    assert host_to_role("davey_mail") == "mail"
    assert host_to_role("inet-firewall") == "inet_firewall"
    assert host_to_role(None) == "unknown"


def test_stage_prefers_event_label() -> None:
    assert resolve_stage("dirb", "webshell_cmd") == "webshell"
    assert resolve_stage("dnsteal", "-") == "exfil"
    assert resolve_stage("false_positive", "-") == "none"


def test_strip_forbidden_chars() -> None:
    raw = "Alert — webshell -- next step"
    cleaned = strip_forbidden_chars(raw)
    assert "—" not in cleaned
    assert "--" not in cleaned
    assert not contains_forbidden_chars(cleaned)
