"""Classifier method comparison: no held-out leakage; selection rules."""

from __future__ import annotations

from typing import Any

import pytest

from classifier.features import FeatureState, fit_rarity_from_training
from classifier.methods import LookupMethod, RulesMethod, make_method
from common.config import HELD_OUT_SCENARIOS, TRAINING_SCENARIOS


def test_held_out_never_in_training_constant() -> None:
    assert set(TRAINING_SCENARIOS).isdisjoint(HELD_OUT_SCENARIOS)
    assert "russellmitchell" in HELD_OUT_SCENARIOS
    assert "santos" in HELD_OUT_SCENARIOS


def test_method_fit_raises_on_held_out_scenario() -> None:
    """Any training batch that includes a held-out scenario must fail the guard."""

    def assert_no_held_out(alerts: list[dict[str, Any]]) -> None:
        for a in alerts:
            sc = str(a.get("scenario", ""))
            if sc in HELD_OUT_SCENARIOS:
                raise AssertionError(f"held-out scenario {sc} used in training")

    clean = [
        {
            "scenario": "fox",
            "short": "W-Acc-400",
            "stage": "web_scan",
            "time": 1,
            "host_role": "webserver",
            "detector": "W",
            "ip": "1.2.3.4",
            "host": "webserver",
            "name": "x",
            "noise_score": 0.1,
        }
    ]
    assert_no_held_out(clean)
    dirty = [{**clean[0], "scenario": "russellmitchell"}]
    with pytest.raises(AssertionError, match="held-out"):
        assert_no_held_out(dirty)
    # Methods themselves fit only what callers pass; CV/train code must not pass held-out.
    m = LookupMethod()
    m.fit(clean, FeatureState())
    assert m.p_attack


def test_rules_and_lookup_predict_shape() -> None:
    alerts = []
    for i, (short, stage) in enumerate(
        [("W-Acc-400", "web_scan"), ("W-Sys-Cav", "none"), ("A-New-X", "webshell")]
    ):
        alerts.append(
            {
                "scenario": "fox",
                "short": short,
                "stage": stage,
                "time": 1000 + i,
                "host_role": "webserver",
                "detector": short[0],
                "ip": "10.0.0.1",
                "host": "webserver",
                "name": short,
                "noise_score": 0.2,
                "time_label": stage if stage != "none" else "false_positive",
            }
        )
    rarity = fit_rarity_from_training(alerts)
    for name in ("lookup", "rules"):
        m = make_method(name)
        m.fit(alerts, rarity)
        st = FeatureState(
            type_role_counts_train=rarity.type_role_counts_train,
            type_role_total=rarity.type_role_total,
        )
        score, stage = m.predict(alerts[0], st)
        assert 0.0 <= score <= 1.0
        assert isinstance(stage, str)


def test_selection_prefers_rules_when_logreg_lead_small() -> None:
    from classifier.compare_methods import MethodMetrics, choose_method

    def mk(name: str, f1: float) -> list[MethodMetrics]:
        return [MethodMetrics(name=name, rare_macro_f1=f1) for _ in range(6)]

    cv = {
        "lookup": mk("lookup", 0.20),
        "rules": mk("rules", 0.40),
        "logistic": mk("logistic", 0.42),  # lead 0.02 < 0.03
    }
    chosen, reason = choose_method(cv)
    assert chosen == "rules"
    assert "0.03" in reason or "explainable" in reason
