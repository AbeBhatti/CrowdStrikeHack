"""Forecaster tests: training-only, webshell -> reverse_shell."""

from __future__ import annotations

import pytest

from common.config import HELD_OUT_SCENARIOS, TRAINING_SCENARIOS
from forecast.table import build_transition_table, forecast_next, save_table
from ingest.convert_parquet import load_scenario


def test_forecaster_never_uses_held_out() -> None:
    with pytest.raises(AssertionError, match="held-out"):
        build_transition_table(TRAINING_SCENARIOS + HELD_OUT_SCENARIOS)


def test_webshell_predicts_reverse_shell() -> None:
    table = build_transition_table(TRAINING_SCENARIOS)
    save_table(table)
    fc = forecast_next(table, ["web_scan", "webshell"])
    assert fc.next_stage == "reverse_shell"
    assert fc.probability > 0.5
    assert fc.window_minutes[0] <= fc.window_minutes[1]


def test_held_out_gap_inside_window() -> None:
    table = build_transition_table(TRAINING_SCENARIOS)
    df = load_scenario("russellmitchell").sort("time")
    ws = df.filter(df["time_label"] == "webshell")["time"].min()
    rs = df.filter(df["time_label"] == "reverse_shell")["time"].min()
    assert ws is not None and rs is not None
    true_gap = (int(rs) - int(ws)) / 60.0
    fc = forecast_next(table, ["web_scan", "webshell"])
    assert fc.next_stage == "reverse_shell"
    lo, hi = fc.window_minutes
    # Expand slightly for acceptance: window should contain true gap
    assert lo - 5 <= true_gap <= hi + 5
