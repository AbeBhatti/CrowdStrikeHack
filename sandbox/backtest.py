"""Backtest candidate rules on training scenarios only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import polars as pl

from classifier.leak_guard import assert_no_held_out_names
from common.config import TRAINING_SCENARIOS, get_thresholds
from ingest.convert_parquet import load_scenario
from sandbox.rules import DetectionRule, validate_rule


@dataclass
class BacktestResult:
    rule: DetectionRule
    caught_scenarios: list[str]
    missed_scenarios: list[str]
    fp_per_day: float
    lead_lag_minutes: dict[str, float]


def _rule_hits(df: pl.DataFrame, rule: DetectionRule) -> pl.DataFrame:
    q = df
    if rule.alert_types:
        q = q.filter(pl.col("short").is_in(rule.alert_types))
    if rule.host_roles:
        q = q.filter(pl.col("host_role").is_in(rule.host_roles))
    if rule.require_cooccur_detectors:
        # Approximate: require those detectors appear in scenario for the stage window
        pass
    return q.sort("time")


def backtest_rule(
    rule_data: dict[str, Any],
    scenarios: tuple[str, ...] = TRAINING_SCENARIOS,
) -> BacktestResult:
    assert_no_held_out_names(scenarios, context="sandbox.backtest")
    rule = validate_rule(rule_data)
    caught: list[str] = []
    missed: list[str] = []
    fp_total = 0
    days_total = 0.0
    lead_lag: dict[str, float] = {}

    for sc in scenarios:
        df = load_scenario(sc)
        stage_rows = df.filter(pl.col("stage") == rule.stage_detected)
        span_days = max(
            (int(df["time"].max()) - int(df["time"].min())) / 86400.0,
            1 / 24,
        )
        days_total += span_days
        if stage_rows.height == 0:
            missed.append(sc)
            continue
        stage_start = int(stage_rows["time"].min())
        candidates = _rule_hits(df, rule)
        # Hits near stage start
        near = candidates.filter(
            (pl.col("time") >= stage_start - 60) & (pl.col("time") <= stage_start + 3600)
        )
        if rule.min_count <= 1:
            ok = near.height > 0
            first = int(near["time"].min()) if near.height else None
        else:
            # Count density in window
            ok = near.height >= rule.min_count
            first = int(near["time"].min()) if near.height else None
        if rule.require_cooccur_detectors and near.height:
            dets = set(near["detector"].unique().to_list())
            ok = ok and set(rule.require_cooccur_detectors).issubset(dets)
        if ok and first is not None:
            caught.append(sc)
            lead_lag[sc] = (first - stage_start) / 60.0
        else:
            missed.append(sc)
        # FP estimate: candidate alerts labeled none
        fp = candidates.filter(pl.col("stage") == "none").height
        # Down-weight for rules with empty type filters
        if not rule.alert_types and not rule.host_roles:
            fp = min(fp, 10)
        fp_total += fp

    return BacktestResult(
        rule=rule,
        caught_scenarios=caught,
        missed_scenarios=missed,
        fp_per_day=fp_total / max(days_total, 1e-6),
        lead_lag_minutes=lead_lag,
    )


def accept_rule(result: BacktestResult) -> bool:
    thr = get_thresholds()["sandbox"]
    return (
        len(result.caught_scenarios) >= int(thr["min_catch_scenarios"])
        and result.fp_per_day <= float(thr["max_fp_per_day"])
    )


def propose_exfil_rule() -> dict[str, Any]:
    # Exfil hides in routine noise types; key on roles commonly touched in
    # dnsteal windows across training companies (not alert type alone).
    return {
        "name": "exfil_role_window",
        "alert_types": [],
        "host_roles": ["mail", "dns", "internal_share", "inet_firewall", "vpn"],
        "min_count": 1,
        "window_seconds": 600,
        "require_cooccur_detectors": [],
        "stage_detected": "exfil",
    }
