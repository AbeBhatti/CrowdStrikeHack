"""Recommendations never lose critical stage alerts."""

from __future__ import annotations

from recommend.tuning import UNSAFE_TYPES, build_recommendations


def test_no_suppress_loses_critical() -> None:
    recs = build_recommendations()
    assert any(r.type == "unsafe_to_suppress" and r.target_rule == "W-Acc-400" for r in recs)
    for r in recs:
        if r.type in {"retune_threshold", "schedule_or_fix_source", "scoped_exception"}:
            assert r.attack_stage_alerts_lost == 0
            assert r.target_rule not in UNSAFE_TYPES or r.type == "unsafe_to_suppress"
