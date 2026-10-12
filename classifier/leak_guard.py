"""Guards that training paths never ingest held-out scenarios."""

from __future__ import annotations

from typing import Any, Iterable

from common.config import HELD_OUT_SCENARIOS


def assert_no_held_out_alerts(alerts: Iterable[dict[str, Any]], *, context: str = "") -> None:
    bad = sorted({str(a.get("scenario", "")) for a in alerts} & set(HELD_OUT_SCENARIOS))
    if bad:
        raise AssertionError(
            f"held-out scenario(s) {bad} used during training/tuning{': ' + context if context else ''}"
        )


def assert_no_held_out_names(scenarios: Iterable[str], *, context: str = "") -> None:
    bad = sorted(set(scenarios) & set(HELD_OUT_SCENARIOS))
    if bad:
        raise AssertionError(
            f"held-out scenario(s) {bad} used during training/tuning{': ' + context if context else ''}"
        )
