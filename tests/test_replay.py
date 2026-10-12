"""Replay engine tests."""

from __future__ import annotations

import time

from ingest.replay import ReplayEngine


def test_replay_order_and_clock() -> None:
    eng = ReplayEngine(scenario="russellmitchell", speed=1e9, target_wall_seconds=None)
    eng.load()
    prev = -1
    count = 0
    for row in eng.iter_alerts(realtime=False, max_alerts=500):
        assert row["time"] >= prev
        assert eng.clock.now() == row["time"]
        prev = row["time"]
        count += 1
    assert count == 500


def test_replay_compresses_to_demo_budget() -> None:
    eng = ReplayEngine(
        scenario="russellmitchell",
        speed=1000.0,
        compress_gaps_above=0.01,
        target_wall_seconds=90.0,
    )
    eng.load()
    est = eng.replay_duration_estimate()
    assert est <= 90.0 + 1.0


def test_replay_seek_and_pause() -> None:
    eng = ReplayEngine(scenario="russellmitchell", speed=1e9, target_wall_seconds=None)
    df = eng.load()
    mid = int(df["time"][df.height // 2])
    eng.seek(mid)
    first = next(eng.iter_alerts(realtime=False, max_alerts=1))
    assert first["time"] >= mid


def test_full_russellmitchell_fast_wall_time() -> None:
    eng = ReplayEngine(
        scenario="russellmitchell",
        speed=1e12,
        compress_gaps_above=0.0,
        target_wall_seconds=None,
    )
    t0 = time.perf_counter()
    n = sum(1 for _ in eng.iter_alerts(realtime=False))
    elapsed = time.perf_counter() - t0
    assert n == 45_544
    assert elapsed < 30.0
