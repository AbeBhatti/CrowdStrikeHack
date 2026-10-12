"""Timestamp-ordered alert replay with compressed empty stretches."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import polars as pl

from ingest.convert_parquet import load_scenario


@dataclass
class ReplayClock:
    """Replay-time clock shared by forecaster, decoys, and on-call rate limits."""

    scenario_start: int = 0
    current_ts: int = 0
    wall_started: float = 0.0
    speed: float = 1.0

    def now(self) -> int:
        return self.current_ts

    def elapsed_scenario_seconds(self) -> int:
        return max(0, self.current_ts - self.scenario_start)


@dataclass
class ReplayEngine:
    scenario: str
    speed: float = 1.0
    compress_gaps_above: float = 5.0  # wall seconds; larger gaps are compressed
    target_wall_seconds: float | None = 90.0
    clock: ReplayClock = field(default_factory=ReplayClock)
    _df: pl.DataFrame | None = None
    _paused: bool = False
    _index: int = 0

    def load(self) -> pl.DataFrame:
        df = load_scenario(self.scenario).sort("time")
        self._df = df
        if df.height:
            self.clock.scenario_start = int(df["time"][0])
            self.clock.current_ts = self.clock.scenario_start
        self.clock.speed = self.speed
        self._index = 0
        return df

    def seek(self, timestamp: int) -> None:
        assert self._df is not None
        times = self._df["time"].to_list()
        # First index with time >= timestamp
        idx = 0
        for i, t in enumerate(times):
            if t >= timestamp:
                idx = i
                break
            idx = i + 1
        self._index = idx
        self.clock.current_ts = timestamp

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    def _gap_sleep(self, prev_ts: int, next_ts: int, scale: float) -> None:
        if self.speed <= 0:
            return
        gap = max(0, next_ts - prev_ts)
        wall = gap / self.speed * scale
        if wall > self.compress_gaps_above:
            wall = self.compress_gaps_above
        while wall > 0:
            if not self._paused:
                chunk = min(0.05, wall)
                time.sleep(chunk)
                wall -= chunk
            else:
                time.sleep(0.05)

    def iter_alerts(
        self,
        on_alert: Callable[[dict], None] | None = None,
        max_alerts: int | None = None,
        realtime: bool = True,
    ) -> Iterator[dict]:
        if self._df is None:
            self.load()
        assert self._df is not None
        df = self._df
        n = df.height
        if n == 0:
            return

        # Auto-scale so full scenario fits target_wall_seconds when set.
        scale = 1.0
        if self.target_wall_seconds and realtime and self.speed > 0:
            span = int(df["time"][-1]) - int(df["time"][0])
            # Rough: many tiny gaps; use mean inter-arrival as basis.
            # Better: compute how long naive replay would take with compression.
            # We pick speed so empty stretches collapse and total ~ target.
            # Effective: treat each gap capped at compress_gaps_above / speed.
            times = df["time"].to_list()
            est = 0.0
            for i in range(1, len(times)):
                g = (times[i] - times[i - 1]) / self.speed
                est += min(g, self.compress_gaps_above)
            if est > 0:
                scale = min(1.0, self.target_wall_seconds / est)

        self.clock.wall_started = time.perf_counter()
        prev_ts = int(df["time"][self._index]) if self._index < n else 0
        emitted = 0
        cols = df.columns
        rows = df.to_dicts()
        while self._index < n:
            while self._paused:
                time.sleep(0.05)
            row = rows[self._index]
            ts = int(row["time"])
            if realtime and self._index > 0:
                self._gap_sleep(prev_ts, ts, scale)
            self.clock.current_ts = ts
            prev_ts = ts
            self._index += 1
            emitted += 1
            if on_alert:
                on_alert(row)
            yield row
            if max_alerts is not None and emitted >= max_alerts:
                break

    def replay_duration_estimate(self) -> float:
        """Estimate wall seconds at current speed with gap compression."""
        if self._df is None:
            self.load()
        assert self._df is not None
        times = self._df["time"].to_list()
        if len(times) < 2:
            return 0.0
        est = 0.0
        for i in range(1, len(times)):
            g = (times[i] - times[i - 1]) / max(self.speed, 1e-9)
            est += min(g, self.compress_gaps_above)
        if self.target_wall_seconds and est > self.target_wall_seconds:
            return self.target_wall_seconds
        return est
