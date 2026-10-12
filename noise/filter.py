"""Causal noise filter: tags alerts, never drops them."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import polars as pl

from common.config import TRAINING_SCENARIOS, get_thresholds
from ingest.convert_parquet import load_scenarios


@dataclass
class NoiseResult:
    noise_score: float
    noise_reasons: list[str]


@dataclass
class NoiseBaselines:
    """Baselines fit on training scenarios only."""

    rate_per_hour: dict[tuple[str, str], float] = field(default_factory=dict)
    periodic_intervals: dict[tuple[str, str], float] = field(default_factory=dict)
    known_benign: set[str] = field(
        default_factory=lambda: {
            "W-Sys-Cav",  # ClamAV updates
            "W-Sys-Pac",  # package manager style
        }
    )

    @classmethod
    def fit(cls, scenarios: tuple[str, ...] = TRAINING_SCENARIOS) -> NoiseBaselines:
        df = load_scenarios(scenarios).sort(["scenario", "host_role", "short", "time"])
        obj = cls()
        # Rate baselines: alerts per hour per (short, host_role)
        for (short, role), group in df.group_by(["short", "host_role"]):
            times = group.sort("time")["time"]
            if times.len() < 2:
                continue
            span_h = max((times[-1] - times[0]) / 3600.0, 1 / 60)
            obj.rate_per_hour[(str(short), str(role))] = times.len() / span_h
        # Periodic: median inter-arrival when mostly constant (ClamAV ~5s)
        for (short, role, host, scenario), group in df.group_by(
            ["short", "host_role", "host", "scenario"]
        ):
            times = group.sort("time")["time"].to_list()
            if len(times) < 20:
                continue
            gaps = [times[i] - times[i - 1] for i in range(1, len(times))]
            gaps_sorted = sorted(gaps)
            med = gaps_sorted[len(gaps_sorted) // 2]
            # Low variance around median => periodic
            within = sum(1 for g in gaps if abs(g - med) <= 2)
            if med > 0 and within / len(gaps) >= 0.7 and med <= 120:
                key = (str(short), str(role))
                # Keep the most common interval seen
                prev = obj.periodic_intervals.get(key)
                if prev is None or med < prev:
                    obj.periodic_intervals[key] = float(med)
        return obj

    def save(self, path: str) -> None:
        import json
        from pathlib import Path

        Path(path).write_text(
            json.dumps(
                {
                    "rate_per_hour": {f"{a}|{b}": v for (a, b), v in self.rate_per_hour.items()},
                    "periodic_intervals": {
                        f"{a}|{b}": v for (a, b), v in self.periodic_intervals.items()
                    },
                    "known_benign": sorted(self.known_benign),
                }
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str) -> NoiseBaselines:
        import json
        from pathlib import Path

        data = json.loads(Path(path).read_text(encoding="utf-8"))
        obj = cls()
        obj.rate_per_hour = {
            tuple(k.split("|", 1)): float(v) for k, v in data["rate_per_hour"].items()  # type: ignore[misc]
        }
        obj.periodic_intervals = {
            tuple(k.split("|", 1)): float(v) for k, v in data["periodic_intervals"].items()  # type: ignore[misc]
        }
        obj.known_benign = set(data.get("known_benign", []))
        return obj


class NoiseFilter:
    """Streaming noise tagger. Causal: only past alerts + training baselines."""

    def __init__(self, baselines: NoiseBaselines | None = None) -> None:
        thr = get_thresholds()["noise"]
        self.periodic_tol = float(thr["periodic_tolerance_seconds"])
        self.burst_z = float(thr["baseline_burst_z"])
        self.learning_minutes = float(thr["learning_period_minutes"])
        self.baselines = baselines or NoiseBaselines()
        self._last_time: dict[tuple[str, str, str], int] = {}
        self._recent: dict[str, deque[tuple[int, str, str]]] = defaultdict(
            lambda: deque(maxlen=5000)
        )
        self._scenario_start: dict[str, int] = {}
        self._seen_type_role: set[tuple[str, str, str]] = set()

    def tag(self, alert: dict[str, Any]) -> NoiseResult:
        reasons: list[str] = []
        score = 0.0
        scenario = str(alert.get("scenario", ""))
        short = str(alert.get("short", ""))
        role = str(alert.get("host_role", "unknown"))
        host = str(alert.get("host", ""))
        detector = str(alert.get("detector", ""))
        ts = int(alert.get("time", 0))
        source = str(alert.get("ip", "")) or host

        if scenario not in self._scenario_start:
            self._scenario_start[scenario] = ts
        start = self._scenario_start[scenario]

        # Periodic on-schedule
        interval = self.baselines.periodic_intervals.get((short, role))
        key_last = (scenario, host, short)
        if interval is not None and key_last in self._last_time:
            gap = ts - self._last_time[key_last]
            if abs(gap - interval) <= self.periodic_tol:
                score += 0.45
                reasons.append(
                    f"periodic:on_schedule:{short}@{role}~{interval:.0f}s|"
                    f"Alert type {short} on {role} fired on its usual schedule"
                )
            else:
                reasons.append(
                    f"periodic:off_schedule:{short}|Off-schedule occurrence of usually periodic {short}"
                )
                score -= 0.1
        self._last_time[key_last] = ts

        # Baseline volume / burst
        base = self.baselines.rate_per_hour.get((short, role), 0.0)
        recent = self._recent[source]
        cutoff = ts - 3600
        while recent and recent[0][0] < cutoff:
            recent.popleft()
        hour_count = sum(1 for t, s, r in recent if s == short and r == role)
        recent.append((ts, short, role))
        if base > 0:
            expected = base  # per hour
            if hour_count > expected + self.burst_z * max(expected**0.5, 1.0):
                score -= 0.2
                reasons.append(
                    f"baseline:burst:{short}@{role}|Burst above baseline rate for {short} on {role}"
                )
            elif hour_count <= expected * 1.2:
                score += 0.25
                reasons.append(
                    f"baseline:normal_rate:{short}@{role}|Within normal rate for {short} on {role}"
                )
        else:
            # First-time type on this role in stream
            seen_key = (scenario, short, role)
            if seen_key not in self._seen_type_role:
                self._seen_type_role.add(seen_key)
                score -= 0.15
                reasons.append(
                    f"baseline:first_seen:{short}@{role}|First time seeing {short} on {role}"
                )

        # Known benign patterns
        if short in self.baselines.known_benign:
            score += 0.3
            reasons.append(
                f"benign_pattern:{short}|Known benign source pattern ({short})"
            )

        # AMiner learning-period novelty
        if detector == "A" and "New" in str(alert.get("name", "")):
            minutes = (ts - start) / 60.0
            if minutes <= self.learning_minutes:
                score += 0.35
                reasons.append(
                    "learning:aminer_novelty|"
                    "AMiner novelty alert during learning period"
                )

        # Clamp
        score = max(0.0, min(1.0, score))
        if not reasons:
            reasons.append("neutral:no_strong_signal|No strong noise or novelty signal")
        return NoiseResult(noise_score=score, noise_reasons=reasons)

    def tag_frame(self, df: pl.DataFrame) -> pl.DataFrame:
        scores: list[float] = []
        reasons: list[list[str]] = []
        for row in df.sort("time").to_dicts():
            res = self.tag(row)
            scores.append(res.noise_score)
            reasons.append(res.noise_reasons)
        return df.sort("time").with_columns(
            pl.Series("noise_score", scores),
            pl.Series("noise_reasons", reasons),
        )
