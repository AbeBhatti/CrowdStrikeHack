"""Causal feature builder for relevance/stage scoring."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from common.config import STAGES
from common.stages import is_attack_stage


STAGE_INDEX = {s: i for i, s in enumerate(STAGES)}


def _new_recent_deque() -> deque[tuple[int, str, str, str]]:
    return deque(maxlen=10000)


def _new_recent_map() -> dict[str, deque[tuple[int, str, str, str]]]:
    return defaultdict(_new_recent_deque)


def _new_stage_map() -> dict[str, set[str]]:
    return defaultdict(set)


@dataclass
class FeatureState:
    """Per-source streaming state (causal)."""

    first_seen: dict[str, int] = field(default_factory=dict)
    recent: dict[str, deque[tuple[int, str, str, str]]] = field(default_factory=_new_recent_map)
    stages_seen: dict[str, set[str]] = field(default_factory=_new_stage_map)
    type_role_counts_train: dict[tuple[str, str], int] = field(default_factory=dict)
    type_role_total: int = 1

    def rarity(self, short: str, role: str) -> float:
        c = self.type_role_counts_train.get((short, role), 0)
        # Higher rarity => closer to 1
        return 1.0 - min(1.0, c / max(self.type_role_total / 1000.0, 1.0))


FEATURE_NAMES = [
    "noise_score",
    "is_wazuh",
    "is_suricata",
    "is_aminer",
    "cnt_1m",
    "cnt_5m",
    "cnt_30m",
    "distinct_roles_30m",
    "distinct_detectors_30m",
    "rarity",
    "minutes_since_first",
    "multi_detector_recent",
    "prior_recon",
    "prior_web_scan",
    "prior_webshell",
    "prior_cracking",
    "prior_reverse_shell",
    "prior_priv_esc",
    "prior_exfil",
    "burst_vs_baseline",
]


def fit_rarity_from_training(rows: list[dict[str, Any]]) -> FeatureState:
    state = FeatureState()
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for r in rows:
        counts[(str(r["short"]), str(r["host_role"]))] += 1
    state.type_role_counts_train = dict(counts)
    state.type_role_total = max(sum(counts.values()), 1)
    return state


def extract_features(
    alert: dict[str, Any],
    state: FeatureState,
    baseline_rate: float = 0.0,
) -> np.ndarray:
    source = str(alert.get("ip") or alert.get("host") or "unknown")
    ts = int(alert["time"])
    short = str(alert["short"])
    role = str(alert["host_role"])
    detector = str(alert.get("detector", "U"))
    noise = float(alert.get("noise_score", 0.0))
    stage_true = str(alert.get("stage", "none"))  # used only AFTER features for labels

    if source not in state.first_seen:
        state.first_seen[source] = ts
    minutes_since = (ts - state.first_seen[source]) / 60.0

    recent = state.recent[source]
    cutoff_30 = ts - 30 * 60
    while recent and recent[0][0] < cutoff_30:
        recent.popleft()

    def count_since(seconds: int) -> int:
        cut = ts - seconds
        return sum(1 for t, *_ in recent if t >= cut)

    roles_30 = {r for t, _s, r, _d in recent if t >= cutoff_30}
    dets_30 = {d for t, _s, _r, d in recent if t >= cutoff_30}
    roles_30.add(role)
    dets_30.add(detector)

    cnt_1 = count_since(60)
    cnt_5 = count_since(5 * 60)
    cnt_30 = count_since(30 * 60)
    # include current
    cnt_1 += 1
    cnt_5 += 1
    cnt_30 += 1

    prior = state.stages_seen[source]
    burst = 0.0
    if baseline_rate > 0:
        burst = cnt_30 / max(baseline_rate * 0.5, 1.0)  # rough

    vec = np.array(
        [
            noise,
            1.0 if detector == "W" else 0.0,
            1.0 if detector == "S" else 0.0,
            1.0 if detector == "A" else 0.0,
            float(cnt_1),
            float(cnt_5),
            float(cnt_30),
            float(len(roles_30)),
            float(len(dets_30)),
            state.rarity(short, role),
            float(minutes_since),
            1.0 if len(dets_30) >= 2 else 0.0,
            1.0 if "recon" in prior else 0.0,
            1.0 if "web_scan" in prior else 0.0,
            1.0 if "webshell" in prior else 0.0,
            1.0 if "cracking" in prior else 0.0,
            1.0 if "reverse_shell" in prior else 0.0,
            1.0 if "privilege_escalation" in prior else 0.0,
            1.0 if "exfil" in prior else 0.0,
            float(burst),
        ],
        dtype=np.float64,
    )

    # Update state AFTER feature extraction (causal)
    recent.append((ts, short, role, detector))
    if is_attack_stage(stage_true):
        # For training feature streams we update from labels after extraction.
        # During live inference, caller should update from predicted stage separately.
        state.stages_seen[source].add(stage_true)
    return vec


def update_predicted_stage(state: FeatureState, alert: dict[str, Any], stage: str) -> None:
    source = str(alert.get("ip") or alert.get("host") or "unknown")
    if is_attack_stage(stage):
        state.stages_seen[source].add(stage)
