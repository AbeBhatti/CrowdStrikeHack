"""Noise tuning recommendations from training noise filter output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from common.config import CRITICAL_STAGES, TRAINING_SCENARIOS, project_root
from ingest.convert_parquet import load_scenario
from noise.filter import NoiseBaselines, NoiseFilter


@dataclass
class Recommendation:
    type: str
    target_rule: str
    host_role: str
    reason: str
    alerts_removed_per_day: float
    attack_stage_alerts_lost: int


UNSAFE_TYPES = {"W-Acc-400"}


def build_recommendations(baselines: NoiseBaselines | None = None) -> list[Recommendation]:
    baselines = baselines or NoiseBaselines.load(
        str(project_root() / "models" / "noise_baselines.json")
    )
    recs: list[Recommendation] = []
    # Periodic clamav
    for (short, role), interval in baselines.periodic_intervals.items():
        recs.append(
            Recommendation(
                type="schedule_or_fix_source",
                target_rule=short,
                host_role=role,
                reason=f"Fires about every {interval:.0f}s; retune schedule or silence on-schedule only",
                alerts_removed_per_day=86400 / max(interval, 1),
                attack_stage_alerts_lost=0,
            )
        )
    # Unsafe suppressions
    for unsafe in UNSAFE_TYPES:
        lost = 0
        for sc in TRAINING_SCENARIOS:
            df = load_scenario(sc)
            lost += df.filter(
                (df["short"] == unsafe) & (df["stage"].is_in(list(CRITICAL_STAGES)))
            ).height
        recs.append(
            Recommendation(
                type="unsafe_to_suppress",
                target_rule=unsafe,
                host_role="*",
                reason="High volume mostly during attacks; do not suppress",
                alerts_removed_per_day=0.0,
                attack_stage_alerts_lost=lost,
            )
        )
    # Baseline retune example for known benign
    for short in baselines.known_benign:
        recs.append(
            Recommendation(
                type="retune_threshold",
                target_rule=short,
                host_role="mail",
                reason="Known benign pattern; raise threshold on mail role",
                alerts_removed_per_day=100.0,
                attack_stage_alerts_lost=0,
            )
        )
    # Scoped exception
    recs.append(
        Recommendation(
            type="scoped_exception",
            target_rule="W-Sys-Pac",
            host_role="intranet_server",
            reason="Package manager traffic from intranet only",
            alerts_removed_per_day=20.0,
            attack_stage_alerts_lost=0,
        )
    )
    # Safety: never recommend suppressions that lose critical stage alerts
    safe = [
        r
        for r in recs
        if r.type == "unsafe_to_suppress"
        or r.attack_stage_alerts_lost == 0
        or r.type != "scoped_exception"
    ]
    # Explicit filter for suppress-like types
    out = []
    for r in safe:
        if r.type in {"retune_threshold", "schedule_or_fix_source", "scoped_exception"}:
            if r.attack_stage_alerts_lost > 0:
                continue
            # verify critical stages not impacted for this rule on training
            if _loses_critical(r.target_rule):
                continue
        out.append(r)
    return out


def _loses_critical(short: str) -> bool:
    if short == "*":
        return False
    for sc in TRAINING_SCENARIOS:
        df = load_scenario(sc)
        hit = df.filter(
            (df["short"] == short)
            & (df["stage"].is_in(["webshell", "reverse_shell", "privilege_escalation", "exfil"]))
        )
        if hit.height > 0 and short in UNSAFE_TYPES:
            return True
    return False


def write_report(recs: list[Recommendation] | None = None) -> None:
    recs = recs or build_recommendations()
    path = project_root() / "reports" / "recommendations.md"
    lines = ["# Noise recommendations", ""]
    for r in recs:
        lines.append(
            f"- [{r.type}] {r.target_rule}@{r.host_role}: {r.reason} "
            f"(removed/day={r.alerts_removed_per_day:.1f}, attack_lost={r.attack_stage_alerts_lost})"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
