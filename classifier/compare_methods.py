"""Compare lookup, rules, and logistic methods; select from CV only."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import polars as pl
from sklearn.metrics import average_precision_score, precision_recall_fscore_support

from classifier.features import FeatureState, fit_rarity_from_training
from classifier.methods import LogisticMethod, LookupMethod, RulesMethod, make_method
from common.config import (
    CRITICAL_STAGES,
    HELD_OUT_SCENARIOS,
    TRAINING_SCENARIOS,
    get_thresholds,
    project_root,
    set_global_seed,
)
from common.stages import is_attack_stage
from ingest.convert_parquet import load_scenario
from noise.filter import NoiseBaselines, NoiseFilter

RARE = ("webshell", "reverse_shell", "privilege_escalation")
METHODS = ("lookup", "rules", "logistic")


@dataclass
class MethodMetrics:
    name: str
    per_stage_f1: dict[str, float] = field(default_factory=dict)
    per_stage_precision: dict[str, float] = field(default_factory=dict)
    per_stage_recall: dict[str, float] = field(default_factory=dict)
    rare_macro_f1: float = 0.0
    relevance_pr_auc: float = 0.0
    detection_latency_min: dict[str, dict[str, float | None]] = field(default_factory=dict)
    alert_reduction: float = 0.0
    fp_per_day: float = 0.0


def _load_tagged(scenario: str, baselines: NoiseBaselines) -> list[dict[str, Any]]:
    df = load_scenario(scenario).sort("time")
    # Keep all rare stages; heavily downsample web_scan and benign for laptop fit time.
    rare_stages = [
        "webshell",
        "reverse_shell",
        "privilege_escalation",
        "exfil",
        "cracking",
        "service_stop",
        "recon",
    ]
    rare = df.filter(pl.col("stage").is_in(rare_stages))
    web = df.filter(pl.col("stage") == "web_scan")
    if web.height > 3_000:
        web = web.sample(n=3_000, seed=42)
    benign = df.filter(pl.col("stage") == "none")
    if benign.height > 5_000:
        benign = benign.sample(n=5_000, seed=42)
    sample = pl.concat([rare, web, benign]).unique(subset=["alert_id"], keep="first").sort("time")
    nf = NoiseFilter(baselines)
    tagged = nf.tag_frame(sample)
    return tagged.to_dicts()


def _load_full_for_latency(scenario: str, baselines: NoiseBaselines) -> list[dict[str, Any]]:
    """Full chronological stream for detection latency (needed for first-hit timing)."""
    df = load_scenario(scenario).sort("time")
    # For latency we can skip pure early benign except last 2k before first attack
    first_attack = df.filter(pl.col("stage") != "none")["time"].min()
    if first_attack is None:
        return _load_tagged(scenario, baselines)
    early = df.filter(pl.col("time") < first_attack).tail(2000)
    rest = df.filter(pl.col("time") >= first_attack)
    rare = rest.filter(
        pl.col("stage").is_in(list(RARE) + ["exfil", "cracking", "service_stop", "recon"])
    )
    web = rest.filter(pl.col("stage") == "web_scan")
    if web.height > 5_000:
        web = web.sample(n=5_000, seed=42)
    other = rest.filter(
        ~pl.col("stage").is_in(
            list(RARE) + ["exfil", "cracking", "service_stop", "web_scan", "recon"]
        )
    )
    if other.height > 5_000:
        other = other.sample(n=5_000, seed=42)
    sample = pl.concat([early, rare, web, other]).unique(subset=["alert_id"], keep="first").sort(
        "time"
    )
    nf = NoiseFilter(baselines)
    return nf.tag_frame(sample).to_dicts()


def _phase_start(alerts: list[dict[str, Any]], stage: str) -> int | None:
    times = [int(a["time"]) for a in alerts if a.get("time_label") == _time_label_for(stage) or a.get("stage") == stage]
    # Prefer time_label window starts from data
    tl = {
        "webshell": "webshell",
        "reverse_shell": "reverse_shell",
        "privilege_escalation": "privilege_escalation",
    }[stage]
    times = [int(a["time"]) for a in alerts if a.get("time_label") == tl]
    return min(times) if times else None


def _time_label_for(stage: str) -> str:
    return {
        "webshell": "webshell",
        "reverse_shell": "reverse_shell",
        "privilege_escalation": "privilege_escalation",
    }[stage]


def evaluate_method(
    method_name: str,
    train_alerts: list[dict[str, Any]],
    eval_alerts_by_scenario: dict[str, list[dict[str, Any]]],
    rarity_state: FeatureState,
) -> MethodMetrics:
    method = make_method(method_name)
    method.fit(train_alerts, rarity_state)

    y_true_stage: list[str] = []
    y_pred_stage: list[str] = []
    y_true_rel: list[int] = []
    y_score: list[float] = []
    surfaced = 0
    total = 0
    fp_benign = 0
    benign_span_s = 0

    latency: dict[str, dict[str, float | None]] = {
        s: {sc: None for sc in eval_alerts_by_scenario} for s in RARE
    }

    for scenario, alerts in eval_alerts_by_scenario.items():
        st = FeatureState(
            type_role_counts_train=rarity_state.type_role_counts_train,
            type_role_total=rarity_state.type_role_total,
        )
        phase_starts = {s: _phase_start(alerts, s) for s in RARE}
        first_hit: dict[str, int | None] = {s: None for s in RARE}
        times = [int(a["time"]) for a in alerts]
        span = (max(times) - min(times)) if times else 1

        for a in alerts:
            score, pred = method.predict(a, st)
            true = str(a["stage"])
            y_true_stage.append(true)
            y_pred_stage.append(pred)
            y_true_rel.append(1 if is_attack_stage(true) else 0)
            y_score.append(score)
            total += 1
            if score >= 0.45 and pred != "none":
                surfaced += 1
                if not is_attack_stage(true):
                    fp_benign += 1
            for s in RARE:
                if first_hit[s] is None and pred == s and true == s:
                    first_hit[s] = int(a["time"])

        for s in RARE:
            ps = phase_starts[s]
            fh = first_hit[s]
            if ps is not None and fh is not None:
                latency[s][scenario] = (fh - ps) / 60.0
            else:
                latency[s][scenario] = None
        benign_span_s += span

    labels = sorted(set(y_true_stage) | set(y_pred_stage))
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true_stage, y_pred_stage, labels=labels, average=None, zero_division=0
    )
    per_f1 = dict(zip(labels, map(float, f1), strict=True))
    per_p = dict(zip(labels, map(float, prec), strict=True))
    per_r = dict(zip(labels, map(float, rec), strict=True))
    rare_f1 = float(np.mean([per_f1.get(s, 0.0) for s in RARE]))
    try:
        pr_auc = float(average_precision_score(y_true_rel, y_score))
    except ValueError:
        pr_auc = 0.0
    days = max(benign_span_s / 86400.0, 1 / 24)
    return MethodMetrics(
        name=method_name,
        per_stage_f1=per_f1,
        per_stage_precision=per_p,
        per_stage_recall=per_r,
        rare_macro_f1=rare_f1,
        relevance_pr_auc=pr_auc,
        detection_latency_min=latency,
        alert_reduction=1.0 - (surfaced / max(total, 1)),
        fp_per_day=fp_benign / days,
    )


def group_kfold_cv(baselines: NoiseBaselines) -> dict[str, list[MethodMetrics]]:
    """Leave-one-scenario-out CV on training scenarios only."""
    set_global_seed(42)
    # Guard: never touch held-out here
    assert set(TRAINING_SCENARIOS).isdisjoint(HELD_OUT_SCENARIOS)

    cached = {s: _load_tagged(s, baselines) for s in TRAINING_SCENARIOS}
    results: dict[str, list[MethodMetrics]] = {m: [] for m in METHODS}

    for hold in TRAINING_SCENARIOS:
        train_sc = [s for s in TRAINING_SCENARIOS if s != hold]
        train_alerts: list[dict[str, Any]] = []
        for s in train_sc:
            train_alerts.extend(cached[s])
        rarity = fit_rarity_from_training(train_alerts)
        eval_map = {hold: _load_full_for_latency(hold, baselines)}
        for m in METHODS:
            metrics = evaluate_method(m, train_alerts, eval_map, rarity)
            results[m].append(metrics)
            print(f"CV hold={hold} method={m} rare_f1={metrics.rare_macro_f1:.3f}", flush=True)
    return results


def mean_rare_f1(ms: list[MethodMetrics]) -> float:
    return float(np.mean([m.rare_macro_f1 for m in ms]))


def choose_method(cv: dict[str, list[MethodMetrics]]) -> tuple[str, str]:
    scores = {m: mean_rare_f1(cv[m]) for m in METHODS}
    # Prefer logistic if it beats rules by >= 0.03; else rules if competitive; else best
    log_f = scores["logistic"]
    rules_f = scores["rules"]
    lookup_f = scores["lookup"]
    if log_f >= rules_f + 0.03 and log_f >= lookup_f:
        return "logistic", (
            f"logistic rare-stage CV F1 {log_f:.3f} beats rules {rules_f:.3f} by "
            f">=0.03 (lookup {lookup_f:.3f})"
        )
    if rules_f >= lookup_f:
        reason = (
            f"rules rare-stage CV F1 {rules_f:.3f} vs logistic {log_f:.3f} "
            f"(delta {log_f - rules_f:.3f} < 0.03); prefer explainable rules"
            if log_f < rules_f + 0.03
            else f"rules rare-stage CV F1 {rules_f:.3f} best among explainable"
        )
        return "rules", reason
    return "lookup", f"lookup rare-stage CV F1 {lookup_f:.3f} best"


def held_out_eval(
    method_name: str, baselines: NoiseBaselines
) -> MethodMetrics:
    train_alerts: list[dict[str, Any]] = []
    for s in TRAINING_SCENARIOS:
        train_alerts.extend(_load_tagged(s, baselines))
    rarity = fit_rarity_from_training(train_alerts)
    eval_map = {s: _load_full_for_latency(s, baselines) for s in HELD_OUT_SCENARIOS}
    return evaluate_method(method_name, train_alerts, eval_map, rarity)


def write_report(
    cv: dict[str, list[MethodMetrics]],
    chosen: str,
    reason: str,
    held: dict[str, MethodMetrics],
) -> Path:
    path = project_root() / "reports" / "method_comparison.md"
    lines = [
        "# Method comparison",
        "",
        "Same splits: GroupKFold k=6 by scenario on training; final on russellmitchell and santos.",
        "",
        f"**Selected method:** `{chosen}`",
        f"**Reason:** {reason}",
        "",
        "## CV rare-stage macro F1 (mean +/- std)",
        "",
        "| method | rare_macro_f1 | relevance_pr_auc | alert_reduction |",
        "| --- | ---: | ---: | ---: |",
    ]
    for m in METHODS:
        f1s = [x.rare_macro_f1 for x in cv[m]]
        aucs = [x.relevance_pr_auc for x in cv[m]]
        reds = [x.alert_reduction for x in cv[m]]
        lines.append(
            f"| {m} | {np.mean(f1s):.3f} +/- {np.std(f1s):.3f} | "
            f"{np.mean(aucs):.3f} +/- {np.std(aucs):.3f} | "
            f"{np.mean(reds):.3f} +/- {np.std(reds):.3f} |"
        )
    lines += ["", "## Held-out per-stage recall", "", "| method | webshell | reverse_shell | privilege_escalation | pr_auc |", "| --- | ---: | ---: | ---: | ---: |"]
    for m, met in held.items():
        lines.append(
            f"| {m} | {met.per_stage_recall.get('webshell', 0):.3f} | "
            f"{met.per_stage_recall.get('reverse_shell', 0):.3f} | "
            f"{met.per_stage_recall.get('privilege_escalation', 0):.3f} | "
            f"{met.relevance_pr_auc:.3f} |"
        )
    lines += ["", "## Held-out detection latency (minutes)", ""]
    for m, met in held.items():
        lines.append(f"### {m}")
        for stage, by_sc in met.detection_latency_min.items():
            parts = ", ".join(
                f"{sc}: {'miss' if v is None else f'{v:.1f}'}" for sc, v in by_sc.items()
            )
            lines.append(f"- {stage}: {parts}")
        lines.append("")

    # ASCII chart of per-stage recall
    lines += ["## Chart: per-stage recall by method (held-out)", "", "```"]
    for stage in RARE:
        lines.append(stage)
        for m, met in held.items():
            r = met.per_stage_recall.get(stage, 0.0)
            bar = "#" * int(round(r * 40))
            lines.append(f"  {m:10} {r:5.2f} |{bar}")
    lines += ["```", ""]

    # PR-AUC as simple bars (ranking quality)
    lines += ["## Chart: relevance PR-AUC by method (held-out)", "", "```"]
    for m, met in held.items():
        bar = "#" * int(round(met.relevance_pr_auc * 40))
        lines.append(f"  {m:10} {met.relevance_pr_auc:5.2f} |{bar}")
    lines += ["```", ""]

    log = held.get("logistic")
    if isinstance(log, MethodMetrics):
        # Re-fit briefly for weights report on training only
        lines += ["## Logistic top weights (critical stages)", ""]
        train_alerts = []
        for s in TRAINING_SCENARIOS:
            train_alerts.extend(_load_tagged(s, NoiseBaselines.load(str(project_root() / "models" / "noise_baselines.json"))))
        rarity = fit_rarity_from_training(train_alerts)
        lm = LogisticMethod()
        lm.fit(train_alerts, rarity)
        for stage in RARE:
            pos, neg = lm.top_weights(stage, 10)
            lines.append(f"### {stage}")
            lines.append("Positive: " + ", ".join(f"{n} ({v:.2f})" for n, v in pos))
            lines.append("Negative: " + ", ".join(f"{n} ({v:.2f})" for n, v in neg))
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def update_config_and_decisions(chosen: str, reason: str) -> None:
    thr_path = project_root() / "config" / "thresholds.yaml"
    text = thr_path.read_text(encoding="utf-8")
    import re

    text2, n = re.subn(r"(classifier:\n(?:.*\n)*?\s*method:\s*)\S+", rf"\1{chosen}", text, count=1)
    if n == 0:
        text2 = text.replace("method: rules", f"method: {chosen}")
    thr_path.write_text(text2, encoding="utf-8")
    get_thresholds.cache_clear()

    dec = project_root() / "DECISIONS.md"
    line = f"- Classifier method selected: {chosen} ({reason})."
    existing = dec.read_text(encoding="utf-8")
    if "Classifier method selected:" not in existing:
        dec.write_text(existing.rstrip() + "\n" + line + "\n", encoding="utf-8")
    else:
        import re as _re

        dec.write_text(_re.sub(r"- Classifier method selected:.*", line, existing), encoding="utf-8")

    # Persist selection artifact
    (project_root() / "models").mkdir(parents=True, exist_ok=True)
    (project_root() / "models" / "method_selection.json").write_text(
        json.dumps({"method": chosen, "reason": reason}), encoding="utf-8"
    )


def main() -> None:
    set_global_seed(42)
    base_path = project_root() / "models" / "noise_baselines.json"
    if not base_path.exists():
        b = NoiseBaselines.fit(TRAINING_SCENARIOS)
        base_path.parent.mkdir(parents=True, exist_ok=True)
        b.save(str(base_path))
    else:
        b = NoiseBaselines.load(str(base_path))

    print("Running GroupKFold CV...", flush=True)
    cv = group_kfold_cv(b)
    chosen, reason = choose_method(cv)
    print(f"CHOSEN={chosen} REASON={reason}", flush=True)

    held: dict[str, MethodMetrics] = {}
    for m in METHODS:
        print(f"Held-out eval {m}...", flush=True)
        held[m] = held_out_eval(m, b)

    write_report(cv, chosen, reason, held)
    update_config_and_decisions(chosen, reason)
    print("Wrote reports/method_comparison.md", flush=True)


if __name__ == "__main__":
    main()
