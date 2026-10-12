"""Train the configured relevance/stage method and write reports/classifier.md."""

from __future__ import annotations

import json
from pathlib import Path

import joblib

from classifier.compare_methods import held_out_eval, main as compare_main
from classifier.features import fit_rarity_from_training
from classifier.methods import make_method
from common.config import TRAINING_SCENARIOS, get_thresholds, project_root, set_global_seed
from ingest.convert_parquet import load_scenario
from noise.filter import NoiseBaselines, NoiseFilter


def _tagged_training(baselines: NoiseBaselines) -> list[dict]:
    from classifier.compare_methods import _load_tagged

    rows: list[dict] = []
    for s in TRAINING_SCENARIOS:
        rows.extend(_load_tagged(s, baselines))
    return rows


def train_selected() -> Path:
    set_global_seed(42)
    thr = get_thresholds()
    method_name = str(thr.get("classifier", {}).get("method", "rules"))
    models = project_root() / "models"
    models.mkdir(parents=True, exist_ok=True)
    base_path = models / "noise_baselines.json"
    if not base_path.exists():
        b = NoiseBaselines.fit(TRAINING_SCENARIOS)
        b.save(str(base_path))
    else:
        b = NoiseBaselines.load(str(base_path))

    train_alerts = _tagged_training(b)
    rarity = fit_rarity_from_training(train_alerts)
    method = make_method(method_name)
    method.fit(train_alerts, rarity)

    artifact = {
        "method": method_name,
        "feature_list": list(__import__("classifier.features", fromlist=["FEATURE_NAMES"]).FEATURE_NAMES),
    }
    (models / "classifier_meta.json").write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    # Persist method without non-pickleable runtime state; rarity counts are enough.
    rarity_blob = {
        "type_role_counts_train": dict(rarity.type_role_counts_train),
        "type_role_total": rarity.type_role_total,
    }
    joblib.dump({"method": method, "rarity": rarity_blob}, models / "classifier.joblib")

    metrics = held_out_eval(method_name, b)
    report = project_root() / "reports" / "classifier.md"
    lines = [
        "# Classifier",
        "",
        f"Configured method: `{method_name}`",
        "",
        f"Rare-stage macro F1 (held-out): {metrics.rare_macro_f1:.3f}",
        f"Relevance PR-AUC: {metrics.relevance_pr_auc:.3f}",
        f"Alert reduction: {metrics.alert_reduction:.3f}",
        f"FP/day: {metrics.fp_per_day:.2f}",
        "",
        "## Per-stage F1 (held-out)",
        "",
    ]
    for s, v in sorted(metrics.per_stage_f1.items()):
        lines.append(
            f"- {s}: P={metrics.per_stage_precision.get(s, 0):.3f} "
            f"R={metrics.per_stage_recall.get(s, 0):.3f} F1={v:.3f}"
        )
    lines += ["", "## Detection latency (minutes)", ""]
    for stage, by_sc in metrics.detection_latency_min.items():
        parts = ", ".join(
            f"{sc}: {'miss' if val is None else f'{val:.1f}'}" for sc, val in by_sc.items()
        )
        lines.append(f"- {stage}: {parts}")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def main() -> None:
    # Ensure comparison exists; if not, run it (selects method into config).
    sel = project_root() / "models" / "method_selection.json"
    if not sel.exists():
        compare_main()
    train_selected()
    print("Classifier training complete.", flush=True)


if __name__ == "__main__":
    main()
