"""Three relevance/stage methods: lookup, hand-written rules, logistic regression."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Protocol

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

from classifier.features import FEATURE_NAMES, FeatureState, extract_features
from common.config import STAGES, get_thresholds
from common.stages import is_attack_stage


class RelevanceMethod(Protocol):
    name: str

    def fit(self, alerts: list[dict[str, Any]], state: FeatureState) -> None: ...

    def predict(self, alert: dict[str, Any], state: FeatureState) -> tuple[float, str]:
        """Return (relevance_score, stage)."""
        ...


@dataclass
class LookupMethod:
    """Empirical P(attack|type) and majority stage per alert type."""

    name: str = "lookup"
    p_attack: dict[str, float] = field(default_factory=dict)
    stage_mode: dict[str, str] = field(default_factory=dict)

    def fit(self, alerts: list[dict[str, Any]], state: FeatureState) -> None:
        from classifier.leak_guard import assert_no_held_out_alerts

        assert_no_held_out_alerts(alerts, context="LookupMethod.fit")
        attack_c: dict[str, int] = defaultdict(int)
        total_c: dict[str, int] = defaultdict(int)
        stage_c: dict[str, Counter[str]] = defaultdict(Counter)
        for a in alerts:
            short = str(a["short"])
            stage = str(a["stage"])
            total_c[short] += 1
            if is_attack_stage(stage):
                attack_c[short] += 1
            stage_c[short][stage] += 1
        self.p_attack = {
            s: attack_c[s] / max(total_c[s], 1) for s in total_c
        }
        rare = {"webshell", "reverse_shell", "privilege_escalation", "exfil"}
        self.stage_mode = {}
        for s in total_c:
            counts = stage_c[s]
            if not counts:
                self.stage_mode[s] = "none"
                continue
            # Prefer attack-stage mode when the type is mostly attack-windowed;
            # boost rare stages slightly so shared noise codes do not bury them.
            attack_counts = {k: v for k, v in counts.items() if k != "none"}
            if self.p_attack[s] >= 0.25 and attack_counts:
                self.stage_mode[s] = max(
                    attack_counts,
                    key=lambda k: attack_counts[k] * (1.35 if k in rare else 1.0),
                )
            else:
                self.stage_mode[s] = counts.most_common(1)[0][0]

    def predict(self, alert: dict[str, Any], state: FeatureState) -> tuple[float, str]:
        short = str(alert["short"])
        score = float(self.p_attack.get(short, 0.0))
        stage = self.stage_mode.get(short, "none")
        if score < 0.05:
            stage = "none"
        return score, stage


# Fixed alert-type to stage mapping used by the rule method (written before eval).
SHORT_STAGE_HINTS: dict[str, str] = {
    # Populated lightly; rules also use time_label-independent type prefixes.
}


@dataclass
class RulesMethod:
    """Transparent weighted checklist over the same context features."""

    name: str = "rules"
    weights: dict[str, float] = field(default_factory=dict)
    cutoff: float = 0.45
    type_stage: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        cfg = get_thresholds().get("classifier", {}).get("rules", {})
        self.weights = {
            "distinct_roles": float(cfg.get("distinct_roles_weight", 0.15)),
            "distinct_detectors": float(cfg.get("distinct_detectors_weight", 0.15)),
            "rarity": float(cfg.get("rarity_weight", 0.2)),
            "burst": float(cfg.get("burst_weight", 0.2)),
            "noise_penalty": float(cfg.get("noise_penalty", 0.25)),
            "prior_stage": float(cfg.get("prior_stage_weight", 0.2)),
        }
        self.cutoff = float(cfg.get("relevant_cutoff", 0.45))

    def fit(self, alerts: list[dict[str, Any]], state: FeatureState) -> None:
        from classifier.leak_guard import assert_no_held_out_alerts

        assert_no_held_out_alerts(alerts, context="RulesMethod.fit")
        # Learn type->majority stage and tune cutoff on provided fold only.
        stage_c: dict[str, Counter[str]] = defaultdict(Counter)
        for a in alerts:
            stage_c[str(a["short"])][str(a["stage"])] += 1
        self.type_stage = {
            s: c.most_common(1)[0][0] for s, c in stage_c.items()
        }
        # Threshold tuning: pick cutoff maximizing rare-stage recall*precision proxy
        # using a small grid on the training fold alerts (no held-out).
        scores: list[tuple[float, str, str]] = []
        st = FeatureState(
            type_role_counts_train=state.type_role_counts_train,
            type_role_total=state.type_role_total,
        )
        for a in alerts:
            sc, pred = self._score(a, st, tune_cutoff=None)
            scores.append((sc, pred, str(a["stage"])))
            # advance state
            extract_features(a, st)
        best_cut = self.cutoff
        best_f = -1.0
        for cut in np.linspace(0.2, 0.8, 13):
            f = self._rare_f1(scores, float(cut))
            if f > best_f:
                best_f = f
                best_cut = float(cut)
        self.cutoff = best_cut

    def _rare_f1(self, scores: list[tuple[float, str, str]], cut: float) -> float:
        rares = ("webshell", "reverse_shell", "privilege_escalation")
        f1s = []
        for stage in rares:
            tp = fp = fn = 0
            for sc, pred, true in scores:
                p = pred if sc >= cut else "none"
                if p == stage and true == stage:
                    tp += 1
                elif p == stage and true != stage:
                    fp += 1
                elif p != stage and true == stage:
                    fn += 1
            prec = tp / max(tp + fp, 1)
            rec = tp / max(tp + fn, 1)
            f1s.append(0.0 if prec + rec == 0 else 2 * prec * rec / (prec + rec))
        return float(np.mean(f1s))

    def _score(
        self,
        alert: dict[str, Any],
        state: FeatureState,
        tune_cutoff: float | None,
    ) -> tuple[float, str]:
        vec = extract_features(alert, state)
        # indices from FEATURE_NAMES
        idx = {n: i for i, n in enumerate(FEATURE_NAMES)}
        w = self.weights
        score = 0.0
        score += w["distinct_roles"] * min(vec[idx["distinct_roles_30m"]] / 3.0, 1.0)
        score += w["distinct_detectors"] * min(vec[idx["distinct_detectors_30m"]] / 2.0, 1.0)
        score += w["rarity"] * vec[idx["rarity"]]
        score += w["burst"] * min(vec[idx["burst_vs_baseline"]] / 5.0, 1.0)
        score -= w["noise_penalty"] * vec[idx["noise_score"]]
        prior_bits = (
            vec[idx["prior_recon"]]
            + vec[idx["prior_web_scan"]]
            + vec[idx["prior_webshell"]]
            + vec[idx["prior_reverse_shell"]]
        )
        score += w["prior_stage"] * min(prior_bits / 2.0, 1.0)
        score = float(max(0.0, min(1.0, score)))

        short = str(alert["short"])
        stage = self.type_stage.get(short, "none")
        # Context upgrade: rare audit/auth after web activity => privilege escalation
        if vec[idx["prior_web_scan"]] or vec[idx["prior_webshell"]]:
            if short.startswith("W-Aut") or short.startswith("W-Sys") or "sudo" in str(
                alert.get("name", "")
            ).lower():
                if vec[idx["rarity"]] > 0.5:
                    stage = "privilege_escalation"
            if "shell" in str(alert.get("name", "")).lower() or short.startswith("A-"):
                if vec[idx["prior_webshell"]]:
                    stage = "reverse_shell"
        if score < (tune_cutoff if tune_cutoff is not None else self.cutoff):
            if stage not in {"webshell", "reverse_shell", "privilege_escalation", "exfil"}:
                stage = "none"
        return score, stage

    def predict(self, alert: dict[str, Any], state: FeatureState) -> tuple[float, str]:
        return self._score(alert, state, tune_cutoff=None)


@dataclass
class LogisticMethod:
    """Logistic regression on the shared causal feature vector."""

    name: str = "logistic"
    relevant_clf: Pipeline | None = None
    stage_clf: Pipeline | None = None
    stage_encoder: LabelEncoder = field(default_factory=LabelEncoder)
    downsample_dirb: float = 0.02
    downsample_wpscan: float = 0.1

    def fit(self, alerts: list[dict[str, Any]], state: FeatureState) -> None:
        from classifier.leak_guard import assert_no_held_out_alerts

        assert_no_held_out_alerts(alerts, context="LogisticMethod.fit")
        thr = get_thresholds().get("classifier", {})
        self.downsample_dirb = float(thr.get("dirb_keep_fraction", 0.02))
        self.downsample_wpscan = float(thr.get("wpscan_keep_fraction", 0.1))
        rng = np.random.default_rng(42)
        st = FeatureState(
            type_role_counts_train=state.type_role_counts_train,
            type_role_total=state.type_role_total,
        )
        xs: list[np.ndarray] = []
        y_rel: list[int] = []
        y_stage: list[str] = []
        for a in alerts:
            stage = str(a["stage"])
            if a.get("time_label") == "dirb" and rng.random() > self.downsample_dirb:
                extract_features(a, st)
                continue
            if a.get("time_label") == "wpscan" and rng.random() > self.downsample_wpscan:
                extract_features(a, st)
                continue
            x = extract_features(a, st)
            xs.append(x)
            y_rel.append(1 if is_attack_stage(stage) else 0)
            y_stage.append(stage if is_attack_stage(stage) else "none")
        X = np.vstack(xs)
        self.relevant_clf = Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=2000,
                        class_weight="balanced",
                        random_state=42,
                        solver="lbfgs",
                    ),
                ),
            ]
        )
        self.relevant_clf.fit(X, np.array(y_rel))
        # Fit encoder on observed labels plus full stage list for stability
        self.stage_encoder.fit(sorted(set(list(STAGES) + y_stage)))
        y_enc = self.stage_encoder.transform(y_stage)
        self.stage_clf = Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=2000,
                        class_weight="balanced",
                        random_state=42,
                        solver="lbfgs",
                    ),
                ),
            ]
        )
        self.stage_clf.fit(X, y_enc)

    def predict(self, alert: dict[str, Any], state: FeatureState) -> tuple[float, str]:
        assert self.relevant_clf is not None and self.stage_clf is not None
        x = extract_features(alert, state).reshape(1, -1)
        score = float(self.relevant_clf.predict_proba(x)[0][1])
        stage_i = int(self.stage_clf.predict(x)[0])
        stage = str(self.stage_encoder.inverse_transform([stage_i])[0])
        if score < 0.35:
            stage = "none"
        return score, stage

    def top_weights(
        self, stage: str, k: int = 10
    ) -> tuple[list[tuple[str, float]], list[tuple[str, float]]]:
        assert self.stage_clf is not None
        classes = list(self.stage_encoder.classes_)
        if stage not in classes:
            return [], []
        idx = classes.index(stage)
        coefs = self.stage_clf.named_steps["clf"].coef_[idx]
        pairs = list(zip(FEATURE_NAMES, coefs, strict=True))
        pos = sorted(pairs, key=lambda t: t[1], reverse=True)[:k]
        neg = sorted(pairs, key=lambda t: t[1])[:k]
        return [(n, float(v)) for n, v in pos], [(n, float(v)) for n, v in neg]


def make_method(name: str) -> RelevanceMethod:
    if name == "lookup":
        return LookupMethod()
    if name == "rules":
        return RulesMethod()
    if name == "logistic":
        return LogisticMethod()
    raise ValueError(f"Unknown method: {name}")
