"""Small JSON detection rule language and schema validation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DetectionRule(BaseModel):
    id: str = ""
    name: str = "candidate"
    alert_types: list[str] = Field(default_factory=list)
    host_roles: list[str] = Field(default_factory=list)
    min_count: int = Field(default=1, ge=1)
    window_seconds: int = Field(default=300, ge=30)
    require_cooccur_detectors: list[str] = Field(default_factory=list)
    stage_detected: str
    origin_company: str = ""


def validate_rule(data: dict[str, Any]) -> DetectionRule:
    return DetectionRule.model_validate(data)


def rule_fires(rule: DetectionRule, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return alerts where the rule condition holds in a sliding sense (simple)."""
    hits: list[dict[str, Any]] = []
    typed = [
        a
        for a in alerts
        if (not rule.alert_types or a.get("short") in rule.alert_types)
        and (not rule.host_roles or a.get("host_role") in rule.host_roles)
    ]
    if not typed:
        return hits
    typed = sorted(typed, key=lambda a: int(a["time"]))
    for i, a in enumerate(typed):
        t0 = int(a["time"])
        window = [
            b
            for b in typed[i:]
            if int(b["time"]) - t0 <= rule.window_seconds
        ]
        if len(window) < rule.min_count:
            continue
        if rule.require_cooccur_detectors:
            dets = {b.get("detector") for b in window}
            if not set(rule.require_cooccur_detectors).issubset(dets):
                continue
        hits.append(a)
    return hits
