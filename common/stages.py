"""Stage label mapping from AIT-ADS time_label / event_label."""

from __future__ import annotations

from common.config import EVENT_LABEL_TO_STAGE, TIME_LABEL_TO_STAGE


def resolve_stage(time_label: str | None, event_label: str | None) -> str:
    """Prefer event_label when present and not '-'; else map time_label.

    Window labels tag every alert inside an attack window, including routine
    noise. Preferring event_label reduces that contamination when available.
    """
    ev = (event_label or "-").strip()
    if ev and ev != "-":
        mapped = EVENT_LABEL_TO_STAGE.get(ev)
        if mapped:
            return mapped
    tl = (time_label or "false_positive").strip()
    return TIME_LABEL_TO_STAGE.get(tl, "none")


def is_attack_stage(stage: str) -> bool:
    return stage not in {"none", ""}
