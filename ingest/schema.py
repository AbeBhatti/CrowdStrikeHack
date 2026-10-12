"""Alert schema and column normalization."""

from __future__ import annotations

from typing import Literal

import polars as pl
from pydantic import BaseModel, Field

from common.hosts import host_to_role
from common.stages import resolve_stage

SCENARIOS = (
    "fox",
    "harrison",
    "russellmitchell",
    "santos",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
)

CSV_COLUMNS = ("time", "name", "ip", "host", "short", "time_label", "event_label")


class Alert(BaseModel):
    alert_id: str
    scenario: str
    time: int
    name: str
    ip: str
    host: str
    short: str
    time_label: str
    event_label: str
    detector: Literal["W", "S", "A", "U"]
    host_role: str
    stage: str
    noise_score: float = 0.0
    noise_reasons: list[str] = Field(default_factory=list)


def detector_from_short(short: str) -> Literal["W", "S", "A", "U"]:
    if not short:
        return "U"
    first = short[0].upper()
    if first in {"W", "S", "A"}:
        return first  # type: ignore[return-value]
    return "U"


def normalize_frame(df: pl.DataFrame, scenario: str) -> pl.DataFrame:
    """Normalize a raw scenario CSV frame to the project schema."""
    missing = [c for c in CSV_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"{scenario}: missing columns {missing}")

    out = df.select(
        pl.col("time").cast(pl.Int64),
        pl.col("name").cast(pl.Utf8).fill_null(""),
        pl.col("ip").cast(pl.Utf8).fill_null(""),
        pl.col("host").cast(pl.Utf8).fill_null(""),
        pl.col("short").cast(pl.Utf8).fill_null(""),
        pl.col("time_label").cast(pl.Utf8).fill_null("false_positive"),
        pl.col("event_label").cast(pl.Utf8).fill_null("-"),
    )
    # Stable alert_id: scenario + row ordinal after time sort
    out = out.sort("time").with_row_index("_row")
    hosts = out["host"].to_list()
    shorts = out["short"].to_list()
    time_labels = out["time_label"].to_list()
    event_labels = out["event_label"].to_list()
    roles = [host_to_role(h) for h in hosts]
    detectors = [detector_from_short(s) for s in shorts]
    stages = [resolve_stage(t, e) for t, e in zip(time_labels, event_labels, strict=True)]
    out = out.with_columns(
        pl.Series("scenario", [scenario] * out.height),
        pl.Series("host_role", roles),
        pl.Series("detector", detectors),
        pl.Series("stage", stages),
        pl.Series(
            "alert_id",
            [f"{scenario}-{i}" for i in out["_row"].to_list()],
        ),
    ).drop("_row")
    return out
