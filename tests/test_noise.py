"""Noise filter: tags, never drops; dnsteal window not all plain noise."""

from __future__ import annotations

from pathlib import Path

import polars as pl
import pytest

from common.config import TRAINING_SCENARIOS, project_root
from ingest.convert_parquet import load_scenario
from noise.filter import NoiseBaselines, NoiseFilter


@pytest.fixture(scope="module")
def baselines() -> NoiseBaselines:
    path = project_root() / "models" / "noise_baselines.json"
    if path.exists():
        return NoiseBaselines.load(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    b = NoiseBaselines.fit(TRAINING_SCENARIOS)
    b.save(str(path))
    return b


def test_noise_never_drops(baselines: NoiseBaselines) -> None:
    df = load_scenario("russellmitchell")
    nf = NoiseFilter(baselines)
    tagged = nf.tag_frame(df.head(2000))
    assert tagged.height == 2000
    assert "noise_score" in tagged.columns
    assert tagged["noise_score"].null_count() == 0


def test_periodic_clamav_tagged_noisy(baselines: NoiseBaselines) -> None:
    df = load_scenario("russellmitchell").filter(pl.col("short") == "W-Sys-Cav").head(50)
    nf = NoiseFilter(baselines)
    tagged = nf.tag_frame(df)
    # After a few observations, on-schedule clamav should be high noise
    assert tagged["noise_score"].mean() > 0.3


def test_dnsteal_window_not_all_plain_noise(baselines: NoiseBaselines) -> None:
    df = load_scenario("russellmitchell")
    dn = df.filter(pl.col("time_label") == "dnsteal")
    assert dn.height > 0
    nf = NoiseFilter(baselines)
    # Feed some prior context then the dnsteal window
    prior = df.filter(pl.col("time") < dn["time"].min()).tail(5000)
    for row in prior.to_dicts():
        nf.tag(row)
    scores = [nf.tag(row).noise_score for row in dn.to_dicts()]
    # Not all marked as plain high noise
    high = sum(1 for s in scores if s >= 0.7)
    assert high < len(scores), "dnsteal-window alerts must not all be plain noise"
    # At least some should look notable (low noise)
    low = sum(1 for s in scores if s < 0.5)
    assert low > 0
