"""Dataset fact verification against the published AIT-ADS numbers."""

from __future__ import annotations

from dataclasses import dataclass

import polars as pl

from common.config import ALL_SCENARIOS
from ingest.convert_parquet import load_scenario, load_scenarios

EXPECTED_TOTAL = 2_655_821
EXPECTED_PER_SCENARIO = {
    "fox": 473_104,
    "harrison": 593_948,
    "russellmitchell": 45_544,
    "santos": 130_779,
    "shaw": 70_782,
    "wardbeck": 91_257,
    "wheeler": 616_161,
    "wilson": 634_246,
}
EXPECTED_DETECTORS = {"W": 2_293_628, "S": 306_635, "A": 55_558}
EXPECTED_SHORT_CODES = 75
EXPECTED_NAMES = 93
EXPECTED_TIME_LABELS = {
    "false_positive",
    "network_scans",
    "service_scans",
    "dirb",
    "wpscan",
    "webshell",
    "cracking",
    "reverse_shell",
    "privilege_escalation",
    "service_stop",
    "dnsteal",
}


@dataclass
class DatasetFacts:
    total: int
    per_scenario: dict[str, int]
    per_detector: dict[str, int]
    n_short: int
    n_names: int
    time_labels: set[str]


def compute_facts() -> DatasetFacts:
    frames = []
    per_scenario: dict[str, int] = {}
    for s in ALL_SCENARIOS:
        df = load_scenario(s)
        per_scenario[s] = df.height
        frames.append(df.select(["short", "name", "detector", "time_label"]))
    all_df = pl.concat(frames)
    per_detector = {
        k: int(v)
        for k, v in all_df.group_by("detector").len().iter_rows()
    }
    return DatasetFacts(
        total=all_df.height,
        per_scenario=per_scenario,
        per_detector=per_detector,
        n_short=all_df["short"].n_unique(),
        n_names=all_df["name"].n_unique(),
        time_labels=set(all_df["time_label"].unique().to_list()),
    )


def assert_dataset_facts(facts: DatasetFacts | None = None) -> DatasetFacts:
    facts = facts or compute_facts()
    assert len(ALL_SCENARIOS) == 8
    assert facts.total == EXPECTED_TOTAL, f"total {facts.total} != {EXPECTED_TOTAL}"
    for s, n in EXPECTED_PER_SCENARIO.items():
        assert facts.per_scenario[s] == n, f"{s}: {facts.per_scenario[s]} != {n}"
    for d, n in EXPECTED_DETECTORS.items():
        got = facts.per_detector.get(d, 0)
        assert got == n, f"detector {d}: {got} != {n}"
    assert facts.n_short == EXPECTED_SHORT_CODES
    assert facts.n_names == EXPECTED_NAMES
    assert EXPECTED_TIME_LABELS <= facts.time_labels
    return facts
