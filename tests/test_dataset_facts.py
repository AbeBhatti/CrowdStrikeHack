"""Assert published AIT-ADS facts after Parquet load."""

from __future__ import annotations

import pytest

from ingest.convert_parquet import parquet_path
from ingest.facts import (
    EXPECTED_DETECTORS,
    EXPECTED_NAMES,
    EXPECTED_PER_SCENARIO,
    EXPECTED_SHORT_CODES,
    EXPECTED_TIME_LABELS,
    EXPECTED_TOTAL,
    assert_dataset_facts,
    compute_facts,
)


@pytest.fixture(scope="module")
def facts():
    for s in EXPECTED_PER_SCENARIO:
        assert parquet_path(s).exists(), f"Run convert_parquet first for {s}"
    return compute_facts()


def test_eight_scenarios(facts) -> None:
    assert len(facts.per_scenario) == 8


def test_total_alerts(facts) -> None:
    assert facts.total == EXPECTED_TOTAL


def test_per_scenario_counts(facts) -> None:
    for s, n in EXPECTED_PER_SCENARIO.items():
        assert facts.per_scenario[s] == n


def test_detector_counts(facts) -> None:
    for d, n in EXPECTED_DETECTORS.items():
        assert facts.per_detector[d] == n


def test_short_and_name_cardinality(facts) -> None:
    assert facts.n_short == EXPECTED_SHORT_CODES
    assert facts.n_names == EXPECTED_NAMES


def test_time_labels(facts) -> None:
    assert EXPECTED_TIME_LABELS <= facts.time_labels


def test_assert_dataset_facts_helper(facts) -> None:
    assert_dataset_facts(facts)
