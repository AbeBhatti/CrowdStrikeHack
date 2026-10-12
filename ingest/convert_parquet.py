"""Convert scenario CSVs to Parquet once under data/processed/."""

from __future__ import annotations

from pathlib import Path

import polars as pl

from common.config import ALL_SCENARIOS, project_root
from ingest.schema import normalize_frame

RAW = project_root() / "data" / "raw"
PROCESSED = project_root() / "data" / "processed"


def csv_path(scenario: str) -> Path:
    return RAW / f"{scenario}_alerts.txt"


def parquet_path(scenario: str) -> Path:
    return PROCESSED / f"{scenario}.parquet"


def convert_scenario(scenario: str, force: bool = False) -> Path:
    dest = parquet_path(scenario)
    if dest.exists() and not force:
        return dest
    src = csv_path(scenario)
    if not src.exists():
        raise FileNotFoundError(f"Missing CSV for {scenario}: {src}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    # AIT CSVs are comma-separated with header.
    df = pl.read_csv(src, infer_schema_length=10000)
    out = normalize_frame(df, scenario)
    out.write_parquet(dest, compression="zstd")
    return dest


def convert_all(force: bool = False) -> list[Path]:
    paths: list[Path] = []
    for scenario in ALL_SCENARIOS:
        paths.append(convert_scenario(scenario, force=force))
    # Combined index (metadata only counts; full concat optional)
    meta = []
    for scenario, path in zip(ALL_SCENARIOS, paths, strict=True):
        n = pl.scan_parquet(path).select(pl.len()).collect().item()
        meta.append({"scenario": scenario, "alerts": n, "path": str(path)})
    pl.DataFrame(meta).write_parquet(PROCESSED / "manifest.parquet")
    return paths


def load_scenario(scenario: str) -> pl.DataFrame:
    path = parquet_path(scenario)
    if not path.exists():
        convert_scenario(scenario)
    return pl.read_parquet(path)


def load_scenarios(scenarios: tuple[str, ...] | list[str]) -> pl.DataFrame:
    frames = [load_scenario(s) for s in scenarios]
    return pl.concat(frames, how="vertical_relaxed")


def main() -> None:
    paths = convert_all()
    print(f"Converted {len(paths)} scenarios to {PROCESSED}")


if __name__ == "__main__":
    main()
