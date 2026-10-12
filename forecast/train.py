"""Fit forecaster transition table and write reports/forecaster.md."""

from __future__ import annotations

from forecast.table import build_transition_table, forecast_next, save_table
from common.config import TRAINING_SCENARIOS, project_root


def main() -> None:
    table = build_transition_table(TRAINING_SCENARIOS)
    path = save_table(table)
    report = project_root() / "reports" / "forecaster.md"
    lines = [
        "# Forecaster",
        "",
        f"Training scenarios: {', '.join(TRAINING_SCENARIOS)}",
        "",
        "## Transitions",
        "",
    ]
    for src, dist in table["transitions"].items():
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(dist.items(), key=lambda x: -x[1]))
        lines.append(f"- {src} -> {parts}")
    lines += ["", "## Gaps (minutes)", ""]
    for k, g in table["gaps"].items():
        lines.append(f"- {k}: median={g['median']:.1f} min={g['min']:.1f} max={g['max']:.1f}")
    # Sanity: webshell should prefer reverse_shell
    fc = forecast_next(table, ["recon", "web_scan", "webshell"])
    lines += [
        "",
        f"After webshell, predicted next={fc.next_stage} p={fc.probability:.2f} "
        f"window={fc.window_minutes}",
        "",
    ]
    report.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {path} and {report}", flush=True)


if __name__ == "__main__":
    main()
