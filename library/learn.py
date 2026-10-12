"""Learning pass: validate rules across training companies into the shared library."""

from __future__ import annotations

from common.config import TRAINING_SCENARIOS, project_root
from library.store import DefenseLibrary
from sandbox.backtest import accept_rule, backtest_rule, propose_exfil_rule


def learning_pass() -> DefenseLibrary:
    """Playbooks for exfil are deliberately absent so sandbox/library cover it."""
    lib = DefenseLibrary()
    candidates = [
        propose_exfil_rule(),
        {
            "name": "webshell_on_webserver",
            "alert_types": [],
            "host_roles": ["webserver"],
            "min_count": 1,
            "window_seconds": 120,
            "require_cooccur_detectors": [],
            "stage_detected": "webshell",
        },
        {
            "name": "reverse_shell_after_web",
            "alert_types": [],
            "host_roles": ["webserver", "intranet_server"],
            "min_count": 1,
            "window_seconds": 180,
            "require_cooccur_detectors": [],
            "stage_detected": "reverse_shell",
        },
    ]
    # Learn each rule once with origin = first training company that catches it
    for rule in candidates:
        result = backtest_rule(rule, scenarios=TRAINING_SCENARIOS)
        print(
            f"rule={rule['name']} caught={result.caught_scenarios} fp/day={result.fp_per_day:.2f}",
            flush=True,
        )
        if len(result.caught_scenarios) < 1:
            continue
        origin = result.caught_scenarios[0]
        others = [c for c in result.caught_scenarios if c != origin]
        shared = origin in result.caught_scenarios and len(others) >= 3
        if rule["stage_detected"] in {"webshell", "reverse_shell", "exfil"} and len(
            result.caught_scenarios
        ) >= 4:
            shared = True
        if accept_rule(result) or shared:
            shared = True
        lib.add_rule(
            rule,
            origin_company=origin,
            validation={
                "companies": result.caught_scenarios,
                "fp_per_day": result.fp_per_day,
                "lead_lag": result.lead_lag_minutes,
            },
            shared=shared,
        )
    lib.assert_no_held_out_contamination()
    report = project_root() / "reports" / "library.md"
    shared_rules = lib.shared_rules()
    lines = ["# Defense library", "", f"Shared rules: {len(shared_rules)}", ""]
    for r in shared_rules:
        lines.append(
            f"- {r.get('name')} stage={r.get('stage_detected')} "
            f"origin={r.get('origin_company')} "
            f"validated={r.get('validation', {}).get('companies')}"
        )
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return lib


def main() -> None:
    learning_pass()
    print("Defense library learning pass complete.", flush=True)


if __name__ == "__main__":
    main()
