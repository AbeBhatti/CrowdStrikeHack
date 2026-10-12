"""Incident grouping tests."""

from __future__ import annotations

from incidents.group import IncidentGrouper, collapse_report
from ingest.convert_parquet import load_scenario


def test_groups_by_proximity() -> None:
    g = IncidentGrouper(proximity_seconds=60)
    alerts = [
        {
            "alert_id": "1",
            "time": 100,
            "ip": "1.1.1.1",
            "host": "webserver",
            "host_role": "webserver",
            "stage": "webshell",
        },
        {
            "alert_id": "2",
            "time": 130,
            "ip": "1.1.1.1",
            "host": "webserver",
            "host_role": "webserver",
            "stage": "reverse_shell",
        },
        {
            "alert_id": "3",
            "time": 1000,
            "ip": "1.1.1.1",
            "host": "webserver",
            "host_role": "webserver",
            "stage": "privilege_escalation",
        },
    ]
    incs = g.group_alerts(alerts)
    assert len(incs) == 2
    assert incs[0].stages == ["webshell", "reverse_shell"]


def test_exfil_separate_type() -> None:
    g = IncidentGrouper(proximity_seconds=900)
    alerts = [
        {
            "alert_id": "a",
            "time": 10,
            "ip": "2.2.2.2",
            "host": "mail",
            "host_role": "mail",
            "stage": "exfil",
        },
        {
            "alert_id": "b",
            "time": 20,
            "ip": "2.2.2.2",
            "host": "mail",
            "host_role": "mail",
            "stage": "webshell",
        },
    ]
    incs = g.group_alerts(alerts)
    types = {i.incident_type for i in incs}
    assert "exfil" in types
    assert "intrusion" in types


def test_russellmitchell_collapses() -> None:
    df = load_scenario("russellmitchell")
    # Use ground-truth attack stages as "relevant"
    alerts = df.filter(df["stage"] != "none").to_dicts()
    g = IncidentGrouper()
    incs = g.group_alerts(alerts)
    report = collapse_report("russellmitchell", alerts, incs)
    print(report)
    assert len(alerts) > 1000
    assert len(incs) < 50
    assert len(incs) >= 1
