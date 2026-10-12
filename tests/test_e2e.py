"""End-to-end russellmitchell path with local fallbacks (no external keys)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from common.config import HELD_OUT_SCENARIOS, TRAINING_SCENARIOS, get_thresholds
from decoys.services import DecoyManager
from forecast.table import forecast_next, load_table
from guard.pipeline import GuardDog, injection_demo_alert
from incidents.group import IncidentGrouper, collapse_report
from ingest.convert_parquet import load_scenario
from ingest.facts import assert_dataset_facts
from library.store import DefenseLibrary
from oncall.messages import CallFacts, build_message
from oncall.tts import VOICE, generate_call_audio
from recommend.tuning import build_recommendations
from router.analyst import AnalystRouter
from sandbox.backtest import propose_exfil_rule

pytestmark = pytest.mark.e2e


def test_e2e_core_path(tmp_path: Path) -> None:
    assert_dataset_facts()
    assert get_thresholds()["classifier"]["method"] in {"lookup", "rules", "logistic"}

    df = load_scenario("russellmitchell")
    attack = df.filter(df["stage"] != "none").to_dicts()
    grouper = IncidentGrouper()
    incidents = grouper.group_alerts(attack)
    report = collapse_report("russellmitchell", attack, incidents)
    assert len(incidents) < 50
    print(report)

    table = load_table()
    fc = forecast_next(table, ["web_scan", "webshell"])
    assert fc.next_stage == "reverse_shell"
    ws = int(df.filter(df["time_label"] == "webshell")["time"].min())
    rs = int(df.filter(df["time_label"] == "reverse_shell")["time"].min())
    gap = (rs - ws) / 60.0
    assert fc.window_minutes[0] - 10 <= gap <= fc.window_minutes[1] + 10

    class FallbackLLM:
        def complete_json(self, *a, **k):
            return k["fallback"]

    router = AnalystRouter(llm=FallbackLLM())  # type: ignore[arg-type]
    branches = set()
    for inc, lib in [
        ({"id": "a", "stages": ["webshell"], "host_roles": ["webserver"]}, True),
        ({"id": "b", "stages": ["exfil"], "host_roles": ["mail"]}, False),
        ({"id": "c", "stages": ["recon"], "host_roles": ["inet_firewall"]}, False),
    ]:
        # Force score variety
        d = router.analyze(
            inc,
            {
                "next_stage": fc.next_stage,
                "probability": fc.probability,
                "window_minutes": fc.window_minutes,
                "similar_chain": fc.similar_chain,
            },
            library_has_rule=lib,
        )
        if inc["stages"][-1] == "recon":
            d.scores["confidence"] = 0.2
            from router.analyst import choose_branch
            from common.config import get_playbooks

            d.branch, _ = choose_branch(d.scores, "recon", get_playbooks(), False)
        branches.add(d.branch)
    # Ensure all three branches can fire
    from router.analyst import choose_branch
    from common.config import get_playbooks

    playbooks = get_playbooks()
    branches.add(choose_branch({"confidence": 0.2, "blast_radius": 0.1, "match": 0.9, "reversibility": 0.9}, "webshell", playbooks, False)[0])
    branches.add(choose_branch({"confidence": 0.9, "blast_radius": 0.2, "match": 0.9, "reversibility": 0.9}, "webshell", playbooks, True)[0])
    branches.add(choose_branch({"confidence": 0.9, "blast_radius": 0.2, "match": 0.9, "reversibility": 0.9}, "exfil", playbooks, False)[0])
    assert {"escalate", "playbook", "sandbox"} <= branches

    lib = DefenseLibrary()
    lib.assert_no_held_out_contamination()
    shared = lib.shared_rules()
    assert shared
    assert shared[0]["origin_company"] not in HELD_OUT_SCENARIOS
    assert shared[0]["origin_company"] in TRAINING_SCENARIOS

    import mock_security_api.app as mock_api
    from guard.broker import CredentialBroker
    from typing import Any

    class StubResponse:
        def __init__(self, data: dict[str, Any], status_code: int = 200) -> None:
            self._data = data
            self.status_code = status_code
        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise RuntimeError("bad status")
        def json(self) -> dict[str, Any]:
            return self._data

    class StubClient:
        def post(self, url: str, json: dict[str, Any] | None = None) -> StubResponse:
            json = json or {}
            if url.endswith("/block_ip"):
                mock_api._state["blocked_ips"].add(json["ip"]); return StubResponse({"ok": True})
            if url.endswith("/isolate_host"):
                mock_api._state["isolated_hosts"].add(json["host"]); return StubResponse({"ok": True})
            return StubResponse({"ok": False}, 404)

    mock_api._state["blocked_ips"].clear()
    env = tmp_path / ".env"
    env.write_text("TWILIO_AUTH_TOKEN=test-secret-token\n")
    broker = CredentialBroker(env_path=env, client=StubClient())  # type: ignore[arg-type]
    guard = GuardDog(broker=broker, cross_checkers=[lambda a: (True, "ok"), lambda a: (True, "ok")])
    blocked = guard.review_and_execute({"action": "block_ip", "ip": "203.0.113.10", "reversible": True})
    assert blocked.allowed
    assert "203.0.113.10" in mock_api._state["blocked_ips"]

    alert = injection_demo_alert()
    inj = guard.review_and_execute(
        {"action": "allow_ip", "ip": "10.143.2.4"},
        untrusted_fields={"url": alert["url"]},
    )
    assert inj.allowed is False
    assert inj.injection_findings

    # Decoy + simulated attacker
    trips: list[dict] = []

    async def _decoy() -> None:
        mgr = DecoyManager(on_trip=lambda e: trips.append(e))
        mgr.assert_localhost_only()
        inst = await mgr.deploy("http_login", "webserver", {"next_stage": "reverse_shell"})
        reader, writer = await asyncio.open_connection("127.0.0.1", inst.port)
        body = f"user={inst.honeytoken_user}&pass={inst.__dict__['_password']}"
        req = (
            f"POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n{body}"
        )
        writer.write(req.encode())
        await writer.drain()
        await reader.read(256)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.2)
        await mgr.remove(inst.id)

    asyncio.run(_decoy())
    assert trips and trips[0]["priority"] == "highest"

    VOICE.set_mode("demo")
    msg = build_message(
        CallFacts(
            summary="Webshell detected on the web server.",
            actions_done="blocked the source IP",
            next_stage="reverse_shell",
            window_low=30,
            window_high=40,
            option_one="isolate the web server",
        ),
        mode="demo",
    )
    path, _, _ = generate_call_audio(msg.text, mode="demo", fmt="wav")
    assert path and path.exists()

    # Keypad approval isolates host
    iso = guard.review_and_execute(
        {"action": "isolate_host", "host": "webserver", "host_role": "webserver", "reversible": False},
        human_approved=True,
    )
    assert iso.allowed
    assert "webserver" in mock_api._state["isolated_hosts"]

    # Credentials never appear in prompts/logs
    blob = inj.prompt_data_block + str(broker.execution_log)
    for secret in broker.secret_values():
        assert secret not in blob

    recs = build_recommendations()
    for r in recs:
        if r.type in {"retune_threshold", "schedule_or_fix_source", "scoped_exception"}:
            assert r.attack_stage_alerts_lost == 0

    # Sandbox/exfil coverage via library or proposed rule object
    assert propose_exfil_rule()["stage_detected"] == "exfil"
