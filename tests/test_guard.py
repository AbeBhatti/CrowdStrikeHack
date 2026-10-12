"""Guard-dog: policy, injection isolation, broker credential hygiene."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from guard.broker import CredentialBroker
from guard.injection import isolate_for_prompt, scan_untrusted_fields
from guard.pipeline import GuardDog, injection_demo_alert
from guard.policy import evaluate_action
import mock_security_api.app as mock_api


class StubResponse:
    def __init__(self, data: dict[str, Any], status_code: int = 200) -> None:
        self._data = data
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"status {self.status_code}")

    def json(self) -> dict[str, Any]:
        return self._data


class StubClient:
    """Minimal httpx-like client hitting mock_security_api in-process."""

    def post(self, url: str, json: dict[str, Any] | None = None) -> StubResponse:
        json = json or {}
        path = url.split("8101", 1)[-1] if "8101" in url else "/" + url.rstrip("/").split("/")[-1]
        if path.endswith("block_ip") or url.endswith("/block_ip"):
            mock_api._state["blocked_ips"].add(json["ip"])
            mock_api._log("block_ip", json)
            return StubResponse({"ok": True})
        if path.endswith("unblock_ip") or url.endswith("/unblock_ip"):
            mock_api._state["blocked_ips"].discard(json["ip"])
            return StubResponse({"ok": True})
        if path.endswith("isolate_host") or url.endswith("/isolate_host"):
            mock_api._state["isolated_hosts"].add(json["host"])
            return StubResponse({"ok": True})
        if path.endswith("release_host") or url.endswith("/release_host"):
            mock_api._state["isolated_hosts"].discard(json["host"])
            return StubResponse({"ok": True})
        if path.endswith("block_dns_egress") or url.endswith("/block_dns_egress"):
            mock_api._state["blocked_dns"].add(json["domain"])
            return StubResponse({"ok": True})
        return StubResponse({"ok": False}, status_code=404)


@pytest.fixture()
def mock_client(tmp_path: Path):
    mock_api._state["blocked_ips"].clear()
    mock_api._state["isolated_hosts"].clear()
    mock_api._state["blocked_dns"].clear()
    mock_api._state["log"].clear()
    env = tmp_path / ".env"
    env.write_text("TWILIO_AUTH_TOKEN=secret-token-abc\nPAGERDUTY_ROUTING_KEY=pd-key-xyz\n")
    broker = CredentialBroker(
        env_path=env, mock_url="http://127.0.0.1:8101", client=StubClient()  # type: ignore[arg-type]
    )
    yield broker
    mock_api._state["blocked_ips"].clear()


def test_injection_scanner_flags_whitelist_instruction() -> None:
    alert = injection_demo_alert()
    findings = scan_untrusted_fields({"url": alert["url"]})
    assert findings
    block = isolate_for_prompt({"url": alert["url"]})
    assert "<<<UNTRUSTED_DATA>>>" in block


def test_policy_rejects_allow_and_irreversible() -> None:
    assert evaluate_action({"action": "allow_ip", "ip": "10.143.2.4"}).allowed is False
    d = evaluate_action(
        {
            "action": "isolate_host",
            "host": "webserver",
            "host_role": "webserver",
            "reversible": False,
        }
    )
    assert d.allowed is False
    assert d.requires_approval


def test_injection_demo_rejects_allow_action(mock_client: CredentialBroker) -> None:
    guard = GuardDog(broker=mock_client, cross_checkers=[lambda a: (True, "ok")])
    alert = injection_demo_alert()
    decision = guard.review_and_execute(
        {"action": "allow_ip", "ip": "10.143.2.4"},
        untrusted_fields={"url": alert["url"]},
    )
    assert decision.allowed is False
    assert decision.injection_findings


def test_block_ip_executes_through_broker(mock_client: CredentialBroker) -> None:
    guard = GuardDog(
        broker=mock_client, cross_checkers=[lambda a: (True, "ok"), lambda a: (True, "ok")]
    )
    decision = guard.review_and_execute(
        {"action": "block_ip", "ip": "10.0.0.9", "reversible": True}
    )
    assert decision.allowed is True
    assert "10.0.0.9" in mock_api._state["blocked_ips"]


def test_no_credential_in_logs_or_prompts(mock_client: CredentialBroker) -> None:
    guard = GuardDog(broker=mock_client, cross_checkers=[lambda a: (True, "ok")])
    alert = injection_demo_alert()
    decision = guard.review_and_execute(
        {"action": "block_ip", "ip": "10.0.0.8", "reversible": True},
        untrusted_fields={"url": alert["url"]},
    )
    blob = decision.prompt_data_block + str(mock_client.execution_log) + str(decision.reasons)
    for secret in mock_client.secret_values():
        assert secret not in blob
