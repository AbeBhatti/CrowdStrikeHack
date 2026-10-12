"""Credential broker: sole reader of .env; executes approved actions.

No LLM prompt, log line, or API response may contain credential strings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from dotenv import dotenv_values

from common.config import project_root
from guard.actions import ACTION_ADAPTER, Action
from guard.policy import PolicyDecision, evaluate_action

SECRET_KEYS = (
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_FROM_NUMBER",
    "ONCALL_PHONE_NUMBER",
    "ONCALL_PIN",
    "PAGERDUTY_ROUTING_KEY",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
)


@dataclass
class BrokerResult:
    ok: bool
    detail: str
    policy: PolicyDecision
    response: dict[str, Any] = field(default_factory=dict)


class CredentialBroker:
    def __init__(
        self,
        env_path: Path | None = None,
        mock_url: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.env_path = env_path or (project_root() / ".env")
        self._secrets: dict[str, str] = {}
        self._load_secrets()
        self.mock_url = (
            mock_url
            or self._secrets.get("MOCK_SECURITY_API_URL")
            or os.environ.get("MOCK_SECURITY_API_URL")
            or "http://127.0.0.1:8101"
        )
        self._client = client or httpx.Client(timeout=10.0)
        self.execution_log: list[dict[str, Any]] = []

    def _load_secrets(self) -> None:
        values: dict[str, str | None] = {}
        if self.env_path.exists():
            values.update(dotenv_values(self.env_path))
        for k in SECRET_KEYS:
            values[k] = values.get(k) or os.environ.get(k)
        self._secrets = {k: str(v) for k, v in values.items() if v}

    def secret(self, key: str) -> str | None:
        return self._secrets.get(key)

    def secret_values(self) -> list[str]:
        return [v for v in self._secrets.values() if v]

    def execute(
        self,
        action: Action | dict[str, Any],
        *,
        human_approved: bool = False,
        cross_check_approved: bool = True,
    ) -> BrokerResult:
        if isinstance(action, dict):
            parsed = ACTION_ADAPTER.validate_python(action)
        else:
            parsed = action
        policy = evaluate_action(parsed, human_approved=human_approved)
        if not policy.allowed:
            self._audit(parsed, policy, ok=False, detail=policy.reason)
            return BrokerResult(False, policy.reason, policy)
        if not cross_check_approved:
            self._audit(parsed, policy, ok=False, detail="cross_check_rejected")
            return BrokerResult(False, "cross_check_rejected", policy)

        name = parsed.action
        payload = parsed.model_dump()
        try:
            if name == "block_ip":
                r = self._client.post(f"{self.mock_url}/block_ip", json={"ip": payload["ip"]})
            elif name == "unblock_ip":
                r = self._client.post(f"{self.mock_url}/unblock_ip", json={"ip": payload["ip"]})
            elif name == "isolate_host":
                r = self._client.post(
                    f"{self.mock_url}/isolate_host",
                    json={"host": payload["host"], "host_role": payload.get("host_role", "unknown")},
                )
            elif name == "release_host":
                r = self._client.post(
                    f"{self.mock_url}/release_host",
                    json={"host": payload["host"], "host_role": payload.get("host_role", "unknown")},
                )
            elif name == "block_dns_egress":
                r = self._client.post(
                    f"{self.mock_url}/block_dns_egress", json={"domain": payload["domain"]}
                )
            elif name in {
                "notify_human",
                "request_approval",
                "deploy_decoy",
                "remove_decoy",
                "deploy_detection_rule",
                "pagerduty_trigger",
                "pagerduty_acknowledge",
                "pagerduty_resolve",
            }:
                # Handled by higher layers; broker records approval only.
                self._audit(parsed, policy, ok=True, detail="recorded")
                return BrokerResult(True, "recorded", policy, {"action": name})
            else:
                return BrokerResult(False, "unhandled_action", policy)
            r.raise_for_status()
            body = r.json()
            self._audit(parsed, policy, ok=True, detail="executed", response=body)
            return BrokerResult(True, "executed", policy, body)
        except Exception as exc:  # noqa: BLE001
            self._audit(parsed, policy, ok=False, detail=str(type(exc).__name__))
            return BrokerResult(False, "execution_error", policy)

    def _audit(
        self,
        action: Action,
        policy: PolicyDecision,
        *,
        ok: bool,
        detail: str,
        response: dict[str, Any] | None = None,
    ) -> None:
        entry = {
            "action": action.model_dump(),
            "policy_reason": policy.reason,
            "ok": ok,
            "detail": detail,
            "response": response or {},
        }
        # Never persist raw secrets
        blob = str(entry)
        for secret in self.secret_values():
            if secret and secret in blob:
                raise RuntimeError("credential leaked into broker audit log")
        self.execution_log.append(entry)
