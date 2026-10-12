"""Policy engine: plain code, no LLM."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from common.hosts import is_protected_role
from guard.actions import ALLOWLIST, Action


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    requires_approval: bool = False


FORBIDDEN_ACTIONS = {"allow_ip", "whitelist_ip", "allow_rule", "whitelist"}


def evaluate_action(
    action: Action | dict[str, Any],
    *,
    human_approved: bool = False,
) -> PolicyDecision:
    if isinstance(action, dict):
        name = str(action.get("action", ""))
        payload = action
        reversible = bool(action.get("reversible", True))
        host_role = str(action.get("host_role", "unknown"))
    else:
        name = action.action
        payload = action.model_dump()
        reversible = bool(getattr(action, "reversible", True))
        host_role = str(getattr(action, "host_role", "unknown"))

    if name in FORBIDDEN_ACTIONS or "whitelist" in name or name.startswith("allow_"):
        return PolicyDecision(False, "whitelisting_or_allow_rule_forbidden")

    if name not in ALLOWLIST:
        return PolicyDecision(False, f"action_not_allowlisted:{name}")

    # Never act on protected infrastructure without approval
    if is_protected_role(host_role) and not human_approved:
        return PolicyDecision(False, "protected_infrastructure_requires_approval", True)

    if name == "isolate_host" and not human_approved:
        return PolicyDecision(False, "irreversible_requires_approval", True)

    if not reversible and not human_approved:
        return PolicyDecision(False, "irreversible_requires_approval", True)

    # Reject allow-style targets hidden in rule JSON
    if name == "deploy_detection_rule":
        rule = payload.get("rule") or {}
        blob = str(rule).lower()
        if "whitelist" in blob or "allowlist" in blob or "allow_ip" in blob:
            return PolicyDecision(False, "rule_contains_allow_semantics")

    return PolicyDecision(True, "ok")
