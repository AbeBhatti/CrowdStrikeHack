"""Normalize scenario-specific host names to stable roles."""

from __future__ import annotations

from common.config import get_host_roles


def host_to_role(host: str | None) -> str:
    if not host:
        return "unknown"
    h = host.strip().lower()
    patterns = get_host_roles().get("role_patterns", {})
    # Prefer longer / more specific substrings by checking each role's patterns.
    best_role = "unknown"
    best_len = -1
    for role, pats in patterns.items():
        for pat in pats:
            p = str(pat).lower()
            if p in h and len(p) > best_len:
                best_role = str(role)
                best_len = len(p)
    return best_role


def role_criticality(role: str) -> float:
    crit = get_host_roles().get("role_criticality", {})
    return float(crit.get(role, crit.get("unknown", 0.5)))


def is_protected_role(role: str) -> bool:
    protected = get_host_roles().get("protected_infrastructure", [])
    return role in protected
