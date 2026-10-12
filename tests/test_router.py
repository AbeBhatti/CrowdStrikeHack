"""Router branch selection is deterministic from scores."""

from __future__ import annotations

from router.analyst import AnalystRouter, choose_branch


def test_branches() -> None:
    playbooks = {"stages": {"webshell": {"actions": [{"action": "block_ip"}]}}}
    b, _ = choose_branch(
        {"confidence": 0.2, "blast_radius": 0.1, "match": 0.9, "reversibility": 0.9},
        "webshell",
        playbooks,
        False,
    )
    assert b == "escalate"
    b, _ = choose_branch(
        {"confidence": 0.8, "blast_radius": 0.9, "match": 0.9, "reversibility": 0.9},
        "webshell",
        playbooks,
        False,
    )
    assert b == "escalate"
    b, _ = choose_branch(
        {"confidence": 0.8, "blast_radius": 0.2, "match": 0.9, "reversibility": 0.9},
        "webshell",
        playbooks,
        False,
    )
    assert b == "playbook"
    b, _ = choose_branch(
        {"confidence": 0.8, "blast_radius": 0.2, "match": 0.9, "reversibility": 0.9},
        "exfil",
        playbooks,
        False,
    )
    assert b == "sandbox"


def test_analyze_with_fallback_llm() -> None:
    class Boom:
        def complete_json(self, *a, **k):
            return k["fallback"]

    r = AnalystRouter(llm=Boom())  # type: ignore[arg-type]
    d = r.analyze(
        {"id": "1", "stages": ["webshell"], "host_roles": ["webserver"]},
        {"next_stage": "reverse_shell", "probability": 0.8, "window_minutes": (30, 40)},
    )
    assert d.branch in {"escalate", "playbook", "sandbox"}
    assert d.explanation
