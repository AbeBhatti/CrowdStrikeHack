"""On-call message builder: normal and demo templates, shared facts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

from common.config import project_root
from common.text import contains_forbidden_chars, strip_forbidden_chars


def _cfg() -> dict[str, Any]:
    return yaml.safe_load((project_root() / "config" / "oncall.yaml").read_text(encoding="utf-8"))


@dataclass
class CallFacts:
    summary: str
    actions_done: str
    next_stage: str
    window_low: int
    window_high: int
    option_one: str


@dataclass
class BuiltMessage:
    mode: str
    text: str
    facts: CallFacts
    options: list[str]


_WORD_RE = re.compile(r"\b[\w']+\b")


def word_count(text: str) -> int:
    return len(_WORD_RE.findall(text))


def build_message(facts: CallFacts, mode: str | None = None) -> BuiltMessage:
    cfg = _cfg()
    mode = mode or str(cfg.get("voice_mode", "normal"))
    if mode == "demo":
        tmpl = str(cfg.get("message_template_demo") or cfg["message_template"])
    else:
        tmpl = str(cfg.get("message_template_normal") or cfg["message_template"])
    # Never interpolate attacker-controlled raw fields; facts.summary is already sanitized.
    summary = strip_forbidden_chars(facts.summary)
    text = tmpl.format(
        summary=summary,
        actions_done=strip_forbidden_chars(facts.actions_done),
        next_stage=facts.next_stage.replace("_", " "),
        window_low=facts.window_low,
        window_high=facts.window_high,
        option_one=facts.option_one,
    )
    text = strip_forbidden_chars(re.sub(r"\s+", " ", text).strip())
    max_words = int(cfg.get("max_call_words", 60))
    words = _WORD_RE.findall(text)
    if len(words) > max_words:
        text = " ".join(words[:max_words])
    if contains_forbidden_chars(text):
        text = strip_forbidden_chars(text)
    options = [
        f"Press 1 to {facts.option_one}",
        "Press 2 to keep watching",
        "Press 3 to call me back in 10 minutes"
        if mode != "demo"
        else "Press 3 to call you back in 10 minutes",
    ]
    return BuiltMessage(mode=mode, text=text, facts=facts, options=options)


def assert_same_facts(a: BuiltMessage, b: BuiltMessage) -> None:
    assert a.facts.summary == b.facts.summary
    assert a.facts.actions_done == b.facts.actions_done
    assert a.facts.next_stage == b.facts.next_stage
    assert a.facts.window_low == b.facts.window_low
    assert a.facts.window_high == b.facts.window_high
    assert a.facts.option_one == b.facts.option_one
