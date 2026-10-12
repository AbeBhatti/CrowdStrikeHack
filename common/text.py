"""Strip characters forbidden in user-facing and spoken text."""

from __future__ import annotations

import re
import unicodedata

# Em dash, en dash, and ASCII double-hyphen used as a dash.
_DASH_RE = re.compile(r"[\u2014\u2013]|--")
_EMOJI_RE = re.compile(
    "["
    "\U0001F300-\U0001F9FF"
    "\U00002700-\U000027BF"
    "\U0001F600-\U0001F64F"
    "\U0001F680-\U0001F6FF"
    "\U00002600-\U000026FF"
    "\U0001FA00-\U0001FAFF"
    "]+",
    flags=re.UNICODE,
)


def strip_forbidden_chars(text: str) -> str:
    """Remove emoji and dash characters from display or speech text."""
    cleaned = _EMOJI_RE.sub("", text)
    cleaned = _DASH_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def contains_forbidden_chars(text: str) -> bool:
    if _DASH_RE.search(text):
        return True
    if _EMOJI_RE.search(text):
        return True
    for ch in text:
        if unicodedata.category(ch) in {"So", "Sk"} and ord(ch) > 127:
            return True
    return False


def escape_untrusted(value: str, max_chars: int = 200) -> str:
    """Length-limit and neutralize untrusted alert fields for prompts."""
    s = value.replace("\x00", "")
    s = s[:max_chars]
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    return s
