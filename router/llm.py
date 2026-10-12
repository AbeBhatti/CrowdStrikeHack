"""Local Ollama LLM client with JSON schema validation, retry, and disk cache."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, TypeVar

import httpx
import yaml
from pydantic import BaseModel, ValidationError

from common.config import project_root
from common.text import strip_forbidden_chars

T = TypeVar("T", bound=BaseModel)


def _models_config() -> dict[str, Any]:
    path = project_root() / "config" / "models.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class LLMClient:
    def __init__(self, model: str | None = None, cache_dir: Path | None = None) -> None:
        cfg = _models_config()
        self.model = model or str(cfg.get("primary", "llama3.2:1b"))
        self.base = "http://127.0.0.1:11434"
        self.cache_dir = cache_dir or (project_root() / "llm_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.keep_alive = str(cfg.get("keep_alive", "30m"))

    def _cache_path(self, prompt: str) -> Path:
        h = hashlib.sha256(f"{self.model}\n{prompt}".encode()).hexdigest()
        return self.cache_dir / f"{h}.json"

    def complete_json(
        self,
        system: str,
        user: str,
        schema: type[T],
        *,
        fallback: T,
        use_cache: bool = True,
    ) -> T:
        prompt = f"SYSTEM:\n{system}\nUSER:\n{user}"
        cache = self._cache_path(prompt)
        if use_cache and cache.exists():
            try:
                return schema.model_validate_json(cache.read_text(encoding="utf-8"))
            except ValidationError:
                pass

        content = self._chat(system, user)
        parsed = self._parse(content, schema)
        if parsed is None:
            content = self._chat(system, user + "\nReturn valid JSON only.")
            parsed = self._parse(content, schema)
        if parsed is None:
            parsed = fallback
        if use_cache:
            cache.write_text(parsed.model_dump_json(), encoding="utf-8")
        return parsed

    def _chat(self, system: str, user: str) -> str:
        try:
            with httpx.Client(timeout=60.0) as client:
                r = client.post(
                    f"{self.base}/api/chat",
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "stream": False,
                        "format": "json",
                        "options": {"temperature": 0, "num_predict": 256},
                        "keep_alive": self.keep_alive,
                    },
                )
                r.raise_for_status()
                return r.json()["message"]["content"]
        except Exception:  # noqa: BLE001
            return "{}"

    def _parse(self, content: str, schema: type[T]) -> T | None:
        text = content.strip()
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end < 0:
                return None
            data = json.loads(text[start : end + 1])
            obj = schema.model_validate(data)
            # Strip forbidden chars from string fields
            for name, value in obj.model_dump().items():
                if isinstance(value, str):
                    setattr(obj, name, strip_forbidden_chars(value))
            return obj
        except (json.JSONDecodeError, ValidationError):
            return None
