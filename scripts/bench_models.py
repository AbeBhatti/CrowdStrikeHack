#!/usr/bin/env python3
"""Benchmark Ollama candidates for JSON reliability and latency.

Selects a primary analyst and two cross-check models from different families.
Writes reports/model_bench.md and records the choice in DECISIONS.md.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "reports" / "model_bench.md"
DECISIONS = ROOT / "DECISIONS.md"
MODELS_YAML = ROOT / "config" / "models.yaml"
OLLAMA = "http://127.0.0.1:11434"

# 16 GB machine: 1B-2B range. Skip heavy phi3:mini (3.8B) for laptop fit.
CANDIDATES = [
    "llama3.2:1b",
    "qwen2.5:1.5b",
    "gemma2:2b",
]

PROMPTS = [
    {
        "system": "Reply with JSON only. Schema: {\"summary\": str, \"confidence\": float}",
        "user": "Webshell on webserver. Summarize in one sentence. confidence 0-1.",
    },
    {
        "system": "Reply with JSON only. Schema: {\"next_stage\": str, \"prob\": float}",
        "user": "Current stage webshell. Predict next stage.",
    },
    {
        "system": "Reply with JSON only. Schema: {\"approve\": bool, \"reason\": str}",
        "user": "Proposed action: block_ip after webshell. Approve?",
    },
    {
        "system": "Reply with JSON only. Schema: {\"match\": float, \"blast_radius\": float}",
        "user": "Incident on mail host after scan. Score match and blast_radius 0-1.",
    },
    {
        "system": "Reply with JSON only. Schema: {\"rule\": {\"types\": [str], \"stage\": str}}",
        "user": "Propose a detection rule for reverse_shell using alert type codes.",
    },
] * 4  # 20 prompts


def mem_gb() -> float:
    import os

    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / (1024**3)


def ensure_model(name: str) -> bool:
    try:
        with httpx.Client(timeout=600.0) as client:
            tags = client.get(f"{OLLAMA}/api/tags")
            tags.raise_for_status()
            have = {m["name"] for m in tags.json().get("models", [])}
            if name in have or any(name in m for m in have):
                return True
            r = client.post(f"{OLLAMA}/api/pull", json={"name": name, "stream": False})
            return r.status_code == 200
    except Exception as exc:  # noqa: BLE001
        print(f"pull failed for {name}: {exc}", flush=True)
        return False


def chat(model: str, system: str, user: str) -> tuple[str, float]:
    t0 = time.perf_counter()
    with httpx.Client(timeout=60.0) as client:
        r = client.post(
            f"{OLLAMA}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": {"temperature": 0, "num_predict": 128},
                "keep_alive": "30m",
                "format": "json",
            },
        )
        r.raise_for_status()
        content = r.json()["message"]["content"]
    return content, time.perf_counter() - t0


def parse_json(text: str) -> bool:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end < 0:
            return False
        json.loads(text[start : end + 1])
        return True
    except json.JSONDecodeError:
        return False


def family(model: str) -> str:
    return model.split(":")[0].split("/")[-1]


def main() -> None:
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    print(f"Memory: {mem_gb():.1f} GB; candidates: {CANDIDATES}", flush=True)

    results: list[dict] = []
    for name in CANDIDATES:
        print(f"=== {name} ===", flush=True)
        if not ensure_model(name):
            results.append(
                {"model": name, "ok": False, "median": None, "p95": None, "json_rate": 0.0}
            )
            continue
        latencies: list[float] = []
        ok_count = 0
        for i, p in enumerate(PROMPTS):
            try:
                content, dt = chat(name, p["system"], p["user"])
                latencies.append(dt)
                good = parse_json(content)
                if good:
                    ok_count += 1
                print(f"  [{i+1}/20] {dt:.2f}s json={good}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"  [{i+1}/20] error: {exc}", flush=True)
                latencies.append(60.0)
        latencies_sorted = sorted(latencies)
        median = statistics.median(latencies_sorted)
        p95 = latencies_sorted[int(0.95 * (len(latencies_sorted) - 1))]
        rate = ok_count / len(PROMPTS)
        print(f"  SUMMARY median={median:.2f}s p95={p95:.2f}s json={rate:.0%}", flush=True)
        results.append(
            {"model": name, "ok": True, "median": median, "p95": p95, "json_rate": rate}
        )

    usable = [
        r
        for r in results
        if r["ok"] and r["json_rate"] >= 0.5 and r["median"] is not None and r["median"] < 5.0
    ]
    usable.sort(key=lambda r: (-r["json_rate"], r["median"]))
    primary = usable[0]["model"] if usable else (CANDIDATES[0] if results else "llama3.2:1b")

    cross: list[str] = []
    used = {family(primary)}
    for r in usable:
        if r["model"] == primary:
            continue
        fam = family(r["model"])
        if fam not in used:
            cross.append(r["model"])
            used.add(fam)
        if len(cross) == 2:
            break
    for r in results:
        if r["ok"] and r["model"] != primary and r["model"] not in cross:
            cross.append(r["model"])
        if len(cross) == 2:
            break
    while len(cross) < 2:
        for c in CANDIDATES:
            if c != primary and c not in cross:
                cross.append(c)
                break
        else:
            break

    lines = [
        "# Model benchmark",
        "",
        f"Memory: {mem_gb():.1f} GB. Target median under 1.5s when possible.",
        "",
        "| model | median_s | p95_s | json_success |",
        "| --- | ---: | ---: | ---: |",
    ]
    for r in results:
        if not r["ok"]:
            lines.append(f"| {r['model']} | - | - | pull failed |")
        else:
            lines.append(
                f"| {r['model']} | {r['median']:.2f} | {r['p95']:.2f} | {r['json_rate']:.0%} |"
            )
    lines += [
        "",
        f"**Primary analyst:** `{primary}`",
        f"**Cross-check models:** {', '.join(f'`{m}`' for m in cross) or 'none'}",
        "",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(REPORT.read_text(), flush=True)

    decision = (
        f"- Model bench: primary={primary}, cross={cross} "
        f"(chosen by JSON rate then median latency on 16GB)."
    )
    existing = DECISIONS.read_text(encoding="utf-8") if DECISIONS.exists() else "# Decisions\n"
    if "Model bench:" not in existing:
        with DECISIONS.open("a", encoding="utf-8") as f:
            f.write("\n" + decision + "\n")

    c0 = cross[0] if cross else "qwen2.5:1.5b"
    c1 = cross[1] if len(cross) > 1 else "gemma2:2b"
    MODELS_YAML.write_text(
        f"primary: {primary}\n"
        f"cross_check:\n"
        f"  - {c0}\n"
        f"  - {c1}\n"
        f"temperature: 0\n"
        f"keep_alive: 30m\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
