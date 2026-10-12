"""FastAPI backend: replay, incidents, on-call, decoys, library, metrics."""

from __future__ import annotations

import asyncio
import secrets
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from common.config import HELD_OUT_SCENARIOS, get_thresholds, project_root
from forecast.table import forecast_next, load_table
from guard.pipeline import GuardDog, injection_demo_alert
from incidents.group import IncidentGrouper
from ingest.replay import ReplayEngine
from library.store import DefenseLibrary
from oncall.messages import CallFacts, build_message
from oncall.tts import VOICE, generate_call_audio
from recommend.tuning import build_recommendations

app = FastAPI(title="On-Call Security Teammate", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_state: dict[str, Any] = {
    "replay": None,
    "events": [],
    "incidents": [],
    "decisions": [],
    "guard": [],
    "calls": [],
    "audio_files": {},
    "subscribers": [],
}


def _guard() -> GuardDog:
    return GuardDog(cross_checkers=[lambda a: (True, "ok"), lambda a: (True, "ok")])


class ReplayStart(BaseModel):
    scenario: str = "russellmitchell"
    speed: float = 1000.0


class VoiceModeBody(BaseModel):
    mode: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/replay/start")
async def replay_start(body: ReplayStart) -> dict[str, Any]:
    if body.scenario not in HELD_OUT_SCENARIOS:
        raise HTTPException(400, "only held-out scenarios allowed for replay")
    eng = ReplayEngine(scenario=body.scenario, speed=body.speed, target_wall_seconds=90)
    eng.load()
    _state["replay"] = eng
    _state["events"] = []
    _state["incidents"] = []
    return {"ok": True, "alerts": eng._df.height if eng._df is not None else 0}


@app.post("/replay/pause")
def replay_pause() -> dict[str, bool]:
    if _state["replay"]:
        _state["replay"].pause()
    return {"ok": True}


@app.post("/replay/resume")
def replay_resume() -> dict[str, bool]:
    if _state["replay"]:
        _state["replay"].resume()
    return {"ok": True}


@app.get("/incidents")
def incidents() -> list[dict[str, Any]]:
    return _state["incidents"]


@app.get("/events")
def events(limit: int = 200) -> list[dict[str, Any]]:
    return _state["events"][-limit:]


@app.get("/forecast/demo")
def forecast_demo() -> dict[str, Any]:
    table = load_table()
    fc = forecast_next(table, ["web_scan", "webshell"])
    return {
        "current_stage": fc.current_stage,
        "next_stage": fc.next_stage,
        "probability": fc.probability,
        "window_minutes": fc.window_minutes,
        "similar_chain": fc.similar_chain,
        "similar_scenario": fc.similar_scenario,
    }


@app.get("/library")
def library() -> list[dict[str, Any]]:
    return DefenseLibrary().shared_rules()


@app.get("/recommendations")
def recommendations() -> list[dict[str, Any]]:
    return [r.__dict__ for r in build_recommendations()]


@app.get("/oncall/voice_mode")
def get_voice_mode() -> dict[str, str]:
    return {"mode": VOICE.get_mode()}


@app.post("/oncall/voice_mode")
def set_voice_mode(body: VoiceModeBody) -> dict[str, str]:
    VOICE.set_mode(body.mode)  # type: ignore[arg-type]
    return {"mode": VOICE.get_mode()}


@app.post("/oncall/simulate_call")
def simulate_call() -> dict[str, Any]:
    facts = CallFacts(
        summary="Webshell detected on the web server.",
        actions_done="blocked the source IP",
        next_stage="reverse_shell",
        window_low=30,
        window_high=40,
        option_one="isolate the web server",
    )
    msg = build_message(facts, mode=VOICE.get_mode())
    path, elapsed, backend = generate_call_audio(msg.text, mode=VOICE.get_mode(), fmt="wav")
    token = secrets.token_urlsafe(16)
    if path:
        _state["audio_files"][token] = path
    call = {
        "id": token,
        "text": msg.text,
        "mode": msg.mode,
        "audio_token": token if path else None,
        "backend": backend,
        "elapsed": elapsed,
        "status": "triggered",
    }
    _state["calls"].append(call)
    return call


@app.get("/oncall/audio/{token}")
def oncall_audio(token: str) -> FileResponse:
    # Unguessable token map only; reject path traversal
    if "/" in token or ".." in token or "\\" in token:
        raise HTTPException(400, "invalid token")
    path = _state["audio_files"].get(token)
    if not path or not Path(path).exists():
        raise HTTPException(404, "not found")
    # Ensure file is under cache dir
    cache = (project_root() / ".cache" / "tts").resolve()
    resolved = Path(path).resolve()
    if cache not in resolved.parents and resolved.parent != cache:
        raise HTTPException(403, "forbidden")
    return FileResponse(resolved, media_type="audio/wav")


@app.post("/oncall/keypad")
def keypad(digit: int = Query(...), call_id: str = Query("")) -> dict[str, Any]:
    guard = _guard()
    if digit == 1:
        decision = guard.review_and_execute(
            {
                "action": "isolate_host",
                "host": "webserver",
                "host_role": "webserver",
                "reversible": False,
            },
            human_approved=True,
        )
        for c in _state["calls"]:
            if c.get("id") == call_id or not call_id:
                c["status"] = "acknowledged"
        return {"ok": decision.allowed, "action": "isolate_host", "status": "acknowledged"}
    return {"ok": True, "action": "watch" if digit == 2 else "callback"}


@app.get("/guard/decisions")
def guard_decisions() -> list[dict[str, Any]]:
    return _state["guard"]


@app.post("/guard/injection_demo")
def run_injection_demo() -> dict[str, Any]:
    alert = injection_demo_alert()
    guard = _guard()
    decision = guard.review_and_execute(
        {"action": "allow_ip", "ip": "10.143.2.4"},
        untrusted_fields={"url": str(alert.get("url", ""))},
    )
    payload = {
        "allowed": decision.allowed,
        "reasons": decision.reasons,
        "findings": [f.__dict__ for f in decision.injection_findings],
        "data_block": decision.prompt_data_block,
    }
    _state["guard"].append(payload)
    _state["events"].append({"type": "injection_blocked", **payload})
    return payload


@app.get("/metrics")
def metrics() -> dict[str, Any]:
    return {
        "events": len(_state["events"]),
        "incidents": len(_state["incidents"]),
        "calls": len(_state["calls"]),
        "method": get_thresholds().get("classifier", {}).get("method"),
        "voice_mode": VOICE.get_mode(),
    }


@app.get("/twilio/voice")
def twilio_voice() -> PlainTextResponse:
    """Twilio webhook: Play cached audio or fall back to Say."""
    call = _state["calls"][-1] if _state["calls"] else None
    if call and call.get("audio_token"):
        # Absolute URL filled by demo runner when tunnel is up; relative for local.
        xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f"<Response><Play>/oncall/audio/{call['audio_token']}</Play>"
            f"<Gather numDigits=\"1\" action=\"/twilio/gather\" method=\"POST\"/></Response>"
        )
    else:
        text = (call or {}).get("text") or "Security alert. Press 1 to isolate. Press 2 to watch."
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f"<Response><Say>{text}</Say>"
            f"<Gather numDigits=\"1\" action=\"/twilio/gather\" method=\"POST\"/></Response>"
        )
    return PlainTextResponse(xml, media_type="application/xml")


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket) -> None:
    await ws.accept()
    _state["subscribers"].append(ws)
    try:
        while True:
            await asyncio.sleep(1.0)
            await ws.send_json({"events": _state["events"][-20:], "incidents": _state["incidents"]})
    except Exception:  # noqa: BLE001
        pass
    finally:
        if ws in _state["subscribers"]:
            _state["subscribers"].remove(ws)


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
