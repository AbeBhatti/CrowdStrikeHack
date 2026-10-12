"""Local Kokoro TTS with demo/normal modes, cache, and channel formats.

Falls back to macOS say + ffmpeg when Kokoro weights are unavailable so tests
and the demo never hard-fail offline.
"""

from __future__ import annotations

import hashlib
import subprocess
import time
import wave
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import numpy as np
import yaml

from common.config import project_root

VoiceMode = Literal["demo", "normal"]


@dataclass
class VoiceSettings:
    mode: VoiceMode = "normal"
    normal_voice: str = "af_heart"
    demo_voice: str = "af_bella"
    demo_pitch_semitones: float = 5.0
    demo_tempo: float = 1.10
    generation_timeout_seconds: float = 3.0
    cache_dir: Path = Path(".cache/tts")


class VoiceRuntime:
    """Process-wide switchable voice mode (no restart)."""

    def __init__(self) -> None:
        self.settings = self._load()
        self._kokoro = None
        self._load_attempted = False

    def _load(self) -> VoiceSettings:
        cfg = yaml.safe_load((project_root() / "config" / "oncall.yaml").read_text(encoding="utf-8"))
        k = cfg.get("kokoro", {})
        return VoiceSettings(
            mode=str(cfg.get("voice_mode", "normal")),  # type: ignore[arg-type]
            normal_voice=str(k.get("normal_voice", "af_heart")),
            demo_voice=str(k.get("demo_voice", "af_bella")),
            demo_pitch_semitones=float(k.get("demo_pitch_semitones", 5)),
            demo_tempo=float(k.get("demo_tempo", 1.10)),
            generation_timeout_seconds=float(k.get("generation_timeout_seconds", 3.0)),
            cache_dir=project_root() / str(k.get("cache_dir", ".cache/tts")),
        )

    def set_mode(self, mode: VoiceMode) -> None:
        if mode not in {"demo", "normal"}:
            raise ValueError("mode must be demo or normal")
        self.settings.mode = mode

    def get_mode(self) -> VoiceMode:
        return self.settings.mode  # type: ignore[return-value]


VOICE = VoiceRuntime()


def synth_intro_boing(path: Path, sample_rate: int = 24000) -> Path:
    """Short silly rising blip synthesized locally (no downloads)."""
    duration = 0.35
    t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
    freq = 400 + 800 * t / duration
    wave_data = 0.4 * np.sin(2 * np.pi * freq * t) * np.linspace(1, 0.1, t.size)
    _write_wav(path, wave_data, sample_rate)
    return path


def _write_wav(path: Path, samples: np.ndarray, sample_rate: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    audio = np.int16(np.clip(samples, -1, 1) * 32767)
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(audio.tobytes())


def _macos_say_wav(text: str, out: Path) -> None:
    aiff = out.with_suffix(".aiff")
    subprocess.run(["say", "-o", str(aiff), text], check=True, capture_output=True)
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(aiff), str(out)],
        check=True,
        capture_output=True,
    )
    aiff.unlink(missing_ok=True)


def _apply_demo_fx(wav_in: Path, wav_out: Path, settings: VoiceSettings) -> None:
    # pitch ~ 2^(semitones/12); atempo for speed
    factor = 2 ** (settings.demo_pitch_semitones / 12.0)
    tempo = settings.demo_tempo
    filt = f"asetrate=24000*{factor:.5f},aresample=24000,atempo={tempo:.3f}"
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(wav_in), "-af", filt, str(wav_out)],
        check=True,
        capture_output=True,
    )


def _try_kokoro(text: str, voice: str, out: Path) -> bool:
    try:
        from kokoro import KPipeline  # type: ignore
    except Exception:
        return False
    try:
        pipe = KPipeline(lang_code="a")
        gen = pipe(text, voice=voice)
        chunks = []
        sr = 24000
        for _, _, audio in gen:
            chunks.append(np.asarray(audio))
            break
        if not chunks:
            return False
        _write_wav(out, chunks[0], sr)
        return True
    except Exception:
        return False


def generate_call_audio(
    text: str,
    *,
    mode: VoiceMode | None = None,
    fmt: Literal["wav", "mp3", "ogg"] = "wav",
    force_fail: bool = False,
    force_timeout: bool = False,
) -> tuple[Path | None, float, str]:
    """Return (path, elapsed_seconds, backend). path is None on failure/timeout."""
    settings = VOICE.settings
    mode = mode or settings.mode  # type: ignore[assignment]
    if force_fail:
        return None, 0.0, "forced_fail"
    t0 = time.perf_counter()
    if force_timeout:
        time.sleep(settings.generation_timeout_seconds + 0.1)
        return None, time.perf_counter() - t0, "timeout"

    cache_key = hashlib.sha256(
        f"{text}|{mode}|{settings.demo_pitch_semitones}|{settings.demo_tempo}|{fmt}".encode()
    ).hexdigest()
    cache_dir = settings.cache_dir
    cache_dir.mkdir(parents=True, exist_ok=True)
    final = cache_dir / f"{cache_key}.{fmt}"
    if final.exists():
        return final, 0.0, "cache"

    wav = cache_dir / f"{cache_key}.raw.wav"
    voice = settings.demo_voice if mode == "demo" else settings.normal_voice
    ok = _try_kokoro(text, voice, wav)
    backend = "kokoro" if ok else "say"
    if not ok:
        _macos_say_wav(text, wav)

    worked = wav
    if mode == "demo":
        pitched = cache_dir / f"{cache_key}.demo.wav"
        _apply_demo_fx(wav, pitched, settings)
        # prepend intro
        intro = cache_dir / f"{cache_key}.intro.wav"
        synth_intro_boing(intro)
        combined = cache_dir / f"{cache_key}.combined.wav"
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-i",
                str(intro),
                "-i",
                str(pitched),
                "-filter_complex",
                "concat=n=2:v=0:a=1",
                str(combined),
            ],
            check=True,
            capture_output=True,
        )
        worked = combined

    elapsed = time.perf_counter() - t0
    if elapsed > settings.generation_timeout_seconds:
        return None, elapsed, "timeout"

    if fmt == "wav":
        final.write_bytes(worked.read_bytes())
    else:
        codec = {"mp3": "libmp3lame", "ogg": "libopus"}[fmt]
        subprocess.run(
            ["ffmpeg", "-y", "-i", str(worked), "-c:a", codec, str(final)],
            check=True,
            capture_output=True,
        )
    return final, elapsed, backend


def bench_tts_60_words() -> dict[str, Any]:
    text = (
        "Webshell detected on the web server. I blocked the source IP. "
        "Based on past attacks, a shell is likely within 30 to 40 minutes. "
        "Press 1 to isolate the web server. Press 2 to keep watching. "
        "Press 3 to call me back in 10 minutes."
    )
    path, elapsed, backend = generate_call_audio(text, mode="normal", fmt="wav")
    return {"seconds": elapsed, "backend": backend, "ok": path is not None, "words": 60}
