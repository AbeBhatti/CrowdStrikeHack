#!/usr/bin/env bash
# Environment check for On-Call Security Teammate (macOS / Apple Silicon).
set -euo pipefail

FAIL=0
warn() { echo "WARN: $*"; }
fail() { echo "FAIL: $*"; FAIL=1; }
ok() { echo "OK: $*"; }

echo "=== On-Call Security Teammate: environment check ==="
echo

# macOS
if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "This project targets macOS. Detected: $(uname -s)"
else
  ok "macOS $(sw_vers -productVersion)"
fi

ARCH="$(uname -m)"
ok "Architecture: ${ARCH}"

# Memory
MEM_BYTES="$(sysctl -n hw.memsize)"
MEM_GB=$(( MEM_BYTES / 1024 / 1024 / 1024 ))
ok "Total memory: ${MEM_GB} GB"
PAGE_SIZE="$(pagesize)"
FREE_PAGES="$(vm_stat | awk '/Pages free/ {gsub(/\./,"",$3); print $3}')"
FREE_GB=$(( FREE_PAGES * PAGE_SIZE / 1024 / 1024 / 1024 ))
ok "Approx free memory: ${FREE_GB} GB"

# Disk
DISK_FREE="$(df -h / | awk 'NR==2 {print $4}')"
ok "Free disk on /: ${DISK_FREE}"

# Python
if command -v python3 >/dev/null 2>&1; then
  PY_VER="$(python3 -c 'import sys; print("%d.%d.%d"%sys.version_info[:3])')"
  PY_MAJOR="$(python3 -c 'import sys; print(sys.version_info[0])')"
  PY_MINOR="$(python3 -c 'import sys; print(sys.version_info[1])')"
  if [[ "${PY_MAJOR}" -lt 3 ]] || [[ "${PY_MAJOR}" -eq 3 && "${PY_MINOR}" -lt 11 ]]; then
    fail "Python 3.11+ required. Found ${PY_VER}. Install: brew install python@3.12"
  else
    ok "Python ${PY_VER}"
  fi
else
  fail "python3 not found. Install: brew install python@3.12"
fi

# Homebrew
if command -v brew >/dev/null 2>&1; then
  ok "Homebrew $(brew --version | head -1)"
else
  fail "Homebrew missing. Install: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
fi

# uv
if command -v uv >/dev/null 2>&1; then
  ok "uv $(uv --version)"
else
  fail "uv missing. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
fi

# Node
if command -v node >/dev/null 2>&1; then
  ok "Node $(node --version)"
else
  fail "Node missing. Install: brew install node"
fi

# ffmpeg (for phone simulator TTS)
if command -v ffmpeg >/dev/null 2>&1; then
  ok "ffmpeg present"
else
  fail "ffmpeg missing. Install: brew install ffmpeg"
fi

# say (macOS TTS)
if command -v say >/dev/null 2>&1; then
  ok "macOS say present"
else
  warn "macOS say not found; phone simulator audio may be limited"
fi

# libomp (LightGBM on Apple Silicon)
if brew list libomp >/dev/null 2>&1; then
  ok "libomp installed"
else
  fail "libomp missing (needed by LightGBM). Install: brew install libomp"
fi

# Ollama
if command -v ollama >/dev/null 2>&1; then
  ok "Ollama $(ollama --version 2>/dev/null | head -1 || echo installed)"
else
  fail "Ollama missing. Install: brew install ollama"
fi

if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  ok "Ollama server is running"
else
  warn "Ollama not responding; attempting ollama serve in background..."
  (ollama serve >/tmp/ollama.log 2>&1 &) || true
  sleep 2
  if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    ok "Ollama server is running"
  else
    fail "Ollama is not running. Start: ollama serve"
  fi
fi

# cloudflared (optional until Twilio keys present)
if command -v cloudflared >/dev/null 2>&1; then
  ok "cloudflared present"
else
  warn "cloudflared missing (needed for Twilio webhooks). Install: brew install cloudflared"
fi

# espeak-ng (Kokoro phonemizer backend)
if command -v espeak-ng >/dev/null 2>&1 || brew list espeak-ng >/dev/null 2>&1; then
  ok "espeak-ng present"
else
  warn "espeak-ng missing (Kokoro). Install: brew install espeak-ng"
fi

echo
if [[ "${FAIL}" -ne 0 ]]; then
  echo "Environment check FAILED. Fix the items above and re-run."
  exit 1
fi
echo "Environment check PASSED."
exit 0

