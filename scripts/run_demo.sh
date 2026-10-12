#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH=.
export LDFLAGS="${LDFLAGS:--L/opt/homebrew/opt/libomp/lib}"
export CPPFLAGS="${CPPFLAGS:--I/opt/homebrew/opt/libomp/include}"

# Ensure Ollama
if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null; then
  ollama serve >/tmp/ollama.log 2>&1 &
  sleep 2
fi

# Mock security API
uv run python -m mock_security_api.app >/tmp/mock_security.log 2>&1 &
MOCK_PID=$!

# Backend
uv run python -m api.app >/tmp/api.log 2>&1 &
API_PID=$!

# Frontend
if [[ -d frontend/node_modules ]]; then
  (cd frontend && npm run dev >/tmp/frontend.log 2>&1 &)
else
  (cd frontend && npm install && npm run dev >/tmp/frontend.log 2>&1 &)
fi

# Optional Cloudflare tunnel when Twilio keys present
if [[ -f .env ]] && grep -q '^TWILIO_ACCOUNT_SID=.\+' .env; then
  if command -v cloudflared >/dev/null; then
    cloudflared tunnel --url http://127.0.0.1:8000 >/tmp/cloudflared.log 2>&1 &
  fi
fi

sleep 2
echo "Demo running."
echo "UI:  http://127.0.0.1:5173"
echo "API: http://127.0.0.1:8000/health"
echo "mock_pid=$MOCK_PID api_pid=$API_PID"
echo "Start the demo in demo voice mode. Switch to normal if a judge asks a serious question."
wait
