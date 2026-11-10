#!/usr/bin/env bash
# Start the app (default) or run the extraction check: bash start.sh [eval <folder>]
# Secrets are read from the environment, or asked for without echo. Nothing is written to disk.
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
if [ -z "${LLM_API_KEY:-}" ]; then
  read -rsp "LLM_API_KEY (Claude, GPT or Gemini; not shown): " LLM_API_KEY; echo; export LLM_API_KEY
fi
echo "API key set: $([ -n "$LLM_API_KEY" ] && echo yes || echo no)"
if [ "${1:-}" = "eval" ]; then
  exec "$PY" eval_cards.py "${2:-local_check}"
fi
if [ ! -f "${DATA_DIR:-data}/app.db" ]; then
  [ -n "${ADMIN_EMAIL:-}" ] || { read -rp "Initial admin email: " ADMIN_EMAIL; export ADMIN_EMAIL; }
  [ -n "${ADMIN_PASSWORD:-}" ] || { read -rsp "Initial admin password (8+ chars, not shown): " ADMIN_PASSWORD; echo; export ADMIN_PASSWORD; }
fi
exec "$PY" -m flask --app app run --port "${PORT:-8000}"
