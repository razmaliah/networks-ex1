#!/usr/bin/env bash
# Starts the PCAP dashboard (macOS / Linux): creates .venv on the first run, installs the requirements
# when requirements.txt changes, starts Streamlit and opens the browser.
set -e
cd "$(dirname "$0")"
PORT=8501
URL="http://localhost:$PORT"

if [ ! -x .venv/bin/python ]; then
  PY="$(command -v python3 || command -v python || true)"
  if [ -z "$PY" ]; then echo "Python 3.10 or newer is required: https://www.python.org/downloads/"; exit 1; fi
  if ! "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then echo "Python 3.10 or newer is required."; exit 1; fi
  echo "[1/3] Creating the virtual environment (.venv)..."
  "$PY" -m venv .venv
fi

if ! cmp -s requirements.txt .venv/installed-requirements.txt; then
  echo "[2/3] Installing the required packages, this can take a minute..."
  .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
  cp requirements.txt .venv/installed-requirements.txt
fi

echo "[3/3] Starting the dashboard at $URL (press Ctrl+C to stop)"
( sleep 4; if command -v open >/dev/null; then open "$URL"; else xdg-open "$URL"; fi ) >/dev/null 2>&1 &
exec .venv/bin/python -m streamlit run dashboard/app.py --server.port "$PORT" --server.headless true \
  --browser.gatherUsageStats false
