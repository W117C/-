#!/usr/bin/env bash
# SecAgent MCP server launcher.
# Sets the env vars secagent needs (DB + binaries paths) then starts the stdio
# MCP server. Designed to be portable: paths resolve relative to this script,
# not hardcoded to a specific developer's home directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export SECAGENT_DB_PATH="${SECAGENT_DB_PATH:-$PROJECT_DIR/data/secagent.db}"
export SECAGENT_BINARIES_DIR="${SECAGENT_BINARIES_DIR:-$PROJECT_DIR/bin}"
export SECAGENT_DEFAULT_QUOTA="${SECAGENT_DEFAULT_QUOTA:-100}"

# Prefer the bundled workbuddy python if present, else fall back to whatever
# `python3` / `python` is on PATH.
if [ -x "$HOME/.workbuddy/binaries/python/envs/default/bin/python" ]; then
    PY="$HOME/.workbuddy/binaries/python/envs/default/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
else
    PY="python"
fi

exec "$PY" -m secagent.server
