#!/usr/bin/env bash
# SecAgent MCP server launcher for Reasonix.
# Sets the env vars secagent needs (absolute DB + binaries paths) then starts
# the stdio MCP server. Reasonix's `name=command` mcp format has no env field,
# so this wrapper is the clean way to inject them.
set -euo pipefail

export SECAGENT_DB_PATH="/Users/ze/Downloads/爬虫/secagent/data/secagent.db"
export SECAGENT_BINARIES_DIR="/Users/ze/Downloads/爬虫/secagent/bin"
export SECAGENT_DEFAULT_QUOTA="100"

exec /Users/ze/.workbuddy/binaries/python/envs/default/bin/python -m secagent.server
