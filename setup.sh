#!/usr/bin/env bash
# Wrapper de setup (Linux/macOS). Delega para install.py. Requer python3.
set -e
PY="$(command -v python3 || command -v python)"
exec "$PY" "$(dirname "$0")/install.py" "$@"
