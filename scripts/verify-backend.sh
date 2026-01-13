#!/usr/bin/env bash
# Quick verification script for the Privara backend APIs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${1:-8000}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required but not installed."
  exit 1
fi

echo "Checking /api/processes on http://localhost:$PORT ..."
curl -s "http://localhost:${PORT}/api/processes" | head -c 400
echo
echo

echo "Triggering one snapshot write via /api/log-snapshot ..."
curl -s "http://localhost:${PORT}/api/log-snapshot"
echo
echo

if command -v sqlite3 >/dev/null 2>&1; then
  echo "Showing latest 5 rows from privara.db (if present) ..."
  sqlite3 privara.db "SELECT ts, pid, name, cpu, mem FROM process_snapshots ORDER BY id DESC LIMIT 5;"
else
  echo "sqlite3 not found; skipping DB inspection."
fi
