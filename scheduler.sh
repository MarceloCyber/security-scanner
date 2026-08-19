#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PYTHON_BIN="$SCRIPT_DIR/venv/bin/python3"
if [ ! -x "$PYTHON_BIN" ]; then
    echo "Ambiente virtual não encontrado. Execute ./install.sh"
    exit 1
fi
if [ "${1:-}" = "--local" ]; then
    export DATABASE_URL="sqlite:///$SCRIPT_DIR/backend/security_scanner.db"
    export REDIS_URL=""
    export APP_ENV="development"
fi
cd "$SCRIPT_DIR/backend"
exec "$PYTHON_BIN" -m workers.scheduler
