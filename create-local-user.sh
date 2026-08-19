#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PYTHON_BIN="$SCRIPT_DIR/venv/bin/python3"
if [ ! -x "$PYTHON_BIN" ]; then
    echo "Ambiente Python não encontrado. Execute ./install.sh"
    exit 1
fi
exec "$PYTHON_BIN" "$SCRIPT_DIR/scripts/create_local_user.py" "$@"
