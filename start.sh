#!/bin/bash

# Obtém o diretório do script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

LOCAL_MODE=0
RELOAD_MODE=0
APP_PORT="${PORT:-8000}"
for arg in "$@"; do
    case "$arg" in
        --local) LOCAL_MODE=1 ;;
        --reload) RELOAD_MODE=1 ;;
    esac
done

# Este script é destinado à execução no computador do operador. A produção
# usa o Procfile/render.yaml e não recebe esta liberação de host local.
export IRON_AI_LOCAL_LAUNCH="true"

if [ "$LOCAL_MODE" -eq 1 ]; then
    export DATABASE_URL="sqlite:///$SCRIPT_DIR/backend/security_scanner.db"
    export REDIS_URL=""
    export APP_ENV="development"
    echo "🧪 Modo local: SQLite habilitado"
fi

echo "🚀 Iniciando Iron AI Security Platform..."
echo ""

# Usa o interpretador do ambiente virtual diretamente. Isso continua
# funcionando mesmo quando o projeto foi movido e o activate guarda path antigo.
PYTHON_BIN="$SCRIPT_DIR/venv/bin/python3"
if [ -x "$PYTHON_BIN" ]; then
    PYTHON_VERSION="$("$PYTHON_BIN" --version 2>&1)"
    echo "✅ Ambiente virtual encontrado: $PYTHON_VERSION"
else
    echo "❌ Ambiente virtual não encontrado. Execute ./install.sh primeiro."
    exit 1
fi

# Verifica se .env existe
if [ ! -f ".env" ]; then
    echo "⚠️  Arquivo .env não encontrado. Usando configurações padrão."
    cp .env.example .env
fi

echo ""
if command -v lsof >/dev/null 2>&1; then
    EXISTING_PID="$(lsof -tiTCP:"$APP_PORT" -sTCP:LISTEN 2>/dev/null | head -n 1)"
    if [ -n "$EXISTING_PID" ]; then
        echo "❌ A porta $APP_PORT já está em uso pelo processo PID $EXISTING_PID."
        echo "💡 Encerre o terminal anterior com Ctrl+C ou execute: kill -TERM $EXISTING_PID"
        exit 1
    fi
fi

echo "🔧 Iniciando servidor na porta $APP_PORT..."
echo "📍 Acesse: http://localhost:$APP_PORT"
echo ""
echo "Pressione Ctrl+C para parar o servidor"
echo ""

cd backend
echo "🗃️  Aplicando migrations do banco..."
"$PYTHON_BIN" ../migrations/run.py || {
    echo "❌ Não foi possível acessar o banco configurado."
    echo "💡 Para testar sem PostgreSQL/Neon, execute: ./start.sh --local"
    exit 1
}
if [ "$RELOAD_MODE" -eq 1 ]; then
    "$PYTHON_BIN" -m uvicorn main:app --reload --host 0.0.0.0 --port "$APP_PORT"
else
    "$PYTHON_BIN" -m uvicorn main:app --host 0.0.0.0 --port "$APP_PORT"
fi
