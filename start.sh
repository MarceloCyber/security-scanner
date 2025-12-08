#!/bin/bash

# Obtém o diretório do script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "🚀 Iniciando Security Scanner..."
echo ""

# Ativa ambiente virtual
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "✅ Ambiente virtual ativado"
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
echo "🔧 Iniciando servidor na porta 8000..."
echo "📍 Acesse: http://localhost:8000"
echo ""
echo "Pressione Ctrl+C para parar o servidor"
echo ""

cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
