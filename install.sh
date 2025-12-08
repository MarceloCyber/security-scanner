#!/bin/bash

echo "🔒 Security Scanner - Inicialização"
echo "=================================="
echo ""

# Verifica se Python está instalado
if ! command -v python3 &> /dev/null
then
    echo "❌ Python 3 não está instalado. Por favor, instale o Python 3.8 ou superior."
    exit 1
fi

echo "✅ Python encontrado: $(python3 --version)"
echo ""

# Cria ambiente virtual se não existir
if [ ! -d "venv" ]; then
    echo "📦 Criando ambiente virtual..."
    python3 -m venv venv
    echo "✅ Ambiente virtual criado"
else
    echo "✅ Ambiente virtual já existe"
fi

echo ""
echo "🔧 Ativando ambiente virtual..."
source venv/bin/activate

echo ""
echo "📥 Instalando dependências..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

echo ""
echo "⚙️  Configurando ambiente..."

# Cria .env se não existir
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✅ Arquivo .env criado. Por favor, edite-o com suas configurações."
else
    echo "✅ Arquivo .env já existe"
fi

echo ""
echo "=================================="
echo "✅ Instalação concluída!"
echo ""
echo "Para iniciar o servidor, execute:"
echo "  cd backend"
echo "  python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "Depois acesse: http://localhost:8000"
echo "=================================="
