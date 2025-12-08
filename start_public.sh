#!/bin/bash

echo "🚀 Iniciando servidor público..."

# Para processos anteriores
pkill -9 -f ngrok 2>/dev/null
pkill -9 -f "uvicorn main:app" 2>/dev/null

# Inicia ngrok em background
ngrok http 8000 > /dev/null &

echo "⏳ Aguardando ngrok iniciar (3 segundos)..."
sleep 3

# Obtém automaticamente a URL do ngrok
PUBLIC_URL=$(curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"https://[^"]*' | grep -o 'https://[^"]*' | head -n 1)
PUBLIC_DOMAIN=$(echo $PUBLIC_URL | sed 's|https://||')

if [ -z "$PUBLIC_DOMAIN" ]; then
    echo "❌ Erro: Não consegui obter o domínio do ngrok"
    echo "Verifique se o ngrok está instalado: brew install ngrok"
    exit 1
fi

echo "✅ Ngrok iniciado!"
echo "🌐 URL Pública: $PUBLIC_URL"
echo "📋 Domínio: $PUBLIC_DOMAIN"
echo ""

# Exporta a variável
export PUBLIC_DOMAIN="$PUBLIC_DOMAIN"

# Inicia o servidor
echo "🚀 Iniciando servidor backend..."
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner
source venv/bin/activate
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
