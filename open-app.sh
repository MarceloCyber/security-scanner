#!/bin/bash

# Script para abrir a aplicação no navegador

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Security Scanner Pro - Links Rápidos${NC}"
echo -e "${BLUE}════════════════════════════════════════════${NC}\n"

# Verificar se o servidor está rodando
if ! lsof -ti:8000 > /dev/null 2>&1; then
    echo -e "${BLUE}⚠️  Servidor não está rodando. Iniciando...${NC}\n"
    cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner
    nohup bash -c 'source venv/bin/activate && cd backend && python main.py' > /tmp/server.log 2>&1 &
    sleep 5
fi

echo -e "${GREEN}✅ Servidor rodando na porta 8000${NC}\n"

echo -e "${BLUE}📄 Páginas Disponíveis:${NC}"
echo "   1. Dashboard:        http://localhost:8000/dashboard.html"
echo "   2. Login:            http://localhost:8000/login.html"
echo "   3. Preços:           http://localhost:8000/pricing.html"
echo "   4. API Health:       http://localhost:8000/api/health"
echo "   5. API Docs:         http://localhost:8000/docs"
echo ""

read -p "Qual página deseja abrir? (1-5 ou Enter para Dashboard): " choice

case $choice in
    1|"")
        URL="http://localhost:8000/dashboard.html"
        ;;
    2)
        URL="http://localhost:8000/login.html"
        ;;
    3)
        URL="http://localhost:8000/pricing.html"
        ;;
    4)
        URL="http://localhost:8000/api/health"
        ;;
    5)
        URL="http://localhost:8000/docs"
        ;;
    *)
        echo "Opção inválida"
        exit 1
        ;;
esac

echo -e "\n${GREEN}🌐 Abrindo: $URL${NC}\n"

# Abrir no navegador padrão
if command -v open > /dev/null 2>&1; then
    open "$URL"
elif command -v xdg-open > /dev/null 2>&1; then
    xdg-open "$URL"
else
    echo "Abra manualmente: $URL"
fi
