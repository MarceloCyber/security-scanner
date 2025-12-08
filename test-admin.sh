#!/bin/bash

echo "🧪 TESTANDO PAINEL ADMINISTRATIVO"
echo "=================================="
echo ""

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

API_URL="http://localhost:8000"

# 1. Testar login admin
echo -e "${BLUE}1. Testando login do admin...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST "${API_URL}/api/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123")

if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
    echo -e "${GREEN}✅ Login admin funcionando${NC}"
    TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    echo "Token obtido: ${TOKEN:0:20}..."
else
    echo -e "${RED}❌ Erro no login${NC}"
    echo "$LOGIN_RESPONSE"
    exit 1
fi

echo ""

# 2. Testar endpoint de stats
echo -e "${BLUE}2. Testando endpoint /api/admin/stats...${NC}"
STATS_RESPONSE=$(curl -s -X GET "${API_URL}/api/admin/stats" \
  -H "Authorization: Bearer $TOKEN")

if echo "$STATS_RESPONSE" | grep -q "total_users"; then
    echo -e "${GREEN}✅ Stats funcionando${NC}"
    echo "$STATS_RESPONSE" | jq '.'
else
    echo -e "${RED}❌ Erro no stats${NC}"
    echo "$STATS_RESPONSE"
fi

echo ""

# 3. Testar endpoint de users
echo -e "${BLUE}3. Testando endpoint /api/admin/users...${NC}"
USERS_RESPONSE=$(curl -s -X GET "${API_URL}/api/admin/users?page=1&limit=10" \
  -H "Authorization: Bearer $TOKEN")

if echo "$USERS_RESPONSE" | grep -q "users"; then
    echo -e "${GREEN}✅ Users funcionando${NC}"
    echo "Total de usuários: $(echo "$USERS_RESPONSE" | jq '.total')"
else
    echo -e "${RED}❌ Erro no users${NC}"
    echo "$USERS_RESPONSE"
fi

echo ""

# 4. Testar endpoint de activity
echo -e "${BLUE}4. Testando endpoint /api/admin/activity...${NC}"
ACTIVITY_RESPONSE=$(curl -s -X GET "${API_URL}/api/admin/activity" \
  -H "Authorization: Bearer $TOKEN")

if [ ! -z "$ACTIVITY_RESPONSE" ]; then
    echo -e "${GREEN}✅ Activity funcionando${NC}"
    echo "Atividades retornadas: $(echo "$ACTIVITY_RESPONSE" | jq 'length')"
else
    echo -e "${RED}❌ Erro no activity${NC}"
fi

echo ""

# 5. Testar endpoint de system
echo -e "${BLUE}5. Testando endpoint /api/admin/system...${NC}"
SYSTEM_RESPONSE=$(curl -s -X GET "${API_URL}/api/admin/system" \
  -H "Authorization: Bearer $TOKEN")

if echo "$SYSTEM_RESPONSE" | grep -q "platform"; then
    echo -e "${GREEN}✅ System funcionando${NC}"
    echo "$SYSTEM_RESPONSE" | jq '.'
else
    echo -e "${RED}❌ Erro no system${NC}"
    echo "$SYSTEM_RESPONSE"
fi

echo ""

# 6. Testar forgot password
echo -e "${BLUE}6. Testando endpoint /api/auth/forgot-password...${NC}"
FORGOT_RESPONSE=$(curl -s -X POST "${API_URL}/api/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@security.com"}')

if echo "$FORGOT_RESPONSE" | grep -q "message"; then
    echo -e "${GREEN}✅ Forgot password funcionando${NC}"
    echo "$FORGOT_RESPONSE" | jq '.'
else
    echo -e "${RED}❌ Erro no forgot password${NC}"
    echo "$FORGOT_RESPONSE"
fi

echo ""

# 7. Verificar token no banco
echo -e "${BLUE}7. Verificando token no banco de dados...${NC}"
cd backend
TOKEN_DB=$(sqlite3 security_scanner.db "SELECT reset_token FROM users WHERE email='admin@security.com';")
if [ ! -z "$TOKEN_DB" ]; then
    echo -e "${GREEN}✅ Token salvo no banco${NC}"
    echo "Token: ${TOKEN_DB:0:30}..."
else
    echo -e "${RED}⚠️  Nenhum token encontrado (normal se email não configurado)${NC}"
fi
cd ..

echo ""
echo "=================================="
echo -e "${GREEN}✅ TODOS OS TESTES CONCLUÍDOS!${NC}"
echo ""
echo "📝 Acesse o painel em: http://localhost:8000/admin-login.html"
echo "🔑 Login: admin / Senha: admin123"
