#!/bin/bash

echo "🧪 TESTANDO TODAS AS FUNCIONALIDADES ADMINISTRATIVAS"
echo "=========================================================="
echo ""

# Cores
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_URL="http://localhost:8000"
ERRORS=0
SUCCESS=0

# Função para testar endpoint
test_endpoint() {
    local name=$1
    local method=$2
    local endpoint=$3
    local data=$4
    local expected_code=${5:-200}
    
    echo -e "${BLUE}🔍 Testando: $name${NC}"
    
    if [ "$method" == "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "${API_URL}${endpoint}" \
          -H "Authorization: Bearer $TOKEN")
    elif [ "$method" == "POST" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}${endpoint}" \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d "$data")
    elif [ "$method" == "PUT" ]; then
        response=$(curl -s -w "\n%{http_code}" -X PUT "${API_URL}${endpoint}" \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d "$data")
    elif [ "$method" == "DELETE" ]; then
        response=$(curl -s -w "\n%{http_code}" -X DELETE "${API_URL}${endpoint}" \
          -H "Authorization: Bearer $TOKEN")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" == "$expected_code" ] || [ "$http_code" == "200" ] || [ "$http_code" == "201" ]; then
        echo -e "${GREEN}✅ SUCESSO - HTTP $http_code${NC}"
        ((SUCCESS++))
        return 0
    else
        echo -e "${RED}❌ FALHA - HTTP $http_code${NC}"
        echo "Resposta: $body"
        ((ERRORS++))
        return 1
    fi
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSO 1: LOGIN E AUTENTICAÇÃO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

LOGIN_RESPONSE=$(curl -s -X POST "${API_URL}/api/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123")

if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
    echo -e "${GREEN}✅ Login realizado com sucesso${NC}"
    TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
    echo "Token: ${TOKEN:0:30}..."
    ((SUCCESS++))
else
    echo -e "${RED}❌ Falha no login${NC}"
    echo "$LOGIN_RESPONSE"
    ((ERRORS++))
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSO 2: DASHBOARD - ESTATÍSTICAS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

test_endpoint "Dashboard Stats" "GET" "/api/admin/stats"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSO 3: USUÁRIOS - LISTAGEM"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

test_endpoint "Listar Usuários (página 1)" "GET" "/api/admin/users?page=1&limit=10"
test_endpoint "Buscar Usuário" "GET" "/api/admin/users?search=admin"
test_endpoint "Filtrar por Plano" "GET" "/api/admin/users?plan=free"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSO 4: USUÁRIOS - DETALHES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

test_endpoint "Detalhes do Usuário 1" "GET" "/api/admin/users/1"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSO 5: USUÁRIOS - ATUALIZAÇÃO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

UPDATE_DATA='{"email":"admin@security.com","subscription_plan":"free","subscription_status":"active","scans_limit":10,"is_admin":true}'
test_endpoint "Atualizar Usuário 1" "PUT" "/api/admin/users/1" "$UPDATE_DATA"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSO 6: USUÁRIOS - RESET DE SCANS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

test_endpoint "Reset Scans do Usuário 3" "POST" "/api/admin/users/3/reset-scans"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSO 7: ATIVIDADES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

test_endpoint "Listar Atividades" "GET" "/api/admin/activity"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSO 8: SISTEMA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

test_endpoint "Informações do Sistema" "GET" "/api/admin/system"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSO 9: RESET DE SENHA (opcional)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

FORGOT_DATA='{"email":"admin@security.com"}'
test_endpoint "Solicitar Reset de Senha" "POST" "/api/auth/forgot-password" "$FORGOT_DATA"

echo ""
echo "=========================================================="
echo "  RESUMO DOS TESTES"
echo "=========================================================="
echo ""
echo -e "${GREEN}✅ Sucessos: $SUCCESS${NC}"
echo -e "${RED}❌ Falhas: $ERRORS${NC}"
echo ""

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}🎉 TODOS OS TESTES PASSARAM!${NC}"
    echo ""
    echo "✅ Dashboard funcionando"
    echo "✅ Listagem de usuários funcionando"
    echo "✅ Detalhes de usuários funcionando"
    echo "✅ Atualização de usuários funcionando"
    echo "✅ Reset de scans funcionando"
    echo "✅ Atividades funcionando"
    echo "✅ Informações do sistema funcionando"
    echo "✅ Reset de senha funcionando"
    echo ""
    echo "📝 Acesse: http://localhost:8000/admin-login.html"
    echo "🔑 Login: admin / Senha: admin123"
    exit 0
else
    echo -e "${RED}⚠️  ALGUNS TESTES FALHARAM${NC}"
    echo "Verifique os erros acima"
    exit 1
fi
