#!/bin/bash

# Script de testes para o sistema de assinaturas
# Uso: ./test-subscription.sh [test-name]

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

API_URL="http://localhost:8000/api"
TOKEN=""

echo -e "${BLUE}🧪 Sistema de Testes - Assinaturas${NC}\n"

# Função para fazer login
login() {
    echo -e "${YELLOW}🔐 Fazendo login...${NC}"
    RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=teste&password=teste123")
    
    TOKEN=$(echo $RESPONSE | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
    
    if [ -z "$TOKEN" ]; then
        echo -e "${RED}❌ Erro ao fazer login${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Login realizado com sucesso${NC}\n"
}

# Teste 1: Obter informações de assinatura
test_subscription_info() {
    echo -e "${BLUE}📊 Teste 1: Informações de Assinatura${NC}"
    
    RESPONSE=$(curl -s "$API_URL/user/subscription-info" \
        -H "Authorization: Bearer $TOKEN")
    
    echo -e "Resposta:"
    echo $RESPONSE | python3 -m json.tool 2>/dev/null || echo $RESPONSE
    echo ""
}

# Teste 2: Listar todos os planos
test_list_plans() {
    echo -e "${BLUE}📋 Teste 2: Listar Planos${NC}"
    
    RESPONSE=$(curl -s "$API_URL/payments/plans")
    
    echo -e "Resposta:"
    echo $RESPONSE | python3 -m json.tool 2>/dev/null || echo $RESPONSE
    echo ""
}

# Teste 3: Upgrade manual para Starter
test_upgrade_starter() {
    echo -e "${BLUE}⬆️  Teste 3: Upgrade para Starter${NC}"
    
    RESPONSE=$(curl -s -X POST "$API_URL/payments/upgrade" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"plan": "starter"}')
    
    echo -e "Resposta:"
    echo $RESPONSE | python3 -m json.tool 2>/dev/null || echo $RESPONSE
    echo ""
    
    # Verificar se funcionou
    test_subscription_info
}

# Teste 4: Upgrade manual para Professional
test_upgrade_professional() {
    echo -e "${BLUE}⬆️  Teste 4: Upgrade para Professional${NC}"
    
    RESPONSE=$(curl -s -X POST "$API_URL/payments/upgrade" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"plan": "professional"}')
    
    echo -e "Resposta:"
    echo $RESPONSE | python3 -m json.tool 2>/dev/null || echo $RESPONSE
    echo ""
    
    # Verificar se funcionou
    test_subscription_info
}

# Teste 5: Downgrade para Free
test_downgrade_free() {
    echo -e "${BLUE}⬇️  Teste 5: Downgrade para Free${NC}"
    
    RESPONSE=$(curl -s -X POST "$API_URL/payments/upgrade" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"plan": "free"}')
    
    echo -e "Resposta:"
    echo $RESPONSE | python3 -m json.tool 2>/dev/null || echo $RESPONSE
    echo ""
    
    # Verificar se funcionou
    test_subscription_info
}

# Teste 6: Criar checkout session (Stripe)
test_create_checkout() {
    echo -e "${BLUE}💳 Teste 6: Criar Checkout Session${NC}"
    
    RESPONSE=$(curl -s -X POST "$API_URL/payments/create-checkout" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"plan": "professional"}')
    
    echo -e "Resposta:"
    echo $RESPONSE | python3 -m json.tool 2>/dev/null || echo $RESPONSE
    echo ""
    
    # Extrair URL do checkout
    CHECKOUT_URL=$(echo $RESPONSE | grep -o '"checkout_url":"[^"]*' | cut -d'"' -f4)
    
    if [ ! -z "$CHECKOUT_URL" ]; then
        echo -e "${GREEN}✅ Checkout criado!${NC}"
        echo -e "${YELLOW}URL: $CHECKOUT_URL${NC}"
        echo -e "\n${BLUE}💡 Abra essa URL no navegador para testar o pagamento${NC}"
    fi
    echo ""
}

# Teste 7: Simular incremento de scans
test_increment_scans() {
    echo -e "${BLUE}📈 Teste 7: Simular uso de scans${NC}"
    
    # Fazer 3 scans de teste
    for i in {1..3}; do
        echo -e "${YELLOW}Scan $i...${NC}"
        curl -s -X POST "$API_URL/scans/port" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"target": "127.0.0.1", "ports": "80"}' > /dev/null
        sleep 1
    done
    
    echo -e "${GREEN}✅ 3 scans executados${NC}\n"
    
    # Verificar contador
    test_subscription_info
}

# Teste 8: Verificar limite de scans (plano free)
test_scan_limit() {
    echo -e "${BLUE}🚫 Teste 8: Verificar Limite de Scans${NC}"
    
    # Garantir que está no plano free
    curl -s -X POST "$API_URL/payments/upgrade" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"plan": "free"}' > /dev/null
    
    echo -e "${YELLOW}Tentando fazer 12 scans (limite free = 10)...${NC}"
    
    for i in {1..12}; do
        RESPONSE=$(curl -s -X POST "$API_URL/scans/port" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"target": "127.0.0.1", "ports": "80"}')
        
        if echo $RESPONSE | grep -q "limit_exceeded\|limite"; then
            echo -e "${RED}❌ Scan $i: Limite excedido!${NC}"
            echo -e "${GREEN}✅ Sistema de limite funcionando corretamente${NC}"
            break
        else
            echo -e "${GREEN}✅ Scan $i: OK${NC}"
        fi
        sleep 0.5
    done
    echo ""
}

# Menu interativo
show_menu() {
    echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     TESTES DO SISTEMA DE ASSINATURAS     ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}\n"
    echo "1) Informações de Assinatura"
    echo "2) Listar Todos os Planos"
    echo "3) Upgrade para Starter"
    echo "4) Upgrade para Professional"
    echo "5) Downgrade para Free"
    echo "6) Criar Checkout Session (Stripe)"
    echo "7) Simular uso de scans"
    echo "8) Testar limite de scans"
    echo "9) Executar TODOS os testes"
    echo "0) Sair"
    echo ""
    read -p "Escolha uma opção: " choice
    
    case $choice in
        1) test_subscription_info ;;
        2) test_list_plans ;;
        3) test_upgrade_starter ;;
        4) test_upgrade_professional ;;
        5) test_downgrade_free ;;
        6) test_create_checkout ;;
        7) test_increment_scans ;;
        8) test_scan_limit ;;
        9) 
            test_subscription_info
            test_list_plans
            test_upgrade_starter
            test_upgrade_professional
            test_increment_scans
            test_create_checkout
            ;;
        0) 
            echo -e "${BLUE}Até logo!${NC}"
            exit 0
            ;;
        *) 
            echo -e "${RED}Opção inválida${NC}"
            ;;
    esac
    
    echo ""
    read -p "Pressione ENTER para continuar..."
    clear
    show_menu
}

# Main
main() {
    # Fazer login primeiro
    login
    
    # Se foi passado argumento, executar teste específico
    if [ ! -z "$1" ]; then
        case $1 in
            info) test_subscription_info ;;
            plans) test_list_plans ;;
            starter) test_upgrade_starter ;;
            professional) test_upgrade_professional ;;
            free) test_downgrade_free ;;
            checkout) test_create_checkout ;;
            scans) test_increment_scans ;;
            limit) test_scan_limit ;;
            all)
                test_subscription_info
                test_list_plans
                test_upgrade_starter
                test_upgrade_professional
                test_increment_scans
                test_create_checkout
                ;;
            *)
                echo -e "${RED}Teste desconhecido: $1${NC}"
                echo "Testes disponíveis: info, plans, starter, professional, free, checkout, scans, limit, all"
                exit 1
                ;;
        esac
    else
        # Modo interativo
        clear
        show_menu
    fi
}

main "$@"
