#!/bin/bash

# Security Scanner CLI - Gerenciador do projeto
# Uso: scanner-cli [comando]

PROJECT_DIR="/Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner"
VENV_PYTHON="$PROJECT_DIR/venv/bin/python"
BACKEND_DIR="$PROJECT_DIR/backend"
LOG_FILE="/tmp/scanner_server.log"

# Cores para output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para mostrar banner
show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          🔒 Security Scanner Professional 🔒            ║"
    echo "║                 Enterprise Edition v1.0                 ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Função para verificar se o servidor está rodando
is_running() {
    lsof -ti:8000 > /dev/null 2>&1
    return $?
}

# Função para iniciar o servidor
start_server() {
    show_banner
    
    if is_running; then
        echo -e "${YELLOW}⚠️  Servidor já está rodando na porta 8000${NC}"
        echo -e "Use '${GREEN}scanner-cli stop${NC}' para parar ou '${GREEN}scanner-cli restart${NC}' para reiniciar"
        exit 0
    fi
    
    echo -e "${BLUE}🚀 Iniciando Security Scanner...${NC}"
    echo ""
    
    # Verifica se o ambiente virtual existe
    if [ ! -d "$PROJECT_DIR/venv" ]; then
        echo -e "${RED}❌ Ambiente virtual não encontrado!${NC}"
        echo -e "Execute: ${GREEN}cd $PROJECT_DIR && ./install.sh${NC}"
        exit 1
    fi
    
    # Verifica se .env existe
    if [ ! -f "$PROJECT_DIR/.env" ]; then
        echo -e "${YELLOW}⚠️  Arquivo .env não encontrado. Criando...${NC}"
        cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    fi
    
    # Mata qualquer processo na porta 8000
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    sleep 1
    
    # Inicia o servidor em background
    cd "$BACKEND_DIR"
    nohup "$VENV_PYTHON" -m uvicorn main:app --reload --host 0.0.0.0 --port 8000 > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!
    
    echo -e "${GREEN}✅ Servidor iniciado! (PID: $SERVER_PID)${NC}"
    echo ""
    
    # Aguarda o servidor iniciar
    echo -e "${BLUE}⏳ Aguardando servidor inicializar...${NC}"
    sleep 3
    
    # Verifica se está rodando
    if is_running; then
        echo -e "${GREEN}✅ Servidor online!${NC}"
        echo ""
        echo -e "${BLUE}📍 URLs de acesso:${NC}"
        echo -e "   • Frontend:  ${GREEN}http://localhost:8000${NC}"
        echo -e "   • API Docs:  ${GREEN}http://localhost:8000/docs${NC}"
        echo -e "   • Health:    ${GREEN}http://localhost:8000/api/health${NC}"
        echo ""
        echo -e "${BLUE}📋 Comandos úteis:${NC}"
        echo -e "   • Ver logs:   ${GREEN}scanner-cli logs${NC}"
        echo -e "   • Parar:      ${GREEN}scanner-cli stop${NC}"
        echo -e "   • Reiniciar:  ${GREEN}scanner-cli restart${NC}"
        echo -e "   • Status:     ${GREEN}scanner-cli status${NC}"
        echo ""
    else
        echo -e "${RED}❌ Erro ao iniciar servidor!${NC}"
        echo -e "Verifique os logs: ${GREEN}scanner-cli logs${NC}"
        exit 1
    fi
}

# Função para parar o servidor
stop_server() {
    echo -e "${BLUE}🛑 Parando Security Scanner...${NC}"
    
    if ! is_running; then
        echo -e "${YELLOW}⚠️  Servidor não está rodando${NC}"
        exit 0
    fi
    
    # Mata o processo
    lsof -ti:8000 | xargs kill -9 2>/dev/null
    pkill -9 -f "uvicorn.*8000" 2>/dev/null
    sleep 1
    
    if ! is_running; then
        echo -e "${GREEN}✅ Servidor parado com sucesso${NC}"
    else
        echo -e "${RED}❌ Erro ao parar servidor${NC}"
        exit 1
    fi
}

# Função para reiniciar o servidor
restart_server() {
    echo -e "${BLUE}🔄 Reiniciando Security Scanner...${NC}"
    stop_server
    sleep 2
    start_server
}

# Função para mostrar status
show_status() {
    show_banner
    
    if is_running; then
        PID=$(lsof -ti:8000)
        echo -e "${GREEN}✅ Status: ONLINE${NC}"
        echo -e "${BLUE}📊 Informações:${NC}"
        echo -e "   • PID:        $PID"
        echo -e "   • Porta:      8000"
        echo -e "   • URL:        http://localhost:8000"
        echo -e "   • Logs:       $LOG_FILE"
        echo ""
        
        # Testa health endpoint
        HEALTH=$(curl -s http://localhost:8000/api/health 2>/dev/null)
        if [ ! -z "$HEALTH" ]; then
            echo -e "${GREEN}✅ API respondendo corretamente${NC}"
            echo -e "   Response: $HEALTH"
        fi
    else
        echo -e "${RED}❌ Status: OFFLINE${NC}"
        echo -e "Use '${GREEN}scanner-cli start${NC}' para iniciar"
    fi
}

# Função para mostrar logs
show_logs() {
    if [ ! -f "$LOG_FILE" ]; then
        echo -e "${YELLOW}⚠️  Arquivo de logs não encontrado${NC}"
        exit 1
    fi
    
    if [ "$1" = "-f" ] || [ "$1" = "--follow" ]; then
        echo -e "${BLUE}📋 Monitorando logs (Ctrl+C para sair)...${NC}"
        echo ""
        tail -f "$LOG_FILE"
    else
        echo -e "${BLUE}📋 Últimas 50 linhas dos logs:${NC}"
        echo ""
        tail -50 "$LOG_FILE"
    fi
}

# Função para abrir frontend no navegador
open_frontend() {
    if ! is_running; then
        echo -e "${RED}❌ Servidor não está rodando!${NC}"
        echo -e "Use '${GREEN}scanner-cli start${NC}' primeiro"
        exit 1
    fi
    
    echo -e "${BLUE}🌐 Abrindo frontend no navegador...${NC}"
    open "http://localhost:8000" 2>/dev/null || \
    xdg-open "http://localhost:8000" 2>/dev/null || \
    echo -e "${YELLOW}⚠️  Não foi possível abrir automaticamente. Acesse: http://localhost:8000${NC}"
}

# Função para mostrar informações do sistema
show_info() {
    show_banner
    
    echo -e "${BLUE}📦 Informações do Sistema:${NC}"
    echo ""
    echo -e "   • Diretório:  $PROJECT_DIR"
    echo -e "   • Python:     $VENV_PYTHON"
    echo -e "   • Backend:    $BACKEND_DIR"
    echo -e "   • Logs:       $LOG_FILE"
    echo ""
    
    if [ -f "$PROJECT_DIR/requirements.txt" ]; then
        echo -e "${BLUE}📚 Dependências Principais:${NC}"
        source "$PROJECT_DIR/venv/bin/activate" 2>/dev/null
        pip list 2>/dev/null | grep -E "(fastapi|uvicorn|sqlalchemy|bcrypt|reportlab|scikit|numpy)" | head -10
    fi
}

# Função para executar testes
run_tests() {
    echo -e "${BLUE}🧪 Executando testes...${NC}"
    
    if ! is_running; then
        echo -e "${YELLOW}⚠️  Iniciando servidor para testes...${NC}"
        start_server
        sleep 3
    fi
    
    echo ""
    echo -e "${BLUE}Testando endpoints principais:${NC}"
    echo ""
    
    # Test 1: Health check
    echo -n "   • Health check... "
    HEALTH=$(curl -s http://localhost:8000/api/health 2>/dev/null)
    if echo "$HEALTH" | grep -q "healthy"; then
        echo -e "${GREEN}✅${NC}"
    else
        echo -e "${RED}❌${NC}"
    fi
    
    # Test 2: API Docs
    echo -n "   • API Docs... "
    DOCS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/docs 2>/dev/null)
    if [ "$DOCS" = "200" ]; then
        echo -e "${GREEN}✅${NC}"
    else
        echo -e "${RED}❌${NC}"
    fi
    
    # Test 3: Languages endpoint
    echo -n "   • Languages endpoint... "
    LANGS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/languages 2>/dev/null)
    if [ "$LANGS" = "200" ]; then
        echo -e "${GREEN}✅${NC}"
    else
        echo -e "${RED}❌${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✅ Testes concluídos!${NC}"
}

# Função para mostrar ajuda
show_help() {
    show_banner
    
    echo -e "${BLUE}📖 Uso: scanner-cli [comando]${NC}"
    echo ""
    echo -e "${BLUE}Comandos disponíveis:${NC}"
    echo ""
    echo -e "   ${GREEN}start${NC}           Inicia o servidor"
    echo -e "   ${GREEN}stop${NC}            Para o servidor"
    echo -e "   ${GREEN}restart${NC}         Reinicia o servidor"
    echo -e "   ${GREEN}status${NC}          Mostra status do servidor"
    echo -e "   ${GREEN}logs${NC}            Mostra logs (use -f para seguir)"
    echo -e "   ${GREEN}open${NC}            Abre frontend no navegador"
    echo -e "   ${GREEN}test${NC}            Executa testes básicos"
    echo -e "   ${GREEN}info${NC}            Mostra informações do sistema"
    echo -e "   ${GREEN}help${NC}            Mostra esta ajuda"
    echo ""
    echo -e "${BLUE}Exemplos:${NC}"
    echo ""
    echo -e "   ${GREEN}scanner-cli start${NC}        # Inicia o servidor"
    echo -e "   ${GREEN}scanner-cli logs -f${NC}      # Monitora logs em tempo real"
    echo -e "   ${GREEN}scanner-cli restart${NC}      # Reinicia o servidor"
    echo ""
}

# Main - Processa comando
case "$1" in
    start)
        start_server
        ;;
    stop)
        stop_server
        ;;
    restart)
        restart_server
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$2"
        ;;
    open)
        open_frontend
        ;;
    test)
        run_tests
        ;;
    info)
        show_info
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        if [ -z "$1" ]; then
            show_help
        else
            echo -e "${RED}❌ Comando desconhecido: $1${NC}"
            echo -e "Use '${GREEN}scanner-cli help${NC}' para ver os comandos disponíveis"
            exit 1
        fi
        ;;
esac
