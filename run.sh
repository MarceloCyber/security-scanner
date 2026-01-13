#!/bin/bash

# 🚀 Security Scanner - Quick Start Script
# Usage: ./run.sh [start|stop|restart|status]

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$SCRIPT_DIR"
VENV_DIR="$PROJECT_DIR/venv"
BACKEND_DIR="$PROJECT_DIR/backend"
PID_FILE="/tmp/security-scanner.pid"
LOG_FILE="/tmp/security-scanner.log"
PORT=8000

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║     🔒 Iron Net Professional         ║"
    echo "║           Enterprise Edition                 ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_port() {
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

start_server() {
    print_banner
    
    # Check if already running
    if check_port; then
        echo -e "${YELLOW}⚠️  Servidor já está rodando na porta $PORT${NC}"
        echo -e "${BLUE}📍 Acesse: http://localhost:$PORT${NC}"
        return 1
    fi
    
    # Check virtual environment
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${RED}❌ Ambiente virtual não encontrado em: $VENV_DIR${NC}"
        echo -e "${YELLOW}💡 Execute: ./install.sh${NC}"
        return 1
    fi
    
    # Activate virtual environment and start server
    cd "$PROJECT_DIR"
    source "$VENV_DIR/bin/activate"
    
    echo -e "${GREEN}✅ Ambiente virtual ativado${NC}"
    echo -e "${BLUE}🔧 Iniciando servidor na porta $PORT...${NC}"
    echo ""
    
    # Start server in background
    cd "$BACKEND_DIR"
    nohup python -m uvicorn main:app --reload --host 0.0.0.0 --port $PORT > "$LOG_FILE" 2>&1 &
    
    # Save PID
    echo $! > "$PID_FILE"
    
    # Wait for server to start
    echo -e "${YELLOW}⏳ Aguardando servidor iniciar...${NC}"
    sleep 5
    
    # Check if started successfully
    if check_port; then
        echo -e "${GREEN}✅ Servidor iniciado com sucesso!${NC}"
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}📍 API Principal:${NC}       http://localhost:$PORT"
        echo -e "${GREEN}📚 Documentação:${NC}        http://localhost:$PORT/docs"
        echo -e "${GREEN}🎯 Dashboard:${NC}           http://localhost:$PORT/dashboard.html"
        echo -e "${GREEN}❤️  Health Check:${NC}       http://localhost:$PORT/api/health"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${BLUE}📋 Ver logs:${NC}            tail -f $LOG_FILE"
        echo -e "${BLUE}🛑 Parar servidor:${NC}      ./run.sh stop"
        echo ""
        
        # Open browser (optional)
        if command -v open &> /dev/null; then
            sleep 2
            open "http://localhost:$PORT/dashboard.html" 2>/dev/null || true
        fi
    else
        echo -e "${RED}❌ Falha ao iniciar servidor${NC}"
        echo -e "${YELLOW}📋 Verifique os logs em: $LOG_FILE${NC}"
        return 1
    fi
}

stop_server() {
    echo -e "${YELLOW}🛑 Parando servidor...${NC}"
    
    # Kill by PID file
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            kill $PID 2>/dev/null || kill -9 $PID 2>/dev/null
            echo -e "${GREEN}✅ Servidor parado (PID: $PID)${NC}"
        fi
        rm -f "$PID_FILE"
    fi
    
    # Kill by port
    if check_port; then
        lsof -ti:$PORT | xargs kill -9 2>/dev/null
        echo -e "${GREEN}✅ Processo na porta $PORT finalizado${NC}"
    fi
    
    # Kill by process name
    pkill -9 -f "uvicorn.*$PORT" 2>/dev/null
    
    sleep 1
    
    if ! check_port; then
        echo -e "${GREEN}✅ Servidor totalmente parado${NC}"
    else
        echo -e "${RED}⚠️  Ainda há processos na porta $PORT${NC}"
    fi
}

restart_server() {
    echo -e "${BLUE}🔄 Reiniciando servidor...${NC}"
    echo ""
    stop_server
    sleep 2
    start_server
}

show_status() {
    print_banner
    
    if check_port; then
        PID=$(lsof -ti:$PORT)
        echo -e "${GREEN}✅ Status: RODANDO${NC}"
        echo -e "${BLUE}📍 URL: http://localhost:$PORT${NC}"
        echo -e "${BLUE}🆔 PID: $PID${NC}"
        echo ""
        echo -e "${YELLOW}Processos ativos:${NC}"
        ps aux | grep -E "uvicorn|python.*main:app" | grep -v grep
    else
        echo -e "${RED}❌ Status: PARADO${NC}"
        echo -e "${YELLOW}💡 Para iniciar: ./run.sh start${NC}"
    fi
}

show_logs() {
    if [ -f "$LOG_FILE" ]; then
        echo -e "${BLUE}📋 Últimas 50 linhas do log:${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        tail -50 "$LOG_FILE"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${BLUE}📋 Ver logs ao vivo:${NC} tail -f $LOG_FILE"
    else
        echo -e "${RED}❌ Arquivo de log não encontrado: $LOG_FILE${NC}"
    fi
}

show_help() {
    print_banner
    echo -e "${GREEN}Uso:${NC} ./run.sh [comando]"
    echo ""
    echo -e "${BLUE}Comandos disponíveis:${NC}"
    echo -e "  ${GREEN}start${NC}      - Inicia o servidor"
    echo -e "  ${GREEN}stop${NC}       - Para o servidor"
    echo -e "  ${GREEN}restart${NC}    - Reinicia o servidor"
    echo -e "  ${GREEN}status${NC}     - Mostra status do servidor"
    echo -e "  ${GREEN}logs${NC}       - Mostra logs do servidor"
    echo -e "  ${GREEN}help${NC}       - Mostra esta ajuda"
    echo ""
    echo -e "${YELLOW}Exemplos:${NC}"
    echo -e "  ./run.sh start     # Inicia o servidor"
    echo -e "  ./run.sh stop      # Para o servidor"
    echo -e "  ./run.sh restart   # Reinicia o servidor"
    echo ""
}

# Main
case "${1:-start}" in
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
        show_logs
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}❌ Comando inválido: $1${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac
