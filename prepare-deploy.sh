#!/bin/bash

echo "🚀 PREPARANDO PROJETO PARA DEPLOY NO RAILWAY"
echo "=============================================="
echo ""

# Cores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Verificar se está no diretório correto
echo -e "${BLUE}[1/6]${NC} Verificando diretório..."
if [ ! -f "backend/main.py" ]; then
    echo "❌ Execute este script na pasta raiz do projeto!"
    exit 1
fi
echo -e "${GREEN}✅ Diretório correto${NC}"
echo ""

# 2. Verificar arquivos necessários
echo -e "${BLUE}[2/6]${NC} Verificando arquivos necessários..."
if [ ! -f "backend/requirements.txt" ]; then
    echo "❌ backend/requirements.txt não encontrado!"
    exit 1
fi
if [ ! -f "backend/Procfile" ]; then
    echo "❌ backend/Procfile não encontrado!"
    exit 1
fi
if [ ! -f "backend/railway.json" ]; then
    echo "❌ backend/railway.json não encontrado!"
    exit 1
fi
echo -e "${GREEN}✅ Todos os arquivos estão presentes${NC}"
echo ""

# 3. Gerar SECRET_KEY
echo -e "${BLUE}[3/6]${NC} Gerando SECRET_KEY..."
SECRET_KEY=$(openssl rand -hex 32)
echo -e "${GREEN}✅ SECRET_KEY gerada:${NC}"
echo -e "${YELLOW}${SECRET_KEY}${NC}"
echo ""
echo "📋 COPIE esta chave e cole no Railway como variável SECRET_KEY"
echo ""

# 4. Criar .env.example
echo -e "${BLUE}[4/6]${NC} Criando .env.example..."
cat > .env.example << EOF
# Database (será preenchido automaticamente pelo Railway)
DATABASE_URL=postgresql://usuario:senha@host:5432/database

# Segurança
SECRET_KEY=${SECRET_KEY}

# URLs
FRONTEND_URL=https://seu-projeto-frontend.up.railway.app

# Stripe (obtenha em: https://dashboard.stripe.com/test/apikeys)
STRIPE_SECRET_KEY=sk_test_SEU_CODIGO_AQUI
STRIPE_PUBLISHABLE_KEY=pk_test_SEU_CODIGO_AQUI
STRIPE_WEBHOOK_SECRET=whsec_SEU_CODIGO_AQUI

# Email (para reset de senha)
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USER=mac526@hotmail.com
SMTP_PASSWORD=sua_senha_de_aplicativo
FROM_EMAIL=mac526@hotmail.com
FROM_NAME=Security Scanner Pro
EOF
echo -e "${GREEN}✅ Arquivo .env.example criado${NC}"
echo ""

# 5. Verificar Git
echo -e "${BLUE}[5/6]${NC} Verificando Git..."
if [ ! -d ".git" ]; then
    echo "⚠️  Git não inicializado. Deseja inicializar? (s/n)"
    read -r response
    if [[ "$response" =~ ^([sS]|[sS][iI][mM])$ ]]; then
        git init
        echo -e "${GREEN}✅ Git inicializado${NC}"
    else
        echo -e "${YELLOW}⏭️  Git não inicializado (você pode fazer manualmente depois)${NC}"
    fi
else
    echo -e "${GREEN}✅ Git já inicializado${NC}"
fi
echo ""

# 6. Criar .gitignore
echo -e "${BLUE}[6/6]${NC} Criando .gitignore..."
cat > .gitignore << EOF
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Environment
.env
.env.local
.env.production

# Database
*.db
*.sqlite
*.sqlite3

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Testing
.pytest_cache/
.coverage
htmlcov/

# Railway
.railway/
EOF
echo -e "${GREEN}✅ Arquivo .gitignore criado${NC}"
echo ""

# Resumo final
echo "=============================================="
echo -e "${GREEN}🎉 PREPARAÇÃO CONCLUÍDA!${NC}"
echo "=============================================="
echo ""
echo "📋 PRÓXIMOS PASSOS:"
echo ""
echo "1️⃣  Crie uma conta no Railway:"
echo "   👉 https://railway.app"
echo ""
echo "2️⃣  Crie um repositório no GitHub e faça push:"
echo "   git add ."
echo "   git commit -m \"Deploy para Railway\""
echo "   git remote add origin https://github.com/SEU_USUARIO/security-scanner.git"
echo "   git push -u origin main"
echo ""
echo "3️⃣  No Railway, faça deploy do GitHub:"
echo "   - New Project → Deploy from GitHub repo"
echo "   - Selecione seu repositório"
echo ""
echo "4️⃣  Adicione PostgreSQL:"
echo "   - + New → Database → PostgreSQL"
echo ""
echo "5️⃣  Configure as variáveis de ambiente no Railway:"
echo -e "   ${YELLOW}SECRET_KEY=${SECRET_KEY}${NC}"
echo "   DATABASE_URL=(preenchido automaticamente)"
echo "   FRONTEND_URL=https://seu-projeto.up.railway.app"
echo "   + Variáveis do Stripe (veja .env.example)"
echo ""
echo "6️⃣  Acesse a URL gerada pelo Railway!"
echo ""
echo "📖 Guia completo em: DEPLOY-RAILWAY-SIMPLES.md"
echo ""
