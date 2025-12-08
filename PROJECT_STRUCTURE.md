# 📁 Estrutura do Projeto Security Scanner

```
security-scanner/
│
├── 📄 README.md                      # Documentação completa
├── 📄 QUICKSTART.md                  # Guia rápido de instalação
├── 📄 requirements.txt               # Dependências Python
├── 📄 .env.example                   # Exemplo de variáveis de ambiente
├── 📄 .gitignore                     # Arquivos ignorados pelo Git
├── 🔧 install.sh                     # Script de instalação
├── 🚀 start.sh                       # Script para iniciar servidor
│
├── 📁 backend/                       # Backend da aplicação
│   ├── 📄 __init__.py
│   ├── 📄 main.py                    # Aplicação principal FastAPI
│   ├── 📄 config.py                  # Configurações da aplicação
│   ├── 📄 database.py                # Conexão com banco de dados
│   ├── 📄 auth.py                    # Sistema de autenticação JWT
│   │
│   ├── 📁 models/                    # Modelos do banco de dados
│   │   ├── 📄 __init__.py
│   │   ├── 📄 user.py                # Modelo de usuário
│   │   └── 📄 scan.py                # Modelo de scan
│   │
│   ├── 📁 routes/                    # Rotas da API
│   │   ├── 📄 __init__.py
│   │   ├── 📄 auth_routes.py         # Rotas de autenticação
│   │   └── 📄 scan_routes.py         # Rotas de scans
│   │
│   └── 📁 scanners/                  # Módulos de análise de segurança
│       ├── 📄 __init__.py
│       ├── 📄 code_scanner.py        # Scanner de código fonte
│       └── 📄 api_scanner.py         # Scanner de APIs
│
├── 📁 frontend/                      # Interface web
│   ├── 📄 index.html                 # Página de login
│   ├── 📄 dashboard.html             # Dashboard principal
│   │
│   ├── 📁 css/                       # Estilos
│   │   └── 📄 style.css              # CSS moderno e responsivo
│   │
│   └── 📁 js/                        # Scripts JavaScript
│       ├── 📄 auth.js                # Lógica de autenticação
│       └── 📄 dashboard.js           # Lógica do dashboard
│
└── 📁 examples/                      # Exemplos de uso
    └── 📄 vulnerable_code.py         # Código vulnerável para testes

```

## 🔍 Descrição dos Componentes

### Backend

#### 📄 main.py
- Aplicação principal FastAPI
- Configuração de CORS
- Inclusão de rotas
- Serve arquivos estáticos

#### 📄 auth.py
- Sistema de autenticação JWT
- Hashing de senhas com bcrypt
- Geração e validação de tokens
- Middleware de autenticação

#### 📄 database.py
- Configuração do SQLAlchemy
- Conexão com banco de dados
- Gerenciador de sessões

#### 📁 models/
- **user.py**: Tabela de usuários (id, username, email, password)
- **scan.py**: Tabela de scans (id, user_id, type, target, results)

#### 📁 routes/
- **auth_routes.py**: 
  - POST /api/auth/register - Criar conta
  - POST /api/auth/token - Login

- **scan_routes.py**: 
  - POST /api/scan/code - Analisar código
  - POST /api/scan/api - Testar API
  - POST /api/scan/upload - Upload arquivo
  - GET /api/scans - Listar scans
  - GET /api/scans/{id} - Detalhes do scan
  - GET /api/dashboard/stats - Estatísticas

#### 📁 scanners/
- **code_scanner.py**: 
  - 9 scanners especializados
  - Detecta OWASP Top 10
  - Análise linha por linha
  - Gera relatório detalhado

- **api_scanner.py**: 
  - Testa SQL Injection
  - Verifica autenticação
  - Testa autorização (IDOR)
  - Detecta exposição de dados
  - Verifica headers de segurança
  - Testa CORS
  - Verifica rate limiting

### Frontend

#### 📄 index.html
- Página de login/registro
- Design moderno com gradiente
- Animações suaves
- Validação de formulários

#### 📄 dashboard.html
- Dashboard com sidebar
- 4 páginas principais:
  1. Dashboard - Estatísticas
  2. Scan de Código - Análise de código
  3. Scan de API - Teste de APIs
  4. Histórico - Scans anteriores

#### 📄 style.css
- Design dark mode moderno
- Cores baseadas em severidade
- Animações e transições
- Totalmente responsivo
- Variáveis CSS personalizáveis

#### 📄 auth.js
- Gerenciamento de login/registro
- Armazenamento de tokens
- Redirecionamento automático

#### 📄 dashboard.js
- Navegação entre páginas
- Requisições à API
- Visualização de resultados
- Upload de arquivos
- Gráficos de severidade

## 🎨 Paleta de Cores

```css
--primary-color: #6366f1     /* Roxo primário */
--critical-color: #dc2626    /* Vermelho crítico */
--high-color: #ea580c        /* Laranja alto */
--medium-color: #f59e0b      /* Amarelo médio */
--low-color: #10b981         /* Verde baixo */
--dark-bg: #0f172a          /* Fundo escuro */
--dark-card: #1e293b        /* Card escuro */
```

## 🔐 Fluxo de Autenticação

1. Usuário registra conta (POST /api/auth/register)
2. Credenciais são validadas e senha é hasheada
3. Login retorna JWT token (POST /api/auth/token)
4. Token é armazenado no localStorage
5. Todas requisições incluem token no header Authorization
6. Backend valida token antes de processar requisição

## 📊 Fluxo de Scan

### Código:
1. Usuário cola código ou faz upload
2. Frontend envia para POST /api/scan/code
3. Backend executa 9 scanners diferentes
4. Resultados são salvos no banco
5. Frontend exibe vulnerabilidades encontradas

### API:
1. Usuário configura URL e endpoints
2. Frontend envia para POST /api/scan/api
3. Backend testa cada endpoint com 8 tipos de vulnerabilidades
4. Resultados são agregados e salvos
5. Frontend mostra vulnerabilidades por endpoint

## 💾 Banco de Dados

```sql
-- Tabela users
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    hashed_password TEXT,
    created_at DATETIME
);

-- Tabela scans
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    scan_type TEXT,
    target TEXT,
    status TEXT,
    results TEXT,
    created_at DATETIME,
    completed_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## 🚀 Tecnologias

### Backend
- **FastAPI 0.104+**: Framework web assíncrono
- **SQLAlchemy 2.0+**: ORM
- **Pydantic 2.5+**: Validação
- **Python-JOSE**: JWT
- **Passlib**: Hashing
- **Requests**: Cliente HTTP

### Frontend
- **Vanilla JavaScript**: Sem frameworks pesados
- **CSS3**: Grid, Flexbox, Animations
- **Font Awesome 6**: Ícones
- **Fetch API**: Requisições

## 📈 Recursos Implementados

✅ Sistema completo de autenticação  
✅ 9 scanners de código (OWASP Top 10)  
✅ 8 testes de API  
✅ Dashboard com estatísticas  
✅ Visualização de resultados  
✅ Histórico de scans  
✅ Upload de arquivos  
✅ Design responsivo  
✅ Dark mode moderno  
✅ Animações suaves  
✅ Feedback visual  
✅ Tratamento de erros  

## 🔄 Próximas Melhorias Possíveis

- [ ] Geração de relatórios PDF
- [ ] Exportação de resultados (CSV, JSON)
- [ ] Comparação entre scans
- [ ] Notificações por email
- [ ] Integração com CI/CD
- [ ] Scanner de dependências
- [ ] Análise de múltiplos arquivos
- [ ] Suporte a mais linguagens
- [ ] API REST documentada (Swagger)
- [ ] Testes automatizados
- [ ] Deploy com Docker
- [ ] Modo multi-usuário avançado

---

**Projeto completo e funcional, pronto para uso!** 🎉
