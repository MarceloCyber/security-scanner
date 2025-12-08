# Security Scanner

![Security Scanner](https://img.shields.io/badge/Security-Scanner-blue)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
![Python](https://img.shields.io/badge/Python-3.8+-green)
![FastAPI](https://img.shields.io/badge/FastAPI-Framework-teal)

## 🔒 Sobre o Projeto

Security Scanner é uma ferramenta profissional de análise de segurança desenvolvida para identificar vulnerabilidades em código fonte e APIs web. A ferramenta é baseada no **OWASP Top 10** e oferece uma interface moderna e intuitiva para auxiliar profissionais de segurança da informação.

### ✨ Características Principais

- 🔍 **Análise de Código Fonte**: Escaneia código em busca de vulnerabilidades comuns
- 🌐 **Teste de APIs**: Realiza testes de segurança abrangentes em endpoints REST
- 📊 **Dashboard Interativo**: Visualização clara e moderna dos resultados
- 🔐 **Sistema de Autenticação**: Login seguro com JWT
- 📈 **Histórico de Scans**: Acompanhe todas as análises realizadas
- 🎯 **OWASP Top 10**: Baseado nas principais vulnerabilidades da web

## 🎯 Vulnerabilidades Detectadas

A ferramenta detecta as seguintes vulnerabilidades baseadas no OWASP Top 10:

1. **SQL Injection** - Injeção de código SQL malicioso
2. **Cross-Site Scripting (XSS)** - Execução de scripts maliciosos
3. **Broken Authentication** - Falhas em autenticação
4. **Sensitive Data Exposure** - Exposição de dados sensíveis
5. **XML External Entity (XXE)** - Processamento inseguro de XML
6. **Broken Access Control** - Falhas no controle de acesso
7. **Security Misconfiguration** - Configurações incorretas
8. **Cross-Site Request Forgery (CSRF)** - Requisições forjadas
9. **Insecure Design** - Padrões de código inseguros
10. **Path Traversal** - Acesso não autorizado a arquivos

## 🚀 Instalação

### Pré-requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### Passo a Passo

1. **Clone ou navegue até o diretório do projeto**

```bash
cd security-scanner
```

2. **Crie um ambiente virtual (recomendado)**

```bash
python3 -m venv venv
source venv/bin/activate  # No macOS/Linux
# ou
venv\Scripts\activate  # No Windows
```

3. **Instale as dependências**

```bash
pip install -r requirements.txt
```

4. **Configure as variáveis de ambiente**

```bash
cp .env.example .env
```

Edite o arquivo `.env` e configure sua chave secreta:

```env
SECRET_KEY=sua-chave-secreta-super-segura-aqui
DATABASE_URL=sqlite:///./security_scanner.db
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

5. **Inicie o servidor**

```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

6. **Acesse a aplicação**

Abra seu navegador e acesse: `http://localhost:8000`

## 📖 Como Usar

### 1. Criar uma Conta

- Acesse a página inicial
- Clique em "Registrar-se"
- Preencha seus dados e crie uma conta

### 2. Fazer Login

- Use suas credenciais para fazer login
- Você será redirecionado para o dashboard

### 3. Análise de Código

#### Opção A: Colar Código

1. Clique em "Scan de Código" no menu lateral
2. Selecione a aba "Colar Código"
3. Cole seu código no campo de texto
4. Clique em "Analisar Código"

#### Opção B: Upload de Arquivo

1. Clique em "Scan de Código"
2. Selecione a aba "Upload de Arquivo"
3. Arraste ou selecione um arquivo (.py, .js, .php, etc.)
4. O scan será iniciado automaticamente

### 4. Teste de API

1. Clique em "Scan de API" no menu lateral
2. Preencha a URL base da API (ex: `https://api.exemplo.com`)
3. Liste os endpoints, um por linha:
   ```
   /api/users
   /api/products
   /api/auth/login
   ```
4. Adicione header de autenticação se necessário
5. Clique em "Iniciar Scan de API"

### 5. Visualizar Resultados

Os resultados mostram:

- **Tipo de Vulnerabilidade**: Nome da vulnerabilidade encontrada
- **Severidade**: CRÍTICA, ALTA, MÉDIA ou BAIXA
- **Localização**: Linha do código ou endpoint afetado
- **Descrição**: Detalhes sobre a vulnerabilidade
- **Recomendação**: Como corrigir o problema

### 6. Histórico

- Clique em "Histórico" para ver todos os scans realizados
- Clique em um scan para ver os detalhes

## 🏗️ Arquitetura

```
security-scanner/
├── backend/
│   ├── main.py              # Aplicação principal FastAPI
│   ├── config.py            # Configurações
│   ├── database.py          # Conexão com banco de dados
│   ├── auth.py              # Autenticação JWT
│   ├── models/              # Modelos do banco de dados
│   │   ├── user.py
│   │   └── scan.py
│   ├── routes/              # Rotas da API
│   │   ├── auth_routes.py
│   │   └── scan_routes.py
│   └── scanners/            # Módulos de análise
│       ├── code_scanner.py  # Scanner de código
│       └── api_scanner.py   # Scanner de API
├── frontend/
│   ├── index.html           # Página de login
│   ├── dashboard.html       # Dashboard principal
│   ├── css/
│   │   └── style.css        # Estilos modernos
│   └── js/
│       ├── auth.js          # Lógica de autenticação
│       └── dashboard.js     # Lógica do dashboard
├── requirements.txt         # Dependências Python
├── .env.example            # Exemplo de configuração
└── README.md               # Esta documentação
```

## 🛠️ Tecnologias Utilizadas

### Backend

- **FastAPI**: Framework web moderno e rápido
- **SQLAlchemy**: ORM para banco de dados
- **JWT**: Autenticação segura
- **Pydantic**: Validação de dados
- **Requests**: Cliente HTTP
- **BeautifulSoup**: Parser HTML/XML

### Frontend

- **HTML5/CSS3**: Interface moderna
- **JavaScript (Vanilla)**: Interatividade
- **Font Awesome**: Ícones

### Banco de Dados

- **SQLite**: Banco de dados leve (padrão)
- Suporte para PostgreSQL e MySQL

## 🔐 Segurança

A ferramenta implementa diversas práticas de segurança:

- ✅ Autenticação JWT com tokens expirantes
- ✅ Hashing de senhas com bcrypt
- ✅ CORS configurável
- ✅ Validação de entrada com Pydantic
- ✅ Proteção contra SQL Injection no próprio código
- ✅ Rate limiting (recomendado em produção)

## ⚠️ Avisos Importantes

### Uso Responsável

Esta ferramenta é destinada **apenas para uso ético e legal**:

- ✅ Teste apenas sistemas que você possui ou tem autorização explícita
- ✅ Use em ambientes de desenvolvimento e staging
- ✅ Obtenha permissão por escrito antes de testar sistemas de terceiros
- ❌ **NUNCA** use para atacar sistemas sem autorização

### Limitações

- Esta é uma ferramenta de análise estática e dinâmica básica
- Não substitui uma auditoria de segurança profissional completa
- Pode gerar falsos positivos
- Deve ser usada como parte de uma estratégia de segurança mais ampla

****## 🚀 Funcionalidades Implementadas

- [x] **Suporte a mais linguagens de programação** - Python, JavaScript, PHP, Java, C#, Ruby, Go
- [x] **Análise de dependências (verificação de CVEs)** - requirements.txt, package.json, composer.json, Gemfile, pom.xml
- [x] **Geração de relatórios PDF** - Relatórios profissionais com gráficos e estatísticas
- [x] **Integração com CI/CD** - GitHub Actions, GitLab CI, Jenkins, Azure DevOps, Bitbucket
- [x] **Scanner de portas e serviços** - Análise de rede e detecção de serviços vulneráveis
- [x] **Análise de containers Docker** - Dockerfile e docker-compose.yml security scanning
- [x] **Suporte a GraphQL APIs** - Testes de segurança específicos para GraphQL
- [x] **Machine Learning para detecção de padrões** - Detecção inteligente com redução de falsos positivos
- [x] **Analytics e Métricas** - Dashboard com estatísticas e análises detalhadas
- [x] **Webhook Integration** - Integração nativa com sistemas de CI/CD

## 📝 API Endpoints

### Autenticação

- `POST /api/auth/register` - Criar nova conta
- `POST /api/auth/token` - Fazer login

### Scans

- `POST /api/scan/code` - Analisar código fonte
- `POST /api/scan/api` - Analisar API
- `POST /api/scan/upload` - Upload de arquivo
- `GET /api/scans` - Listar scans do usuário
- `GET /api/scans/{id}` - Detalhes de um scan
- `GET /api/dashboard/stats` - Estatísticas do dashboard

## 🐛 Troubleshooting

### Erro de conexão com o servidor

```bash
# Verifique se o servidor está rodando
curl http://localhost:8000/api/health
```

### Erro ao instalar dependências

```bash
# Atualize o pip
pip install --upgrade pip

# Instale novamente
pip install -r requirements.txt
```

### Banco de dados não criado

```bash
# Delete o banco existente e reinicie o servidor
rm security_scanner.db
python -m uvicorn backend.main:app --reload
```

## 📄 Licença

Este projeto é fornecido "como está" para fins educacionais e de pesquisa em segurança.

## 👤 Autor

Desenvolvido por profissional de segurança da informação para a comunidade de segurança.

## 🤝 Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para:

- Reportar bugs
- Sugerir novas features
- Melhorar a documentação
- Adicionar novos scanners

## 📞 Suporte

Para questões e suporte:

1. Verifique a documentação
2. Consulte a seção de Troubleshooting
3. Abra uma issue no repositório

---

**⚠️ AVISO LEGAL**: Esta ferramenta é destinada exclusivamente para testes de segurança autorizados. O uso não autorizado contra sistemas de terceiros é ilegal e antiético. O autor não se responsabiliza pelo uso indevido desta ferramenta.

**🔒 Use com responsabilidade. Teste apenas o que você possui ou tem autorização.**
