# 🚀 Como Executar o Projeto Localmente

## 📋 Pré-requisitos

- ✅ Python 3.9+ instalado
- ✅ pip (gerenciador de pacotes Python)
- ✅ Banco de dados (SQLite ou PostgreSQL)

---

## ⚡ Início Rápido (3 passos)

### 1️⃣ Instalar Dependências

```bash
cd backend
pip3 install -r requirements.txt
```

### 2️⃣ Iniciar o Servidor

```bash
# Opção 1: Usando uvicorn diretamente (RECOMENDADO)
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Opção 2: Usando Python
python3 main.py
```

### 3️⃣ Acessar a Plataforma

Abra seu navegador em: **http://localhost:8000**

---

## 🔧 Passo a Passo Detalhado

### Passo 1: Navegar até a pasta do projeto

```bash
cd "/Users/marcelorodrigues/Desktop/Mesa - MacBook Pro de Marcelo/Hacking-Tools/security-scanner"
```

### Passo 2: Instalar as dependências do Python

```bash
cd backend
pip3 install -r requirements.txt
```

**Saída esperada:**
```
Successfully installed fastapi-0.104.1 uvicorn-0.24.0 ...
```

### Passo 3: Verificar a configuração do banco de dados

O projeto está configurado para usar **SQLite** por padrão (arquivo local).

**Arquivo:** `backend/config.py`

Para PostgreSQL, configure a variável de ambiente:
```bash
export DATABASE_URL="postgresql://usuario:senha@localhost/ironnet"
```

### Passo 4: Executar migrações (se necessário)

As tabelas são criadas automaticamente na primeira execução, mas para garantir que o Viggio Shield está instalado:

```bash
# Ainda dentro da pasta backend
python3 migrate_viggio_shield.py
```

**Saída esperada:**
```
🛡️  Iniciando migração do Viggio Shield...
✅ Tabela 'monitor_targets' criada com sucesso!
✅ Tabela 'monitor_incidents' criada com sucesso!
✅ Tabela 'monitor_logs' criada com sucesso!
✅ Tabela 'blocked_ips' criada com sucesso!
```

### Passo 5: Iniciar o servidor backend

```bash
# Método 1: Uvicorn (RECOMENDADO)
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Método 2: Python direto
python3 main.py
```

**Saída esperada:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

### Passo 6: Acessar a aplicação

Abra seu navegador e acesse:

- **Landing Page:** http://localhost:8000
- **Login:** http://localhost:8000/index.html
- **Dashboard:** http://localhost:8000/dashboard.html (após login)
- **Viggio Shield:** http://localhost:8000/viggio-shield.html (após login)
- **API Docs:** http://localhost:8000/api/docs

---

## 🎯 Testando o Viggio Shield

### 1. Criar uma conta

1. Acesse: http://localhost:8000/register.html
2. Preencha os dados
3. Clique em "Registrar"

### 2. Fazer Login

1. Acesse: http://localhost:8000/index.html
2. Use suas credenciais
3. Será redirecionado para o dashboard

### 3. Acessar o Viggio Shield

1. No menu lateral, clique em **"Viggio Shield"**
2. Ou acesse diretamente: http://localhost:8000/viggio-shield.html

### 4. Criar seu primeiro alvo de monitoramento

1. Clique em **"Adicionar Alvo"**
2. Preencha:
   ```
   Nome: Google (Teste)
   Tipo: API
   Endereço: https://www.google.com
   Intervalo: 300
   Threshold: 3
   ```
3. Clique em **"Criar Alvo"**

### 5. Testar a verificação

1. No card do alvo criado, clique em **"Verificar"**
2. Aguarde alguns segundos
3. Você verá: ✅ "Alvo está saudável!"
4. O uptime deve mostrar 100%

---

## 🛠️ Comandos Úteis

### Ver logs do servidor em tempo real

```bash
# O servidor já mostra logs, mas você pode aumentar o nível de detalhes
uvicorn main:app --reload --log-level debug
```

### Resetar o banco de dados

```bash
# ATENÇÃO: Isso apaga todos os dados!
rm security_scanner.db
python3 main.py  # Recria as tabelas
```

### Criar usuário admin

```bash
python3 backend/migrate_add_admin.py
```

### Testar endpoints da API

```bash
# Verificar saúde do servidor
curl http://localhost:8000/api/health

# Criar conta via API
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"teste","email":"teste@example.com","password":"senha123"}'
```

---

## 🐛 Troubleshooting

### Erro: "Address already in use"

Porta 8000 já está em uso. Mude a porta:

```bash
uvicorn main:app --reload --port 8001
```

### Erro: "Module not found"

Instale as dependências novamente:

```bash
pip3 install -r backend/requirements.txt
```

### Erro: "Database locked"

O SQLite está sendo usado por outro processo. Reinicie o servidor:

```bash
# Pressione Ctrl+C e execute novamente
uvicorn main:app --reload
```

### Frontend não carrega

Certifique-se de que o servidor está rodando e acesse:
```
http://localhost:8000
```

**NÃO** tente abrir os arquivos HTML diretamente (file://) - eles precisam ser servidos pelo servidor.

---

## 📁 Estrutura do Projeto

```
security-scanner/
├── backend/
│   ├── main.py              # Servidor principal
│   ├── config.py            # Configurações
│   ├── database.py          # Conexão com banco
│   ├── auth.py              # Autenticação JWT
│   ├── requirements.txt     # Dependências Python
│   ├── models/              # Models do banco
│   │   ├── user.py
│   │   ├── scan.py
│   │   └── monitor.py       # 🆕 Viggio Shield
│   ├── routes/              # Endpoints da API
│   │   ├── auth_routes.py
│   │   ├── scan_routes.py
│   │   └── viggio_shield_routes.py  # 🆕 Viggio Shield
│   └── migrate_viggio_shield.py     # 🆕 Migração
│
├── frontend/
│   ├── index.html           # Login
│   ├── register.html        # Registro
│   ├── dashboard.html       # Dashboard principal
│   ├── viggio-shield.html   # 🆕 Viggio Shield
│   ├── css/
│   └── js/
│
└── security_scanner.db      # Banco de dados SQLite
```

---

## 🔐 Credenciais Padrão

### Admin (se criado com migrate_add_admin.py)
```
Usuário: admin
Email: admin@ironnet.com
Senha: admin123
```

### Usuário de Teste (crie você mesmo)
```
Acesse: http://localhost:8000/register.html
```

---

## 🌐 URLs Disponíveis

### Frontend
- **Landing:** http://localhost:8000
- **Login:** http://localhost:8000/index.html
- **Registro:** http://localhost:8000/register.html
- **Dashboard:** http://localhost:8000/dashboard.html
- **Viggio Shield:** http://localhost:8000/viggio-shield.html
- **Admin Panel:** http://localhost:8000/admin.html
- **Pricing:** http://localhost:8000/pricing.html
- **Manual:** http://localhost:8000/manual.html

### API
- **Documentação:** http://localhost:8000/api/docs
- **ReDoc:** http://localhost:8000/api/redoc
- **Health Check:** http://localhost:8000/api/health

### Viggio Shield API
- **Dashboard:** http://localhost:8000/api/viggio-shield/dashboard
- **Alvos:** http://localhost:8000/api/viggio-shield/targets
- **Incidentes:** http://localhost:8000/api/viggio-shield/incidents

---

## 🚀 Modo Produção

Para executar em produção:

```bash
# Com Gunicorn (recomendado para produção)
pip3 install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000

# Ou com Uvicorn sem reload
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## 📊 Verificando Status

### Servidor rodando?
```bash
curl http://localhost:8000/api/health
```

### Banco de dados OK?
```bash
# Se SQLite
ls -lh security_scanner.db

# Se PostgreSQL
psql -U usuario -d ironnet -c "\dt"
```

### Frontend acessível?
Abra: http://localhost:8000

---

## ⚡ Quick Start (Copiar e Colar)

```bash
# 1. Navegar até o projeto
cd "/Users/marcelorodrigues/Desktop/Mesa - MacBook Pro de Marcelo/Hacking-Tools/security-scanner"

# 2. Instalar dependências
cd backend
pip3 install -r requirements.txt

# 3. Migrar Viggio Shield (opcional, mas recomendado)
python3 migrate_viggio_shield.py

# 4. Iniciar servidor
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 5. Abrir no navegador
# http://localhost:8000
```

---

## 🎉 Pronto!

Seu servidor está rodando! 

Acesse **http://localhost:8000** e comece a usar a plataforma Iron Net com o módulo **Viggio Shield** totalmente funcional! 🛡️

---

## 📞 Suporte

- 📚 Documentação Viggio Shield: `VIGGIO_SHIELD_README.md`
- 🚀 Guia de Instalação: `VIGGIO_SHIELD_QUICKSTART.md`
- 💡 Detalhes Técnicos: `VIGGIO_SHIELD_IMPLEMENTATION.md`
