# 🚀 DEPLOY COMPLETO NO RAILWAY - PASSO A PASSO

**Tempo estimado**: 1 hora
**Custo**: $0 (Gratuito com $5 de crédito mensal)

---

## ✅ PASSO 1: PREPARAR O PROJETO (5 minutos)

### 1.1 - Criar arquivo .env de exemplo

Crie o arquivo `.env.example`:
```env
SECRET_KEY=sua_chave_secreta_aqui
DATABASE_URL=postgresql://usuario:senha@host:5432/database
FRONTEND_URL=https://seu-projeto.up.railway.app
STRIPE_SECRET_KEY=sk_test_seu_codigo
STRIPE_PUBLISHABLE_KEY=pk_test_seu_codigo
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USER=mac526@hotmail.com
SMTP_PASSWORD=sua_senha
FROM_EMAIL=mac526@hotmail.com
FROM_NAME=Security Scanner Pro
```

### 1.2 - Verificar arquivos criados

✅ `backend/requirements.txt` - Já criado
✅ `backend/Procfile` - Já criado  
✅ `backend/railway.json` - Já criado

---

## 🎯 PASSO 2: CRIAR CONTA NO RAILWAY (5 minutos)

1. **Acesse**: https://railway.app
2. **Clique em "Start a New Project"**
3. **Login com GitHub** (recomendado) ou Email
4. Você ganha **$5 de crédito grátis por mês**
5. **Suficiente para rodar o projeto completo!**

---

## 📦 PASSO 3: FAZER DEPLOY DO BACKEND (10 minutos)

### Opção A: Deploy via GitHub (Recomendado)

1. **Crie um repositório no GitHub**:
   ```bash
   cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner
   git init
   git add .
   git commit -m "Initial commit - Security Scanner Pro"
   ```

2. **Crie repositório no GitHub.com**
   - Nome: `security-scanner`
   - Privado ou Público (sua escolha)

3. **Push para GitHub**:
   ```bash
   git remote add origin https://github.com/SEU_USUARIO/security-scanner.git
   git branch -M main
   git push -u origin main
   ```

4. **No Railway**:
   - Clique em **"New Project"**
   - Selecione **"Deploy from GitHub repo"**
   - Autorize o Railway a acessar seus repos
   - Selecione **security-scanner**
   - Railway detectará automaticamente que é Python/FastAPI

### Opção B: Deploy Direto (Mais Rápido)

1. **No Railway Dashboard**:
   - Clique em **"New Project"**
   - Selecione **"Deploy from GitHub repo"**
   - Clique em **"Deploy from local directory"**
   - Arraste a pasta `backend/` para o Railway

---

## 🗄️ PASSO 4: ADICIONAR BANCO DE DADOS (2 minutos)

1. **No seu projeto Railway**, clique em **"+ New"**
2. Selecione **"Database"** → **"PostgreSQL"**
3. Railway criará automaticamente o banco
4. A variável `DATABASE_URL` será criada automaticamente
5. **Pronto!** O banco está conectado ao backend

---

## ⚙️ PASSO 5: CONFIGURAR VARIÁVEIS DE AMBIENTE (10 minutos)

1. **No Railway**, clique no seu projeto (backend)
2. Vá em **"Variables"**
3. **Adicione estas variáveis**:

```env
SECRET_KEY=cole_aqui_resultado_do_comando_abaixo
DATABASE_URL=automaticamente_preenchido_pelo_railway
FRONTEND_URL=https://security-scanner-production.up.railway.app
STRIPE_SECRET_KEY=sk_test_SEU_CODIGO_AQUI
STRIPE_PUBLISHABLE_KEY=pk_test_SEU_CODIGO_AQUI
STRIPE_WEBHOOK_SECRET=whsec_SEU_CODIGO_AQUI
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USER=mac526@hotmail.com
SMTP_PASSWORD=sua_senha_de_app
FROM_EMAIL=mac526@hotmail.com
FROM_NAME=Security Scanner Pro
```

### Como gerar SECRET_KEY:

```bash
openssl rand -hex 32
```

**Copie o resultado e cole em `SECRET_KEY`**

---

## 💳 PASSO 6: CONFIGURAR STRIPE (15 minutos)

### 6.1 - Criar conta Stripe

1. Acesse: https://stripe.com
2. Clique em **"Start now"** (Gratuito)
3. Preencha seus dados
4. **Ative o modo de teste** (canto superior direito)

### 6.2 - Obter chaves da API

1. No Dashboard Stripe, vá em **"Developers"** → **"API keys"**
2. Copie:
   - **Publishable key**: `pk_test_...`
   - **Secret key**: `sk_test_...` (clique em "Reveal")
3. Cole no Railway:
   - `STRIPE_PUBLISHABLE_KEY=pk_test_...`
   - `STRIPE_SECRET_KEY=sk_test_...`

### 6.3 - Criar produtos no Stripe

1. No Dashboard, vá em **"Products"** → **"Add product"**

**Crie 4 produtos**:

**1. Free Plan**
```
Name: Free Plan
Price: $0.00 USD
Billing: One-time (ou Monthly com $0)
Description: 10 scans por mês, Port Scanner básico
```

**2. Starter Plan**
```
Name: Starter Plan  
Price: $29.00 USD
Billing: Recurring - Monthly
Description: 50 scans/mês, todas as ferramentas
```
→ **Copie o Price ID**: `price_xxxxx` (depois da criação)

**3. Professional Plan**
```
Name: Professional Plan
Price: $79.00 USD  
Billing: Recurring - Monthly
Description: 200 scans/mês, suporte prioritário
```
→ **Copie o Price ID**: `price_yyyyy`

**4. Enterprise Plan**
```
Name: Enterprise Plan
Price: $199.00 USD
Billing: Recurring - Monthly  
Description: Scans ilimitados, API access, suporte dedicado
```
→ **Copie o Price ID**: `price_zzzzz`

---

## 🔗 PASSO 7: OBTER URLS DO RAILWAY (2 minutos)

1. No Railway, clique no seu projeto
2. Vá em **"Settings"** → **"Domains"**
3. Clique em **"Generate Domain"**
4. Railway gerará algo como:
   ```
   https://security-scanner-production.up.railway.app
   ```
5. **Copie esta URL!**

---

## 🎨 PASSO 8: CONFIGURAR FRONTEND (10 minutos)

### 8.1 - Atualizar URLs da API

Precisamos apontar o frontend para o backend no Railway.

**Execute estes comandos**:

```bash
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner

# Substituir em todos os arquivos JS
find frontend/js -name "*.js" -exec sed -i '' 's|http://localhost:8000/api|https://security-scanner-production.up.railway.app/api|g' {} \;
```

**OU** edite manualmente estes arquivos:
- `frontend/js/modern-app.js` (linha ~3)
- `frontend/js/admin.js` (linha ~3)  
- `frontend/js/auth.js` (se houver)

**Mudar de**:
```javascript
const API_URL = 'http://localhost:8000/api';
```

**Para**:
```javascript
const API_URL = 'https://security-scanner-production.up.railway.app/api';
```

### 8.2 - Fazer Deploy do Frontend

**No Railway** (mesmo projeto):
1. Clique em **"+ New"** → **"Empty Service"**
2. Nomeie como **"frontend"**
3. Em **"Settings"**, configure:
   - **Root Directory**: `frontend`
   - **Build Command**: (deixe vazio)
   - **Start Command**: `python -m http.server 8080`
4. Clique em **"Deploy"**

### 8.3 - Gerar domínio do frontend

1. No serviço **frontend**, vá em **"Settings"** → **"Domains"**
2. Clique em **"Generate Domain"**
3. URL gerada: `https://security-scanner-frontend.up.railway.app`

---

## 🔗 PASSO 9: SUAS URLs FINAIS

Após tudo configurado, você terá:

```
🌐 PLATAFORMA PRINCIPAL (Frontend)
https://security-scanner-frontend.up.railway.app

📊 DASHBOARD DOS USUÁRIOS
https://security-scanner-frontend.up.railway.app/dashboard.html

👑 ÁREA ADMINISTRATIVA  
https://security-scanner-frontend.up.railway.app/admin-login.html

📚 MANUAL DE USO
https://security-scanner-frontend.up.railway.app/manual.html

🔌 API BACKEND
https://security-scanner-production.up.railway.app

📖 DOCUMENTAÇÃO DA API
https://security-scanner-production.up.railway.app/api/docs
```

---

## ✅ PASSO 10: CONFIGURAR WEBHOOK DO STRIPE (5 minutos)

1. No Stripe Dashboard: **"Developers"** → **"Webhooks"**
2. Clique em **"Add endpoint"**
3. **Endpoint URL**:
   ```
   https://security-scanner-production.up.railway.app/api/stripe/webhook
   ```
4. **Eventos a escutar**:
   - ✅ `checkout.session.completed`
   - ✅ `customer.subscription.created`
   - ✅ `customer.subscription.updated`
   - ✅ `customer.subscription.deleted`
   - ✅ `invoice.payment_succeeded`
   - ✅ `invoice.payment_failed`
5. Clique em **"Add endpoint"**
6. **Copie o Webhook Secret**: `whsec_...`
7. Adicione no Railway: `STRIPE_WEBHOOK_SECRET=whsec_...`

---

## 🧪 PASSO 11: TESTAR TUDO (10 minutos)

### Teste 1: API está online?
```bash
curl https://security-scanner-production.up.railway.app/api/health
```
✅ Deve retornar: `{"status":"healthy"}`

### Teste 2: Frontend carrega?
Abra no navegador:
```
https://security-scanner-frontend.up.railway.app
```
✅ Página de login deve aparecer

### Teste 3: Login funciona?
1. Vá para a URL do frontend
2. Faça login com: `admin` / `admin123`
3. ✅ Dashboard deve carregar

### Teste 4: Pagamento de teste
1. No dashboard, clique em **"Upgrade Plan"**
2. Escolha **"Starter Plan"**
3. Use cartão de teste Stripe:
   ```
   Número: 4242 4242 4242 4242
   Data: 12/34
   CVV: 123
   CEP: 12345
   ```
4. Complete o pagamento
5. ✅ Plano deve atualizar para "Starter"

### Teste 5: Admin Panel
1. Acesse: `https://security-scanner-frontend.up.railway.app/admin-login.html`
2. Login: `admin` / `admin123`
3. ✅ Dashboard admin deve carregar com estatísticas

---

## 🎉 ESTÁ NO AR!

### Seus Links para Compartilhar:

**Para Clientes (Plataforma)**:
```
https://security-scanner-frontend.up.railway.app
```

**Para Você (Admin)**:
```
https://security-scanner-frontend.up.railway.app/admin-login.html
```

**Manual de Uso**:
```
https://security-scanner-frontend.up.railway.app/manual.html
```

---

## 💰 CUSTOS

### Plano Gratuito Railway:
- ✅ $5 de crédito por mês (GRÁTIS)
- ✅ 500 horas de execução (~20 dias rodando 24/7)
- ✅ Banco PostgreSQL incluído
- ✅ 100GB de bandwidth

### Quando precisar escalar:
- **Railway Pro**: $20/mês (uso ilimitado)
- **Stripe**: Sem mensalidade, apenas 2.9% + $0.30 por transação

---

## 🔧 TROUBLESHOOTING

### ❌ Erro: "Application failed to start"
**Solução**: Verifique os logs no Railway (aba "Deployments")

### ❌ Erro: CORS / API não responde
**Solução**: Verifique se atualizou `API_URL` no frontend

### ❌ Erro: Database connection
**Solução**: Verifique se o PostgreSQL está conectado ao backend

### ❌ Erro: Stripe webhook não funciona
**Solução**: Verifique se a URL do webhook está correta e `STRIPE_WEBHOOK_SECRET` está configurado

---

## 📞 PRÓXIMOS PASSOS

1. ✅ **HOJE**: Deploy funcionando
2. ⏭️ **Amanhã**: Testar todos os fluxos de pagamento
3. ⏭️ **Semana 1**: Adicionar domínio próprio (opcional)
4. ⏭️ **Semana 2**: Monitoramento e analytics

---

**🎯 TEMPO TOTAL**: ~1-2 horas
**💵 CUSTO**: $0 (totalmente gratuito para começar)
**✅ STATUS**: Pronto para receber clientes pagantes!
