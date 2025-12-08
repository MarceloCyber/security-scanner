# ✅ CHECKLIST: COLOCAR EM PRODUÇÃO HOJE

**⏰ Tempo total: 1-2 horas**
**💰 Custo: $0 (100% Gratuito)**

---

## 📋 PARTE 1: PREPARAÇÃO (JÁ FEITO! ✅)

- [x] Arquivos de configuração criados
- [x] SECRET_KEY gerada: `b1069ede48484fbb763984406f1004da7dee4d46203e5cac0af309b9a780621b`
- [x] Git inicializado
- [x] .gitignore criado
- [x] requirements.txt pronto
- [x] Procfile pronto
- [x] railway.json pronto

---

## 🚀 PARTE 2: RAILWAY (FAÇA AGORA - 15 min)

### Passo 1: Criar conta Railway
- [ ] Acesse: https://railway.app
- [ ] Clique em "Start a New Project"
- [ ] Faça login com GitHub
- [ ] ✅ Pronto! Você tem $5 grátis/mês

### Passo 2: Criar repositório GitHub
- [ ] Acesse: https://github.com/new
- [ ] Nome: `security-scanner`
- [ ] Privado: ✅ (recomendado)
- [ ] Clique em "Create repository"

### Passo 3: Fazer push para GitHub

Execute no terminal:
```bash
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner

git add .
git commit -m "Deploy inicial - Security Scanner Pro"
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/security-scanner.git
git push -u origin main
```

**⚠️ SUBSTITUA `SEU_USUARIO` pelo seu usuário do GitHub!**

### Passo 4: Deploy no Railway
- [ ] No Railway, clique em "New Project"
- [ ] Selecione "Deploy from GitHub repo"
- [ ] Autorize o Railway (se aparecer)
- [ ] Selecione o repositório `security-scanner`
- [ ] Aguarde 2-3 minutos (Railway detectará Python automaticamente)

### Passo 5: Adicionar PostgreSQL
- [ ] No projeto Railway, clique em "+ New"
- [ ] Selecione "Database" → "PostgreSQL"
- [ ] ✅ Banco criado! (automático)

### Passo 6: Conectar banco ao backend
- [ ] Clique no serviço "PostgreSQL"
- [ ] Vá em "Variables"
- [ ] Copie o valor de `DATABASE_URL`
- [ ] Volte para o serviço principal (backend)
- [ ] Em "Variables", cole `DATABASE_URL`

---

## 💳 PARTE 3: STRIPE (15 min)

### Passo 1: Criar conta Stripe
- [ ] Acesse: https://stripe.com
- [ ] Clique em "Start now"
- [ ] Preencha seus dados
- [ ] ✅ Ative o modo de TESTE (canto superior direito)

### Passo 2: Obter chaves
- [ ] Dashboard Stripe → "Developers" → "API keys"
- [ ] Copie **Publishable key**: `pk_test_...`
- [ ] Copie **Secret key**: `sk_test_...` (clique em Reveal)

### Passo 3: Criar produtos

**Produto 1: Starter Plan**
- [ ] "Products" → "Add product"
- [ ] Name: `Starter Plan`
- [ ] Price: `$29.00 USD`
- [ ] Recurring: `Monthly`
- [ ] Description: `50 scans/mês, todas as ferramentas`
- [ ] Save → Copie o **Price ID**: `price_xxxxx`

**Produto 2: Professional Plan**
- [ ] Name: `Professional Plan`
- [ ] Price: `$79.00 USD`
- [ ] Recurring: `Monthly`
- [ ] Description: `200 scans/mês, suporte prioritário`
- [ ] Save → Copie o **Price ID**: `price_yyyyy`

**Produto 3: Enterprise Plan**
- [ ] Name: `Enterprise Plan`
- [ ] Price: `$199.00 USD`
- [ ] Recurring: `Monthly`
- [ ] Description: `Scans ilimitados, API access`
- [ ] Save → Copie o **Price ID**: `price_zzzzz`

---

## ⚙️ PARTE 4: CONFIGURAR VARIÁVEIS NO RAILWAY (10 min)

No Railway, vá em "Variables" e adicione:

```bash
SECRET_KEY=b1069ede48484fbb763984406f1004da7dee4d46203e5cac0af309b9a780621b
DATABASE_URL=postgresql://... (já deve estar)
FRONTEND_URL=https://security-scanner-production.up.railway.app
STRIPE_SECRET_KEY=sk_test_... (cole aqui)
STRIPE_PUBLISHABLE_KEY=pk_test_... (cole aqui)
STRIPE_WEBHOOK_SECRET=whsec_... (vamos obter no próximo passo)
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USER=mac526@hotmail.com
SMTP_PASSWORD=sua_senha_de_app
FROM_EMAIL=mac526@hotmail.com
FROM_NAME=Security Scanner Pro
```

**Checklist:**
- [ ] SECRET_KEY
- [ ] DATABASE_URL (automático)
- [ ] FRONTEND_URL
- [ ] STRIPE_SECRET_KEY
- [ ] STRIPE_PUBLISHABLE_KEY
- [ ] SMTP_HOST
- [ ] SMTP_PORT
- [ ] SMTP_USER
- [ ] SMTP_PASSWORD
- [ ] FROM_EMAIL
- [ ] FROM_NAME

---

## 🔗 PARTE 5: OBTER URL DO RAILWAY (2 min)

- [ ] No Railway, clique no seu serviço (backend)
- [ ] Vá em "Settings" → "Networking"
- [ ] Clique em "Generate Domain"
- [ ] ✅ URL gerada! Exemplo: `https://security-scanner-production.up.railway.app`

**✏️ ANOTE SUA URL AQUI:**
```
Backend: https://_____________________________________.up.railway.app
```

---

## 🌐 PARTE 6: ATUALIZAR FRONTEND (5 min)

Agora precisa atualizar o frontend para apontar para o Railway.

Execute no terminal:

```bash
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner

# Substitua pela SUA URL do Railway!
URL_RAILWAY="https://security-scanner-production.up.railway.app"

# Atualizar todos os arquivos JS
sed -i '' "s|http://localhost:8000/api|${URL_RAILWAY}/api|g" frontend/js/modern-app.js
sed -i '' "s|http://localhost:8000/api|${URL_RAILWAY}/api|g" frontend/js/admin.js
sed -i '' "s|http://localhost:8000/api|${URL_RAILWAY}/api|g" frontend/js/auth.js

echo "✅ Frontend atualizado!"
```

**OU** edite manualmente:
- [ ] `frontend/js/modern-app.js` - linha 3
- [ ] `frontend/js/admin.js` - linha 3

Mudar de:
```javascript
const API_URL = 'http://localhost:8000/api';
```

Para:
```javascript
const API_URL = 'https://sua-url.up.railway.app/api';
```

---

## 📤 PARTE 7: FAZER PUSH DO FRONTEND (3 min)

```bash
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner

git add .
git commit -m "Atualizar URLs do frontend para Railway"
git push
```

**Railway fará re-deploy automaticamente!**

---

## 🔔 PARTE 8: CONFIGURAR WEBHOOK STRIPE (5 min)

- [ ] Dashboard Stripe → "Developers" → "Webhooks"
- [ ] Clique em "Add endpoint"
- [ ] **Endpoint URL**: `https://sua-url.up.railway.app/api/stripe/webhook`
- [ ] **Events to send**:
  - [x] checkout.session.completed
  - [x] customer.subscription.created
  - [x] customer.subscription.updated
  - [x] customer.subscription.deleted
  - [x] invoice.payment_succeeded
  - [x] invoice.payment_failed
- [ ] Clique em "Add endpoint"
- [ ] Copie o **Webhook Secret**: `whsec_...`
- [ ] Cole no Railway: `STRIPE_WEBHOOK_SECRET=whsec_...`

---

## ✅ PARTE 9: TESTAR TUDO (10 min)

### Teste 1: API está online?
```bash
curl https://sua-url.up.railway.app/api/health
```
- [ ] ✅ Retornou: `{"status":"healthy"}`

### Teste 2: Frontend carrega?
Abra no navegador:
```
https://sua-url.up.railway.app/index.html
```
- [ ] ✅ Página de login aparece

### Teste 3: Login funciona?
- [ ] Login: `admin`
- [ ] Senha: `admin123`
- [ ] ✅ Dashboard carrega

### Teste 4: Admin Panel funciona?
```
https://sua-url.up.railway.app/admin-login.html
```
- [ ] Login: `admin` / `admin123`
- [ ] ✅ Painel admin carrega

### Teste 5: Pagamento de teste
- [ ] No dashboard, clique em "Upgrade"
- [ ] Escolha "Starter Plan"
- [ ] Use cartão teste: `4242 4242 4242 4242`
- [ ] Data: `12/34`, CVV: `123`
- [ ] ✅ Pagamento processado e plano atualizado

---

## 🎉 ESTÁ NO AR!

### 📝 ANOTE SUAS URLs:

```
🌐 PLATAFORMA (Usuários):
https://_____________________________________.up.railway.app

👑 ADMIN (Você):
https://_____________________________________.up.railway.app/admin-login.html

📚 MANUAL:
https://_____________________________________.up.railway.app/manual.html

📖 API Docs:
https://_____________________________________.up.railway.app/api/docs
```

---

## 💰 CUSTOS

- **Railway**: $5 grátis/mês (suficiente para começar)
- **Stripe**: $0 mensalidade (apenas 2.9% + $0.30 por transação)
- **PostgreSQL**: Incluído no Railway
- **TOTAL**: **$0 para começar!**

---

## 🆘 PROBLEMAS?

### Erro: "Application failed to start"
✅ Verifique os logs: Railway → Deployments → View Logs

### Erro: CORS / API não responde
✅ Verifique se atualizou as URLs no frontend

### Erro: Database connection
✅ Verifique se DATABASE_URL está configurado

### Erro: Stripe webhook
✅ Verifique se STRIPE_WEBHOOK_SECRET está configurado

---

## 📞 PRÓXIMOS PASSOS

Após tudo funcionando:

1. ⏭️ Testar todos os fluxos (login, scan, pagamento)
2. ⏭️ Adicionar domínio próprio (opcional)
3. ⏭️ Configurar monitoramento
4. ⏭️ Ativar modo PRODUÇÃO no Stripe (quando quiser receber dinheiro real)

---

**🎯 Status Final:**
- [ ] Backend no ar
- [ ] Frontend no ar  
- [ ] Stripe configurado
- [ ] Pagamentos funcionando
- [ ] Admin panel acessível
- [ ] ✅ PRONTO PARA RECEBER CLIENTES!

**Data**: 8 de dezembro de 2025
