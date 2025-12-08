# 🚀 COMECE AGORA - 3 PASSOS SIMPLES

## ⚡ PASSO 1: RAILWAY (10 minutos)

1. **Acesse**: https://railway.app
2. **Clique em**: "Start a New Project"
3. **Faça login** com GitHub
4. ✅ Pronto! Você tem $5 grátis/mês

---

## 📦 PASSO 2: GITHUB (5 minutos)

1. **Acesse**: https://github.com/new
2. **Nome**: `security-scanner`
3. **Privado**: ✅
4. **Create repository**

No terminal, execute:

```bash
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner

git add .
git commit -m "Deploy inicial"
git branch -M main
git remote add origin https://github.com/SEU_USUARIO/security-scanner.git
git push -u origin main
```

**⚠️ Substitua SEU_USUARIO pelo seu usuário do GitHub!**

---

## 🚢 PASSO 3: DEPLOY (10 minutos)

### No Railway:

1. **New Project** → **Deploy from GitHub repo**
2. Selecione: `security-scanner`
3. Aguarde 2 minutos (deploy automático)
4. **+ New** → **Database** → **PostgreSQL**
5. **Variables** (adicione estas):

```
SECRET_KEY=b1069ede48484fbb763984406f1004da7dee4d46203e5cac0af309b9a780621b
FRONTEND_URL=https://seu-projeto.up.railway.app
STRIPE_SECRET_KEY=sk_test_... (vem do Stripe)
STRIPE_PUBLISHABLE_KEY=pk_test_... (vem do Stripe)
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USER=mac526@hotmail.com
SMTP_PASSWORD=sua_senha
FROM_EMAIL=mac526@hotmail.com
FROM_NAME=Security Scanner Pro
```

6. **Settings** → **Networking** → **Generate Domain**
7. ✅ Copie a URL: `https://xxx.up.railway.app`

---

## 💳 PASSO 4: STRIPE (15 minutos)

1. **Acesse**: https://stripe.com
2. **Crie conta** (gratuito)
3. **Ative modo TESTE** (canto superior)
4. **Developers** → **API keys**:
   - Copie **Publishable key**: `pk_test_...`
   - Copie **Secret key**: `sk_test_...`
5. **Products** → **Add product**:
   - **Starter**: $29/mês (copie o Price ID)
   - **Professional**: $79/mês (copie o Price ID)
   - **Enterprise**: $199/mês (copie o Price ID)
6. Cole as chaves no Railway (Variáveis)

---

## 🔗 SEUS LINKS FINAIS

```
🌐 PLATAFORMA:
https://seu-projeto.up.railway.app

👑 ADMIN:
https://seu-projeto.up.railway.app/admin-login.html

📚 MANUAL:
https://seu-projeto.up.railway.app/manual.html

📖 API:
https://seu-projeto.up.railway.app/api/docs
```

---

## ✅ PRONTO!

**Login**: `admin` / `admin123`

**Teste de pagamento**:
- Cartão: `4242 4242 4242 4242`
- Data: `12/34`
- CVV: `123`

---

## 📞 Guia completo em:

- `DEPLOY-RAILWAY-SIMPLES.md` - Passo a passo detalhado
- `CHECKLIST-DEPLOY.md` - Checklist completa

**💰 Custo**: $0 para começar!
**⏰ Tempo**: 30-40 minutos
**✅ Status**: Pronto para receber clientes pagantes!
