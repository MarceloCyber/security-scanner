# 🚀 GUIA COMPLETO: DEPLOY EM PRODUÇÃO - SECURITY SCANNER PRO

**Data**: 8 de dezembro de 2025  
**Tempo estimado**: 2-3 horas  
**Custo inicial**: $0 (planos gratuitos)

---

## 📊 ARQUITETURA EM PRODUÇÃO

```
┌─────────────────────────────────────────────────────────────┐
│                    USUÁRIOS / CLIENTES                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                 VERCEL (Frontend - GRATUITO)                │
│  • https://security-scanner.vercel.app                      │
│  • https://security-scanner.vercel.app/dashboard.html       │
│  • https://security-scanner.vercel.app/admin.html           │
│  • https://security-scanner.vercel.app/manual.html          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼ (API Calls)
┌─────────────────────────────────────────────────────────────┐
│              RAILWAY/RENDER (Backend - GRATUITO)            │
│  • https://security-scanner-api.up.railway.app              │
│  • FastAPI + Uvicorn                                         │
│  • PostgreSQL Database                                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼ (Webhook)
┌─────────────────────────────────────────────────────────────┐
│                    STRIPE (Pagamentos)                       │
│  • Webhook: /api/stripe/webhook                             │
│  • Checkout Sessions                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 FASE 1: PREPARAÇÃO DO PROJETO (30 minutos)

### Passo 1.1: Criar Estrutura para Deploy

```bash
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner

# Criar arquivos necessários
touch backend/requirements.txt
touch backend/Procfile
touch backend/railway.json
touch vercel.json
touch .env.production
```

### Passo 1.2: Separar Frontend do Backend

O frontend será servido pela Vercel, então precisamos adaptar:

**Estrutura Final:**
```
security-scanner/
├── frontend/              # Deploy na Vercel
│   ├── index.html
│   ├── dashboard.html
│   ├── admin.html
│   ├── admin-login.html
│   ├── manual.html
│   ├── css/
│   ├── js/
│   └── vercel.json
├── backend/               # Deploy no Railway/Render
│   ├── main.py
│   ├── requirements.txt
│   ├── Procfile
│   ├── railway.json
│   └── .env
└── docs/
```

---

## 🔧 FASE 2: CONFIGURAR BACKEND (Railway) - 45 minutos

### Passo 2.1: Criar requirements.txt

**Arquivo**: `backend/requirements.txt`
```txt
fastapi==0.104.1
uvicorn[standard]==0.24.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
sqlalchemy==2.0.23
pydantic==2.5.0
pydantic-settings==2.1.0
stripe==7.5.0
python-dotenv==1.0.0
psycopg2-binary==2.9.9
alembic==1.12.1
aiosmtplib==3.0.1
email-validator==2.1.0
```

### Passo 2.2: Criar Procfile

**Arquivo**: `backend/Procfile`
```
web: uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
```

### Passo 2.3: Criar railway.json

**Arquivo**: `backend/railway.json`
```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "uvicorn main:app --host 0.0.0.0 --port $PORT",
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
```

### Passo 2.4: Adaptar main.py para Produção

**Arquivo**: `backend/main.py` - Adicionar no início:

```python
import os
from fastapi.middleware.cors import CORSMiddleware

# Configuração de CORS para produção
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
ALLOWED_ORIGINS = [
    FRONTEND_URL,
    "https://*.vercel.app",
    "http://localhost:8000",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Passo 2.5: Migrar de SQLite para PostgreSQL

**Arquivo**: `backend/database.py` - Atualizar:

```python
import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Suporte para SQLite (dev) e PostgreSQL (prod)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./security_scanner.db"
)

# Railway/Render usa postgres://, mas SQLAlchemy precisa postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

### Passo 2.6: Deploy no Railway

1. **Acesse**: https://railway.app
2. **Cadastre-se** com GitHub (gratuito)
3. **Clique em "New Project"**
4. **Selecione "Deploy from GitHub repo"**
5. **Conecte seu repositório** (ou faça upload do backend/)
6. **Adicione PostgreSQL**:
   - Clique em "+ New"
   - Selecione "Database" → "PostgreSQL"
   - Railway criará automaticamente
7. **Configure Variáveis de Ambiente**:
   ```
   DATABASE_URL=<auto-preenchido pelo Railway>
   SECRET_KEY=sua_chave_secreta_super_segura_aqui_123456789
   FRONTEND_URL=https://seu-projeto.vercel.app
   STRIPE_SECRET_KEY=sk_test_...
   STRIPE_PUBLISHABLE_KEY=pk_test_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   SMTP_HOST=smtp-mail.outlook.com
   SMTP_PORT=587
   SMTP_USER=mac526@hotmail.com
   SMTP_PASSWORD=sua_senha_app
   FROM_EMAIL=mac526@hotmail.com
   FROM_NAME=Security Scanner Pro
   ```
8. **Deploy**: Railway fará deploy automaticamente
9. **Copie a URL**: Exemplo: `https://security-scanner-api.up.railway.app`

---

## 🎨 FASE 3: CONFIGURAR FRONTEND (Vercel) - 30 minutos

### Passo 3.1: Criar vercel.json

**Arquivo**: `frontend/vercel.json`
```json
{
  "version": 2,
  "builds": [
    {
      "src": "**/*.html",
      "use": "@vercel/static"
    }
  ],
  "routes": [
    {
      "src": "/",
      "dest": "/index.html"
    },
    {
      "src": "/dashboard",
      "dest": "/dashboard.html"
    },
    {
      "src": "/admin",
      "dest": "/admin-login.html"
    },
    {
      "src": "/admin/panel",
      "dest": "/admin.html"
    },
    {
      "src": "/manual",
      "dest": "/manual.html"
    },
    {
      "src": "/(.*)",
      "dest": "/$1"
    }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-XSS-Protection",
          "value": "1; mode=block"
        }
      ]
    }
  ]
}
```

### Passo 3.2: Atualizar URLs da API no Frontend

**Arquivos a editar**:
- `frontend/js/modern-app.js`
- `frontend/js/admin.js`
- `frontend/js/auth.js`

**Mudar de**:
```javascript
const API_URL = 'http://localhost:8000/api';
```

**Para**:
```javascript
const API_URL = 'https://security-scanner-api.up.railway.app/api';
// OU usar variável de ambiente
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
```

### Passo 3.3: Criar arquivo de configuração

**Arquivo**: `frontend/config.js`
```javascript
// Configuração de ambiente
const CONFIG = {
  API_URL: 'https://security-scanner-api.up.railway.app/api',
  STRIPE_PUBLISHABLE_KEY: 'pk_test_...',
  APP_NAME: 'Security Scanner Pro',
  VERSION: '1.0.0'
};

// Export para uso nos outros scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CONFIG;
}
```

**Incluir em todos os HTML**:
```html
<script src="/config.js"></script>
<script src="/js/auth.js"></script>
```

### Passo 3.4: Deploy na Vercel

1. **Acesse**: https://vercel.com
2. **Cadastre-se** com GitHub (gratuito)
3. **Clique em "Add New..." → "Project"**
4. **Import do GitHub** ou **Upload manual** da pasta `frontend/`
5. **Configure o projeto**:
   - Framework Preset: Other
   - Root Directory: `frontend` (se subir repo completo)
   - Build Command: (deixe vazio)
   - Output Directory: (deixe vazio)
6. **Configure Variáveis de Ambiente**:
   ```
   VITE_API_URL=https://security-scanner-api.up.railway.app/api
   VITE_STRIPE_KEY=pk_test_...
   ```
7. **Deploy**: Vercel fará deploy automaticamente
8. **URLs geradas**:
   - Principal: `https://security-scanner.vercel.app`
   - Dashboard: `https://security-scanner.vercel.app/dashboard.html`
   - Admin: `https://security-scanner.vercel.app/admin-login.html`
   - Manual: `https://security-scanner.vercel.app/manual.html`

---

## 💳 FASE 4: CONFIGURAR STRIPE (45 minutos)

### Passo 4.1: Criar Conta Stripe

1. **Acesse**: https://stripe.com
2. **Cadastre-se** (gratuito)
3. **Ative o modo de teste** (barra superior)

### Passo 4.2: Obter Chaves da API

1. **Acesse**: https://dashboard.stripe.com/test/apikeys
2. **Copie**:
   - Publishable key: `pk_test_...`
   - Secret key: `sk_test_...`

### Passo 4.3: Criar Produtos e Preços

**Via Dashboard Stripe**:
1. **Products** → **Add product**

**Plano FREE** (0/mês):
```
Name: Free Plan
Description: 10 scans/mês, Port Scanner básico
Price: $0.00 USD / month
Recurring: Monthly
```

**Plano STARTER** ($29/mês):
```
Name: Starter Plan
Description: 50 scans/mês, todas as ferramentas
Price: $29.00 USD / month
Recurring: Monthly
```

**Plano PROFESSIONAL** ($79/mês):
```
Name: Professional Plan
Description: 200 scans/mês, suporte prioritário
Price: $79.00 USD / month
Recurring: Monthly
```

**Plano ENTERPRISE** ($199/mês):
```
Name: Enterprise Plan
Description: Scans ilimitados, API access, suporte dedicado
Price: $199.00 USD / month
Recurring: Monthly
```

### Passo 4.4: Adicionar Rotas Stripe no Backend

**Arquivo**: `backend/routes/stripe_routes.py` (criar)

```python
from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.orm import Session
import stripe
import os
from database import get_db
from models.user import User

router = APIRouter(prefix="/api/stripe", tags=["stripe"])

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# IDs dos produtos (copiar do Stripe Dashboard)
PRICE_IDS = {
    "starter": "price_1234567890",  # Substituir pelos IDs reais
    "professional": "price_0987654321",
    "enterprise": "price_1122334455"
}

@router.post("/create-checkout-session")
async def create_checkout_session(
    plan: str,
    user_id: int,
    db: Session = Depends(get_db)
):
    """Criar sessão de checkout do Stripe"""
    if plan not in PRICE_IDS:
        raise HTTPException(status_code=400, detail="Plano inválido")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=user.email,
            payment_method_types=['card'],
            line_items=[{
                'price': PRICE_IDS[plan],
                'quantity': 1,
            }],
            mode='subscription',
            success_url=os.getenv("FRONTEND_URL") + "/dashboard.html?success=true",
            cancel_url=os.getenv("FRONTEND_URL") + "/dashboard.html?canceled=true",
            metadata={
                'user_id': user_id,
                'plan': plan
            }
        )
        return {"checkout_url": checkout_session.url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """Webhook para eventos do Stripe"""
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    # Lidar com diferentes tipos de eventos
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = int(session['metadata']['user_id'])
        plan = session['metadata']['plan']
        
        # Atualizar usuário no banco
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.subscription_plan = plan
            user.stripe_customer_id = session.get('customer')
            user.stripe_subscription_id = session.get('subscription')
            db.commit()
    
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        # Downgrade para Free
        user = db.query(User).filter(
            User.stripe_subscription_id == subscription['id']
        ).first()
        if user:
            user.subscription_plan = 'free'
            user.stripe_subscription_id = None
            db.commit()
    
    return {"status": "success"}

@router.get("/plans")
async def get_plans():
    """Retornar informações dos planos"""
    return {
        "plans": [
            {
                "id": "free",
                "name": "Free",
                "price": 0,
                "scans_limit": 10,
                "features": ["Port Scanner", "10 scans/mês"]
            },
            {
                "id": "starter",
                "name": "Starter",
                "price": 29,
                "scans_limit": 50,
                "features": ["Todas ferramentas", "50 scans/mês", "Suporte email"],
                "stripe_price_id": PRICE_IDS["starter"]
            },
            {
                "id": "professional",
                "name": "Professional",
                "price": 79,
                "scans_limit": 200,
                "features": ["Todas ferramentas", "200 scans/mês", "Suporte prioritário"],
                "stripe_price_id": PRICE_IDS["professional"]
            },
            {
                "id": "enterprise",
                "name": "Enterprise",
                "price": 199,
                "scans_limit": -1,  # Ilimitado
                "features": ["Scans ilimitados", "API access", "Suporte dedicado"],
                "stripe_price_id": PRICE_IDS["enterprise"]
            }
        ]
    }
```

**Registrar rotas no main.py**:
```python
from routes import stripe_routes
app.include_router(stripe_routes.router)
```

### Passo 4.5: Configurar Webhook no Stripe

1. **Dashboard Stripe** → **Developers** → **Webhooks**
2. **Add endpoint**:
   - URL: `https://security-scanner-api.up.railway.app/api/stripe/webhook`
   - Events: Selecione:
     - `checkout.session.completed`
     - `customer.subscription.created`
     - `customer.subscription.updated`
     - `customer.subscription.deleted`
     - `invoice.payment_succeeded`
     - `invoice.payment_failed`
3. **Copie o Webhook Secret**: `whsec_...`
4. **Adicione no Railway**: Variável `STRIPE_WEBHOOK_SECRET`

---

## 🔐 FASE 5: SEGURANÇA E OTIMIZAÇÕES (30 minutos)

### Passo 5.1: Variáveis de Ambiente

**Railway (Backend)**:
```env
DATABASE_URL=<auto>
SECRET_KEY=<gerar com: openssl rand -hex 32>
FRONTEND_URL=https://security-scanner.vercel.app
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USER=mac526@hotmail.com
SMTP_PASSWORD=<senha_app>
```

**Vercel (Frontend)**:
```env
VITE_API_URL=https://security-scanner-api.up.railway.app/api
VITE_STRIPE_KEY=pk_test_...
```

### Passo 5.2: Domínio Personalizado (Opcional)

**Vercel**:
1. Settings → Domains
2. Adicione seu domínio: `security-scanner.com.br`
3. Configure DNS conforme instruções

**Railway**:
1. Settings → Domains
2. Adicione: `api.security-scanner.com.br`

---

## 📝 FASE 6: TESTES FINAIS (30 minutos)

### Checklist de Testes:

**Frontend**:
- [ ] Login funciona
- [ ] Dashboard carrega
- [ ] Ferramentas funcionam
- [ ] Manual acessível
- [ ] Admin panel funciona (se admin)

**Backend**:
- [ ] API responde: `https://sua-api.railway.app/docs`
- [ ] Autenticação funciona
- [ ] Scans salvam no banco
- [ ] Email de reset funciona

**Stripe**:
- [ ] Página de checkout abre
- [ ] Pagamento teste funciona (use cartão teste: `4242 4242 4242 4242`)
- [ ] Plano atualiza após pagamento
- [ ] Webhook recebe eventos

**Cartões de teste Stripe**:
```
Sucesso: 4242 4242 4242 4242
Falha: 4000 0000 0000 0002
3D Secure: 4000 0027 6000 3184
```

---

## 🚀 URLS FINAIS

Após deploy completo, você terá:

```
🌐 APLICAÇÃO PRINCIPAL
https://security-scanner.vercel.app

🔐 ÁREA DO USUÁRIO
https://security-scanner.vercel.app/dashboard

👑 ÁREA ADMINISTRATIVA
https://security-scanner.vercel.app/admin

📚 MANUAL DE USO
https://security-scanner.vercel.app/manual

🔌 API BACKEND
https://security-scanner-api.up.railway.app

📄 DOCUMENTAÇÃO API
https://security-scanner-api.up.railway.app/docs

💳 STRIPE DASHBOARD
https://dashboard.stripe.com
```

---

## 💰 CUSTOS MENSAIS

### Planos Gratuitos (Início):
- **Vercel**: Gratuito (100GB bandwidth)
- **Railway**: $5/mês de crédito grátis (depois ~$5-10/mês)
- **Stripe**: Gratuito (2.9% + $0.30 por transação)
- **PostgreSQL**: Incluído no Railway

### Quando Escalar:
- **Railway Pro**: $20/mês (8GB RAM, 8 vCPU)
- **Vercel Pro**: $20/mês (1TB bandwidth)
- **Stripe**: Sem taxa mensal, apenas por transação

---

## 🆘 TROUBLESHOOTING

### Erro: CORS
**Solução**: Adicione frontend URL no `ALLOWED_ORIGINS`

### Erro: Database connection
**Solução**: Verifique `DATABASE_URL` no Railway

### Erro: Stripe webhook
**Solução**: Verifique `STRIPE_WEBHOOK_SECRET`

### Erro: 502 Bad Gateway
**Solução**: Aguarde 2-3 minutos (cold start)

---

## 📞 PRÓXIMOS PASSOS

1. ✅ Deploy básico funcionando
2. ⏭️ Adicionar analytics (Google Analytics, Plausible)
3. ⏭️ Configurar monitoramento (Sentry)
4. ⏭️ Adicionar cache (Redis no Railway)
5. ⏭️ Configurar CDN para assets
6. ⏭️ Implementar rate limiting
7. ⏭️ Adicionar testes automatizados
8. ⏭️ CI/CD com GitHub Actions

---

**Data de criação**: 8 de dezembro de 2025  
**Autor**: GitHub Copilot  
**Status**: ✅ Pronto para produção
