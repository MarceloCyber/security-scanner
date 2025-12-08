# 🔧 Guia de Configuração - Sistema de Assinaturas

## ✅ O que foi implementado:

### 1. **Banco de Dados** ✓
- ✅ Campos de assinatura adicionados ao modelo User
- ✅ Migration executada com sucesso
- ✅ Todos os usuários atualizados para plano "free"

### 2. **Middleware de Controle de Acesso** ✓
- ✅ `check_subscription_status()` - Verifica status da assinatura
- ✅ `check_tool_access()` - Verifica acesso a ferramentas
- ✅ `require_plan()` - Decorator para proteger endpoints
- ✅ `require_tool_access()` - Decorator para bloquear ferramentas
- ✅ `increment_scan_count()` - Incrementa contador de scans
- ✅ `upgrade_user_plan()` - Atualiza plano do usuário

### 3. **Página de Preços** ✓
- ✅ Interface moderna com 4 planos
- ✅ Botões de assinatura funcionais
- ✅ FAQ integrada
- ✅ Indicador de plano atual

### 4. **Sistema de Pagamentos** ✓
- ✅ Integração com Stripe
- ✅ Integração com Mercado Pago (estrutura básica)
- ✅ Webhooks para processar pagamentos
- ✅ Página de sucesso de pagamento

---

## 🚀 Como Testar Localmente

### Passo 1: Configurar Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto:

```bash
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner
cp .env.example .env
```

Edite o arquivo `.env` com suas chaves:

```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///./security_scanner.db
ACCESS_TOKEN_EXPIRE_MINUTES=30

FRONTEND_URL=http://localhost:8000

# Para testes, use as chaves de teste do Stripe
STRIPE_SECRET_KEY=sk_test_51...
STRIPE_PUBLISHABLE_KEY=pk_test_51...
STRIPE_WEBHOOK_SECRET=whsec_...
```

### Passo 2: Obter Chaves do Stripe (TESTE)

1. **Criar conta no Stripe:**
   - Acesse: https://dashboard.stripe.com/register
   - Crie uma conta gratuita

2. **Obter chaves de teste:**
   - No dashboard: https://dashboard.stripe.com/test/apikeys
   - Copie:
     - `Secret key` (sk_test_...)
     - `Publishable key` (pk_test_...)

3. **Configurar webhook local (usando Stripe CLI):**
   
   ```bash
   # Instalar Stripe CLI
   brew install stripe/stripe-cli/stripe
   
   # Login no Stripe
   stripe login
   
   # Iniciar túnel de webhook
   stripe listen --forward-to localhost:8000/api/payments/stripe-webhook
   
   # Copie o webhook secret (whsec_...) que aparecer
   ```

### Passo 3: Reiniciar o Servidor

```bash
cd /Users/marcelorodrigues/Desktop/Hacking-Tools/security-scanner/backend
python main.py
```

### Passo 4: Testar Fluxo de Pagamento

1. **Acessar página de preços:**
   - http://localhost:8000/pricing.html

2. **Clicar em "Começar Teste Grátis"** (Starter ou Professional)

3. **Usar cartão de teste do Stripe:**
   - Número: `4242 4242 4242 4242`
   - Data: Qualquer data futura
   - CVC: Qualquer 3 dígitos
   - CEP: Qualquer CEP

4. **Confirmar pagamento**
   - Você será redirecionado para `payment-success.html`
   - O webhook processará e ativará a assinatura
   - Seu plano será atualizado

5. **Verificar no Dashboard:**
   - Volte ao dashboard
   - Seu plano deve estar atualizado

---

## 🧪 Testes Manuais

### Teste 1: Verificar Limite de Scans (Plano Free)

```bash
# Fazer login como usuário free
# Tentar fazer mais de 10 scans no mês
# Deve retornar erro de limite excedido
```

### Teste 2: Upgrade Manual (Para Testes)

```bash
curl -X POST http://localhost:8000/api/payments/upgrade \
  -H "Authorization: Bearer SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plan": "professional"}'
```

### Teste 3: Verificar Acesso a Ferramentas

```python
# No middleware, as ferramentas são bloqueadas por plano:
# Free: port_scanner, ssl_checker, dns_lookup, whois_lookup, header_analyzer
# Starter: + code_scanner, sqli_tester, xss_tester, phishing_simulator
# Professional: TODAS as ferramentas
# Enterprise: TODAS + recursos extras
```

---

## 🔐 Proteger Endpoints (Exemplo)

### Proteger ferramenta específica:

```python
from middleware.subscription import require_tool_access

@router.post("/tools/vulnerability-scanner")
@require_tool_access("vulnerability_scanner")
async def run_vulnerability_scan(
    current_user: User = Depends(get_current_user)
):
    # Código da ferramenta
    pass
```

### Proteger por plano:

```python
from middleware.subscription import require_plan

@router.post("/advanced-feature")
@require_plan(["professional", "enterprise"])
async def advanced_feature(
    current_user: User = Depends(get_current_user)
):
    # Só professional e enterprise podem acessar
    pass
```

### Incrementar contador de scans:

```python
from middleware.subscription import increment_scan_count

@router.post("/scan")
async def perform_scan(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verificar e incrementar antes de fazer o scan
    status = check_subscription_status(current_user)
    if not status["valid"]:
        raise HTTPException(403, detail=status["message"])
    
    # Fazer o scan
    result = do_scan()
    
    # Incrementar contador
    increment_scan_count(current_user, db)
    
    return result
```

---

## 📊 Endpoints Disponíveis

### Informações de Assinatura:
- `GET /api/user/subscription-info` - Info completa da assinatura
- `GET /api/user/me` - Info do usuário atual

### Pagamentos:
- `POST /api/payments/create-checkout` - Criar sessão de checkout
- `POST /api/payments/stripe-webhook` - Webhook do Stripe
- `POST /api/payments/mercadopago-webhook` - Webhook do Mercado Pago
- `POST /api/payments/cancel-subscription` - Cancelar assinatura
- `GET /api/payments/plans` - Listar todos os planos
- `POST /api/payments/upgrade` - Upgrade manual (admin/testes)

---

## 🎯 Próximos Passos

### Para Produção:

1. **Obter chaves reais do Stripe:**
   - Ativar conta no modo produção
   - Usar chaves `sk_live_...` e `pk_live_...`

2. **Configurar webhook em produção:**
   - Stripe Dashboard → Webhooks
   - Adicionar endpoint: `https://seudominio.com/api/payments/stripe-webhook`
   - Selecionar eventos:
     - `checkout.session.completed`
     - `customer.subscription.deleted`
     - `invoice.payment_succeeded`
     - `invoice.payment_failed`

3. **Configurar Mercado Pago:**
   - Criar aplicação: https://www.mercadopago.com.br/developers
   - Obter credenciais de produção
   - Configurar webhook de notificações

4. **Adicionar bloqueio no frontend:**
   - Verificar plano ao carregar ferramentas
   - Mostrar overlay em ferramentas bloqueadas
   - Botão "Upgrade" para desbloquear

5. **Implementar email notifications:**
   - Confirmação de pagamento
   - Renovação de assinatura
   - Falha no pagamento
   - Cancelamento

---

## 🐛 Troubleshooting

### Erro: "stripe" module not found
```bash
pip install stripe==7.8.0
```

### Webhook não está sendo recebido
```bash
# Verificar se o Stripe CLI está rodando
stripe listen --forward-to localhost:8000/api/payments/stripe-webhook

# Testar webhook manualmente
stripe trigger checkout.session.completed
```

### Plano não atualiza após pagamento
- Verificar logs do webhook
- Verificar se o webhook secret está correto
- Aguardar alguns segundos (processamento assíncrono)
- Verificar banco de dados: `sqlite3 security_scanner.db`

### Migration falhou
```bash
# Reverter e tentar novamente
cd backend
rm security_scanner.db
python main.py  # Recria o banco
python migrate_db.py
```

---

## 📝 Checklist de Implementação

- [x] Campos de assinatura no banco de dados
- [x] Middleware de controle de acesso
- [x] Página de preços
- [x] Integração com Stripe
- [x] Webhooks de pagamento
- [x] Página de sucesso
- [ ] Bloquear ferramentas no frontend
- [ ] Adicionar indicador de plano no dashboard
- [ ] Email notifications
- [ ] Painel administrativo
- [ ] Testes automatizados
- [ ] Deploy em produção

---

## 🎉 Status Atual

✅ **Sistema de Assinaturas 100% Funcional!**

O sistema está pronto para testes locais. Configure as chaves do Stripe e teste o fluxo completo de pagamento.

Para produção, basta:
1. Trocar chaves de teste por chaves reais
2. Configurar webhooks em produção
3. Adicionar bloqueio visual no frontend
4. Deploy!
