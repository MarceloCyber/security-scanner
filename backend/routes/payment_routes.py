"""
Rotas para gerenciamento de assinaturas e pagamentos
"""
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional
import os
import stripe
import hmac
import hashlib
import requests
import time

from database import get_db
from models.user import User
from auth import get_current_user
from middleware.subscription import (
    check_subscription_status,
    get_plan_info,
    upgrade_user_plan,
    SCAN_LIMITS
)
from utils.email_service import email_service

router = APIRouter(prefix="/payments", tags=["payments"])

# Configurar Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# Detectar ambiente e configuração de Stripe
FRONTEND_ORIGIN = os.getenv("FRONTEND_URL", "http://localhost:8000")
STRIPE_CONFIGURED = bool(stripe.api_key) and stripe.api_key.startswith("sk_") and ("..." not in stripe.api_key) and len(stripe.api_key) > 20

# Configurar Mercado Pago
MERCADOPAGO_ACCESS_TOKEN = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "APP_USR-...")
MERCADOPAGO_WEBHOOK_SECRET = os.getenv("MERCADOPAGO_WEBHOOK_SECRET", "")

# Preços dos planos (em centavos para Stripe)
PLAN_PRICES = {
    "starter": 4990,      # R$ 49.90
    "professional": 14990, # R$ 149.90
    "enterprise": 49990    # R$ 499.90
}

# Rate limiting simples por usuário
_RATE_COUNTERS = {}

def _rate_check(key: str, limit: int = 10, window: int = 60):
    now = int(time.time())
    bucket = _RATE_COUNTERS.get(key)
    if not bucket:
        _RATE_COUNTERS[key] = {"count": 1, "start": now}
        return True
    if now - bucket["start"] > window:
        _RATE_COUNTERS[key] = {"count": 1, "start": now}
        return True
    bucket["count"] += 1
    if bucket["count"] > limit:
        return False
    return True

def rate_limit_checkout(current_user: User = Depends(get_current_user)):
    key = f"checkout:{current_user.id}"
    if not _rate_check(key, limit=8, window=60):
        raise HTTPException(status_code=429, detail="Muitas tentativas de pagamento. Tente novamente em instantes.")

def rate_limit_payment_status(current_user: User = Depends(get_current_user)):
    key = f"payment_status:{current_user.id}"
    if not _rate_check(key, limit=20, window=60):
        raise HTTPException(status_code=429, detail="Muitas consultas de status. Aguarde alguns segundos.")

@router.get("/invoices")
async def list_invoices(
    current_user: User = Depends(get_current_user)
):
    """
    Lista faturas do Stripe para o usuário atual
    """
    try:
        if not current_user.stripe_customer_id:
            return {"invoices": []}
        invoices = stripe.Invoice.list(customer=current_user.stripe_customer_id, limit=50)
        result = []
        for inv in invoices.data:
            result.append({
                "id": inv.id,
                "status": getattr(inv, "status", None),
                "amount_paid": getattr(inv, "amount_paid", 0),
                "currency": getattr(inv, "currency", "brl"),
                "hosted_invoice_url": getattr(inv, "hosted_invoice_url", None),
                "invoice_pdf": getattr(inv, "invoice_pdf", None),
                "created": datetime.fromtimestamp(inv.created).isoformat() if getattr(inv, "created", None) else None
            })
        return {"invoices": result}
    except Exception as e:
        print(f"Erro ao listar faturas: {e}")
        raise HTTPException(status_code=500, detail="Erro ao listar faturas")


@router.get("/subscription-info")
async def get_subscription_info(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna informações da assinatura do usuário
    """
    status = check_subscription_status(current_user)
    plan_info = get_plan_info(current_user.subscription_plan)
    
    return {
        "subscription_plan": current_user.subscription_plan,
        "subscription_status": current_user.subscription_status,
        "scans_used": current_user.scans_this_month,
        "scans_limit": current_user.scans_limit,
        "subscription_start": current_user.subscription_start.isoformat() if current_user.subscription_start else None,
        "subscription_end": current_user.subscription_end.isoformat() if current_user.subscription_end else None,
        "status": status,
        "plan_info": plan_info
    }


@router.post("/create-checkout")
async def create_checkout_session(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limiter: None = Depends(rate_limit_checkout)
):
    """
    Cria uma sessão de checkout:
    - Cartão: Stripe Subscription Checkout
    - PIX/Boleto: Mercado Pago pagamento transparente
    """
    data = await request.json()
    plan = data.get("plan", "starter")
    payment_method = data.get("payment_method", "credit-card")

    if plan not in PLAN_PRICES:
        raise HTTPException(status_code=400, detail="Plano inválido")

    try:
        if payment_method == "credit-card":
            if not STRIPE_CONFIGURED:
                raise HTTPException(status_code=500, detail="Stripe não configurado. Defina STRIPE_SECRET_KEY e STRIPE_WEBHOOK_SECRET no .env e use chaves de teste reais (sk_test_..., pk_test_...) via https://dashboard.stripe.com/test/apikeys")
            # Criar ou recuperar customer do Stripe
            if current_user.stripe_customer_id:
                customer_id = current_user.stripe_customer_id
                try:
                    stripe.Customer.retrieve(customer_id)
                except Exception:
                    customer = stripe.Customer.create(
                        email=current_user.email,
                        metadata={
                            "user_id": current_user.id,
                            "username": current_user.username
                        }
                    )
                    customer_id = customer.id
                    current_user.stripe_customer_id = customer_id
                    db.commit()
            else:
                customer = stripe.Customer.create(
                    email=current_user.email,
                    metadata={
                        "user_id": current_user.id,
                        "username": current_user.username
                    }
                )
                customer_id = customer.id
                current_user.stripe_customer_id = customer_id
                db.commit()

            # Suporte a Price IDs via env: STRIPE_PRICE_ID_STARTER, STRIPE_PRICE_ID_PROFESSIONAL, STRIPE_PRICE_ID_ENTERPRISE
            price_id = os.getenv(f"STRIPE_PRICE_ID_{plan.upper()}")

            if price_id:
                line_items = [{
                    'price': price_id,
                    'quantity': 1,
                }]
            else:
                line_items = [{
                    'price_data': {
                        'currency': 'brl',
                        'unit_amount': PLAN_PRICES[plan],
                        'product_data': {
                            'name': f'Iron Net - {plan.title()}',
                            'description': f'Assinatura mensal do plano {plan.title()}',
                        },
                        'recurring': {
                            'interval': 'month',
                            'interval_count': 1,
                        },
                    },
                    'quantity': 1,
                }]

            checkout_session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=line_items,
                mode='subscription',
                success_url=f"{os.getenv('FRONTEND_URL', 'http://localhost:8000')}/payment-success.html?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{os.getenv('FRONTEND_URL', 'http://localhost:8000')}/pricing.html?canceled=true",
                metadata={
                    "user_id": current_user.id,
                    "plan": plan
                }
            )

            return {
                "checkout_url": checkout_session.url,
                "session_id": checkout_session.id
            }

        elif payment_method in ["pix", "boleto"]:
            if not MERCADOPAGO_ACCESS_TOKEN or MERCADOPAGO_ACCESS_TOKEN.startswith("APP_USR-") is False:
                # Ainda sem credenciais reais, retornamos erro controlado
                raise HTTPException(status_code=400, detail="Mercado Pago não configurado")

            mp_headers = {
                'Authorization': f'Bearer {MERCADOPAGO_ACCESS_TOKEN}',
                'Content-Type': 'application/json'
            }
            # Valor em reais para MP
            amount = round(PLAN_PRICES[plan] / 100.0, 2)

            payload = {
                "transaction_amount": amount,
                "description": f"Iron Net - Assinatura {plan.title()}",
                "payment_method_id": "pix" if payment_method == "pix" else "bolbradesco",
                "payer": {
                    "email": current_user.email,
                    "first_name": current_user.username or "",
                    "last_name": "",
                    "identification": {
                        "type": "email",
                        "number": current_user.email
                    }
                },
                "metadata": {
                    "user_id": current_user.id,
                    "plan": plan
                }
            }

            mp_resp = requests.post(
                'https://api.mercadopago.com/v1/payments',
                headers=mp_headers,
                json=payload,
                timeout=15
            )
            if mp_resp.status_code >= 300:
                raise HTTPException(status_code=502, detail="Erro ao iniciar pagamento no Mercado Pago")

            mp_data = mp_resp.json()

            if payment_method == "pix":
                poi = mp_data.get('point_of_interaction', {})
                tx_data = poi.get('transaction_data', {})
                return {
                    "pix": {
                        "id": mp_data.get('id'),
                        "status": mp_data.get('status'),
                        "qr_code": tx_data.get('qr_code'),
                        "qr_code_base64": tx_data.get('qr_code_base64'),
                        "ticket_url": tx_data.get('ticket_url')
                    }
                }
            else:
                trans_details = mp_data.get('transaction_details', {})
                return {
                    "boleto": {
                        "id": mp_data.get('id'),
                        "status": mp_data.get('status'),
                        "external_resource_url": trans_details.get('external_resource_url')
                    }
                }

        else:
            raise HTTPException(status_code=400, detail="Método de pagamento inválido")

    except HTTPException:
        raise
    except Exception as e:
        print(f"Erro ao criar checkout: {e}")
        msg = str(e)
        if "Invalid API Key provided" in msg:
            detail = "Stripe não configurado corretamente (Invalid API Key). Verifique STRIPE_SECRET_KEY no .env"
        else:
            detail = f"Erro ao criar sessão de pagamento: {msg}"
        raise HTTPException(status_code=500, detail=detail)

@router.get("/verify-session")
async def verify_checkout_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        if not STRIPE_CONFIGURED:
            raise HTTPException(status_code=500, detail="Stripe não configurado")
        session = stripe.checkout.Session.retrieve(session_id)
        meta = getattr(session, "metadata", {}) or {}
        meta_user_id = int(meta.get("user_id")) if meta.get("user_id") else None
        plan = meta.get("plan")
        if not meta_user_id or meta_user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Sessão de pagamento inválida")
        status = getattr(session, "status", None)
        payment_status = getattr(session, "payment_status", None)
        subscription_id = getattr(session, "subscription", None)
        if status == "complete" and payment_status in ("paid", "no_payment_required") and subscription_id:
            user = db.query(User).filter(User.id == current_user.id).first()
            if user:
                if plan and (user.subscription_plan != plan or not user.stripe_subscription_id):
                    upgrade_user_plan(user, plan, 1, db)
                    user.stripe_subscription_id = subscription_id
                    user.subscription_status = "active"
                    db.commit()
            return {"verified": True, "plan": plan, "subscription_id": subscription_id}
        return {"verified": False, "status": status, "payment_status": payment_status}
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stripe-webhook")
async def stripe_webhook(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Webhook do Stripe para processar eventos de pagamento
    """
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Payload inválido")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Assinatura inválida")
    
    # Processar evento
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # Recuperar informações do metadata
        user_id = int(session['metadata']['user_id'])
        plan = session['metadata']['plan']
        subscription_id = session.get('subscription')
        
        # Atualizar usuário
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            upgrade_user_plan(user, plan, 1, db)
            user.stripe_subscription_id = subscription_id
            db.commit()
            
            # Enviar email de confirmação em background
            plan_prices = {'starter': 49.90, 'professional': 149.90, 'enterprise': 499.90}
            background_tasks.add_task(
                email_service.send_subscription_confirmation,
                user.email,
                user.username,
                plan,
                plan_prices.get(plan, 0)
            )
            
            print(f"✅ Assinatura ativada para usuário {user.username} - Plano: {plan}")
    
    elif event['type'] == 'customer.subscription.deleted':
        # Assinatura cancelada
        subscription = event['data']['object']
        subscription_id = subscription['id']
        
        user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
        if user:
            user.subscription_status = 'cancelled'
            user.subscription_plan = 'free'
            user.scans_limit = 10
            db.commit()
            
            print(f"❌ Assinatura cancelada para usuário {user.username}")
    
    elif event['type'] == 'invoice.payment_succeeded':
        # Pagamento recorrente bem-sucedido
        invoice = event['data']['object']
        subscription_id = invoice['subscription']
        
        user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
        if user:
            # Renovar assinatura por mais um mês
            if user.subscription_end:
                user.subscription_end = user.subscription_end + timedelta(days=30)
            else:
                user.subscription_end = datetime.utcnow() + timedelta(days=30)
            
            user.subscription_status = 'active'
            user.scans_this_month = 0  # Resetar contador
            db.commit()
            
            print(f"💳 Pagamento processado para {user.username}")
    
    elif event['type'] == 'invoice.payment_failed':
        # Falha no pagamento
        invoice = event['data']['object']
        subscription_id = invoice['subscription']
        
        user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
        if user:
            user.subscription_status = 'payment_failed'
            db.commit()
            try:
                email_service.send_email(
                    user.email,
                    'Falha no pagamento da assinatura',
                    f'<p>Olá, {user.username}!</p><p>O pagamento da sua assinatura falhou. Verifique seu método de pagamento no painel.</p>',
                    f'Olá, {user.username}! O pagamento da sua assinatura falhou. Verifique seu método de pagamento no painel.'
                )
            except Exception:
                pass
            print({"event": "stripe_payment_failed", "user": user.username})

    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        subscription_id = subscription['id']
        status = subscription.get('status', '')
        user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
        if user:
            status_map = {
                'active': 'active',
                'trialing': 'active',
                'past_due': 'pending',
                'unpaid': 'rejected',
                'incomplete': 'pending',
                'incomplete_expired': 'expired',
                'canceled': 'cancelled'
            }
            user.subscription_status = status_map.get(status, status)
            db.commit()
            try:
                if user.subscription_status in ('pending', 'expired', 'cancelled', 'rejected'):
                    subj = {
                        'pending': 'Pagamento pendente da assinatura',
                        'expired': 'Assinatura expirada',
                        'cancelled': 'Assinatura cancelada',
                        'rejected': 'Pagamento rejeitado'
                    }[user.subscription_status]
                    html = f"<p>Olá, {user.username}!</p><p>Status da sua assinatura: {user.subscription_status}.</p>"
                    txt = f"Olá, {user.username}! Status da sua assinatura: {user.subscription_status}."
                    email_service.send_email(user.email, subj, html, txt)
            except Exception:
                pass
            print({"event": "stripe_subscription_updated", "user": user.username, "status": user.subscription_status})
    
    return {"status": "success"}


@router.post("/mercadopago-webhook")
async def mercadopago_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Webhook do Mercado Pago para processar eventos de pagamento
    """
    try:
        raw_body = await request.body()
        x_signature = request.headers.get('x-signature')
        x_request_id = request.headers.get('x-request-id')

        if MERCADOPAGO_WEBHOOK_SECRET and x_signature and x_request_id:
            try:
                v1 = None
                for part in x_signature.split(','):
                    p = part.strip()
                    if p.startswith('v1='):
                        v1 = p.split('=', 1)[1]
                        break
                digest = hmac.new(MERCADOPAGO_WEBHOOK_SECRET.encode('utf-8'), (x_request_id + raw_body.decode('utf-8')).encode('utf-8'), hashlib.sha256).hexdigest()
                if not v1 or digest != v1:
                    raise HTTPException(status_code=400, detail="Assinatura inválida")
            except Exception:
                raise HTTPException(status_code=400, detail="Assinatura inválida")

        data = await request.json()
        notification_type = data.get('type')

        if notification_type == 'payment':
            payment_id = data.get('data', {}).get('id')
            if not payment_id:
                raise HTTPException(status_code=400, detail="Notificação sem ID de pagamento")

            mp_headers = {
                'Authorization': f'Bearer {MERCADOPAGO_ACCESS_TOKEN}',
                'Content-Type': 'application/json'
            }
            payment_response = requests.get(
                f'https://api.mercadopago.com/v1/payments/{payment_id}',
                headers=mp_headers,
                timeout=15
            )
            if payment_response.status_code >= 300:
                raise HTTPException(status_code=502, detail="Falha ao consultar pagamento no Mercado Pago")

            payment_data = payment_response.json()
            status = payment_data.get('status')

            if status == 'approved':
                meta = payment_data.get('metadata', {})
                user_id = meta.get('user_id')
                plan = meta.get('plan')
                payer = payment_data.get('payer', {})
                payer_id = payer.get('id')

                if not user_id or not plan:
                    raise HTTPException(status_code=400, detail="Pagamento sem metadados de usuário/plano")

                user = db.query(User).filter(User.id == int(user_id)).first()
                if user:
                    upgrade_user_plan(user, plan, 1, db)
                    user.subscription_status = 'active'
                    user.mercadopago_customer_id = payer_id
                    db.commit()

            elif status in ('expired', 'cancelled', 'rejected'):
                meta = payment_data.get('metadata', {})
                user_id = meta.get('user_id')
                if user_id:
                    user = db.query(User).filter(User.id == int(user_id)).first()
                    if user:
                        user.subscription_status = status
                        db.commit()
                        try:
                            email_service.send_email(
                                user.email,
                                'Pagamento não aprovado',
                                f'<p>Olá, {user.username}!</p><p>Seu pagamento via Mercado Pago não foi aprovado ({status}).</p>',
                                f'Olá, {user.username}! Seu pagamento via Mercado Pago não foi aprovado ({status}).'
                            )
                        except Exception:
                            pass
                        print({"event": "mercadopago_payment_status", "user_id": int(user_id), "status": status})

        return {"status": "success"}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Erro no webhook Mercado Pago: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mercadopago/payment-status/{payment_id}")
async def mercadopago_payment_status(payment_id: str, current_user: User = Depends(get_current_user), limiter: None = Depends(rate_limit_payment_status)):
    """
    Consulta status de pagamento no Mercado Pago (para PIX/Boleto)
    """
    try:
        mp_headers = {
            'Authorization': f'Bearer {MERCADOPAGO_ACCESS_TOKEN}',
            'Content-Type': 'application/json'
        }
        resp = requests.get(
            f'https://api.mercadopago.com/v1/payments/{payment_id}',
            headers=mp_headers,
            timeout=15
        )
        if resp.status_code >= 300:
            raise HTTPException(status_code=502, detail="Erro ao consultar pagamento")
        data = resp.json()
        status = data.get('status')
        status_detail = data.get('status_detail')
        return {
            "id": data.get('id'),
            "status": status,
            "status_detail": status_detail
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Erro ao consultar status MP: {e}")
        raise HTTPException(status_code=500, detail="Erro inesperado ao consultar pagamento")


@router.post("/cancel-subscription")
async def cancel_subscription(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Cancela a assinatura do usuário
    """
    try:
        if current_user.stripe_subscription_id:
            # Cancelar no Stripe
            stripe.Subscription.delete(current_user.stripe_subscription_id)
        
        # Atualizar status e rebaixar plano/limites
        current_user.subscription_status = 'cancelled'
        current_user.subscription_plan = 'free'
        current_user.scans_limit = 10
        current_user.scans_this_month = 0
        db.commit()
        
        return {
            "success": True,
            "message": "Assinatura cancelada com sucesso. Você terá acesso até o final do período pago."
        }
        
    except Exception as e:
        print(f"Erro ao cancelar assinatura: {e}")
        raise HTTPException(status_code=500, detail="Erro ao cancelar assinatura")


@router.get("/plans")
async def get_all_plans():
    """
    Retorna informações sobre todos os planos disponíveis
    """
    plans = ["free", "starter", "professional", "enterprise"]
    return {
        "plans": [get_plan_info(plan) for plan in plans]
    }


@router.post("/upgrade")
async def upgrade_plan(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upgrade imediato de plano (para testes ou admin)
    """
    data = await request.json()
    new_plan = data.get("plan", "free")
    
    if new_plan not in ["free", "starter", "professional", "enterprise"]:
        raise HTTPException(status_code=400, detail="Plano inválido")
    
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(status_code=403, detail="Acesso negado")
    upgrade_user_plan(current_user, new_plan, 1, db)
    
    return {
        "success": True,
        "message": f"Plano atualizado para {new_plan}",
        "new_plan": new_plan
    }
@router.get("/status")
async def payments_status():
    """
    Retorna status de configuração dos pagamentos (Stripe/Mercado Pago)
    """
    return {
        "stripe_configured": STRIPE_CONFIGURED,
        "stripe_mode": ("test" if os.getenv("STRIPE_SECRET_KEY", "").startswith("sk_test_") else "live") if os.getenv("STRIPE_SECRET_KEY") else None,
        "stripe_webhook_configured": bool(STRIPE_WEBHOOK_SECRET) and len(STRIPE_WEBHOOK_SECRET) > 20,
        "frontend_url": os.getenv("FRONTEND_URL", "http://localhost:8000"),
        "mercadopago_configured": bool(MERCADOPAGO_ACCESS_TOKEN) and MERCADOPAGO_ACCESS_TOKEN.startswith("APP_USR-"),
    }
