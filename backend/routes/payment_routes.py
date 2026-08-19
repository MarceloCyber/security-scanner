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
import secrets
import requests
import time
import re

from database import get_db
from models.user import User
from auth import decode_renewal_token, get_current_user, get_password_hash
from middleware.subscription import (
    check_subscription_status,
    get_plan_info,
    normalize_subscription_plan,
    sync_owned_organization_plans,
    upgrade_user_plan,
    get_allowed_dashboard_tools,
    SCAN_LIMITS,
    CANCELLATION_WINDOW_DAYS,
)
from utils.email_service import email_service
from services.plan_policy import PLAN_POLICY, get_plan_policy, is_fixed_term_plan, is_plan_expired

router = APIRouter(prefix="/payments", tags=["payments"])

# Configurar Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

# Detectar ambiente e configuração de Stripe
FRONTEND_ORIGIN = os.getenv("FRONTEND_URL", "http://localhost:8000")
STRIPE_CONFIGURED = bool(stripe.api_key) and stripe.api_key.startswith("sk_") and ("..." not in stripe.api_key) and len(stripe.api_key) > 20
STRIPE_WEBHOOK_CONFIGURED = STRIPE_WEBHOOK_SECRET.startswith("whsec_") and "..." not in STRIPE_WEBHOOK_SECRET and len(STRIPE_WEBHOOK_SECRET) > 20

# Configurar Mercado Pago
MERCADOPAGO_ACCESS_TOKEN = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "")
MERCADOPAGO_WEBHOOK_SECRET = os.getenv("MERCADOPAGO_WEBHOOK_SECRET", "")
MERCADOPAGO_CONFIGURED = (
    MERCADOPAGO_ACCESS_TOKEN.startswith("APP_USR-")
    and "..." not in MERCADOPAGO_ACCESS_TOKEN
    and len(MERCADOPAGO_ACCESS_TOKEN) > 20
    and len(MERCADOPAGO_WEBHOOK_SECRET) > 20
)

# Preços dos planos (em centavos para Stripe)
PLAN_PRICES = {
    plan: policy["amount_cents"] for plan, policy in PLAN_POLICY.items()
}


def _stripe_line_items(plan: str) -> list[dict]:
    policy = get_plan_policy(plan)
    price_id = os.getenv(f"STRIPE_PRICE_ID_{plan.upper()}")
    if price_id:
        return [{"price": price_id, "quantity": 1}]
    price_data = {
        "currency": "brl",
        "unit_amount": policy["amount_cents"],
        "product_data": {
            "name": f"Iron AI - {policy['name']}",
            "description": (
                "Assinatura mensal recorrente"
                if policy["recurring"]
                else f"Pagamento único com {policy['access_months']} meses de acesso"
            ),
        },
    }
    if policy["recurring"]:
        price_data["recurring"] = {"interval": "month", "interval_count": 1}
    return [{"price_data": price_data, "quantity": 1}]


def _stripe_checkout(plan: str, customer_id: str, success_url: str, cancel_url: str, metadata: dict):
    policy = get_plan_policy(plan)
    params = {
        "customer": customer_id,
        "payment_method_types": ["card"],
        "line_items": _stripe_line_items(plan),
        "mode": policy["billing_mode"],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": str(metadata.get("user_id") or metadata.get("username") or "iron-ai"),
        "metadata": {key: str(value) for key, value in metadata.items() if value is not None},
    }
    if policy["installments"]:
        params["payment_method_options"] = {"card": {"installments": {"enabled": True}}}
    return stripe.checkout.Session.create(**params)

def _issue_access_key(user: User, db: Session) -> str:
    """Cria uma chave única; apenas o hash fica armazenado no banco."""
    if user.access_key_hash:
        if not user.access_key_used_at and not user.access_key_required:
            user.access_key_required = True
            db.commit()
        return ""
    raw_key = f"IRON-{secrets.token_urlsafe(32)}"
    user.access_key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    user.access_key_last4 = raw_key[-4:]
    user.access_key_issued_at = datetime.utcnow()
    user.access_key_required = True
    db.commit()
    return raw_key

def _trial_is_active(user: User) -> bool:
    return bool(
        user.is_trial and user.subscription_plan == "starter"
        and user.trial_started_at
        and datetime.utcnow() <= user.trial_started_at + timedelta(days=CANCELLATION_WINDOW_DAYS)
    )

def _refund_initial_stripe_payment(subscription_id: str):
    """Reembolsa a primeira cobrança paga da assinatura."""
    invoices = stripe.Invoice.list(subscription=subscription_id, limit=10)
    for invoice in invoices.data:
        if getattr(invoice, "status", None) != "paid":
            continue
        payment_intent_id = getattr(invoice, "payment_intent", None)
        if payment_intent_id:
            payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
            charge_id = getattr(payment_intent, "latest_charge", None)
            if charge_id:
                return stripe.Refund.create(
                    charge=charge_id,
                    idempotency_key=f"iron-ai-cancel-{subscription_id}-{charge_id}",
                )
        charge_id = getattr(invoice, "charge", None)
        if charge_id:
            return stripe.Refund.create(
                charge=charge_id,
                idempotency_key=f"iron-ai-cancel-{subscription_id}-{charge_id}",
            )
    return None


def _activate_paid_plan(user: User, plan: str, db: Session, subscription_id: Optional[str] = None) -> None:
    """Applies the exact paid entitlement after provider confirmation."""
    policy = get_plan_policy(plan)
    upgrade_user_plan(user, plan, None, db)
    user.stripe_subscription_id = subscription_id if policy["recurring"] else None
    user.subscription_status = "active"
    user.is_trial = plan == "starter"
    user.trial_started_at = datetime.utcnow() if plan == "starter" else None
    sync_owned_organization_plans(user, db)
    db.commit()

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


def rate_limit_registration_checkout(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_check(f"registration_checkout:{client_ip}", limit=4, window=300):
        raise HTTPException(status_code=429, detail="Muitas tentativas de cadastro. Aguarde alguns minutos.")

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
    plan = normalize_subscription_plan(current_user.subscription_plan)
    plan_info = get_plan_info(plan)
    subscription_active = status.get("valid", False)
    
    return {
        "subscription_plan": plan,
        "subscription_status": current_user.subscription_status,
        "scans_used": current_user.scans_this_month,
        "scans_limit": current_user.scans_limit,
        "subscription_start": current_user.subscription_start.isoformat() if current_user.subscription_start else None,
        "subscription_end": current_user.subscription_end.isoformat() if current_user.subscription_end else None,
        "is_trial": _trial_is_active(current_user),
        "trial_started_at": current_user.trial_started_at.isoformat() if current_user.trial_started_at else None,
        "trial_ends_at": (current_user.trial_started_at + timedelta(days=CANCELLATION_WINDOW_DAYS)).isoformat()
            if current_user.trial_started_at else None,
        "cancellation_window_days": CANCELLATION_WINDOW_DAYS,
        "can_cancel_recurring": plan == "starter" and current_user.subscription_status == "active",
        "renewal_required": is_plan_expired(plan, current_user.subscription_end),
        "status": status,
        "plan_info": plan_info,
        "allowed_dashboard_tools": get_allowed_dashboard_tools(plan) if subscription_active else [],
        "tools_count": plan_info.get("tools_count"),
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
            if not STRIPE_CONFIGURED or not STRIPE_WEBHOOK_CONFIGURED:
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

            checkout_session = _stripe_checkout(
                plan,
                customer_id,
                f"{FRONTEND_ORIGIN}/payment-success.html?session_id={{CHECKOUT_SESSION_ID}}",
                f"{FRONTEND_ORIGIN}/pricing.html?canceled=true",
                {"user_id": current_user.id, "plan": plan},
            )

            return {
                "checkout_url": checkout_session.url,
                "session_id": checkout_session.id
            }

        elif payment_method in ["pix", "boleto"]:
            if get_plan_policy(plan)["recurring"]:
                raise HTTPException(status_code=400, detail="O plano Starter recorrente deve ser contratado por cartão no Stripe.")
            if not MERCADOPAGO_CONFIGURED:
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
                "description": f"Iron AI - {get_plan_policy(plan)['name']}",
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

@router.post("/create-checkout-registration")
async def create_checkout_registration(request: Request, db: Session = Depends(get_db), limiter: None = Depends(rate_limit_registration_checkout)):
    data = await request.json()
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    full_name = (data.get("full_name") or "").strip()
    plan = data.get("selected_plan") or "starter"

    if plan not in PLAN_PRICES:
        raise HTTPException(status_code=400, detail="Plano inválido para checkout")
    if not STRIPE_CONFIGURED or not STRIPE_WEBHOOK_CONFIGURED:
        raise HTTPException(status_code=503, detail="Stripe ou webhook não configurado")
    if not username or not email or not password:
        raise HTTPException(status_code=400, detail="Dados de cadastro incompletos")
    if len(username) > 80 or not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", username):
        raise HTTPException(status_code=400, detail="Nome de usuário inválido")
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=400, detail="Email inválido")
    if len(password) < 8 or len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="A senha deve ter entre 8 e 72 bytes")

    existing = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Usuário já existente. Faça login para assinar")

    try:
        password_hash = get_password_hash(password)

        customer = stripe.Customer.create(
            email=email,
            metadata={
                "username": username,
                "pre_register": "true"
            }
        )

        checkout_session = _stripe_checkout(
            plan,
            customer.id,
            f"{FRONTEND_ORIGIN}/payment-success.html?session_id={{CHECKOUT_SESSION_ID}}",
            f"{FRONTEND_ORIGIN}/register.html?plan={plan}&canceled=true",
            {
                "pre_register": "true",
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "full_name": full_name,
                "plan": plan
            },
        )

        return {
            "checkout_url": checkout_session.url,
            "session_id": checkout_session.id
        }
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/renewal-checkout")
async def create_renewal_checkout(request: Request, db: Session = Depends(get_db)):
    """Creates a fixed-term renewal checkout without issuing a platform session."""
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_check(f"renewal_checkout:{client_ip}", limit=5, window=300):
        raise HTTPException(status_code=429, detail="Muitas tentativas de renovação. Aguarde alguns minutos.")
    data = await request.json()
    payload = decode_renewal_token(data.get("renewal_token") or "")
    user = db.query(User).filter(User.id == int(payload["uid"]), User.username == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=404, detail="Conta não encontrada.")
    plan = normalize_subscription_plan(user.subscription_plan)
    if plan != payload.get("plan") or not is_fixed_term_plan(plan) or not is_plan_expired(plan, user.subscription_end):
        raise HTTPException(status_code=409, detail="Esta conta não precisa de renovação por prazo agora.")
    if not STRIPE_CONFIGURED or not STRIPE_WEBHOOK_CONFIGURED:
        raise HTTPException(status_code=503, detail="Stripe ou webhook não configurado para renovação.")

    customer_id = user.stripe_customer_id
    if customer_id:
        try:
            stripe.Customer.retrieve(customer_id)
        except Exception:
            customer_id = None
    if not customer_id:
        customer = stripe.Customer.create(email=user.email, metadata={"user_id": user.id, "username": user.username})
        customer_id = customer.id
        user.stripe_customer_id = customer_id
        db.commit()

    checkout_session = _stripe_checkout(
        plan,
        customer_id,
        f"{FRONTEND_ORIGIN}/payment-success.html?session_id={{CHECKOUT_SESSION_ID}}&renewal=true",
        f"{FRONTEND_ORIGIN}/index.html?renewal_canceled=true",
        {"user_id": user.id, "plan": plan, "renewal": "true"},
    )
    return {"checkout_url": checkout_session.url, "session_id": checkout_session.id}

@router.get("/verify-session")
async def verify_checkout_session(
    session_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
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
        if status == "complete" and payment_status in ("paid", "no_payment_required"):
            user = db.query(User).filter(User.id == current_user.id).first()
            if user:
                if plan and get_plan_policy(plan)["recurring"] and (user.subscription_plan != plan or not user.stripe_subscription_id):
                    _activate_paid_plan(user, plan, db, subscription_id)
                    access_key = _issue_access_key(user, db)
                    if access_key and background_tasks:
                        background_tasks.add_task(
                            email_service.send_subscription_confirmation,
                            user.email, user.username, plan,
                            PLAN_PRICES.get(plan, 0) / 100,
                            access_key,
                        )
            return {"verified": True, "plan": plan, "subscription_id": subscription_id, "activation": "webhook" if is_fixed_term_plan(plan) else "confirmed"}
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
    if not STRIPE_CONFIGURED or not STRIPE_WEBHOOK_CONFIGURED:
        raise HTTPException(status_code=503, detail="Webhook Stripe não configurado")
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
        checkout_session_id = session.get('id')
        meta = session.get('metadata', {}) or {}
        plan = meta.get('plan')
        subscription_id = session.get('subscription')
        customer_id = session.get('customer')
        if session.get('payment_status') not in ('paid', 'no_payment_required'):
            return {"status": "ignored", "reason": "payment_not_confirmed"}

        pre_register = meta.get('pre_register') == 'true'
        if pre_register:
            username = meta.get('username')
            email = meta.get('email')
            password_hash = meta.get('password_hash')

            user = None
            if email:
                user = db.query(User).filter(User.email == email).first()
            if not user and username:
                user = db.query(User).filter(User.username == username).first()

            if not user:
                user = User(
                    username=username,
                    email=email,
                    hashed_password=password_hash,
                    subscription_plan='starter',
                    subscription_status='pending',
                    scans_limit=100,
                    scans_this_month=0
                )
                db.add(user)
                db.commit()
                db.refresh(user)

            if checkout_session_id and user.last_stripe_checkout_session_id == checkout_session_id:
                return {"status": "success", "duplicate": True}

            if plan:
                _activate_paid_plan(user, plan, db, subscription_id)
            user.stripe_customer_id = customer_id
            user.last_stripe_checkout_session_id = checkout_session_id
            access_key = _issue_access_key(user, db)
            db.commit()

            manual_url = f"{FRONTEND_ORIGIN}/documentation.html"
            if access_key:
                background_tasks.add_task(
                    email_service.send_paid_welcome_email,
                    user.email,
                    user.username,
                    plan,
                    manual_url,
                    access_key
                )
            print(f"✅ Cadastro pós-pagamento ativado para usuário {user.username} - Plano: {plan}")
        else:
            user_id = meta.get('user_id')
            if user_id:
                user = db.query(User).filter(User.id == int(user_id)).first()
                if user:
                    if checkout_session_id and user.last_stripe_checkout_session_id == checkout_session_id:
                        return {"status": "success", "duplicate": True}
                    if plan:
                        _activate_paid_plan(user, plan, db, subscription_id)
                    user.last_stripe_checkout_session_id = checkout_session_id
                    access_key = _issue_access_key(user, db)
                    db.commit()
                    if access_key:
                        background_tasks.add_task(
                            email_service.send_subscription_confirmation,
                            user.email,
                            user.username,
                            plan,
                            PLAN_PRICES.get(plan, 0) / 100,
                            access_key
                        )
                    print(f"✅ Assinatura ativada para usuário {user.username} - Plano: {plan}")
    
    elif event['type'] == 'customer.subscription.deleted':
        # Assinatura cancelada
        subscription = event['data']['object']
        subscription_id = subscription['id']
        
        user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
        if user and normalize_subscription_plan(user.subscription_plan) == "starter":
            user.subscription_status = 'cancelled'
            user.subscription_plan = 'starter'
            user.scans_limit = 100
            user.is_trial = False
            sync_owned_organization_plans(user, db)
            db.commit()
            
            print(f"❌ Assinatura cancelada para usuário {user.username}")
    
    elif event['type'] == 'invoice.payment_succeeded':
        # Pagamento recorrente bem-sucedido
        invoice = event['data']['object']
        subscription_id = invoice['subscription']
        
        user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
        if user:
            # Use the period confirmed by Stripe to avoid extending twice when
            # checkout.session.completed and the initial invoice arrive together.
            lines = (invoice.get("lines") or {}).get("data") or []
            period_ends = [line.get("period", {}).get("end") for line in lines if line.get("period", {}).get("end")]
            if period_ends:
                user.subscription_end = datetime.utcfromtimestamp(max(period_ends))
            elif not user.subscription_end or user.subscription_end <= datetime.utcnow():
                from services.plan_policy import access_end_for_plan
                user.subscription_end = access_end_for_plan("starter")
            
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
        if not MERCADOPAGO_CONFIGURED:
            raise HTTPException(status_code=503, detail="Webhook Mercado Pago não configurado")
        raw_body = await request.body()
        x_signature = request.headers.get('x-signature')
        x_request_id = request.headers.get('x-request-id')
        data_id = request.query_params.get('data.id')
        if not x_signature or not x_request_id or not data_id:
            raise HTTPException(status_code=401, detail="Assinatura ausente")
        signature_parts = {}
        for part in x_signature.split(','):
            key_value = part.strip().split('=', 1)
            if len(key_value) == 2:
                signature_parts[key_value[0]] = key_value[1]
        timestamp = signature_parts.get('ts')
        signature = signature_parts.get('v1')
        if not timestamp or not signature:
            raise HTTPException(status_code=401, detail="Assinatura inválida")
        manifest = f"id:{data_id.lower()};request-id:{x_request_id};ts:{timestamp};"
        digest = hmac.new(MERCADOPAGO_WEBHOOK_SECRET.encode('utf-8'), manifest.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(digest, signature):
            raise HTTPException(status_code=401, detail="Assinatura inválida")

        import json
        data = json.loads(raw_body)
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
                    _activate_paid_plan(user, plan, db)
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
        if not MERCADOPAGO_CONFIGURED:
            raise HTTPException(status_code=503, detail="Mercado Pago não configurado")
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
    """Cancela a assinatura no provedor e revoga o acesso local."""
    if normalize_subscription_plan(current_user.subscription_plan) != "starter":
        raise HTTPException(
            status_code=409,
            detail="Professional e Enterprise são licenças de prazo fixo. Elas permanecem válidas até o vencimento e não possuem assinatura recorrente para cancelar.",
        )
    if current_user.subscription_status == "cancelled":
        return {
            "success": True,
            "message": "A assinatura já está cancelada.",
            "refunded": False,
            "already_cancelled": True,
        }

    try:
        trial_refunded = False
        if _trial_is_active(current_user) and current_user.stripe_subscription_id:
            refund = _refund_initial_stripe_payment(current_user.stripe_subscription_id)
            trial_refunded = refund is not None

        if current_user.stripe_subscription_id:
            # O delete é remoto: se falhar, o acesso local não é alterado.
            stripe.Subscription.delete(current_user.stripe_subscription_id)
            current_user.stripe_subscription_id = None
        
        # O Free foi removido: usuário cancelado fica sem acesso até assinar novamente.
        current_user.subscription_status = 'cancelled'
        current_user.subscription_plan = 'starter'
        current_user.scans_limit = 100
        current_user.scans_this_month = 0
        current_user.is_trial = False
        current_user.subscription_end = datetime.utcnow()
        sync_owned_organization_plans(current_user, db)
        db.commit()
        
        return {
            "success": True,
            "message": "Assinatura cancelada e valor estornado com sucesso." if trial_refunded else "Assinatura cancelada com sucesso.",
            "refunded": trial_refunded
        }
        
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        print(f"Erro ao cancelar assinatura: {e}")
        raise HTTPException(status_code=502, detail="Não foi possível confirmar o cancelamento com o provedor. Nenhuma alteração local foi aplicada.")


@router.get("/plans")
async def get_all_plans():
    """
    Retorna informações sobre todos os planos disponíveis
    """
    plans = ["starter", "professional", "enterprise"]
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
    new_plan = data.get("plan", "starter")
    
    if new_plan not in ["starter", "professional", "enterprise"]:
        raise HTTPException(status_code=400, detail="Plano inválido")
    
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(status_code=403, detail="Acesso negado")
    upgrade_user_plan(current_user, new_plan, None, db)
    
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
        "stripe_webhook_configured": STRIPE_WEBHOOK_CONFIGURED,
        "frontend_url": os.getenv("FRONTEND_URL", "http://localhost:8000"),
        "mercadopago_configured": MERCADOPAGO_CONFIGURED,
    }
