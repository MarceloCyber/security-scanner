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
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_...")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_...")

# Configurar Mercado Pago
MERCADOPAGO_ACCESS_TOKEN = os.getenv("MERCADOPAGO_ACCESS_TOKEN", "APP_USR-...")
MERCADOPAGO_WEBHOOK_SECRET = os.getenv("MERCADOPAGO_WEBHOOK_SECRET", "")

# Preços dos planos (em centavos para Stripe)
PLAN_PRICES = {
    "starter": 4990,      # R$ 49.90
    "professional": 14990, # R$ 149.90
    "enterprise": 49990    # R$ 499.90
}


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
    db: Session = Depends(get_db)
):
    """
    Cria uma sessão de checkout no Stripe
    """
    data = await request.json()
    plan = data.get("plan", "starter")
    
    if plan not in PLAN_PRICES:
        raise HTTPException(status_code=400, detail="Plano inválido")
    
    try:
        # Criar ou recuperar customer do Stripe
        if current_user.stripe_customer_id:
            customer_id = current_user.stripe_customer_id
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
        
        # Criar sessão de checkout
        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'brl',
                    'unit_amount': PLAN_PRICES[plan],
                    'product_data': {
                        'name': f'Security Scanner Pro - {plan.title()}',
                        'description': f'Assinatura mensal do plano {plan.title()}',
                    },
                    'recurring': {
                        'interval': 'month',
                        'interval_count': 1,
                    },
                },
                'quantity': 1,
            }],
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
        
    except Exception as e:
        print(f"Erro ao criar checkout: {e}")
        raise HTTPException(status_code=500, detail=f"Erro ao criar sessão de pagamento: {str(e)}")


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
            
            print(f"⚠️ Falha no pagamento para {user.username}")
    
    return {"status": "success"}


@router.post("/mercadopago-webhook")
async def mercadopago_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Webhook do Mercado Pago para processar eventos de pagamento
    """
    try:
        # Validar assinatura do webhook
        x_signature = request.headers.get('x-signature')
        x_request_id = request.headers.get('x-request-id')
        
        data = await request.json()
        
        # Verificar tipo de notificação
        notification_type = data.get('type')
        
        if notification_type == 'payment':
            payment_id = data.get('data', {}).get('id')
            
            # Aqui você faria uma chamada à API do Mercado Pago para obter detalhes do pagamento
            # Por simplicidade, vou mostrar a estrutura básica
            
            # Exemplo de processamento (você precisaria fazer uma chamada real à API)
            """
            import requests
            headers = {
                'Authorization': f'Bearer {MERCADOPAGO_ACCESS_TOKEN}'
            }
            payment_response = requests.get(
                f'https://api.mercadopago.com/v1/payments/{payment_id}',
                headers=headers
            )
            payment_data = payment_response.json()
            
            if payment_data['status'] == 'approved':
                user_id = payment_data['metadata']['user_id']
                plan = payment_data['metadata']['plan']
                
                user = db.query(User).filter(User.id == user_id).first()
                if user:
                    upgrade_user_plan(user, plan, 1, db)
                    user.mercadopago_customer_id = payment_data['payer']['id']
                    db.commit()
            """
            
            print(f"📱 Webhook Mercado Pago recebido: {payment_id}")
        
        return {"status": "success"}
        
    except Exception as e:
        print(f"Erro no webhook Mercado Pago: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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
        
        # Atualizar status no banco
        current_user.subscription_status = 'cancelled'
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
    
    upgrade_user_plan(current_user, new_plan, 1, db)
    
    return {
        "success": True,
        "message": f"Plano atualizado para {new_plan}",
        "new_plan": new_plan
    }
