"""
Middleware para controle de acesso baseado em assinatura
"""
from fastapi import HTTPException, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional
from models.user import User
from auth import get_current_user
from database import get_db
from functools import wraps
import inspect

# Definição de ferramentas por plano
TOOL_PERMISSIONS = {
    "free": [
        "port_scanner",
        "ssl_checker",
        "dns_lookup",
        "whois_lookup",
        "header_analyzer"
    ],
    "starter": [
        "port_scanner",
        "ssl_checker",
        "dns_lookup",
        "whois_lookup",
        "header_analyzer",
        "code_scanner",
        "sqli_tester",
        "xss_tester",
        "phishing_simulator",
        "subdomain_finder"
    ],
    "professional": [
        "port_scanner",
        "ssl_checker",
        "dns_lookup",
        "whois_lookup",
        "header_analyzer",
        "code_scanner",
        "sqli_tester",
        "xss_tester",
        "phishing_simulator",
        "subdomain_finder",
        "directory_enumerator",
        "network_mapper",
        "vulnerability_scanner",
        "exploit_finder",
        "password_auditor",
        "log_analyzer",
        "ioc_analyzer",
        "threat_intelligence",
        "api_security_tester",
        "container_scanner"
    ],
    "enterprise": "all"  # Acesso ilimitado
}

# Limites de scans por plano
SCAN_LIMITS = {
    "free": 10,
    "starter": 100,
    "professional": -1,  # Ilimitado
    "enterprise": -1     # Ilimitado
}


def check_subscription_status(user: User) -> dict:
    """
    Verifica o status da assinatura do usuário
    Returns dict com status e informações
    """
    now = datetime.utcnow()
    
    # Verificar se a assinatura expirou
    if user.subscription_end and user.subscription_end < now:
        return {
            "valid": False,
            "active": False,
            "reason": "subscription_expired",
            "message": "Sua assinatura expirou. Renove para continuar usando."
        }
    
    # Verificar se está cancelada
    if user.subscription_status == "cancelled":
        return {
            "valid": False,
            "active": False,
            "reason": "subscription_cancelled",
            "message": "Sua assinatura foi cancelada."
        }
    
    # Verificar limite de scans
    if user.scans_limit != -1 and user.scans_this_month >= user.scans_limit:
        return {
            "valid": False,
            "active": False,
            "reason": "limit_exceeded",
            "message": f"Você atingiu o limite de {user.scans_limit} scans este mês. Faça upgrade para continuar ou aguarde a renovação mensal.",
            "scans_used": user.scans_this_month,
            "scans_limit": user.scans_limit
        }
    
    return {
        "valid": True,
        "active": True,
        "plan": user.subscription_plan,
        "scans_used": user.scans_this_month,
        "scans_limit": user.scans_limit,
        "expires_at": user.subscription_end.isoformat() if user.subscription_end else None
    }


def check_tool_access(tool_name: str, user: User) -> bool:
    """
    Verifica se o usuário tem acesso à ferramenta
    """
    plan = user.subscription_plan
    
    # Enterprise tem acesso a tudo
    if plan == "enterprise":
        return True
    
    # Verificar se a ferramenta está na lista do plano
    allowed_tools = TOOL_PERMISSIONS.get(plan, [])
    
    if isinstance(allowed_tools, str) and allowed_tools == "all":
        return True
    
    return tool_name in allowed_tools


def require_plan(required_plans: list):
    """
    Decorator para proteger endpoints que requerem planos específicos
    
    Uso:
    @router.post("/premium-feature")
    @require_plan(["professional", "enterprise"])
    async def premium_feature(current_user: User = Depends(get_current_user)):
        ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            if current_user.subscription_plan not in required_plans:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "upgrade_required",
                        "message": f"Esta funcionalidade requer o plano {', '.join(required_plans)}",
                        "current_plan": current_user.subscription_plan,
                        "required_plans": required_plans
                    }
                )
            return await func(*args, current_user=current_user, **kwargs)
        wrapper.__signature__ = inspect.signature(func)
        return wrapper
    return decorator


def require_tool_access(tool_name: str):
    """
    Decorator para proteger ferramentas específicas
    
    Uso:
    @router.post("/tools/vulnerability-scanner")
    @require_tool_access("vulnerability_scanner")
    async def run_vuln_scanner(current_user: User = Depends(get_current_user)):
        ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            # Verificar acesso à ferramenta
            if not check_tool_access(tool_name, current_user):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "tool_locked",
                        "message": f"Esta ferramenta não está disponível no seu plano atual",
                        "tool": tool_name,
                        "current_plan": current_user.subscription_plan,
                        "upgrade_url": "/pricing"
                    }
                )
            
            # Verificar status da assinatura
            status = check_subscription_status(current_user)
            if not status["valid"]:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": status["reason"],
                        "message": status["message"],
                        "current_plan": current_user.subscription_plan
                    }
                )
            
            return await func(*args, current_user=current_user, **kwargs)
        wrapper.__signature__ = inspect.signature(func)
        return wrapper
    return decorator


def increment_scan_count(user: User, db: Session):
    """
    Incrementa o contador de scans do usuário
    Reseta o contador se mudou de mês
    """
    now = datetime.utcnow()
    
    print(f"[INCREMENT_SCAN] Usuário: {user.username}, Plano: {user.subscription_plan}")
    print(f"[INCREMENT_SCAN] Scans atuais: {user.scans_this_month}, Limite: {user.scans_limit}")
    
    # Se não tem subscription_start, definir agora
    if not user.subscription_start:
        user.subscription_start = now
        print(f"[INCREMENT_SCAN] Definindo subscription_start: {now}")
    
    # Verificar se mudou de mês (resetar contador)
    if user.subscription_start:
        month_diff = (now.year - user.subscription_start.year) * 12 + now.month - user.subscription_start.month
        if month_diff >= 1:
            print(f"[INCREMENT_SCAN] Mudou de mês! Resetando contador...")
            user.scans_this_month = 0
            user.subscription_start = now
    
    # Incrementar apenas se não for ilimitado
    if user.scans_limit != -1:
        user.scans_this_month += 1
        print(f"[INCREMENT_SCAN] Incrementando: {user.scans_this_month - 1} → {user.scans_this_month}")
    else:
        print(f"[INCREMENT_SCAN] Scans ilimitados - não incrementa contador")
    
    db.commit()
    db.refresh(user)
    
    print(f"[INCREMENT_SCAN] ✅ Finalizado. Scans após commit: {user.scans_this_month}")


def get_plan_info(plan_name: str) -> dict:
    """
    Retorna informações sobre um plano específico
    """
    plans = {
        "free": {
            "name": "Free",
            "price": 0,
            "currency": "BRL",
            "scans_limit": 10,
            "features": [
                "10 scans por mês",
                "Ferramentas básicas",
                "Suporte via email"
            ],
            "tools": TOOL_PERMISSIONS["free"]
        },
        "starter": {
            "name": "Starter",
            "price": 49.90,
            "currency": "BRL",
            "scans_limit": 100,
            "features": [
                "100 scans por mês",
                "Red/Blue Team básico",
                "Relatórios em PDF",
                "Suporte prioritário"
            ],
            "tools": TOOL_PERMISSIONS["starter"]
        },
        "professional": {
            "name": "Professional",
            "price": 149.90,
            "currency": "BRL",
            "scans_limit": -1,
            "features": [
                "Scans ilimitados",
                "Todas as ferramentas",
                "API access",
                "Relatórios avançados",
                "Suporte 24/7"
            ],
            "tools": TOOL_PERMISSIONS["professional"]
        },
        "enterprise": {
            "name": "Enterprise",
            "price": 499.90,
            "currency": "BRL",
            "scans_limit": -1,
            "features": [
                "Tudo do Professional",
                "Multi-usuário",
                "White label",
                "Custom integrations",
                "Gerente dedicado"
            ],
            "tools": "all"
        }
    }
    
    return plans.get(plan_name, plans["free"])


def upgrade_user_plan(user: User, new_plan: str, duration_months: int, db: Session):
    """
    Atualiza o plano do usuário
    """
    now = datetime.utcnow()
    
    user.subscription_plan = new_plan
    user.subscription_status = "active"
    user.subscription_start = now
    user.subscription_end = now + timedelta(days=30 * duration_months)
    user.scans_limit = SCAN_LIMITS.get(new_plan, 10)
    user.scans_this_month = 0
    
    db.commit()
    db.refresh(user)
    
    return user
