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
# Starter: 5 ferramentas | Professional: 10 ferramentas | Enterprise: todas
#
# REGRA: todos os itens aqui DEVEM ter página dedicada no dashboard (data-page).
# ssl_checker / dns_lookup / whois_lookup / header_analyzer são sub-features do
# Port Scanner (deep scan) e não possuem página própria – por isso não aparecem.
TOOL_PERMISSIONS = {
    "starter": [
        "port_scanner",       # data-page="port-scan"
        "subdomain_finder",   # data-page="subdomain"
        "hash_analyzer",      # data-page="hash-analyzer"
        "encoder_decoder",    # data-page="encoder"
        "password_strength_checker",  # data-page="password-strength"
    ],
    "professional": [
        # Ferramentas do Starter (5):
        "port_scanner",
        "subdomain_finder",
        "hash_analyzer",
        "encoder_decoder",
        "password_strength_checker",
        # Ferramentas exclusivas do Professional (5):
        "code_scanner",       # data-page="scanner"
        "sqli_tester",        # data-page="sql-injection"
        "xss_tester",         # data-page="xss-tester"
        "phishing_simulator", # data-page="phishing"
        "directory_enumerator", # data-page="directory-enum"
    ],
    "enterprise": "all",  # Acesso ilimitado
}

# Páginas do dashboard (data-page) permitidas por plano
PLAN_DASHBOARD_TOOLS = {
    "starter": [
        "port-scan",
        "subdomain",
        "hash-analyzer",
        "encoder",
        "password-strength",
    ],
    "professional": [
        "port-scan",
        "subdomain",
        "hash-analyzer",
        "encoder",
        "password-strength",
        "scanner",
        "sql-injection",
        "xss-tester",
        "phishing",
        "directory-enum",
    ],
    "enterprise": "all",
}

# Mapeamento das páginas do dashboard para nomes de ferramenta no backend
DASHBOARD_TOOL_MAP = {
    "port-scan": "port_scanner",
    "scanner": "code_scanner",
    "sql-injection": "sqli_tester",
    "xss-tester": "xss_tester",
    "phishing": "phishing_simulator",
    "subdomain": "subdomain_finder",
    "payloads": "payload_generator",
    "encoder": "encoder_decoder",
    "api-scanner": "api_security_tester",
    "dependency-scanner": "dependency_scanner",
    "docker-scanner": "container_scanner",
    "graphql-scanner": "graphql_scanner",
    "brute-force": "password_auditor",
    "directory-enum": "directory_enumerator",
    "log-analyzer": "log_analyzer",
    "threat-intel": "threat_intelligence",
    "hash-analyzer": "hash_analyzer",
    "ioc-analyzer": "ioc_analyzer",
    "password-strength": "password_auditor",
    "reports": "reports_generator",
    "ai-assistant": "ai_assistant",
    "intelligent-automation": "intelligent_automation",
}

PLAN_TOOL_COUNTS = {
    "starter": 5,
    "professional": 10,
    "enterprise": -1,
}

# Limites de scans por plano
SCAN_LIMITS = {
    "starter": 100,
    "professional": -1,  # Ilimitado
    "enterprise": -1     # Ilimitado
}


def normalize_subscription_plan(plan: Optional[str]) -> str:
    """Retorna apenas um plano reconhecido, tratando registros legados vazios como Starter."""
    normalized_plan = (plan or "").strip().lower()
    return normalized_plan if normalized_plan in TOOL_PERMISSIONS else "starter"


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
    if user.subscription_status in ("cancelled", "pending", "payment_failed", "expired"):
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
        "plan": normalize_subscription_plan(user.subscription_plan),
        "scans_used": user.scans_this_month,
        "scans_limit": user.scans_limit,
        "expires_at": user.subscription_end.isoformat() if user.subscription_end else None
    }


def get_allowed_dashboard_tools(plan: Optional[str]) -> list:
    """Retorna os IDs de página do dashboard liberados para o plano."""
    normalized_plan = normalize_subscription_plan(plan)
    allowed = PLAN_DASHBOARD_TOOLS.get(normalized_plan, PLAN_DASHBOARD_TOOLS["starter"])
    if allowed == "all":
        return list(DASHBOARD_TOOL_MAP.keys())
    return list(allowed)


def check_tool_access(tool_name: str, user: User) -> bool:
    """
    Verifica se o usuário tem acesso à ferramenta
    """
    if getattr(user, "is_admin", False):
        return True

    plan = normalize_subscription_plan(user.subscription_plan)
    
    # Enterprise tem acesso a tudo
    if plan == "enterprise":
        return True
    
    # Verificar se a ferramenta está na lista do plano
    allowed_tools = TOOL_PERMISSIONS.get(plan, [])
    
    if isinstance(allowed_tools, str) and allowed_tools == "all":
        return True
    
    return tool_name in allowed_tools


def ensure_tool_access(tool_name: str, user: User) -> None:
    """Interrompe a requisição quando a assinatura ou o plano não permite a ferramenta."""
    if getattr(user, "is_admin", False):
        return

    subscription = check_subscription_status(user)
    if not subscription["valid"]:
        raise HTTPException(
            status_code=403,
            detail={
                "error": subscription["reason"],
                "message": subscription["message"],
                "current_plan": user.subscription_plan,
            },
        )

    if not check_tool_access(tool_name, user):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "tool_locked",
                "message": "Esta ferramenta não está disponível no seu plano atual",
                "tool": tool_name,
                "current_plan": user.subscription_plan,
                "upgrade_url": "/pricing",
            },
        )


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
        "starter": {
            "name": "Starter",
            "price": 289.90,
            "currency": "BRL",
            "scans_limit": 100,
            "tools_count": PLAN_TOOL_COUNTS["starter"],
            "features": [
                "100 scans por mês",
                "5 ferramentas de segurança",
                "Relatórios em PDF",
                "Suporte prioritário"
            ],
            "tools": TOOL_PERMISSIONS["starter"],
            "dashboard_tools": get_allowed_dashboard_tools("starter"),
        },
        "professional": {
            "name": "Professional",
            "price": 439.90,
            "currency": "BRL",
            "scans_limit": -1,
            "tools_count": PLAN_TOOL_COUNTS["professional"],
            "features": [
                "Scans ilimitados",
                "10 ferramentas de segurança",
                "API access",
                "Relatórios avançados",
                "Suporte 24/7"
            ],
            "tools": TOOL_PERMISSIONS["professional"],
            "dashboard_tools": get_allowed_dashboard_tools("professional"),
        },
        "enterprise": {
            "name": "Enterprise",
            "price": None,
            "currency": "BRL",
            "scans_limit": -1,
            "tools_count": PLAN_TOOL_COUNTS["enterprise"],
            "features": [
                "Todas as ferramentas",
                "Multi-usuário",
                "White label",
                "Custom integrations",
                "Gerente dedicado"
            ],
            "tools": "all",
            "dashboard_tools": get_allowed_dashboard_tools("enterprise"),
        }
    }
    
    return plans.get(plan_name, plans["starter"])


def upgrade_user_plan(user: User, new_plan: str, duration_months: int, db: Session):
    """
    Atualiza o plano do usuário
    """
    now = datetime.utcnow()
    
    user.subscription_plan = new_plan
    user.subscription_status = "active"
    user.subscription_start = now
    user.subscription_end = now + timedelta(days=30 * duration_months)
    user.scans_limit = SCAN_LIMITS.get(new_plan, SCAN_LIMITS["starter"])
    user.scans_this_month = 0
    
    db.commit()
    db.refresh(user)
    
    return user
