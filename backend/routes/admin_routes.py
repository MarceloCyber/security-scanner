from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List
from datetime import datetime, timedelta
from database import get_db
from models.user import User
from models.scan import Scan
from auth import get_current_user
from pydantic import BaseModel

router = APIRouter(prefix="/api/admin", tags=["admin"])

# Middleware para verificar se é admin
def require_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado. Apenas administradores podem acessar este recurso."
        )
    return current_user

# Schemas
class UserUpdate(BaseModel):
    email: str = None
    subscription_plan: str = None
    subscription_status: str = None
    scans_limit: int = None
    is_admin: bool = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime
    subscription_plan: str
    subscription_status: str
    scans_this_month: int
    scans_limit: int
    is_admin: bool
    last_login: datetime = None

# ==================== DASHBOARD STATS ====================
@router.get("/stats")
def get_admin_stats(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Retorna estatísticas gerais da plataforma"""
    
    # Total de usuários
    total_users = db.query(User).count()
    
    # Usuários ativos (com scans nos últimos 30 dias)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    active_users = db.query(User).join(Scan).filter(
        Scan.created_at >= thirty_days_ago
    ).distinct().count()
    
    # Usuários por plano
    users_by_plan = db.query(
        User.subscription_plan,
        func.count(User.id).label('count')
    ).group_by(User.subscription_plan).all()
    
    plans_dict = {plan: count for plan, count in users_by_plan}
    
    # Total de scans
    total_scans = db.query(Scan).count()
    
    # Scans hoje
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    scans_today = db.query(Scan).filter(Scan.created_at >= today_start).count()
    
    # Scans últimos 7 dias
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    scans_last_7_days = db.query(Scan).filter(Scan.created_at >= seven_days_ago).count()
    
    # Receita mensal estimada (baseado nos planos)
    revenue_map = {
        'starter': 49,
        'professional': 149,
        'enterprise': 499
    }
    
    monthly_revenue = sum(
        plans_dict.get(plan, 0) * revenue
        for plan, revenue in revenue_map.items()
    )
    
    # Novos usuários últimos 7 dias
    new_users_7_days = db.query(User).filter(
        User.created_at >= seven_days_ago
    ).count()
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "total_scans": total_scans,
        "scans_today": scans_today,
        "scans_last_7_days": scans_last_7_days,
        "new_users_7_days": new_users_7_days,
        "monthly_revenue": monthly_revenue,
        "users_by_plan": {
            "free": plans_dict.get('free', 0),
            "starter": plans_dict.get('starter', 0),
            "professional": plans_dict.get('professional', 0),
            "enterprise": plans_dict.get('enterprise', 0)
        }
    }

# ==================== USER MANAGEMENT ====================
@router.get("/users")
def get_all_users(
    page: int = 1,
    limit: int = 20,
    search: str = None,
    plan: str = None,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Lista todos os usuários com paginação e filtros"""
    
    query = db.query(User)
    
    # Filtro de busca
    if search:
        query = query.filter(
            (User.username.contains(search)) |
            (User.email.contains(search))
        )
    
    # Filtro por plano
    if plan:
        query = query.filter(User.subscription_plan == plan)
    
    # Total
    total = query.count()
    
    # Paginação
    users = query.order_by(desc(User.created_at)).offset((page - 1) * limit).limit(limit).all()
    
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at,
                "subscription_plan": user.subscription_plan,
                "subscription_status": user.subscription_status,
                "scans_this_month": user.scans_this_month or 0,
                "scans_limit": user.scans_limit or 0,
                "is_admin": user.is_admin or False
            }
            for user in users
        ]
    }

@router.get("/users/{user_id}")
def get_user_details(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Retorna detalhes completos de um usuário"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    # Buscar scans do usuário
    total_scans = db.query(Scan).filter(Scan.user_id == user_id).count()
    
    # Último scan
    last_scan = db.query(Scan).filter(
        Scan.user_id == user_id
    ).order_by(desc(Scan.created_at)).first()
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "created_at": user.created_at,
        "subscription_plan": user.subscription_plan,
        "subscription_status": user.subscription_status,
        "subscription_start": user.subscription_start,
        "subscription_end": user.subscription_end,
        "scans_this_month": user.scans_this_month or 0,
        "scans_limit": user.scans_limit or 0,
        "stripe_customer_id": user.stripe_customer_id,
        "is_admin": user.is_admin or False,
        "total_scans": total_scans,
        "last_scan_date": last_scan.created_at if last_scan else None
    }

@router.put("/users/{user_id}")
def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Atualiza informações de um usuário"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    # Atualizar campos fornecidos
    if user_update.email is not None:
        user.email = user_update.email
    
    if user_update.subscription_plan is not None:
        user.subscription_plan = user_update.subscription_plan
        
        # Atualizar limite de scans baseado no plano
        if user_update.subscription_plan == 'free':
            user.scans_limit = 10
        elif user_update.subscription_plan == 'starter':
            user.scans_limit = 100
        else:  # professional, enterprise
            user.scans_limit = -1  # ilimitado
    
    if user_update.subscription_status is not None:
        user.subscription_status = user_update.subscription_status
    
    if user_update.scans_limit is not None:
        user.scans_limit = user_update.scans_limit
    
    if user_update.is_admin is not None:
        user.is_admin = user_update.is_admin
    
    db.commit()
    db.refresh(user)
    
    return {
        "message": "Usuário atualizado com sucesso",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "subscription_plan": user.subscription_plan,
            "subscription_status": user.subscription_status,
            "scans_limit": user.scans_limit,
            "is_admin": user.is_admin
        }
    }

@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Exclui um usuário permanentemente"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    # Não permitir excluir admin próprio
    if user.id == admin.id:
        raise HTTPException(
            status_code=400,
            detail="Você não pode excluir sua própria conta de administrador"
        )
    
    username = user.username
    
    # Excluir scans do usuário primeiro (cascade)
    db.query(Scan).filter(Scan.user_id == user_id).delete()
    
    # Excluir usuário
    db.delete(user)
    db.commit()
    
    return {
        "message": f"Usuário '{username}' excluído com sucesso",
        "deleted_user_id": user_id
    }

@router.post("/users/{user_id}/reset-scans")
def reset_user_scans(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Reseta o contador de scans de um usuário"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    old_count = user.scans_this_month
    user.scans_this_month = 0
    db.commit()
    
    return {
        "message": "Contador de scans resetado com sucesso",
        "user_id": user_id,
        "username": user.username,
        "old_count": old_count,
        "new_count": 0
    }

# ==================== ACTIVITY LOGS ====================
@router.get("/activity")
def get_recent_activity(
    limit: int = 50,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Retorna atividades recentes da plataforma"""
    
    # Buscar scans recentes com informações do usuário
    recent_scans = db.query(Scan).join(User).order_by(
        desc(Scan.created_at)
    ).limit(limit).all()
    
    activities = []
    for scan in recent_scans:
        user = db.query(User).filter(User.id == scan.user_id).first()
        activities.append({
            "id": scan.id,
            "type": "scan",
            "user_id": scan.user_id,
            "username": user.username if user else "Unknown",
            "scan_type": scan.scan_type,
            "target": scan.target if hasattr(scan, 'target') else None,
            "created_at": scan.created_at,
            "status": "completed"
        })
    
    return {
        "total": len(activities),
        "activities": activities
    }

# ==================== SYSTEM INFO ====================
@router.get("/system")
def get_system_info(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Retorna informações do sistema"""
    
    import platform
    
    # Tenta importar psutil, se não estiver instalado, retorna valores padrão
    try:
        import psutil
        resources = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent
        }
    except ImportError:
        resources = {
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0
        }
    
    return {
        "system": {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "python_version": platform.python_version(),
            "hostname": platform.node()
        },
        "resources": resources,
        "database": {
            "total_users": db.query(User).count(),
            "total_scans": db.query(Scan).count()
        }
    }

print("Admin routes loaded successfully!")