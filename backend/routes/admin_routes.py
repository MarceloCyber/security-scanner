from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List
from datetime import datetime, timedelta
from database import get_db
from models.user import User
from models.scan import Scan
from auth import get_current_user, get_password_hash
from middleware.subscription import upgrade_user_plan
from utils.email_service import email_service
import json
import stripe
from pydantic import BaseModel
import os
import stripe
from pathlib import Path
import shutil
from typing import Dict, Any

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

class BackupRestoreRequest(BaseModel):
    filename: str

class BootstrapAdminRequest(BaseModel):
    username: str
    email: str
    password: str

@router.post("/bootstrap")
def bootstrap_admin(
    req: BootstrapAdminRequest,
    db: Session = Depends(get_db)
):
    existing_admins = db.query(User).filter(User.is_admin == True).count()
    if existing_admins > 0:
        raise HTTPException(status_code=403, detail="Administrador já existe")
    username = (req.username or "").strip()
    email = (req.email or "").strip().lower()
    password = (req.password or "").strip()
    if not username or not email or not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Dados inválidos")
    user = db.query(User).filter((User.username == username) | (User.email == email)).first()
    if user:
        user.is_admin = True
        user.hashed_password = get_password_hash(password)
        user.subscription_plan = user.subscription_plan or "free"
        user.subscription_status = user.subscription_status or "active"
        user.scans_limit = user.scans_limit or 10
        db.commit()
        db.refresh(user)
        return {"success": True, "message": "Administrador habilitado", "user_id": user.id}
    new_user = User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        subscription_plan="free",
        subscription_status="active",
        scans_limit=10,
        is_admin=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"success": True, "message": "Administrador criado", "user_id": new_user.id}

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

@router.delete("/activity")
def clear_activity_logs(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    try:
        deleted = db.query(Scan).delete(synchronize_session=False)
        db.commit()
        return {"success": True, "deleted": deleted}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Erro ao apagar histórico: {str(e)}")

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

@router.get("/payments/sessions")
def list_checkout_sessions(
    limit: int = 50,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    try:
        api_key = os.getenv("STRIPE_SECRET_KEY", "")
        if not api_key:
            return {"total": 0, "sessions": [], "message": "Stripe não configurado"}
        stripe.api_key = api_key
        # Expand customer to obter email/nome quando possível
        sessions = stripe.checkout.Session.list(limit=limit, expand=['data.customer'])
    except Exception as e:
        return {"total": 0, "sessions": [], "message": f"Erro ao consultar Stripe: {str(e)}"}

    result = []
    for s in sessions.data:
        user_id = None
        plan = None
        if hasattr(s, "metadata") and s.metadata:
            user_id = int(s.metadata.get("user_id")) if s.metadata.get("user_id") else None
            plan = s.metadata.get("plan")
        user_info = None
        if user_id:
            u = db.query(User).filter(User.id == user_id).first()
            if u:
                user_info = {
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "plan": u.subscription_plan,
                    "status": u.subscription_status
                }
        result.append({
            "id": s.id,
            "url": getattr(s, "url", None),
            "status": getattr(s, "status", None),
            "payment_status": getattr(s, "payment_status", None),
            "created": datetime.fromtimestamp(s.created).isoformat() if getattr(s, "created", None) else None,
            "plan": plan,
            "amount_total": getattr(s, "amount_total", None),
            "currency": getattr(s, "currency", None),
            "payment_methods": list(getattr(s, "payment_method_types", []) or []),
            "user": user_info or (
                {
                    "username": getattr(getattr(s, 'customer', None), 'name', None),
                    "email": getattr(getattr(s, 'customer', None), 'email', None),
                } if getattr(s, 'customer', None) else None
            )
        })
    return {"total": len(result), "sessions": result}


@router.post("/subscriptions/{user_id}/change-plan")
def change_plan(
    user_id: int,
    new_plan: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if new_plan not in ["free", "starter", "professional", "enterprise"]:
        raise HTTPException(status_code=400, detail="Plano inválido")
    upgrade_user_plan(user, new_plan, 1, db)
    try:
        if new_plan == 'free':
            email_service.send_email(
                user.email,
                'Plano alterado para Free',
                f'<p>Olá, {user.username}!</p><p>Seu plano foi alterado para Free. Você pode fazer upgrade a qualquer momento.</p>',
                f'Olá, {user.username}! Seu plano foi alterado para Free. Você pode fazer upgrade a qualquer momento.'
            )
        else:
            plan_prices = {'starter': 49.90, 'professional': 149.90, 'enterprise': 499.90}
            email_service.send_subscription_confirmation(
                user.email,
                user.username,
                new_plan,
                plan_prices.get(new_plan, 0)
            )
    except Exception:
        pass
    print(json.dumps({"event": "admin_change_plan", "user_id": user_id, "new_plan": new_plan}))
    return {"success": True, "message": "Plano atualizado", "user_id": user_id, "new_plan": new_plan}


@router.post("/subscriptions/{user_id}/cancel")
def cancel_subscription_admin(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    try:
        if user.stripe_subscription_id:
            stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_...")
            stripe.Subscription.delete(user.stripe_subscription_id)
        user.subscription_status = 'cancelled'
        user.subscription_plan = 'free'
        user.scans_limit = 10
        user.scans_this_month = 0
        db.commit()
        print(json.dumps({"event": "admin_cancel_subscription", "user_id": user_id}))
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/subscriptions/{user_id}/refund")
def refund_last_invoice(
    user_id: int,
    provider: str = "stripe",
    payment_id: str = None,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if provider == "stripe":
        try:
            stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "sk_test_...")
            invoices = stripe.Invoice.list(customer=user.stripe_customer_id, limit=1)
            if not invoices.data:
                raise HTTPException(status_code=404, detail="Nenhuma fatura encontrada")
            inv = invoices.data[0]
            charge_id = getattr(inv, 'charge', None)
            if not charge_id:
                raise HTTPException(status_code=400, detail="Fatura sem charge para reembolso")
            refund = stripe.Refund.create(charge=charge_id)
            print(json.dumps({"event": "admin_refund", "user_id": user_id, "provider": "stripe", "refund_id": refund.id}))
            return {"success": True, "refund_id": refund.id}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    elif provider == "mercadopago":
        try:
            if not payment_id:
                raise HTTPException(status_code=400, detail="payment_id é obrigatório para Mercado Pago")
            import requests
            headers = {
                'Authorization': f"Bearer {os.getenv('MERCADOPAGO_ACCESS_TOKEN', '')}",
                'Content-Type': 'application/json'
            }
            resp = requests.post(f"https://api.mercadopago.com/v1/payments/{payment_id}/refunds", headers=headers, json={})
            if resp.status_code >= 300:
                raise HTTPException(status_code=502, detail="Erro ao solicitar reembolso no Mercado Pago")
            print(json.dumps({"event": "admin_refund", "user_id": user_id, "provider": "mercadopago", "payment_id": payment_id}))
            return {"success": True}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="Provider inválido")

# ==================== BACKUPS ====================
@router.get("/backups")
def list_backups(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    base_dir = Path(__file__).resolve().parents[1]
    backups_dir = base_dir / "backups"
    if not backups_dir.exists():
        return {"total": 0, "backups": []}
    items = []
    for f in sorted(backups_dir.glob("security_scanner-*.db"), key=lambda p: p.stat().st_mtime, reverse=True):
        st = f.stat()
        items.append({
            "filename": f.name,
            "size_bytes": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime).isoformat()
        })
    return {"total": len(items), "backups": items}

@router.post("/backups/create")
def create_backup(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    base_dir = Path(__file__).resolve().parents[1]
    db_path = base_dir / "security_scanner.db"
    backups_dir = base_dir / "backups"
    backups_dir.mkdir(parents=True, exist_ok=True)
    if not db_path.exists():
        raise HTTPException(status_code=404, detail="Banco de dados não encontrado")
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    backup_file = backups_dir / f"security_scanner-{ts}.db"
    shutil.copy2(db_path, backup_file)
    print(json.dumps({"event": "admin_backup_create", "file": str(backup_file)}))
    st = backup_file.stat()
    return {"success": True, "filename": backup_file.name, "size_bytes": st.st_size}

@router.post("/backups/restore")
def restore_backup(
    req: BackupRestoreRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    base_dir = Path(__file__).resolve().parents[1]
    db_path = base_dir / "security_scanner.db"
    backups_dir = base_dir / "backups"
    backup_file = backups_dir / req.filename
    if not backup_file.exists():
        raise HTTPException(status_code=404, detail="Backup não encontrado")
    if db_path.exists():
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        pre_file = backups_dir / f"pre-restore-{ts}.db"
        shutil.copy2(db_path, pre_file)
    shutil.copy2(backup_file, db_path)
    print(json.dumps({"event": "admin_backup_restore", "file": str(backup_file)}))
    return {"success": True, "restored_from": backup_file.name}

# ==================== INTEGRITY CHECK ====================
@router.get("/integrity")
def integrity_check(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    users_total = db.query(User).count()
    scans_total = db.query(Scan).count()
    orphan_scans = db.query(Scan).filter(~db.query(User.id).filter(User.id == Scan.user_id).exists()).count()
    null_emails = db.query(User).filter((User.email == None) | (User.email == "")).count()
    return {
        "users_total": users_total,
        "scans_total": scans_total,
        "orphan_scans": orphan_scans,
        "null_emails": null_emails,
        "ok": orphan_scans == 0 and null_emails == 0
    }

# ==================== EXPORT ====================
@router.get("/export")
def export_data(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
) -> Dict[str, Any]:
    users = db.query(User).all()
    scans = db.query(Scan).all()
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "hashed_password": u.hashed_password,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "subscription_plan": u.subscription_plan,
                "subscription_status": u.subscription_status,
                "subscription_start": u.subscription_start.isoformat() if u.subscription_start else None,
                "subscription_end": u.subscription_end.isoformat() if u.subscription_end else None,
                "scans_this_month": u.scans_this_month,
                "scans_limit": u.scans_limit,
                "stripe_customer_id": u.stripe_customer_id,
                "stripe_subscription_id": u.stripe_subscription_id,
                "mercadopago_customer_id": u.mercadopago_customer_id,
                "is_admin": u.is_admin,
            } for u in users
        ],
        "scans": [
            {
                "id": s.id,
                "user_id": s.user_id,
                "scan_type": s.scan_type,
                "target": s.target,
                "status": s.status,
                "results": s.results,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            } for s in scans
        ]
    }

@router.post("/import")
def import_data(
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    users_data = payload.get("users", []) or []
    scans_data = payload.get("scans", []) or []
    stats = {
        "users_inserted": 0,
        "users_updated": 0,
        "scans_inserted": 0,
        "scans_skipped": 0
    }
    for u in users_data:
        username = u.get("username")
        email = u.get("email")
        existing = None
        if username:
            existing = db.query(User).filter(User.username == username).first()
        if not existing and email:
            existing = db.query(User).filter(User.email == email).first()
        if existing:
            existing.email = email or existing.email
            existing.hashed_password = u.get("hashed_password") or existing.hashed_password
            existing.subscription_plan = u.get("subscription_plan") or existing.subscription_plan
            existing.subscription_status = u.get("subscription_status") or existing.subscription_status
            existing.scans_this_month = u.get("scans_this_month") or existing.scans_this_month
            existing.scans_limit = u.get("scans_limit") or existing.scans_limit
            existing.stripe_customer_id = u.get("stripe_customer_id") or existing.stripe_customer_id
            existing.stripe_subscription_id = u.get("stripe_subscription_id") or existing.stripe_subscription_id
            existing.mercadopago_customer_id = u.get("mercadopago_customer_id") or existing.mercadopago_customer_id
            existing.is_admin = bool(u.get("is_admin", existing.is_admin))
            try:
                ca = u.get("created_at")
                if ca:
                    existing.created_at = datetime.fromisoformat(ca)
            except Exception:
                pass
            try:
                ss = u.get("subscription_start")
                se = u.get("subscription_end")
                if ss:
                    existing.subscription_start = datetime.fromisoformat(ss)
                if se:
                    existing.subscription_end = datetime.fromisoformat(se)
            except Exception:
                pass
            stats["users_updated"] += 1
        else:
            new_u = User(
                username=username,
                email=email,
                hashed_password=u.get("hashed_password") or "",
                subscription_plan=u.get("subscription_plan") or "free",
                subscription_status=u.get("subscription_status") or "active",
                scans_this_month=u.get("scans_this_month") or 0,
                scans_limit=u.get("scans_limit") or 10,
                stripe_customer_id=u.get("stripe_customer_id"),
                stripe_subscription_id=u.get("stripe_subscription_id"),
                mercadopago_customer_id=u.get("mercadopago_customer_id"),
                is_admin=bool(u.get("is_admin", False))
            )
            try:
                ca = u.get("created_at")
                if ca:
                    new_u.created_at = datetime.fromisoformat(ca)
            except Exception:
                pass
            db.add(new_u)
            stats["users_inserted"] += 1
    db.commit()
    for s in scans_data:
        sid = s.get("id")
        existing_scan = None
        if sid is not None:
            existing_scan = db.query(Scan).filter(Scan.id == int(sid)).first()
        if existing_scan:
            stats["scans_skipped"] += 1
            continue
        new_s = Scan(
            id=s.get("id"),
            user_id=s.get("user_id"),
            scan_type=s.get("scan_type"),
            target=s.get("target"),
            status=s.get("status") or "completed",
            results=s.get("results")
        )
        try:
            ca = s.get("created_at")
            if ca:
                new_s.created_at = datetime.fromisoformat(ca)
            ce = s.get("completed_at")
            if ce:
                new_s.completed_at = datetime.fromisoformat(ce)
        except Exception:
            pass
        db.add(new_s)
        stats["scans_inserted"] += 1
    db.commit()
    return {"success": True, "stats": stats}
