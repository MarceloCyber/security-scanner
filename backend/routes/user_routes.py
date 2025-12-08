"""
Rotas relacionadas ao usuário e assinatura
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models.user import User
from auth import get_current_user
from middleware.subscription import check_subscription_status, get_plan_info

router = APIRouter(prefix="/user", tags=["user"])


@router.get("/subscription-info")
async def get_user_subscription_info(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna informações completas da assinatura do usuário
    """
    status = check_subscription_status(current_user)
    plan_info = get_plan_info(current_user.subscription_plan)
    
    return {
        "username": current_user.username,
        "subscription_plan": current_user.subscription_plan,
        "subscription_status": current_user.subscription_status,
        "scans_this_month": current_user.scans_this_month or 0,
        "scans_limit": current_user.scans_limit or 0,
        "subscription_start": current_user.subscription_start.isoformat() if current_user.subscription_start else None,
        "subscription_end": current_user.subscription_end.isoformat() if current_user.subscription_end else None,
        "is_trial": current_user.is_trial,
        "is_admin": current_user.is_admin or False,
        "status": status,
        "plan_info": plan_info
    }


@router.get("/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Retorna informações do usuário atual
    """
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "subscription_plan": current_user.subscription_plan,
        "subscription_status": current_user.subscription_status,
        "scans_used": current_user.scans_this_month,
        "scans_limit": current_user.scans_limit
    }
