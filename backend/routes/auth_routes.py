from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Form, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
import logging
import os
from database import get_db
from models.user import User
from auth import get_password_hash, verify_password, create_session_token, get_current_user, session_hash, verify_access_key, SESSION_IDLE_TIMEOUT
from config import settings
from pydantic import BaseModel, EmailStr
from utils.email_service import email_service
import secrets
import hmac
from datetime import datetime
from jose import jwt

router = APIRouter()
logger = logging.getLogger(__name__)


def send_email_in_background(email_method, recipient: str, *args) -> None:
    try:
        if not email_method(recipient, *args):
            logger.error("Email nao enviado para %s pelo metodo %s", recipient, email_method.__name__)
    except Exception:
        logger.exception("Falha inesperada ao enviar email para %s pelo metodo %s", recipient, email_method.__name__)

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str = None
    selected_plan: str = 'starter'

class Token(BaseModel):
    access_token: str
    token_type: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

@router.post("/register", response_model=dict)
def register(user: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        # Verifica se usuário já existe
        db_user = db.query(User).filter(User.username == user.username).first()
        if db_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Username already registered"
            )
        
        db_email = db.query(User).filter(User.email == user.email).first()
        if db_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Email already registered"
            )
        
        # Não existe mais cadastro no plano Free; a assinatura é ativada pelo Stripe.
        hashed_password = get_password_hash(user.password)
        new_user = User(
            username=user.username,
            email=user.email,
            hashed_password=hashed_password,
            subscription_plan='starter',
            subscription_status='pending',
            scans_limit=100,
            scans_this_month=0
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Criar token de acesso automático
        session_id = secrets.token_urlsafe(32)
        new_user.active_session_hash = session_hash(session_id)
        new_user.active_session_last_activity = datetime.utcnow()
        db.commit()
        access_token = create_session_token(new_user.username, session_id)
        
        # Enviar email de boas-vindas em background
        background_tasks.add_task(
            send_email_in_background,
            email_service.send_welcome_email,
            new_user.email,
            new_user.username,
            'starter'
        )
        
        return {
            "message": "User created successfully", 
            "username": new_user.username,
            "email": new_user.email,
            "access_token": access_token,
            "token_type": "bearer",
            "selected_plan": user.selected_plan
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating user: {str(e)}"
        )

@router.post("/token", response_model=Token)
def login(
    username: str = Form(...),
    password: str = Form(...),
    access_key: str = Form(default=""),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.access_key_hash and not user.access_key_used_at:
        if not verify_access_key(access_key, user.access_key_hash):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Informe a chave de acesso enviada para o seu email no primeiro login.",
            )

    now = datetime.utcnow()
    if user.active_session_hash and user.active_session_last_activity and now - user.active_session_last_activity <= SESSION_IDLE_TIMEOUT:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Esta conta já está conectada em outro dispositivo. Encerre a sessão anterior antes de entrar.",
        )

    # O prazo de 10 dias começa no primeiro login após uma assinatura paga.
    if user.is_trial and user.subscription_plan in ('starter', 'professional') and not user.trial_started_at:
        user.trial_started_at = datetime.utcnow()
    session_id = secrets.token_urlsafe(32)
    user.active_session_hash = session_hash(session_id)
    user.active_session_last_activity = now
    if user.access_key_hash and not user.access_key_used_at:
        user.access_key_used_at = now
    db.commit()
    access_token = create_session_token(user.username, session_id)
    
    return {"access_token": access_token, "token_type": "bearer", "access_key_required": False}

@router.post("/refresh", response_model=Token)
def refresh_token(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = auth_header.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], options={"verify_exp": False})
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        session_id = payload.get("sid")
        if not session_id or not user.active_session_hash or not hmac.compare_digest(session_hash(session_id), user.active_session_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessão encerrada. Faça login novamente.")
        if not user.active_session_last_activity or datetime.utcnow() - user.active_session_last_activity > SESSION_IDLE_TIMEOUT:
            user.active_session_hash = None
            user.active_session_last_activity = None
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessão expirada por inatividade. Faça login novamente.")
        user.active_session_last_activity = datetime.utcnow()
        db.commit()
        new_token = create_session_token(user.username, session_id)
        return {"access_token": new_token, "token_type": "bearer"}
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@router.post("/logout")
def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current_user.active_session_hash = None
    current_user.active_session_last_activity = None
    db.commit()
    return {"success": True}

@router.post("/forgot-password", response_model=dict)
def forgot_password(request: ForgotPasswordRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Endpoint para solicitar reset de senha via email
    """
    try:
        # Busca usuário por email
        user = db.query(User).filter(User.email == request.email).first()
        
        # Por segurança, sempre retornar sucesso mesmo se o email não existir
        # Isso evita que atacantes descubram quais emails estão cadastrados
        if not user:
            return {"message": "Se o email existir no sistema, você receberá instruções para resetar sua senha"}
        
        # Gera token único
        reset_token = secrets.token_urlsafe(32)
        
        # Salva token no usuário (precisa adicionar campos no modelo)
        user.reset_token = reset_token
        user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
        db.commit()
        
        # Envia email com link de reset (admin e usuário comum)
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8000").rstrip("/")
        if user.is_admin:
            reset_link = f"{frontend_url}/admin-reset-password.html?token={reset_token}"
            background_tasks.add_task(
                send_email_in_background,
                email_service.send_password_reset_email,
                user.email,
                user.username,
                reset_link
            )
        else:
            reset_link = f"{frontend_url}/reset-password.html?token={reset_token}"
            background_tasks.add_task(
                send_email_in_background,
                email_service.send_user_password_reset_email,
                user.email,
                user.username,
                reset_link
            )
        
        return {"message": "Se o email existir no sistema, você receberá instruções para resetar sua senha"}
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao processar solicitação: {str(e)}"
        )

@router.post("/reset-password", response_model=dict)
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Endpoint para resetar senha com token
    """
    try:
        # Busca usuário pelo token
        user = db.query(User).filter(User.reset_token == request.token).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token inválido ou expirado"
            )
        
        # Verifica se token não expirou
        if user.reset_token_expires < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token expirado. Solicite um novo reset de senha"
            )
        
        # Atualiza senha
        user.hashed_password = get_password_hash(request.new_password)
        user.reset_token = None
        user.reset_token_expires = None
        db.commit()
        
        return {"message": "Senha alterada com sucesso! Você já pode fazer login com a nova senha"}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao resetar senha: {str(e)}"
        )
