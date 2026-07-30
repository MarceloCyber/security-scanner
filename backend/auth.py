from datetime import datetime, timedelta
from typing import Optional
import hashlib
import hmac
import secrets
from jose import JWTError, jwt
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from config import settings
from database import get_db
from models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha corresponde ao hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    """Gera hash da senha com bcrypt, limitando a 72 bytes"""
    # Bcrypt tem limite de 72 bytes, então truncamos a senha se necessário
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

SESSION_IDLE_TIMEOUT = timedelta(hours=1)

def session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()

def create_session_token(username: str, session_id: str):
    return create_access_token(
        {"sub": username, "sid": session_id},
        expires_delta=SESSION_IDLE_TIMEOUT,
    )

def verify_access_key(provided_key: str, stored_hash: str) -> bool:
    if not provided_key or not stored_hash:
        return False
    candidate = hashlib.sha256(provided_key.strip().encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, stored_hash)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        session_id: str = payload.get("sid")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    now = datetime.utcnow()
    if not session_id or not user.active_session_hash or not hmac.compare_digest(
        session_hash(session_id), user.active_session_hash
    ):
        raise HTTPException(status_code=401, detail="Sessão encerrada. Faça login novamente.")
    if not user.active_session_last_activity or now - user.active_session_last_activity > SESSION_IDLE_TIMEOUT:
        user.active_session_hash = None
        user.active_session_last_activity = None
        db.commit()
        raise HTTPException(status_code=401, detail="Sessão expirada por inatividade. Faça login novamente.")

    # Atualiza a atividade sem gravar em excesso em requisições concorrentes.
    if now - user.active_session_last_activity >= timedelta(seconds=30):
        user.active_session_last_activity = now
        db.commit()
    return user
