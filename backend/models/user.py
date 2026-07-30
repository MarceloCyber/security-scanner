from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Subscription fields
    subscription_plan = Column(String, default="starter")  # starter, professional, enterprise
    subscription_status = Column(String, default="active")  # active, cancelled, expired
    subscription_start = Column(DateTime, nullable=True)
    subscription_end = Column(DateTime, nullable=True)
    scans_this_month = Column(Integer, default=0)
    scans_limit = Column(Integer, default=100)  # 100 for starter, -1 for unlimited
    stripe_customer_id = Column(String, nullable=True)
    stripe_subscription_id = Column(String, nullable=True)
    mercadopago_customer_id = Column(String, nullable=True)
    is_trial = Column(Boolean, default=False)
    # O trial começa no primeiro login após a assinatura ser confirmada.
    trial_started_at = Column(DateTime, nullable=True)

    # Chave de acesso: somente o hash é persistido; o segredo é enviado uma vez por email.
    access_key_hash = Column(String, nullable=True, unique=True)
    access_key_last4 = Column(String, nullable=True)
    access_key_issued_at = Column(DateTime, nullable=True)
    access_key_used_at = Column(DateTime, nullable=True)

    # Sessão única por usuário e expiração por inatividade.
    active_session_hash = Column(String, nullable=True)
    active_session_last_activity = Column(DateTime, nullable=True)
    
    # Admin field
    is_admin = Column(Boolean, default=False)
    
    # Password reset fields
    reset_token = Column(String, nullable=True)
    reset_token_expires = Column(DateTime, nullable=True)
