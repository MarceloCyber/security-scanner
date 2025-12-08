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
    subscription_plan = Column(String, default="free")  # free, starter, professional, enterprise
    subscription_status = Column(String, default="active")  # active, cancelled, expired
    subscription_start = Column(DateTime, nullable=True)
    subscription_end = Column(DateTime, nullable=True)
    scans_this_month = Column(Integer, default=0)
    scans_limit = Column(Integer, default=10)  # 10 for free, 100 for starter, -1 for unlimited
    stripe_customer_id = Column(String, nullable=True)
    stripe_subscription_id = Column(String, nullable=True)
    mercadopago_customer_id = Column(String, nullable=True)
    is_trial = Column(Boolean, default=False)
    
    # Admin field
    is_admin = Column(Boolean, default=False)
    
    # Password reset fields
    reset_token = Column(String, nullable=True)
    reset_token_expires = Column(DateTime, nullable=True)
