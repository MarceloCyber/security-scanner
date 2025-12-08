from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from datetime import datetime
from database import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    scan_type = Column(String)  # 'code' or 'api'
    target = Column(String)  # URL or file path
    status = Column(String, default="pending")  # pending, running, completed, failed
    results = Column(Text)  # JSON string of results
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
