from sqlalchemy import Column, Integer
from database import Base


class PublicStats(Base):
    """Contadores acumulados exibidos publicamente na landing page."""
    __tablename__ = "public_stats"

    id = Column(Integer, primary_key=True)
    users = Column(Integer, nullable=False, default=0)
    scans = Column(Integer, nullable=False, default=0)
    vulnerabilities = Column(Integer, nullable=False, default=0)
