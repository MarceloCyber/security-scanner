from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from config import settings

def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")

def _make_engine(url: str):
    try:
        return create_engine(
            url,
            connect_args={"check_same_thread": False} if _is_sqlite(url) else {},
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
        )
    except Exception:
        if _is_sqlite(url) or "<" in url or ">" in url:
            return create_engine(
                "sqlite:///./security_scanner.db",
                connect_args={"check_same_thread": False},
                pool_pre_ping=True,
                pool_size=5,
                max_overflow=10,
                pool_timeout=30,
            )
        raise

engine = _make_engine(settings.DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
