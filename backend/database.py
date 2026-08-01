from sqlalchemy import create_engine, inspect, text
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

_user_schema_ready = False

def ensure_user_security_schema():
    """Garante as colunas adicionadas ao User antes de qualquer ORM query."""
    global _user_schema_ready
    if _user_schema_ready:
        return

    datetime_type = "TIMESTAMP" if engine.dialect.name == "postgresql" else "DATETIME"
    columns_to_add = {
        "trial_started_at": datetime_type,
        "access_key_hash": "VARCHAR",
        "access_key_last4": "VARCHAR",
        "access_key_issued_at": datetime_type,
        "access_key_used_at": datetime_type,
        "access_key_required": "BOOLEAN DEFAULT FALSE",
        "active_session_hash": "VARCHAR",
        "active_session_last_activity": datetime_type,
    }
    try:
        with engine.begin() as connection:
            existing = {column["name"] for column in inspect(engine).get_columns("users")}
            for name, column_type in columns_to_add.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE users ADD COLUMN {name} {column_type}"))
            _user_schema_ready = True
    except Exception:
        # Não mascara a exceção real de conexão/schema; a rota retornará o erro
        # apropriado e uma nova requisição tentará novamente.
        raise

def get_db():
    db = SessionLocal()
    try:
        ensure_user_security_schema()
        yield db
    finally:
        db.close()
