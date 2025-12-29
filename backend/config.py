import os
from dotenv import load_dotenv

load_dotenv()

def _with_sslmode(url: str) -> str:
    if url.startswith("postgresql") and "sslmode=" not in url:
        if "?" in url:
            return url + ("&sslmode=require")
        else:
            return url + ("?sslmode=require")
    return url

def _normalize_db_url(url: str) -> str:
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return _with_sslmode(url)

class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    DATABASE_URL: str = _normalize_db_url(os.getenv("DATABASE_URL", "sqlite:///./security_scanner.db"))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    ALGORITHM: str = "HS256"

settings = Settings()
