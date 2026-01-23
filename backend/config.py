import os
import socket
import json
from urllib.parse import urlparse
from dotenv import load_dotenv
import requests

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
    url = _with_sslmode(url)
    if url.startswith("postgresql") and "connect_timeout=" not in url:
        if "?" in url:
            url = url + "&connect_timeout=5"
        else:
            url = url + "?connect_timeout=5"
    try:
        if url.startswith("postgresql") and "hostaddr=" not in url:
            p = urlparse(url)
            host = p.hostname or ""
            if host:
                ip = None
                try:
                    infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
                    if infos:
                        ip = infos[0][4][0]
                except Exception:
                    ip = None
                if not ip:
                    try:
                        r = requests.get(
                            "https://cloudflare-dns.com/dns-query",
                            params={"name": host, "type": "A"},
                            headers={"accept": "application/dns-json"},
                            timeout=3,
                        )
                        if r.ok:
                            data = r.json()
                            ans = data.get("Answer") or []
                            for a in ans:
                                if a.get("type") == 1 and a.get("data"):
                                    ip = a.get("data")
                                    break
                    except Exception:
                        ip = None
                if ip:
                    os.environ["PGHOSTADDR"] = ip
                    os.environ["PGHOST"] = host
                    if "?" in url:
                        url = url + ("&hostaddr=" + ip)
                    else:
                        url = url + ("?hostaddr=" + ip)
    except Exception:
        pass
    return url

class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    DATABASE_URL: str = _normalize_db_url(os.getenv("DATABASE_URL", "sqlite:///./security_scanner.db"))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    ALGORITHM: str = "HS256"

settings = Settings()
