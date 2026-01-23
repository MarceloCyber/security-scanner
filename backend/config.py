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
                        def doh(url_doh):
                            r = requests.get(
                                url_doh,
                                params={"name": host, "type": "A"},
                                headers={"accept": "application/dns-json"},
                                timeout=3,
                            )
                            if r.ok:
                                data = r.json()
                                ans = data.get("Answer") or []
                                for a in ans:
                                    if a.get("type") == 1 and a.get("data"):
                                        return a.get("data")
                                cnames = [a.get("data") for a in ans if a.get("type") == 5 and a.get("data")]
                                for cname in cnames:
                                    r2 = requests.get(
                                        url_doh,
                                        params={"name": cname, "type": "A"},
                                        headers={"accept": "application/dns-json"},
                                        timeout=3,
                                    )
                                    if r2.ok:
                                        d2 = r2.json()
                                        a2 = d2.get("Answer") or []
                                        for a in a2:
                                            if a.get("type") == 1 and a.get("data"):
                                                return a.get("data")
                            return None
                        ip = doh("https://cloudflare-dns.com/dns-query") or doh("https://1.1.1.1/dns-query") or doh("https://dns.google/resolve")
                    except Exception:
                        ip = None
                if ip:
                    os.environ["PGHOSTADDR"] = ip
                    os.environ["PGHOST"] = host
                    try:
                        u = urlparse(url)
                        user = u.username or ""
                        pwd = u.password or ""
                        port = u.port
                        path = u.path or ""
                        q = u.query or ""
                        netloc = f"{user}:{pwd}@{ip}:{port}" if port else f"{user}:{pwd}@{ip}"
                        base = f"{u.scheme}://{netloc}{path}"
                        if q:
                            url = base + "?" + q
                        else:
                            url = base
                    except Exception:
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
