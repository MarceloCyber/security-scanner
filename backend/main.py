from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import sys
import time
from jose import jwt
from datetime import datetime
from pathlib import Path
import shutil
import asyncio
from starlette.middleware.base import BaseHTTPMiddleware

# Adiciona o diretório pai ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import engine, Base
from sqlalchemy import inspect, text
from routes import auth_routes, scan_routes, extended_scan_routes, tools_routes, redteam_routes, blueteam_routes, payment_routes, user_routes, admin_routes
from utils.email_service import email_service

inspector = inspect(engine)
if not inspector.get_table_names():
    Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Iron Net API",
    description="API para análise de segurança de código e APIs baseada no OWASP Top 10",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

UPTIME_START = time.time()

# Configuração CORS para produção
ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://localhost:3000",
    os.getenv("FRONTEND_URL", "http://localhost:8000")
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"https://(.+\\.vercel\\.app|.+\\.onrender\\.com)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        path = request.url.path
        if path.startswith("/phishing/") or path.startswith("/api/tools/phishing"):
            response.headers["Permissions-Policy"] = "geolocation=(self), microphone=(), camera=(self)"
        else:
            response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdnjs.cloudflare.com data:; "
            "connect-src 'self' https://api.mercadopago.com https://api.stripe.com https://ipapi.co https://ip-api.com https://nominatim.openstreetmap.org https://api.ipify.org "
            f"{os.getenv('FRONTEND_URL', 'http://localhost:8000')} http://localhost:8000; "
            "frame-src 'self' https://www.openstreetmap.org https://www.google.com https://maps.google.com; "
            "frame-ancestors 'none'; base-uri 'self'"
        )
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting por plano (requests/min)
PLAN_RATE_LIMITS = {
    "free": 10,
    "starter": 50,
    "professional": 100,
    "enterprise": 500,
}

# Store em memória (mínimo viável). Em produção use Redis.
RATE_LIMIT_CACHE = {}

from database import SessionLocal
from config import settings
from models.user import User

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api"):
        return await call_next(request)

    # Determina chave e plano
    key = None
    plan = "free"
    username = None
    token = request.headers.get("authorization", "")
    if token.lower().startswith("bearer "):
        try:
            payload = jwt.decode(token.split(" ", 1)[1], settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username = payload.get("sub")
        except Exception:
            username = None
    
    if username:
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            if user and user.subscription_plan:
                plan = user.subscription_plan
            key = f"user:{user.id}" if user else f"user:{username}"
        finally:
            db.close()
    else:
        client_ip = request.client.host if request.client else "unknown"
        key = f"ip:{client_ip}"

    limit = PLAN_RATE_LIMITS.get(plan, 10)
    client_host = request.client.host if request.client else None
    if client_host in ("127.0.0.1", "::1", "0.0.0.0"):
        limit = max(limit, 200)
    now = int(time.time())
    window = now // 60
    entry = RATE_LIMIT_CACHE.get(key)
    if not entry or entry.get("window") != window:
        entry = {"window": window, "count": 0}
        RATE_LIMIT_CACHE[key] = entry

    if entry["count"] >= limit:
        reset_ts = (window + 1) * 60
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded", "plan": plan},
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_ts),
            },
        )

    entry["count"] += 1
    response = await call_next(request)
    remaining = max(limit - entry["count"], 0)
    reset_ts = (window + 1) * 60
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(reset_ts)
    return response

# Rotas da API (DEVEM VIR ANTES do mount de arquivos estáticos)
@app.get("/api/health")
def health_check():
    return {"status": "healthy", "message": "Iron Net API is running"}

@app.get("/api/uptime")
def uptime():
    return {"uptime_seconds": int(time.time() - UPTIME_START), "started_at": datetime.utcfromtimestamp(UPTIME_START).isoformat() + "Z"}

@app.on_event("startup")
async def schedule_backups():
    from config import settings
    if settings.DATABASE_URL.startswith("sqlite"):
        async def _task():
            base_dir = Path(__file__).resolve().parents[1]
            db_path = base_dir / "security_scanner.db"
            backups_dir = base_dir / "backups"
            backups_dir.mkdir(parents=True, exist_ok=True)
            while True:
                try:
                    if db_path.exists():
                        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
                        backup_file = backups_dir / f"security_scanner-{ts}.db"
                        shutil.copy2(db_path, backup_file)
                    await asyncio.sleep(21600)
                except Exception:
                    await asyncio.sleep(21600)
        asyncio.create_task(_task())

@app.on_event("startup")
async def align_sequences():
    if not settings.DATABASE_URL.startswith("sqlite"):
        try:
            with engine.begin() as conn:
                conn.execute(text("SELECT setval(pg_get_serial_sequence('scans','id'), COALESCE((SELECT MAX(id) FROM scans), 0));"))
        except Exception:
            pass

app.include_router(auth_routes.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan_routes.router, prefix="/api", tags=["Scans"])
app.include_router(extended_scan_routes.router, prefix="/api", tags=["Extended Scans"])
app.include_router(tools_routes.router, prefix="/api/tools", tags=["Security Tools"])
app.include_router(redteam_routes.router, prefix="/api", tags=["Red Team"])
app.include_router(blueteam_routes.router, prefix="/api", tags=["Blue Team"])
app.include_router(payment_routes.router, prefix="/api", tags=["Payments"])
app.include_router(user_routes.router, prefix="/api", tags=["User"])
app.include_router(admin_routes.router, tags=["Admin"])

# Rota de redirecionamento curto (sem /api para links públicos)
@app.get("/p/{short_id}")
async def redirect_short_url(short_id: str):
    """Short URL redirect to phishing page"""
    import json
    from datetime import datetime
    from fastapi.responses import RedirectResponse
    
    pages_meta_file = "/tmp/phishing_pages_meta.json"
    if os.path.exists(pages_meta_file):
        with open(pages_meta_file, 'r') as f:
            pages_meta = json.load(f)
        
        for meta in pages_meta:
            if meta['page_id'][:8] == short_id:
                # Check expiration
                if meta.get('expires_at'):
                    expiration = datetime.fromisoformat(meta['expires_at'])
                    if datetime.now() > expiration:
                        raise HTTPException(status_code=410, detail="This link has expired")
                
                # Redirect to full phishing page
                return RedirectResponse(url=f"/phishing/{meta['filename']}", status_code=302)
    
    raise HTTPException(status_code=404, detail="Link not found")

# Rota especial para servir páginas de phishing (sem /api para facilitar acesso)
# IMPORTANTE: Esta rota deve vir DEPOIS dos includes para não sobrescrever /api/tools/phishing/captures
@app.get("/phishing/{filename:path}")
async def serve_phishing_page_direct(filename: str):
    """Serve phishing pages directly without /api prefix - only HTML files"""
    import json
    from datetime import datetime
    
    # Garante que só arquivos .html são servidos por esta rota
    if not filename.endswith('.html'):
        raise HTTPException(status_code=404, detail="Page not found")
    
    # Check if page has expired
    pages_meta_file = "/tmp/phishing_pages_meta.json"
    if os.path.exists(pages_meta_file):
        with open(pages_meta_file, 'r') as f:
            pages_meta = json.load(f)
        
        for page in pages_meta:
            if page['filename'] == filename:
                if page.get('expires_at'):
                    expiration = datetime.fromisoformat(page['expires_at'])
                    if datetime.now() > expiration:
                        # Page expired - delete files
                        filepath = os.path.join("/tmp/phishing_pages", filename)
                        if os.path.exists(filepath):
                            os.remove(filepath)
                        
                        # Remove from metadata
                        pages_meta = [p for p in pages_meta if p['filename'] != filename]
                        with open(pages_meta_file, 'w') as f:
                            json.dump(pages_meta, f, indent=2)
                        
                        raise HTTPException(status_code=410, detail="This phishing page has expired")
                break
    
    filepath = os.path.join("/tmp/phishing_pages", filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Page not found")
    return FileResponse(filepath, media_type="text/html")

# Página pública do contrato LGPD
@app.get("/contrato/lgpd", response_class=HTMLResponse)
async def contract_lgpd(plan: str = "Free"):
    html_content, _ = email_service.generate_lgpd_contract_content(plan)
    base = os.getenv('FRONTEND_URL', 'http://localhost:8000')
    page = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8" />
        <title>Contrato LGPD - Iron Net</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f4f6f8; }}
            .container {{ max-width: 860px; margin: 40px auto; background: #fff; padding: 24px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.06); }}
            .actions {{ display: flex; gap: 12px; margin-bottom: 16px; }}
            .btn {{ display: inline-block; padding: 10px 18px; border-radius: 6px; text-decoration: none; color: #fff; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
            .btn.secondary {{ background: #2c3e50; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="actions">
                <a class="btn" href="{base}/contrato/lgpd.pdf?plan={plan}">Baixar PDF</a>
                <a class="btn secondary" href="{base}/index.html">Voltar à Plataforma</a>
            </div>
            {html_content}
            <div class="actions" style="margin-top:24px;">
                <a class="btn" href="{base}/contrato/lgpd.pdf?plan={plan}">Baixar PDF</a>
            </div>
        </div>
    </body>
    </html>
    """
    return page

@app.get("/contrato/lgpd.pdf")
async def contract_lgpd_pdf(plan: str = "Free"):
    pdf_bytes = email_service.generate_lgpd_contract_pdf(plan)
    return Response(content=pdf_bytes, media_type="application/pdf")

# Serve arquivos estáticos do frontend (DEVE SER O ÚLTIMO)
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
