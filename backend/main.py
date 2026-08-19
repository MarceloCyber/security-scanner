from fastapi import FastAPI, HTTPException, Request, Response, Body, Depends
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
import psycopg2
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import sys
import time
import json
import logging
from logging.handlers import RotatingFileHandler
from jose import jwt
from datetime import datetime
from pathlib import Path
import shutil
import asyncio
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel, EmailStr, Field
from html import escape

# Adiciona o diretório pai ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import engine, Base
from sqlalchemy import inspect, text
from routes import auth_routes, scan_routes, extended_scan_routes, tools_routes, redteam_routes, blueteam_routes, payment_routes, user_routes, admin_routes, viggio_shield_routes, saas_routes, risk_routes, ai_routes, job_routes, report_routes, integration_routes, ai_action_routes, platform_routes, pipeline_routes, compliance_routes, assurance_routes, sso_routes, security_monitoring_routes
from utils.email_service import email_service
from models.public_stats import PublicStats
from auth import require_enterprise, require_enterprise_developer
from config import settings

email_log_path = Path(__file__).resolve().parent / 'email.log'
email_handler = RotatingFileHandler(email_log_path, maxBytes=10 * 1024 * 1024, backupCount=5)
email_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
email_logger = logging.getLogger('utils.email_service')
if not any(isinstance(handler, RotatingFileHandler) and handler.baseFilename == str(email_log_path) for handler in email_logger.handlers):
    email_logger.addHandler(email_handler)
email_logger.setLevel(logging.INFO)

tables = []
try:
    inspector = inspect(engine)
    tables = inspector.get_table_names()
except Exception:
    tables = []
try:
    Base.metadata.create_all(bind=engine)
except Exception:
    pass

# Compatibilidade com bancos existentes: create_all não adiciona colunas novas.
try:
    from sqlalchemy import inspect as _inspect
    with engine.begin() as _conn:
        _columns = {column["name"] for column in _inspect(engine).get_columns("users")}
        _datetime_type = "TIMESTAMP" if engine.dialect.name == "postgresql" else "DATETIME"
        _security_columns = {
            "trial_started_at": _datetime_type,
            "access_key_hash": "VARCHAR",
            "access_key_last4": "VARCHAR",
            "access_key_issued_at": _datetime_type,
            "access_key_used_at": _datetime_type,
            "access_key_required": "BOOLEAN DEFAULT FALSE",
            "active_session_hash": "VARCHAR",
            "active_session_last_activity": _datetime_type,
            "is_developer": "BOOLEAN DEFAULT FALSE",
        }
        for _name, _type in _security_columns.items():
            if _name not in _columns:
                _conn.execute(text(f"ALTER TABLE users ADD COLUMN {_name} {_type}"))
        if "access_key_required" not in _columns:
            _conn.execute(text("UPDATE users SET access_key_required = FALSE WHERE access_key_required IS NULL"))
        _conn.execute(text(
            "UPDATE users SET access_key_required = TRUE "
            "WHERE access_key_hash IS NOT NULL AND access_key_used_at IS NULL AND COALESCE(is_admin, FALSE) = FALSE"
        ))
        _conn.execute(text(
            "UPDATE users SET access_key_required = FALSE "
            "WHERE access_key_used_at IS NOT NULL"
        ))
except Exception as _migration_error:
    logging.getLogger(__name__).warning("Migração de segurança de usuários não aplicada: %s", _migration_error)

app = FastAPI(
    title="Iron AI Security Platform API",
    description="Plataforma brasileira de postura e segurança contínua",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

UPTIME_START = time.time()


@app.on_event('startup')
async def validate_email_configuration():
    is_valid, message = email_service.validate_config()
    if is_valid:
        email_logger.info('Configuracao SMTP carregada para %s:%s', email_service.smtp_host, email_service.smtp_port)
    else:
        email_logger.error('Configuracao SMTP invalida: %s', message)

# CORS fechado por padrão em produção. Origens adicionais precisam ser explícitas.
_configured_origins = [item.strip() for item in os.getenv("ALLOWED_ORIGINS", "").split(",") if item.strip()]
_frontend_origin = os.getenv("FRONTEND_URL", "http://localhost:8000").rstrip("/")
ALLOWED_ORIGINS = list(dict.fromkeys([_frontend_origin, *_configured_origins]))
if settings.is_development:
    ALLOWED_ORIGINS = list(dict.fromkeys([*ALLOWED_ORIGINS, "http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:3000"]))

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With", "X-Organization-ID", "X-Iron-AI-Key"],
)

from urllib.parse import urlparse
_allowed_hosts = [item.strip() for item in os.getenv("ALLOWED_HOSTS", "").split(",") if item.strip()]
_frontend_host = urlparse(_frontend_origin).hostname
if _frontend_host:
    _allowed_hosts.append(_frontend_host)
if settings.is_development or os.getenv("IRON_AI_LOCAL_LAUNCH", "").lower() == "true":
    _allowed_hosts.extend(["localhost", "127.0.0.1", "0.0.0.0", "testserver"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(dict.fromkeys(_allowed_hosts)) or ["localhost"])

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        forwarded_proto = forwarded_proto.split(",", 1)[0].strip().lower()
        host = request.headers.get("host", "").split(":", 1)[0].lower()
        if forwarded_proto == "http" and host not in {"localhost", "127.0.0.1", "0.0.0.0"}:
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(url=str(https_url), status_code=308)

        response = await call_next(request)
        for header in ("server", "x-powered-by"):
            if header in response.headers:
                del response.headers[header]
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        path = request.url.path
        if path.startswith("/phishing/") or path.startswith("/api/tools/phishing"):
            response.headers["Permissions-Policy"] = "geolocation=(self), microphone=(), camera=(self)"
        else:
            response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if forwarded_proto == "https":
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
            "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'"
        )
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting por plano (requests/min)
PLAN_RATE_LIMITS = {
    "free": 60,
    "starter": 50,
    "professional": 100,
    "enterprise": 500,
}

from database import SessionLocal
from models.user import User
from models.scan import Scan
from models.saas import OrganizationMember
from services.rate_limit import rate_limit_backend

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api"):
        return await call_next(request)

    if path in ("/api/health", "/api/uptime") or path.startswith("/api/payments/"):
        return await call_next(request)

    # Determina chave e plano
    key = None
    plan = "free"
    username = None
    organization_id = "public"
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
            if user:
                membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
                organization_id = membership.organization_id if membership else "none"
            key = f"ratelimit:{organization_id}:{user.id if user else username}:{path}"
        finally:
            db.close()
    else:
        client_ip = request.client.host if request.client else "unknown"
        key = f"ratelimit:public:{client_ip}:{path}"

    limit = PLAN_RATE_LIMITS.get(plan, 10)
    client_host = request.client.host if request.client else None
    if client_host in ("127.0.0.1", "::1", "0.0.0.0"):
        limit = max(limit, 200)
    allowed, remaining, reset_ts = rate_limit_backend.hit(key, limit, 60)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded", "plan": plan},
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(reset_ts),
            },
        )

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(reset_ts)
    return response

# Rotas da API (DEVEM VIR ANTES do mount de arquivos estáticos)
@app.get("/api/health")
def health_check():
    return {"status": "healthy", "message": "Iron AI API is running"}

@app.get("/api/ready")
def readiness_check():
    """Dependency-safe readiness probe without exposing internal details."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        if settings.REDIS_URL and not rate_limit_backend.distributed:
            raise RuntimeError("distributed coordination unavailable")
        if not settings.is_development:
            secret = settings.SECRET_KEY or ""
            if len(secret) < 48 or any(marker in secret.lower() for marker in ("change", "replace", "secret-key", "...")):
                raise RuntimeError("unsafe session secret")
            if engine.dialect.name == "sqlite":
                raise RuntimeError("production database unavailable")
            if not settings.REDIS_URL:
                raise RuntimeError("distributed coordination not configured")
            if not settings.CREDENTIAL_ENCRYPTION_KEY:
                raise RuntimeError("credential vault not configured")
            if not os.getenv("FRONTEND_URL", "").startswith("https://"):
                raise RuntimeError("https frontend not configured")
            if not os.getenv("GROQ_API_KEY", "") and not os.getenv("OPENROUTER_API_KEY", "") and not os.getenv("KIMI_API_KEY", "") and not os.getenv("MOONSHOT_API_KEY", ""):
                raise RuntimeError("AI provider not configured")
            if not os.getenv("STRIPE_SECRET_KEY", "").startswith("sk_"):
                raise RuntimeError("Stripe not configured")
            if not os.getenv("STRIPE_WEBHOOK_SECRET", "").startswith("whsec_"):
                raise RuntimeError("Stripe webhook not configured")
        return {"status": "ready"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not_ready"})

@app.get("/api/public/stats")
def public_stats():
    """Retorna estatísticas públicas exibidas na landing page."""
    db = SessionLocal()
    try:
        total_users = db.query(User).count()
        scans = db.query(Scan).all()
        total_vulnerabilities = 0

        for scan in scans:
            if not scan.results:
                continue
            try:
                results = json.loads(scan.results)
            except (TypeError, ValueError):
                continue

            if isinstance(results.get("total_vulnerabilities"), (int, float)):
                total_vulnerabilities += int(results["total_vulnerabilities"])
            elif isinstance(results.get("summary"), dict) and isinstance(
                results["summary"].get("total_vulnerabilities"), (int, float)
            ):
                total_vulnerabilities += int(results["summary"]["total_vulnerabilities"])
            elif isinstance(results.get("vulnerabilities"), list):
                total_vulnerabilities += len(results["vulnerabilities"])

        accumulated = db.query(PublicStats).filter(PublicStats.id == 1).first()
        if not accumulated:
            accumulated = PublicStats(id=1, users=0, scans=0, vulnerabilities=0)
            db.add(accumulated)

        accumulated.users = max(accumulated.users or 0, total_users)
        accumulated.scans = max(accumulated.scans or 0, len(scans))
        accumulated.vulnerabilities = max(
            accumulated.vulnerabilities or 0, total_vulnerabilities
        )
        db.commit()

        return {
            "users": accumulated.users,
            "scans": accumulated.scans,
            "vulnerabilities": accumulated.vulnerabilities,
        }
    finally:
        db.close()

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

@app.on_event("startup")
async def start_intelligent_automation():
    """Executa continuamente as verificacoes de monitoramento que chegaram ao prazo."""
    async def _automation_loop():
        from routes.viggio_shield_routes import run_automatic_target_check
        from models.monitor import MonitorTarget
        while True:
            db = SessionLocal()
            try:
                now = datetime.utcnow()
                targets = db.query(MonitorTarget).filter(
                    MonitorTarget.is_active == True,
                    MonitorTarget.status == "active"
                ).all()
                for target in targets:
                    interval = max(int(target.check_interval or 300), 60)
                    if not target.last_check or (now - target.last_check).total_seconds() >= interval:
                        try:
                            await run_automatic_target_check(target, db)
                        except Exception as exc:
                            db.rollback()
                            print(f"Erro na automacao do alvo {target.id}: {exc}")
            except Exception as exc:
                # Uma falha temporária do banco não pode encerrar a tarefa de
                # automação silenciosamente. O próximo ciclo tenta novamente.
                db.rollback()
                print(f"Banco indisponível para automacao; nova tentativa no próximo ciclo: {exc}")
            finally:
                db.close()
            await asyncio.sleep(30)
    asyncio.create_task(_automation_loop())

app.include_router(auth_routes.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scan_routes.router, prefix="/api", tags=["Scans"], dependencies=[Depends(require_enterprise_developer)])
app.include_router(extended_scan_routes.router, prefix="/api", tags=["Extended Scans"], dependencies=[Depends(require_enterprise_developer)])
app.include_router(tools_routes.router, prefix="/api/tools", tags=["Security Tools"], dependencies=[Depends(require_enterprise_developer)])
app.include_router(redteam_routes.router, prefix="/api", tags=["Red Team"], dependencies=[Depends(require_enterprise_developer)])
app.include_router(blueteam_routes.router, prefix="/api", tags=["Blue Team"], dependencies=[Depends(require_enterprise_developer)])
app.include_router(payment_routes.router, prefix="/api", tags=["Payments"])
app.include_router(user_routes.router, prefix="/api", tags=["User"])
app.include_router(admin_routes.router, tags=["Admin"])
app.include_router(viggio_shield_routes.router, tags=["Iron AI Shield"], dependencies=[Depends(require_enterprise)])
app.include_router(saas_routes.router, prefix="/api", tags=["SaaS Platform"])
app.include_router(risk_routes.router, prefix="/api", tags=["Risk Intelligence"])
app.include_router(ai_routes.router, prefix="/api", tags=["Iron AI"])
app.include_router(job_routes.router, prefix="/api", tags=["Background Jobs"])
app.include_router(report_routes.router, prefix="/api", tags=["Organization Reports"])
app.include_router(integration_routes.router, prefix="/api", tags=["Integrations"])
app.include_router(ai_action_routes.router, prefix="/api", tags=["AI Actions"])
app.include_router(platform_routes.router, prefix="/api", tags=["Platform Experience"])
app.include_router(pipeline_routes.router, prefix="/api", tags=["Iron AI DevSecOps"])
app.include_router(compliance_routes.router, prefix="/api", tags=["Iron AI Compliance"])
app.include_router(assurance_routes.router, prefix="/api", tags=["Operations and Assurance"])
app.include_router(sso_routes.router, prefix="/api", tags=["Enterprise SSO"])
app.include_router(security_monitoring_routes.router, prefix="/api", tags=["Realtime Security Monitoring"])

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
        <title>Contrato LGPD - Iron AI</title>
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

# Endpoint público de contato (precisa vir antes do mount de estáticos)
class ContactRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    message: str = Field(min_length=10, max_length=5000)
    consent: bool
    plan: str = Field(default="Free", max_length=40)

@app.post("/api/contact")
async def contact_form(payload: ContactRequest):
    try:
        if not payload.consent:
            raise HTTPException(status_code=400, detail="É necessário aceitar o tratamento dos dados para enviar a mensagem.")
        name = payload.name.strip()
        email = str(payload.email).strip()
        message = payload.message.strip()
        plan = payload.plan.strip() or "Free"
        support_email = os.getenv("SUPPORT_EMAIL", "thomaz2523@gmail.com")
        # Evita quebra de cabeçalho caso caracteres de controle cheguem ao endpoint.
        subject_name = " ".join(name.replace("\r", " ").replace("\n", " ").split())
        subject_plan = " ".join(plan.replace("\r", " ").replace("\n", " ").split())
        subject = f"Contato - {subject_name or 'Usuário'} (Plano {subject_plan or 'Free'})"
        safe_name = escape(name)
        safe_email = escape(email)
        safe_message = escape(message).replace("\n", "<br>")
        html = f"""
        <!DOCTYPE html>
        <html><body style='font-family:Arial,sans-serif;'>
        <h2>Nova mensagem de contato</h2>
        <p><strong>Nome:</strong> {safe_name}</p>
        <p><strong>Email:</strong> {safe_email}</p>
        <p><strong>Plano:</strong> {escape(plan)}</p>
        <p><strong>Mensagem:</strong></p>
        <div style='background:#f4f6f8;padding:10px;border-radius:6px;border:1px solid #e1e4e8;color:#2c3e50;'>
        {safe_message}
        </div>
        </body></html>
        """
        text = (
            "Nova mensagem de contato\n\n" +
            f"Nome: {name or 'N/A'}\n" +
            f"Email: {email or 'N/A'}\n" +
            f"Plano: {plan}\n\n" +
            f"Mensagem:\n{message or 'N/A'}\n"
        )
        ok = email_service.send_email(support_email, subject, html, text, reply_to=email)
        if not ok:
            raise HTTPException(status_code=500, detail="Falha ao enviar email")
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao processar contato: {str(e)}")

# Favicon explícito para navegadores e crawlers, antes do mount estático geral.
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    icon_path = Path(__file__).resolve().parents[1] / "frontend" / "favicon.ico"
    return FileResponse(icon_path, media_type="image/x-icon", headers={"Cache-Control": "public, max-age=86400"})

# Serve arquivos estáticos do frontend (DEVE SER O ÚLTIMO)
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
# Páginas de erro customizadas (HTML para não-API)
def _error_page(title: str, message: str, status_code: int = 404):
    base = os.getenv('FRONTEND_URL', 'http://localhost:8000')
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='utf-8' />
        <title>{title}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f6f8; color: #2c3e50; }}
            .wrap {{ max-width: 860px; margin: 60px auto; background: #fff; padding: 28px; border-radius: 10px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }}
            h1 {{ margin: 0 0 12px; font-size: 24px; }}
            p {{ margin: 10px 0; line-height: 1.6; }}
            .actions {{ margin-top: 20px; display: flex; gap: 12px; }}
            .btn {{ display: inline-block; padding: 10px 18px; border-radius: 6px; text-decoration: none; color: #fff; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
            .btn.secondary {{ background: #2c3e50; }}
        </style>
    </head>
    <body>
        <div class='wrap'>
            <h1>{title}</h1>
            <p>{message}</p>
            <div class='actions'>
                <a class='btn' href='{base}/index.html'>Voltar ao Início</a>
                <a class='btn secondary' id='supportLink' href='mailto:thomaz2523@gmail.com'>Suporte</a>
            </div>
        </div>
        <script>
            (function(){{
                try {{
                    var plan = (localStorage.getItem('userPlan') || 'Free');
                    var user = (localStorage.getItem('username') || 'Usuário');
                    var subject = 'Suporte Iron AI - Plano ' + String(plan);
                    var body = 'Usuário: ' + String(user) + '\nPlano: ' + String(plan) + '\nURL: ' + window.location.href + '\nMensagem: ';
                    var mailto = 'mailto:thomaz2523@gmail.com?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);
                    var el = document.getElementById('supportLink');
                    if (el) {{
                        el.setAttribute('href', mailto);
                        el.addEventListener('click', function(ev){{
                            try {{ ev.preventDefault(); window.location.href = mailto; }} catch(e) {{}}
                        }});
                    }}
                }} catch (e) {{}}
            }})();
        </script>
    </body>
    </html>
    """

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith('/api'):
        return JSONResponse(status_code=404, content={'detail': 'Not Found'})
    return HTMLResponse(_error_page('Página não encontrada (404)', 'A URL que você tentou acessar não existe ou foi movida.'), status_code=404)

@app.exception_handler(503)
async def service_unavailable_handler(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith('/api'):
        return JSONResponse(status_code=503, content={'detail': 'Service Unavailable'})
    return HTMLResponse(_error_page('Serviço indisponível (503)', 'Estamos reestabelecendo o serviço. Em breve tudo voltará ao normal.'), status_code=503)
@app.exception_handler(psycopg2.OperationalError)
async def db_op_error_handler(request, exc):
    return JSONResponse(status_code=503, content={"detail": "Database unavailable"})

@app.exception_handler(Exception)
async def unhandled_error_handler(request, exc):
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
