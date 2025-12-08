from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import sys

# Adiciona o diretório pai ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import engine, Base
from routes import auth_routes, scan_routes, extended_scan_routes, tools_routes, redteam_routes, blueteam_routes, payment_routes, user_routes, admin_routes

# Cria tabelas no banco de dados
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Security Scanner API",
    description="API para análise de segurança de código e APIs baseada no OWASP Top 10",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configuração CORS para produção
ALLOWED_ORIGINS = [
    "https://*.vercel.app",
    "http://localhost:8000",
    "http://localhost:3000",
    os.getenv("FRONTEND_URL", "http://localhost:8000")
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Liberado para desenvolvimento, restringir em produção
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rotas da API (DEVEM VIR ANTES do mount de arquivos estáticos)
@app.get("/api/health")
def health_check():
    return {"status": "healthy", "message": "Security Scanner API is running"}

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

# Serve arquivos estáticos do frontend (DEVE SER O ÚLTIMO)
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
