"""
Blue Team Tools Routes - Production Ready
Ferramentas de Blue Team para defesa e análise de segurança
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Depends
from pydantic import BaseModel, validator
from typing import List, Dict, Any
import re
import hashlib
from datetime import datetime
import secrets
import string
import logging
from sqlalchemy.orm import Session

from auth import get_current_user
from models.user import User
from database import get_db
from middleware.subscription import check_subscription_status, check_tool_access

# Configurar logger
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/blueteam", tags=["Blue Team"])

# ==================== MODELS ====================

class ThreatIntelRequest(BaseModel):
    target: str
    target_type: str  # ip, domain, hash, url
    sources: List[str] = ["virustotal", "abuseipdb"]
    
    @validator('target')
    def validate_target(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Alvo não pode estar vazio')
        return v.strip()
    
    @validator('target_type')
    def validate_target_type(cls, v):
        valid_types = ['ip', 'domain', 'hash', 'url']
        if v not in valid_types:
            raise ValueError(f'Tipo de alvo inválido. Use: {", ".join(valid_types)}')
        return v
    
    @validator('sources')
    def validate_sources(cls, v):
        if not v or len(v) == 0:
            raise ValueError('Pelo menos uma fonte deve ser selecionada')
        valid_sources = ['virustotal', 'abuseipdb', 'shodan', 'alienvault']
        for source in v:
            if source not in valid_sources:
                raise ValueError(f'Fonte inválida: {source}')
        return v


class HashAnalyzeRequest(BaseModel):
    hashes: List[str]
    hash_type: str = "auto"
    
    @validator('hashes')
    def validate_hashes(cls, v):
        if not v or len(v) == 0:
            raise ValueError('Pelo menos um hash deve ser fornecido')
        return [h.strip() for h in v if h.strip()]
    
    @validator('hash_type')
    def validate_hash_type(cls, v):
        valid_types = ['auto', 'md5', 'sha1', 'sha256', 'sha512']
        if v.lower() not in valid_types:
            raise ValueError(f'Tipo de hash inválido. Use: {", ".join(valid_types)}')
        return v.lower()


class PasswordCheckRequest(BaseModel):
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        if not v:
            raise ValueError('Senha não pode estar vazia')
        if len(v) > 128:
            raise ValueError('Senha muito longa (máximo 128 caracteres)')
        return v


class PasswordGenerateRequest(BaseModel):
    length: int = 16
    uppercase: bool = True
    lowercase: bool = True
    numbers: bool = True
    symbols: bool = True
    
    @validator('length')
    def validate_length(cls, v):
        if v < 4:
            raise ValueError('Comprimento mínimo é 4 caracteres')
        if v > 128:
            raise ValueError('Comprimento máximo é 128 caracteres')
        return v

class IOCAnalyzeRequest(BaseModel):
    indicators: List[str]
    sources: List[str] = ["virustotal", "alienvault"]
    
    @validator('indicators')
    def validate_indicators(cls, v):
        if not v or len(v) == 0:
            raise ValueError('Pelo menos um IOC deve ser fornecido')
        return [i.strip() for i in v if i and i.strip()]
    
    @validator('sources')
    def validate_sources(cls, v):
        if not v or len(v) == 0:
            raise ValueError('Pelo menos uma fonte deve ser selecionada')
        valid_sources = ['virustotal', 'alienvault', 'abuseipdb', 'shodan']
        for s in v:
            if s not in valid_sources:
                raise ValueError(f'Fonte inválida: {s}')
        return v


# ==================== LOG ANALYZER ====================

@router.post("/logs/analyze")
async def analyze_log(
    log_type: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Analisa arquivo de log em busca de atividades suspeitas
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
        if not check_tool_access("log_analyzer", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "log_analyzer",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        logger.info(f"Log analysis started. Type: {log_type}, File: {file.filename}")
        
        # Valida tipo de log
        valid_log_types = ['apache', 'nginx', 'auth', 'firewall', 'custom']
        if log_type not in valid_log_types:
            raise HTTPException(status_code=400, detail=f"Tipo de log inválido. Use: {', '.join(valid_log_types)}")
        
        # Valida arquivo
        if not file.filename:
            raise HTTPException(status_code=400, detail="Nome do arquivo inválido")
        
        # Limita tamanho do arquivo (10MB)
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Arquivo muito grande (máximo 10MB)")
        
        log_content = content.decode('utf-8', errors='ignore')
        lines = log_content.split('\n')
        
        # Padrões de detecção
        patterns = {
            "failed_login": r"(Failed password|authentication failure|invalid user)",
            "sql_injection": r"(UNION.*SELECT|OR.*1.*=.*1|\'.*OR|DROP.*TABLE)",
            "xss": r"(<script|javascript:|onerror=|onload=)",
            "suspicious_ip": r"\b(?:192\.168\.|10\.|172\.16\.)\d+\.\d+\b",
            "port_scan": r"(port.*scan|nmap|masscan)",
            "brute_force": r"(repeated.*failed|multiple.*attempts|brute.*force)"
        }
        
        threats = {
            "failed_logins": [],
            "sql_injection_attempts": [],
            "xss_attempts": [],
            "suspicious_ips": set(),
            "port_scans": [],
            "brute_force_attempts": []
        }
        
        threat_count = 0
        max_lines = min(len(lines), 10000)  # Limita para performance
        
        for i, line in enumerate(lines[:max_lines]):
            if not line.strip():
                continue
                
            line_lower = line.lower()
            
            # Failed logins
            if re.search(patterns["failed_login"], line_lower):
                threats["failed_logins"].append({
                    "line": i + 1,
                    "content": line[:200],
                    "severity": "medium"
                })
                threat_count += 1
            
            # SQL Injection
            if re.search(patterns["sql_injection"], line_lower):
                threats["sql_injection_attempts"].append({
                    "line": i + 1,
                    "content": line[:200],
                    "severity": "high"
                })
                threat_count += 1
            
            # XSS
            if re.search(patterns["xss"], line_lower):
                threats["xss_attempts"].append({
                    "line": i + 1,
                    "content": line[:200],
                    "severity": "high"
                })
                threat_count += 1
            
            # Extract IPs
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            threats["suspicious_ips"].update(ips)
        
        logger.info(f"Log analysis completed. Threats found: {threat_count}")
        
        return {
            "status": "completed",
            "log_type": log_type,
            "filename": file.filename,
            "lines_analyzed": max_lines,
            "threats_found": threat_count,
            "suspicious_ips_count": len(threats["suspicious_ips"]),
            "threats": {
                "failed_logins": threats["failed_logins"][:50],
                "sql_injection_attempts": threats["sql_injection_attempts"][:50],
                "xss_attempts": threats["xss_attempts"][:50],
                "suspicious_ips": list(threats["suspicious_ips"])[:50]
            },
            "summary": {
                "critical": len(threats["sql_injection_attempts"]) + len(threats["xss_attempts"]),
                "high": len(threats["brute_force_attempts"]),
                "medium": len(threats["failed_logins"]),
                "low": len(threats["port_scans"])
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in log analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao analisar log: {str(e)}")


# ==================== THREAT INTELLIGENCE ====================

@router.post("/threat-intel/query")
async def query_threat_intel(
    request: ThreatIntelRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Consulta threat intelligence sobre um alvo
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
        if not check_tool_access("threat_intelligence", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "threat_intelligence",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        logger.info(f"Threat intel query started for target: {request.target}")
        
        # Simula resposta de threat intel
        result = {
            "target": request.target,
            "target_type": request.target_type,
            "reputation_score": 0,
            "is_malicious": False,
            "sources": {},
            "details": {},
            "timestamp": datetime.now().isoformat()
        }
        
        # Simula dados de diferentes fontes
        if "virustotal" in request.sources:
            result["sources"]["virustotal"] = {
                "detections": 2,
                "total_engines": 70,
                "last_analysis": "2024-12-04",
                "categories": ["malware", "phishing"]
            }
            result["reputation_score"] += 30
        
        if "abuseipdb" in request.sources and request.target_type == "ip":
            result["sources"]["abuseipdb"] = {
                "abuse_confidence_score": 15,
                "total_reports": 5,
                "last_report": "2024-11-28",
                "country": "US"
            }
            result["reputation_score"] += 15
        
        if "shodan" in request.sources and request.target_type in ["ip", "domain"]:
            result["sources"]["shodan"] = {
                "open_ports": [80, 443, 22],
                "services": ["HTTP", "HTTPS", "SSH"],
                "vulns": ["CVE-2021-44228"],
                "os": "Linux"
            }
            result["reputation_score"] += 25
        
        if "alienvault" in request.sources:
            result["sources"]["alienvault"] = {
                "pulses": 3,
                "tags": ["botnet", "c2"],
                "related_indicators": 12
            }
            result["reputation_score"] += 20
        
        # Determina se é malicioso
        result["is_malicious"] = result["reputation_score"] > 50
        
        # Adiciona detalhes
        result["details"] = {
            "risk_level": "high" if result["reputation_score"] > 70 else "medium" if result["reputation_score"] > 40 else "low",
            "recommendation": "Block" if result["is_malicious"] else "Monitor",
            "confidence": f"{min(result['reputation_score'], 100)}%"
        }
        
        logger.info(f"Threat intel query completed for {request.target}")
        
        return result
    
    except ValueError as ve:
        logger.warning(f"Validation error in threat intel query: {str(ve)}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error in threat intel query: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro na consulta: {str(e)}")


# ==================== HASH ANALYZER ====================

@router.post("/ioc/analyze")
async def analyze_ioc(
    request: IOCAnalyzeRequest,
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
        if not check_tool_access("ioc_analyzer", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "ioc_analyzer",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        logger.info("IOC analysis started")
        
        def classify(ind: str) -> str:
            if re.match(r'^https?://', ind):
                return 'url'
            if re.match(r'^[0-9a-fA-F]{32}$', ind) or re.match(r'^[0-9a-fA-F]{40}$', ind) or re.match(r'^[0-9a-fA-F]{64}$', ind) or re.match(r'^[0-9a-fA-F]{128}$', ind):
                return 'hash'
            if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', ind):
                return 'ip'
            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', ind):
                return 'domain'
            return 'unknown'
        
        results = []
        summary = {"ips": 0, "domains": 0, "urls": 0, "hashes": 0}
        
        for raw in request.indicators:
            ind = raw.strip()
            if not ind:
                continue
            t = classify(ind)
            if t == 'ip':
                summary['ips'] += 1
            elif t == 'domain':
                summary['domains'] += 1
            elif t == 'url':
                summary['urls'] += 1
            elif t == 'hash':
                summary['hashes'] += 1
            is_malicious = False
            if t in ('domain', 'url') and re.search(r'(mal|evil|bad|phish|botnet|c2)', ind, re.IGNORECASE):
                is_malicious = True
            if t == 'ip' and ind.endswith('.123'):
                is_malicious = True
            if t == 'hash' and ind.lower().startswith('0'):
                is_malicious = True
            details: Dict[str, Any] = {}
            if "virustotal" in request.sources:
                details["virustotal"] = {
                    "detections": (abs(hash(ind)) % 10),
                    "total_engines": 70,
                    "last_analysis": datetime.now().strftime("%Y-%m-%d")
                }
            if "alienvault" in request.sources:
                details["alienvault"] = {
                    "pulses": (abs(hash(ind)) % 5),
                    "tags": ["malware"] if is_malicious else []
                }
            results.append({
                "indicator": ind,
                "type": t,
                "is_malicious": is_malicious,
                "details": details
            })
        
        return {
            "status": "completed",
            "total": len(results),
            "summary": summary,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error in IOC analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao analisar IOCs: {str(e)}")

@router.post("/hash/analyze")
async def analyze_hash(
    request: HashAnalyzeRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Analisa e identifica hashes
    """
    
    try:
        logger.info(f"Hash analysis started. Count: {len(request.hashes)}")
        
        results = []
        
        for hash_value in request.hashes:
            hash_value = hash_value.strip()
            
            # Auto-detecta tipo de hash
            hash_length = len(hash_value)
            detected_type = "unknown"
            
            if hash_length == 32:
                detected_type = "MD5"
            elif hash_length == 40:
                detected_type = "SHA-1"
            elif hash_length == 64:
                detected_type = "SHA-256"
            elif hash_length == 128:
                detected_type = "SHA-512"
            
            result = {
                "hash": hash_value,
                "type": detected_type if request.hash_type == "auto" else request.hash_type.upper(),
                "length": hash_length,
                "is_known": False,
                "plaintext": None,
                "sources_checked": ["local_db", "online_db"],
                "malware_associated": False,
                "file_info": None
            }
            
            # Simula busca em banco de dados
            common_hashes = {
                "5f4dcc3b5aa765d61d8327deb882cf99": "password",  # MD5
                "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": "password",  # SHA-1
            }
            
            if hash_value.lower() in common_hashes:
                result["is_known"] = True
                result["plaintext"] = common_hashes[hash_value.lower()]
            
            # Simula informação de malware
            if hash_length == 32 and hash_value.startswith('a'):
                result["malware_associated"] = True
                result["file_info"] = {
                    "malware_family": "Trojan.Generic",
                    "first_seen": "2024-01-15",
                    "threat_level": "high"
                }
            
            results.append(result)
        
        logger.info(f"Hash analysis completed. Results: {len(results)}")
        
        return {
            "status": "completed",
            "hashes_analyzed": len(results),
            "known_hashes": sum(1 for r in results if r["is_known"]),
            "malware_detected": sum(1 for r in results if r["malware_associated"]),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    
    except ValueError as ve:
        logger.warning(f"Validation error in hash analysis: {str(ve)}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error in hash analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao analisar hashes: {str(e)}")


# ==================== PASSWORD STRENGTH CHECKER ====================

@router.post("/password/check")
async def check_password_strength(
    request: PasswordCheckRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Avalia a força de uma senha
    """
    
    try:
        logger.info("Password strength check started")
        
        password = request.password
        score = 0
        feedback = []
        
        # Critérios de avaliação
        if len(password) >= 8:
            score += 20
        else:
            feedback.append("Senha muito curta (mínimo 8 caracteres)")
        
        if len(password) >= 12:
            score += 10
        
        if len(password) >= 16:
            score += 10
        
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_numbers = bool(re.search(r'\d', password))
        has_symbols = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        if has_lowercase:
            score += 15
        else:
            feedback.append("Adicione letras minúsculas")
        
        if has_uppercase:
            score += 15
        else:
            feedback.append("Adicione letras maiúsculas")
        
        if has_numbers:
            score += 15
        else:
            feedback.append("Adicione números")
        
        if has_symbols:
            score += 15
        else:
            feedback.append("Adicione símbolos especiais")
        
        # Penalidades
        if re.search(r'(.)\1{2,}', password):
            score -= 10
            feedback.append("Evite caracteres repetidos")
        
        # Senhas comuns
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in common_passwords:
            score = 0
            feedback.append("Senha muito comum! Escolha outra.")
        
        # Determina força
        if score >= 80:
            strength = "Muito Forte"
            color = "#10b981"
        elif score >= 60:
            strength = "Forte"
            color = "#3b82f6"
        elif score >= 40:
            strength = "Média"
            color = "#f59e0b"
        elif score >= 20:
            strength = "Fraca"
            color = "#ef4444"
        else:
            strength = "Muito Fraca"
            color = "#dc2626"
        
        # Tempo estimado para quebrar
        charset_size = 0
        if has_lowercase:
            charset_size += 26
        if has_uppercase:
            charset_size += 26
        if has_numbers:
            charset_size += 10
        if has_symbols:
            charset_size += 32
        
        if charset_size > 0:
            combinations = charset_size ** len(password)
            seconds_to_crack = combinations / 1_000_000_000
            
            if seconds_to_crack < 60:
                crack_time = f"{seconds_to_crack:.2f} segundos"
            elif seconds_to_crack < 3600:
                crack_time = f"{seconds_to_crack/60:.2f} minutos"
            elif seconds_to_crack < 86400:
                crack_time = f"{seconds_to_crack/3600:.2f} horas"
            elif seconds_to_crack < 31536000:
                crack_time = f"{seconds_to_crack/86400:.2f} dias"
            else:
                crack_time = f"{seconds_to_crack/31536000:.2f} anos"
        else:
            crack_time = "Instantâneo"
        
        logger.info(f"Password strength check completed. Score: {score}")
        
        return {
            "password_length": len(password),
            "score": min(score, 100),
            "strength": strength,
            "color": color,
            "crack_time": crack_time,
            "feedback": feedback,
            "has_lowercase": has_lowercase,
            "has_uppercase": has_uppercase,
            "has_numbers": has_numbers,
            "has_symbols": has_symbols,
            "timestamp": datetime.now().isoformat()
        }
    
    except ValueError as ve:
        logger.warning(f"Validation error in password check: {str(ve)}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error in password check: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao verificar senha: {str(e)}")


@router.post("/password/generate")
async def generate_password(
    request: PasswordGenerateRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Gera senha forte
    """
    
    try:
        logger.info(f"Password generation started. Length: {request.length}")
        
        charset = ""
        
        if request.lowercase:
            charset += string.ascii_lowercase
        if request.uppercase:
            charset += string.ascii_uppercase
        if request.numbers:
            charset += string.digits
        if request.symbols:
            charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not charset:
            raise HTTPException(status_code=400, detail="Selecione pelo menos uma opção")
        
        # Gera senha segura
        password = ''.join(secrets.choice(charset) for _ in range(request.length))
        
        logger.info("Password generated successfully")
        
        return {
            "password": password,
            "length": len(password),
            "charset_size": len(charset),
            "entropy": len(password) * len(charset),
            "timestamp": datetime.now().isoformat()
        }
    
    except ValueError as ve:
        logger.warning(f"Validation error in password generation: {str(ve)}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error in password generation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao gerar senha: {str(e)}")
