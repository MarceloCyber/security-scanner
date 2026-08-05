"""
Blue Team Tools Routes - Production Ready
Ferramentas de Blue Team para defesa e análise de segurança
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Depends
from pydantic import BaseModel, validator
from typing import List, Dict, Any
import re
import hashlib
import ipaddress
from datetime import datetime
import secrets
import string
import logging
import os
import requests
from urllib.parse import quote, urlsplit
from sqlalchemy.orm import Session

from auth import get_current_user
from models.user import User
from database import get_db
from middleware.subscription import check_subscription_status, check_tool_access, ensure_tool_access

# Configurar logger
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/blueteam", tags=["Blue Team"])

TI_TIMEOUT = (3.05, 10)


def _intel_unavailable(source: str, reason: str) -> Dict[str, Any]:
    return {"status": "not_queried", "source": source, "reason": reason}


def _intel_not_configured(source: str, reason: str) -> Dict[str, Any]:
    return {"status": "not_configured", "source": source, "reason": reason}


def _query_public_intel(target: str, target_type: str) -> Dict[str, Any]:
    """Consulta fontes públicas reais, sem tratar contexto como veredito de ameaça."""
    try:
        if target_type == "ip":
            response = requests.get(
                f"https://ipwho.is/{quote(target, safe='')}",
                timeout=TI_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            if not data.get("success", False):
                return {"status": "not_found", "source": "public_context", "reason": data.get("message", "IP não localizado")}
            connection = data.get("connection") or {}
            reverse_dns = None
            try:
                ptr_name = ipaddress.ip_address(data.get("ip")).reverse_pointer
                ptr_response = requests.get(
                    "https://dns.google/resolve", params={"name": ptr_name, "type": "PTR"}, timeout=TI_TIMEOUT
                )
                ptr_answers = ptr_response.json().get("Answer") or []
                reverse_dns = ptr_answers[0].get("data") if ptr_answers else None
            except (ValueError, requests.RequestException):
                pass
            return {
                "status": "queried", "source": "public_context", "reputation_source": False,
                "ip": data.get("ip"), "ip_type": data.get("type"),
                "continent": data.get("continent"), "country": data.get("country"),
                "country_code": data.get("country_code"), "region": data.get("region"),
                "region_code": data.get("region_code"), "city": data.get("city"),
                "postal": data.get("postal"), "is_eu": data.get("is_eu"),
                "latitude": data.get("latitude"), "longitude": data.get("longitude"),
                "isp": connection.get("isp"), "organization": connection.get("org"),
                "asn": connection.get("asn"), "reverse_dns": reverse_dns,
                "timezone": (data.get("timezone") or {}).get("id"),
            }

        if target_type == "hash":
            hash_type = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(target.lower()))
            if not hash_type or not re.fullmatch(r"[0-9a-fA-F]+", target):
                return {"status": "invalid", "source": "circl_hashlookup", "reason": "hash MD5, SHA-1 ou SHA-256 inválido"}
            response = requests.get(
                f"https://hashlookup.circl.lu/lookup/{hash_type}/{quote(target.lower(), safe='')}",
                timeout=TI_TIMEOUT,
            )
            if response.status_code == 404:
                return {"status": "not_found", "source": "circl_hashlookup", "hash_type": hash_type}
            response.raise_for_status()
            data = response.json()
            return {
                "status": "queried", "source": "circl_hashlookup", "reputation_source": False,
                "hash_type": hash_type, "known_file": True,
                "file_name": data.get("fileName"), "file_size": data.get("fileSize"),
                "file_type": data.get("fileType"),
            }

        raw_target = target.strip()
        # Aceita tanto https://site.tld/caminho quanto site.tld/caminho.
        # O prefixo // faz o urlsplit tratar entradas sem esquema como URL.
        parsed_target = urlsplit(raw_target if "://" in raw_target else f"//{raw_target}")
        hostname = parsed_target.hostname or ""
        hostname = hostname.strip().rstrip(".").lower()
        if not hostname or not re.fullmatch(r"[a-z0-9][a-z0-9.:-]{0,252}", hostname):
            return {"status": "invalid", "source": "public_context", "reason": "domínio/URL inválido"}
        dns_records = {}
        for record_type in ("A", "AAAA", "MX", "NS"):
            response = requests.get(
                "https://dns.google/resolve",
                params={"name": hostname, "type": record_type},
                timeout=TI_TIMEOUT,
            )
            response.raise_for_status()
            answers = response.json().get("Answer") or []
            if answers:
                dns_records[record_type] = [answer.get("data") for answer in answers]
        certificates = []
        if target_type == "domain":
            response = requests.get(
                "https://crt.sh/", params={"q": f"%.{hostname}", "output": "json"}, timeout=TI_TIMEOUT
            )
            if response.ok:
                certificate_data = response.json()
                certificates = certificate_data[:100] if isinstance(certificate_data, list) else []
        resolved_ips = (dns_records.get("A") or []) + (dns_records.get("AAAA") or [])
        resolved_context = {}
        if resolved_ips:
            ip_response = requests.get(
                f"https://ipwho.is/{quote(str(resolved_ips[0]), safe='')}", timeout=TI_TIMEOUT
            )
            if ip_response.ok:
                ip_data = ip_response.json()
                ip_connection = ip_data.get("connection") or {}
                resolved_context = {
                    "ip": ip_data.get("ip"), "continent": ip_data.get("continent"),
                    "country": ip_data.get("country"), "country_code": ip_data.get("country_code"),
                    "region": ip_data.get("region"), "city": ip_data.get("city"),
                    "latitude": ip_data.get("latitude"), "longitude": ip_data.get("longitude"),
                    "isp": ip_connection.get("isp"), "organization": ip_connection.get("org"),
                    "asn": ip_connection.get("asn"), "timezone": (ip_data.get("timezone") or {}).get("id"),
                }
        return {
            "status": "queried", "source": "public_context", "reputation_source": False,
            "hostname": hostname, "dns_records": dns_records, "resolved_ips": resolved_ips,
            **resolved_context,
            "certificate_count": len(certificates),
            "certificate_names": sorted({name.strip() for cert in certificates for name in str(cert.get("name_value", "")).splitlines() if name.strip()})[:100],
        }
    except (requests.RequestException, ValueError) as exc:
        return _intel_unavailable("public_intel", f"falha da fonte pública: {exc}")


def _query_intel(source: str, target: str, target_type: str) -> Dict[str, Any]:
    """Query configured providers and preserve provider evidence verbatim."""
    try:
        if source == "virustotal":
            key = os.getenv("VIRUSTOTAL_API_KEY")
            if not key: return _intel_not_configured(source, "VIRUSTOTAL_API_KEY não configurada")
            kind = "ip_addresses" if target_type == "ip" else "domains" if target_type == "domain" else "urls" if target_type == "url" else "files"
            value = quote(target, safe="") if target_type == "url" else target
            r = requests.get(f"https://www.virustotal.com/api/v3/{kind}/{value}", headers={"x-apikey": key}, timeout=TI_TIMEOUT)
            if r.status_code == 404: return {"status": "not_found", "source": source}
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {"status": "queried", "source": source, "detections": stats.get("malicious", 0), "total_engines": sum(stats.values()), "last_analysis": attrs.get("last_analysis_date")}
        if source == "abuseipdb":
            key = os.getenv("ABUSEIPDB_API_KEY")
            if not key: return _intel_not_configured(source, "ABUSEIPDB_API_KEY não configurada")
            if target_type != "ip": return _intel_unavailable(source, "fonte aceita apenas IP")
            r = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": target}, headers={"Key": key, "Accept": "application/json"}, timeout=TI_TIMEOUT)
            r.raise_for_status(); data = r.json().get("data", {})
            return {"status": "queried", "source": source, "abuse_confidence_score": data.get("abuseConfidenceScore"), "total_reports": data.get("totalReports"), "country": data.get("countryCode")}
        if source == "shodan":
            key = os.getenv("SHODAN_API_KEY")
            if not key: return _intel_not_configured(source, "SHODAN_API_KEY não configurada")
            if target_type not in {"ip", "domain"}: return _intel_unavailable(source, "fonte aceita IP/domínio")
            r = requests.get(f"https://api.shodan.io/host/{quote(target, safe='')}", params={"key": key}, timeout=TI_TIMEOUT)
            if r.status_code == 404: return {"status": "not_found", "source": source}
            r.raise_for_status(); data = r.json()
            return {"status": "queried", "source": source, "open_ports": data.get("ports", []), "os": data.get("os"), "vulns": data.get("vulns", [])}
        if source == "alienvault":
            key = os.getenv("OTX_API_KEY")
            if not key: return _intel_not_configured(source, "OTX_API_KEY não configurada")
            section = "IPv4" if target_type == "ip" else "domain" if target_type == "domain" else "URL" if target_type == "url" else "file"
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(target, safe='')}/general", headers={"X-OTX-API-KEY": key}, timeout=TI_TIMEOUT)
            if r.status_code == 404: return {"status": "not_found", "source": source}
            r.raise_for_status(); data = r.json()
            return {"status": "queried", "source": source, "pulses": data.get("pulse_info", {}).get("count", 0), "tags": data.get("pulse_info", {}).get("related", [])}
    except requests.RequestException as exc:
        return _intel_unavailable(source, f"falha do provedor: {exc}")
    return _intel_unavailable(source, "fonte não suportada")

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
        
        result = {
            "target": request.target,
            "target_type": request.target_type,
            "sources": {},
            "timestamp": datetime.now().isoformat()
        }
        for source in request.sources:
            result["sources"][source] = _query_intel(source, request.target, request.target_type)
        public_intel = _query_public_intel(request.target, request.target_type)
        result["sources"][public_intel.get("source", "public_intel")] = public_intel
        if public_intel.get("status") == "queried":
            result["indicator_context"] = {
                "ip": public_intel.get("ip") or (
                    (public_intel.get("dns_records") or {}).get("A") or [None]
                )[0],
                "location": {
                    "continent": public_intel.get("continent"),
                    "country": public_intel.get("country"),
                    "country_code": public_intel.get("country_code"),
                    "region": public_intel.get("region"),
                    "city": public_intel.get("city"),
                    "postal": public_intel.get("postal"),
                    "latitude": public_intel.get("latitude"),
                    "longitude": public_intel.get("longitude"),
                    "timezone": public_intel.get("timezone"),
                },
                "network": {
                    "isp": public_intel.get("isp"),
                    "organization": public_intel.get("organization"),
                    "asn": public_intel.get("asn"),
                    "dns_records": public_intel.get("dns_records") or {},
                    "reverse_dns": public_intel.get("reverse_dns"),
                },
                "exposure": {},
                "certificates": {
                    "count": public_intel.get("certificate_count", 0),
                    "names": public_intel.get("certificate_names", []),
                },
                "identity": {
                    "cpf": None,
                    "status": "not_collected",
                    "reason": "CPF não é inferido nem coletado a partir de indicadores técnicos.",
                },
            }
            shodan = result["sources"].get("shodan") or {}
            if shodan.get("status") == "queried":
                result["indicator_context"]["exposure"] = {
                    "open_ports": shodan.get("open_ports") or [],
                    "operating_system": shodan.get("os"),
                    "vulnerabilities": shodan.get("vulns") or [],
                }
        queried = [v for v in result["sources"].values() if v.get("status") == "queried" and v.get("reputation_source", True)]
        available = [v for v in result["sources"].values() if v.get("status") in {"queried", "not_found"}]
        detections = sum(int(v.get("detections") or 0) for v in queried)
        abuse = max((int(v.get("abuse_confidence_score") or 0) for v in queried), default=0)
        result["reputation_score"] = min(100, max(abuse, detections * 10)) if queried else None
        result["is_malicious"] = (result["reputation_score"] or 0) >= 50 if queried else None
        result["details"] = {
            "risk_level": "high" if result["is_malicious"] else "low" if queried else "not_classified",
            "recommendation": "block" if result["is_malicious"] else "monitor" if queried else "review provider data",
            "confidence": "provider evidence" if queried else "contextual data only" if available else "no provider response",
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
            details: Dict[str, Any] = {}
            for source in request.sources:
                if t in ('ip', 'domain', 'url', 'hash'):
                    details[source] = _query_intel(source, ind, t)
            queried = [v for v in details.values() if v.get("status") == "queried"]
            is_malicious = any((v.get("detections", 0) or 0) > 0 or (v.get("abuse_confidence_score", 0) or 0) >= 50 or (v.get("pulses", 0) or 0) > 0 for v in queried)
            results.append({
                "indicator": ind,
                "type": t,
                "is_malicious": is_malicious,
                "details": details,
                "evidence_status": "queried" if queried else "not_queried"
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
        ensure_tool_access("hash_analyzer", current_user)
        logger.info(f"Hash analysis started. Count: {len(request.hashes)}")
        
        results = []
        
        for hash_value in request.hashes:
            hash_value = hash_value.strip()
            if not re.fullmatch(r"[0-9a-fA-F]+", hash_value):
                results.append({"hash": hash_value, "type": "invalid", "is_known": False,
                                "plaintext": None, "malware_associated": None,
                                "evidence_status": "invalid_hash"})
                continue
            
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
                "sources_checked": ["local_common_hashes", "virustotal"],
                "malware_associated": None,
                "file_info": None
            }
            
            # Pequena base local de referência; não é apresentada como inteligência de malware.
            common_hashes = {
                "5f4dcc3b5aa765d61d8327deb882cf99": "password",  # MD5
                "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": "password",  # SHA-1
            }
            
            if hash_value.lower() in common_hashes:
                result["is_known"] = True
                result["plaintext"] = common_hashes[hash_value.lower()]
            
            # No fabricated malware verdict: query VirusTotal only when configured.
            intel = _query_intel("virustotal", hash_value, "hash")
            result["threat_intel"] = intel
            result["malware_associated"] = (intel.get("detections", 0) or 0) > 0 if intel.get("status") == "queried" else None
            result["evidence_status"] = intel.get("status")
            
            results.append(result)
        
        logger.info(f"Hash analysis completed. Results: {len(results)}")
        
        return {
            "status": "completed",
            "hashes_analyzed": len(results),
            "known_hashes": sum(1 for r in results if r["is_known"]),
            "malware_detected": sum(1 for r in results if r.get("malware_associated") is True),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    
    except HTTPException:
        raise
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
        ensure_tool_access("password_strength_checker", current_user)
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
    
    except HTTPException:
        raise
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
        ensure_tool_access("password_strength_checker", current_user)
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
    
    except HTTPException:
        raise
    except ValueError as ve:
        logger.warning(f"Validation error in password generation: {str(ve)}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error in password generation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao gerar senha: {str(e)}")
