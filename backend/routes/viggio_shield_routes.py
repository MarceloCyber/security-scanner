from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from pydantic import BaseModel, validator
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from database import get_db
from models.user import User
from models.monitor import MonitorTarget, MonitorIncident, MonitorLog, BlockedIP
from auth import get_current_user
from scanners.port_scanner import scan_ports
from scanners.deep_security_scanner import deep_web_scan
from scanners.appsec_platform_scanner import run_appsec_scan, add_governance
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import ipaddress
import socket
import requests
import subprocess
import re
import hashlib
from collections import defaultdict

router = APIRouter(prefix="/api/viggio-shield", tags=["Viggio Shield"])

AUTOMATION_MONTHLY_LIMITS = {
    "free": 2,
    "starter": 10,
    "professional": 300,
    "enterprise": -1,
}

VULNERABILITY_DISPLAY_LIMITS = {
    "free": 3,
    "starter": 10,
    "professional": 300,
    "enterprise": -1,
}

def current_month_start() -> datetime:
    now = datetime.utcnow()
    return datetime(now.year, now.month, 1)

def remediation_for_incident(incident: MonitorIncident) -> str:
    """Transforma achados tecnicos em uma orientacao curta e acionavel."""
    stored_recommendation = (incident.extra_data or {}).get("recommendation")
    if stored_recommendation:
        return stored_recommendation
    description = (incident.description or "").lower()
    if "status code" in description or "retornou erro" in description:
        return "Verifique os logs da aplicação, a rota monitorada e a configuração do servidor; restaure uma resposta HTTP abaixo de 400."
    if "timeout" in description or "resposta lenta" in description:
        return "Revise desempenho, banco de dados e serviços dependentes; configure cache e ajuste os limites de timeout quando necessário."
    if "dns" in description:
        return "Corrija os registros DNS, confirme a propagação e valide se o domínio aponta para o servidor correto."
    if "porta" in description or "conexão" in description:
        return "Confirme se o serviço está ativo, revise firewall e regras de rede e exponha somente as portas necessárias."
    if incident.incident_type == "port_scan":
        return "Restrinja portas públicas, aplique rate limiting e revise regras de firewall e registros de acesso."
    return "Revise os logs do alvo, valide a disponibilidade do serviço e aplique as correções recomendadas pela equipe responsável."

# ============= Modelos Pydantic =============

class CreateTargetRequest(BaseModel):
    name: str
    target_type: str  # network, server, application, api
    target_address: str
    monitoring_ports: Optional[List[int]] = None
    check_interval: int = 300
    alert_threshold: int = 3
    enable_email_alerts: bool = True
    enable_telegram_alerts: bool = False
    telegram_chat_id: Optional[str] = None
    
    @validator('target_type')
    def validate_type(cls, v):
        allowed = ['network', 'server', 'application', 'api']
        if v not in allowed:
            raise ValueError(f'target_type deve ser um de: {", ".join(allowed)}')
        return v

    @validator('name')
    def validate_name(cls, v):
        v = (v or '').strip()
        if len(v) < 2:
            raise ValueError('name deve ter pelo menos 2 caracteres')
        if len(v) > 100:
            raise ValueError('name deve ter no máximo 100 caracteres')
        return v

    @validator('target_address')
    def validate_address(cls, v):
        v = (v or '').strip()
        if len(v) < 3:
            raise ValueError('target_address inválido')
        if any(ch.isspace() for ch in v):
            raise ValueError('target_address não pode conter espaços')
        return v

    @validator('monitoring_ports')
    def validate_ports(cls, v):
        if not v:
            return None
        ports = []
        for port in v:
            if port < 1 or port > 65535:
                raise ValueError('monitoring_ports deve conter portas entre 1 e 65535')
            if port not in ports:
                ports.append(port)
        if len(ports) > 50:
            raise ValueError('monitoring_ports permite no máximo 50 portas por alvo')
        return ports

    @validator('check_interval')
    def validate_interval(cls, v):
        if v < 60 or v > 86400:
            raise ValueError('check_interval deve ficar entre 60 e 86400 segundos')
        return v

    @validator('alert_threshold')
    def validate_threshold(cls, v):
        if v < 1 or v > 20:
            raise ValueError('alert_threshold deve ficar entre 1 e 20')
        return v

class UpdateTargetRequest(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    check_interval: Optional[int] = None
    alert_threshold: Optional[int] = None
    enable_email_alerts: Optional[bool] = None
    enable_telegram_alerts: Optional[bool] = None
    telegram_chat_id: Optional[str] = None

    @validator('status')
    def validate_status(cls, v):
        if v is None:
            return v
        allowed = ['active', 'paused', 'inactive']
        if v not in allowed:
            raise ValueError(f'status deve ser um de: {", ".join(allowed)}')
        return v

    @validator('check_interval')
    def validate_interval(cls, v):
        if v is not None and (v < 60 or v > 86400):
            raise ValueError('check_interval deve ficar entre 60 e 86400 segundos')
        return v

    @validator('alert_threshold')
    def validate_threshold(cls, v):
        if v is not None and (v < 1 or v > 20):
            raise ValueError('alert_threshold deve ficar entre 1 e 20')
        return v

class IncidentUpdateRequest(BaseModel):
    status: str
    notes: Optional[str] = None

    @validator('status')
    def validate_status(cls, v):
        allowed = ['open', 'investigating', 'resolved', 'false_positive']
        if v not in allowed:
            raise ValueError(f'status deve ser um de: {", ".join(allowed)}')
        return v

class BlockIPRequest(BaseModel):
    ip_address: str
    reason: str
    duration_hours: Optional[int] = None  # None = permanente

    @validator('ip_address')
    def validate_ip(cls, v):
        try:
            return str(ipaddress.ip_address((v or '').strip()))
        except ValueError:
            raise ValueError('ip_address inválido')

    @validator('reason')
    def validate_reason(cls, v):
        v = (v or '').strip()
        if len(v) < 3:
            raise ValueError('reason deve ter pelo menos 3 caracteres')
        return v

    @validator('duration_hours')
    def validate_duration(cls, v):
        if v is not None and (v < 1 or v > 8760):
            raise ValueError('duration_hours deve ficar entre 1 e 8760 horas')
        return v

class AppSecScanRequest(BaseModel):
    scan_type: str
    content: Optional[str] = ""
    filename: Optional[str] = ""
    target_url: Optional[str] = ""
    policy: Optional[Dict[str, Any]] = None

    @validator('scan_type')
    def validate_scan_type(cls, value):
        allowed = {'sast', 'sca', 'iac', 'container', 'api_inventory', 'graphql', 'sbom'}
        if value not in allowed:
            raise ValueError(f"scan_type deve ser um de: {', '.join(sorted(allowed))}")
        return value

    @validator('content')
    def validate_content_size(cls, value):
        if len(value or '') > 2_000_000:
            raise ValueError('Conteúdo excede o limite de 2 MB')
        return value or ''

# ============= Funções Auxiliares =============

def normalize_target_address(target_type: str, address: str) -> str:
    """Normaliza endereço sem mudar o alvo pretendido pelo usuário."""
    address = address.strip()
    if target_type in ["api", "application"] and not re.match(r"^https?://", address, re.I):
        return f"https://{address}"
    return address

def extract_host(address: str) -> str:
    """Extrai host de IP, domínio ou URL."""
    parsed = urlparse(address if re.match(r"^[a-z]+://", address, re.I) else f"//{address}")
    host = parsed.hostname or address.split("/")[0].split(":")[0]
    return host.strip("[]")

def classify_health_severity(issues: List[str], metadata: Dict[str, Any]) -> str:
    """Classifica severidade de falhas de disponibilidade."""
    status_code = metadata.get("status_code")
    issue_text = " ".join(issues).lower()
    if status_code and int(status_code) >= 500:
        return "high"
    if "timeout" in issue_text or "erro de conexão" in issue_text or "dns" in issue_text:
        return "high"
    if len(issues) >= 3:
        return "high"
    return "medium"

def upsert_open_incident(
    db: Session,
    target: MonitorTarget,
    user_id: int,
    incident_type: str,
    severity: str,
    title: str,
    description: str,
    metadata: Optional[Dict[str, Any]] = None
):
    """Evita incidentes duplicados enquanto um problema igual continua aberto."""
    incident = db.query(MonitorIncident).filter(
        MonitorIncident.target_id == target.id,
        MonitorIncident.user_id == user_id,
        MonitorIncident.incident_type == incident_type,
        MonitorIncident.status == "open"
    ).first()

    if incident:
        incident.severity = severity
        incident.title = title
        incident.description = description
        incident.extra_data = metadata or {}
        incident.detected_at = datetime.utcnow()
        return incident

    incident = MonitorIncident(
        target_id=target.id,
        user_id=user_id,
        incident_type=incident_type,
        severity=severity,
        title=title,
        description=description,
        extra_data=metadata or {}
    )
    db.add(incident)
    return incident

def deactivate_expired_blocks(db: Session, user_id: int):
    """Desativa bloqueios temporários vencidos antes de listar/contabilizar."""
    db.query(BlockedIP).filter(
        BlockedIP.user_id == user_id,
        BlockedIP.is_active == True,
        BlockedIP.is_permanent == False,
        BlockedIP.expires_at.isnot(None),
        BlockedIP.expires_at <= datetime.utcnow()
    ).update({"is_active": False}, synchronize_session=False)

def check_tcp_port(host: str, port: int, timeout: int = 3) -> Dict[str, Any]:
    """Testa uma porta TCP de forma isolada para permitir execução paralela."""
    started_at = datetime.now()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "port": port,
                "open": True,
                "response_time": (datetime.now() - started_at).total_seconds() * 1000,
                "error": None
            }
    except Exception as exc:
        return {
            "port": port,
            "open": False,
            "response_time": (datetime.now() - started_at).total_seconds() * 1000,
            "error": str(exc)
        }

def check_tcp_ports(host: str, ports: List[int]) -> List[Dict[str, Any]]:
    """Executa checagens de portas em paralelo para reduzir latência total."""
    if not ports:
        return []

    workers = min(16, len(ports))
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(check_tcp_port, host, port) for port in ports]
        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda item: item["port"])

async def check_target_health(target: MonitorTarget) -> Dict[str, Any]:
    """Verifica saúde do alvo monitorado"""
    result = {
        "target_id": target.id,
        "is_healthy": True,
        "response_time": 0,
        "issues": [],
        "metadata": {}
    }
    
    try:
        address = normalize_target_address(target.target_type, target.target_address)

        if target.target_type == "api":
            # Testa endpoint API
            start_time = datetime.now()
            response = await asyncio.to_thread(
                requests.get,
                address,
                timeout=(3.05, 10),
                allow_redirects=True,
                headers={"User-Agent": "IronNet-ViggioShield/1.0"}
            )
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result["response_time"] = response_time
            result["metadata"]["status_code"] = response.status_code
            result["metadata"]["content_length"] = len(response.content)
            
            if response.status_code >= 400:
                result["is_healthy"] = False
                result["issues"].append(f"Status code anormal: {response.status_code}")
            
            if response_time > 5000:
                result["issues"].append(f"Resposta lenta: {response_time:.2f}ms")
                
        elif target.target_type in ["server", "network"]:
            # Testa conectividade e portas
            host = extract_host(target.target_address)
            result["metadata"]["host"] = host

            try:
                socket.gethostbyname(host)
            except socket.gaierror:
                result["is_healthy"] = False
                result["issues"].append("DNS não resolve o alvo")
                return result
            
            # Testa ping
            ping_ok = None
            try:
                ping_result = await asyncio.to_thread(
                    subprocess.run,
                    ["ping", "-c", "1", "-W", "2", host],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                ping_ok = ping_result.returncode == 0
                result["metadata"]["ping_ok"] = ping_ok
            except:
                result["metadata"]["ping_ok"] = None
            
            # Testa portas específicas
            if target.monitoring_ports:
                started_at = datetime.now()
                port_results = await asyncio.to_thread(check_tcp_ports, host, target.monitoring_ports)
                open_ports = [item["port"] for item in port_results if item["open"]]
                closed_ports = [item["port"] for item in port_results if not item["open"]]
                result["response_time"] = (datetime.now() - started_at).total_seconds() * 1000
                result["metadata"]["open_ports"] = open_ports
                result["metadata"]["closed_ports"] = closed_ports
                result["metadata"]["port_results"] = port_results
                if closed_ports:
                    result["is_healthy"] = False
                    result["issues"].append(f"Portas inacessíveis: {', '.join(map(str, closed_ports))}")
            elif ping_ok is False:
                result["is_healthy"] = False
                result["issues"].append("Host não responde ao ping")

        elif target.target_type == "application":
            # Testa aplicação web
            start_time = datetime.now()
            response = await asyncio.to_thread(
                requests.get,
                address,
                timeout=(3.05, 10),
                allow_redirects=True,
                headers={"User-Agent": "IronNet-ViggioShield/1.0"}
            )
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result["response_time"] = response_time
            result["metadata"]["status_code"] = response.status_code
            result["metadata"]["content_length"] = len(response.content)
            result["is_healthy"] = response.status_code < 400
            
            if not result["is_healthy"]:
                result["issues"].append(f"Aplicação retornou erro: {response.status_code}")

        # Viggio Shield e Automacao Inteligente tambem executam a mesma analise
        # de servicos, banners e riscos conhecidos utilizada pelo Port Scanner.
        host = extract_host(address)
        security_scan = await asyncio.to_thread(scan_ports, host, target.monitoring_ports)
        port_vulnerabilities = security_scan.get("vulnerabilities", [])
        deep_assessment = None
        deep_vulnerabilities = []
        if target.target_type in ["api", "application"]:
            try:
                deep_assessment = await asyncio.to_thread(deep_web_scan, address, target.target_type)
                deep_vulnerabilities = deep_assessment.get("findings", [])
            except Exception as deep_error:
                deep_assessment = {"error": str(deep_error), "findings": [], "summary": {"total": 0}}
        result["metadata"]["security_scan"] = security_scan
        result["metadata"]["deep_assessment"] = deep_assessment
        result["metadata"]["vulnerabilities"] = port_vulnerabilities + deep_vulnerabilities
        result["metadata"]["security_summary"] = security_scan.get("summary", {})
                
    except requests.exceptions.Timeout:
        result["is_healthy"] = False
        result["issues"].append("Timeout na requisição")
    except requests.exceptions.ConnectionError:
        result["is_healthy"] = False
        result["issues"].append("Erro de conexão")
    except Exception as e:
        result["is_healthy"] = False
        result["issues"].append(f"Erro: {str(e)}")
    
    return result

def sync_port_vulnerabilities(target: MonitorTarget, db: Session, health_result: Dict[str, Any]) -> int:
    """Persiste os achados atuais do Port Scanner e resolve os que desapareceram."""
    vulnerabilities = health_result.get("metadata", {}).get("vulnerabilities", []) or []
    now = datetime.utcnow()
    current_keys = set()

    for vulnerability in vulnerabilities:
        port = int(vulnerability.get("port") or 0)
        finding_type = str(vulnerability.get("type") or "Security Finding")
        identity = f"{port}:{finding_type}:{vulnerability.get('cwe')}:{vulnerability.get('evidence')}"
        finding_key = hashlib.sha1(identity.lower().encode("utf-8")).hexdigest()
        current_keys.add(finding_key)
        incident_type = f"security_finding:{finding_key}"
        incident = db.query(MonitorIncident).filter(
            MonitorIncident.target_id == target.id,
            MonitorIncident.user_id == target.user_id,
            MonitorIncident.incident_type == incident_type,
            MonitorIncident.status == "open"
        ).first()
        metadata = {
            "source": "port_scanner",
            "finding_key": finding_key,
            "port": port,
            "service": vulnerability.get("service"),
            "recommendation": vulnerability.get("recommendation"),
            "cves": vulnerability.get("cves", []),
            "cwe": vulnerability.get("cwe"),
            "owasp": vulnerability.get("owasp"),
            "cvss": vulnerability.get("cvss"),
            "evidence": vulnerability.get("evidence"),
            "layer": vulnerability.get("layer", "Network Services")
        }
        severity = str(vulnerability.get("severity") or "medium").lower()
        title = f"{finding_type} na porta {port}" if port else finding_type
        if incident:
            incident.severity = severity
            incident.title = title
            incident.description = vulnerability.get("description") or finding_type
            incident.detected_at = now
            incident.extra_data = metadata
        else:
            db.add(MonitorIncident(
                target_id=target.id,
                user_id=target.user_id,
                incident_type=incident_type,
                severity=severity,
                title=title,
                description=vulnerability.get("description") or finding_type,
                extra_data=metadata
            ))

    open_findings = db.query(MonitorIncident).filter(
        MonitorIncident.target_id == target.id,
        MonitorIncident.user_id == target.user_id,
        or_(
            MonitorIncident.incident_type.like("security_finding:%"),
            MonitorIncident.incident_type.like("port_vulnerability:%")
        ),
        MonitorIncident.status == "open"
    ).all()
    for incident in open_findings:
        finding_key = (incident.extra_data or {}).get("finding_key")
        if finding_key and finding_key not in current_keys:
            incident.status = "resolved"
            incident.resolved_at = now
            incident.resolved_by = "automacao"

    return len(vulnerabilities)

async def detect_threats(target: MonitorTarget, db: Session) -> List[Dict]:
    """Detecta ameaças potenciais no alvo"""
    threats = []
    
    try:
        # Análise de logs recentes (últimas 10 tentativas)
        recent_logs = db.query(MonitorLog).filter(
            MonitorLog.target_id == target.id,
            MonitorLog.log_type == "check",
            MonitorLog.created_at >= datetime.utcnow() - timedelta(hours=1)
        ).all()
        
        # Detecta scan de portas (múltiplas tentativas em portas diferentes)
        if len(recent_logs) > 10:
            threats.append({
                "type": "port_scan",
                "severity": "medium",
                "description": "Possível varredura de portas detectada",
                "details": f"{len(recent_logs)} tentativas na última hora"
            })
        
        # Verifica incidentes recentes similares
        recent_incidents = db.query(MonitorIncident).filter(
            MonitorIncident.target_id == target.id,
            MonitorIncident.detected_at >= datetime.utcnow() - timedelta(hours=24),
            MonitorIncident.status == "open"
        ).count()
        
        if recent_incidents > 5:
            threats.append({
                "type": "repeated_attacks",
                "severity": "high",
                "description": "Múltiplos incidentes detectados",
                "details": f"{recent_incidents} incidentes nas últimas 24h"
            })
            
    except Exception as e:
        print(f"Erro ao detectar ameaças: {e}")
    
    return threats

async def run_automatic_target_check(target: MonitorTarget, db: Session) -> Dict[str, Any]:
    """Executa e persiste uma verificacao agendada sem depender de uma requisicao HTTP."""
    health_result = await check_target_health(target)
    target.total_checks = (target.total_checks or 0) + 1
    target.last_check = datetime.utcnow()
    new_incident = False
    vulnerabilities_found = sync_port_vulnerabilities(target, db, health_result)

    if health_result["is_healthy"]:
        target.status = "active"
    else:
        target.failed_checks = (target.failed_checks or 0) + 1
        if target.failed_checks >= target.alert_threshold:
            existing = db.query(MonitorIncident).filter(
                MonitorIncident.target_id == target.id,
                MonitorIncident.user_id == target.user_id,
                MonitorIncident.incident_type == "anomaly",
                MonitorIncident.status == "open"
            ).first()
            severity = classify_health_severity(health_result["issues"], health_result["metadata"])
            upsert_open_incident(
                db, target, target.user_id, "anomaly", severity,
                f"Falha detectada em {target.name}",
                "; ".join(health_result["issues"]),
                {**health_result["metadata"], "source": "automation"}
            )
            new_incident = existing is None

    target.uptime_percentage = (
        ((target.total_checks - (target.failed_checks or 0)) / target.total_checks) * 100
        if target.total_checks else 100.0
    )
    db.add(MonitorLog(
        target_id=target.id,
        user_id=target.user_id,
        log_type="alert" if not health_result["is_healthy"] else "check",
        message=f"Verificacao automatica: {'Saudavel' if health_result['is_healthy'] else 'Problemas detectados'}",
        level="info" if health_result["is_healthy"] else "warning",
        data=health_result
    ))
    db.commit()
    return {"health": health_result, "new_incident": new_incident, "vulnerabilities_found": vulnerabilities_found}

# ============= Rotas =============

@router.post("/appsec/scan")
async def run_viggio_appsec_scan(
    request: AppSecScanRequest,
    current_user: User = Depends(get_current_user)
):
    """Executa um scanner real do workspace AppSec unificado do Viggio."""
    if request.scan_type == 'graphql' and not request.target_url:
        raise HTTPException(status_code=400, detail='Informe a URL do endpoint GraphQL')
    if request.scan_type != 'graphql' and not request.content.strip():
        raise HTTPException(status_code=400, detail='Informe o conteúdo que será analisado')
    try:
        result = await asyncio.to_thread(
            run_appsec_scan, request.scan_type, request.content,
            request.filename or '', request.target_url or ''
        )
        result = add_governance(result, request.policy, request.filename or request.target_url or 'source')
        return {'success': True, 'scan_type': request.scan_type, 'result': result, 'scanned_at': datetime.utcnow()}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'Falha no scanner {request.scan_type}: {exc}')

@router.post("/targets")
async def create_monitor_target(
    request: CreateTargetRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cria um novo alvo de monitoramento"""
    
    # A cota contabiliza criacoes no mes, inclusive automacoes removidas, e renova
    # automaticamente no primeiro dia de cada novo mes UTC.
    automations_this_month = db.query(MonitorTarget).filter(
        MonitorTarget.user_id == current_user.id,
        MonitorTarget.created_at >= current_month_start()
    ).count()

    max_targets = AUTOMATION_MONTHLY_LIMITS.get(current_user.subscription_plan, 2)
    
    if max_targets != -1 and automations_this_month >= max_targets:
        raise HTTPException(
            status_code=403,
            detail=f"Limite mensal de {max_targets} automações atingido para o plano {current_user.subscription_plan}. A cota será renovada no próximo mês."
        )
    
    target = MonitorTarget(
        user_id=current_user.id,
        name=request.name,
        target_type=request.target_type,
        target_address=normalize_target_address(request.target_type, request.target_address),
        monitoring_ports=request.monitoring_ports,
        check_interval=request.check_interval,
        alert_threshold=request.alert_threshold,
        enable_email_alerts=request.enable_email_alerts,
        enable_telegram_alerts=request.enable_telegram_alerts,
        telegram_chat_id=request.telegram_chat_id
    )
    
    db.add(target)
    db.commit()
    db.refresh(target)
    
    # Log de criação
    log = MonitorLog(
        target_id=target.id,
        user_id=current_user.id,
        log_type="check",
        message=f"Alvo de monitoramento criado: {target.name}",
        level="info"
    )
    db.add(log)
    db.commit()
    
    return {
        "success": True,
        "target": {
            "id": target.id,
            "name": target.name,
            "type": target.target_type,
            "address": target.target_address,
            "status": target.status,
            "created_at": target.created_at
        }
    }

@router.get("/targets")
async def list_monitor_targets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista todos os alvos de monitoramento do usuário"""
    
    targets = db.query(MonitorTarget).filter(
        MonitorTarget.user_id == current_user.id,
        MonitorTarget.is_active == True
    ).order_by(MonitorTarget.created_at.desc()).all()
    
    result = []
    for target in targets:
        # Conta incidentes ativos
        active_incidents = db.query(MonitorIncident).filter(
            MonitorIncident.target_id == target.id,
            MonitorIncident.status == "open"
        ).count()
        
        result.append({
            "id": target.id,
            "name": target.name,
            "type": target.target_type,
            "address": target.target_address,
            "status": target.status,
            "uptime": target.uptime_percentage,
            "active_incidents": active_incidents,
            "last_check": target.last_check,
            "created_at": target.created_at
        })
    
    return {"targets": result}

@router.get("/targets/{target_id}")
async def get_target_details(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Obtém detalhes completos de um alvo"""
    
    target = db.query(MonitorTarget).filter(
        MonitorTarget.id == target_id,
        MonitorTarget.user_id == current_user.id
    ).first()
    
    if not target:
        raise HTTPException(status_code=404, detail="Alvo não encontrado")
    
    # Incidentes recentes
    incident_query = db.query(MonitorIncident).filter(
        MonitorIncident.target_id == target_id
    ).order_by(MonitorIncident.detected_at.desc())
    details_limit = VULNERABILITY_DISPLAY_LIMITS.get(current_user.subscription_plan, 3)
    incidents = incident_query.all() if details_limit == -1 else incident_query.limit(details_limit).all()
    
    # IPs bloqueados
    blocked_ips = db.query(BlockedIP).filter(
        BlockedIP.target_id == target_id,
        BlockedIP.is_active == True
    ).all()
    
    return {
        "target": {
            "id": target.id,
            "name": target.name,
            "type": target.target_type,
            "address": target.target_address,
            "ports": target.monitoring_ports,
            "status": target.status,
            "uptime": target.uptime_percentage,
            "total_checks": target.total_checks,
            "failed_checks": target.failed_checks,
            "last_check": target.last_check,
            "check_interval": target.check_interval,
            "created_at": target.created_at
        },
        "recent_incidents": [
            {
                "id": inc.id,
                "type": inc.incident_type,
                "severity": inc.severity,
                "title": inc.title,
                "description": inc.description,
                "remediation": remediation_for_incident(inc),
                "cves": (inc.extra_data or {}).get("cves", []),
                "cwe": (inc.extra_data or {}).get("cwe"),
                "owasp": (inc.extra_data or {}).get("owasp"),
                "cvss": (inc.extra_data or {}).get("cvss"),
                "evidence": (inc.extra_data or {}).get("evidence"),
                "layer": (inc.extra_data or {}).get("layer"),
                "port": (inc.extra_data or {}).get("port"),
                "service": (inc.extra_data or {}).get("service"),
                "source_ip": inc.source_ip,
                "status": inc.status,
                "detected_at": inc.detected_at
            } for inc in incidents
        ],
        "blocked_ips": [
            {
                "id": ip.id,
                "address": ip.ip_address,
                "reason": ip.reason,
                "blocked_at": ip.blocked_at,
                "expires_at": ip.expires_at,
                "is_permanent": ip.is_permanent
            } for ip in blocked_ips
        ]
    }

@router.post("/targets/{target_id}/check")
async def manual_check_target(
    target_id: int,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Executa verificação manual de um alvo"""
    
    target = db.query(MonitorTarget).filter(
        MonitorTarget.id == target_id,
        MonitorTarget.user_id == current_user.id
    ).first()
    
    if not target:
        raise HTTPException(status_code=404, detail="Alvo não encontrado")
    
    # Executa verificação
    health_result = await check_target_health(target)
    vulnerabilities_found = sync_port_vulnerabilities(target, db, health_result)
    
    # Atualiza estatísticas
    target.total_checks = (target.total_checks or 0) + 1
    target.last_check = datetime.utcnow()
    
    if not health_result["is_healthy"]:
        target.failed_checks = (target.failed_checks or 0) + 1
        
        # Cria incidente se threshold atingido
        if target.failed_checks >= target.alert_threshold:
            severity = classify_health_severity(health_result["issues"], health_result["metadata"])
            upsert_open_incident(
                db=db,
                target=target,
                user_id=current_user.id,
                incident_type="anomaly",
                severity=severity,
                title=f"Falha detectada em {target.name}",
                description="; ".join(health_result["issues"]),
                metadata=health_result["metadata"]
            )
    elif target.status != "paused":
        target.status = "active"

    threats = await detect_threats(target, db)
    for threat in threats:
        upsert_open_incident(
            db=db,
            target=target,
            user_id=current_user.id,
            incident_type=threat["type"],
            severity=threat["severity"],
            title=threat["description"],
            description=threat["details"],
            metadata={"source": "viggio_shield_threat_detection"}
        )
    
    # Atualiza uptime
    if target.total_checks > 0:
        target.uptime_percentage = ((target.total_checks - target.failed_checks) / target.total_checks) * 100
    
    db.commit()
    
    # Log
    log = MonitorLog(
        target_id=target.id,
        user_id=current_user.id,
        log_type="check",
        message=f"Verificação manual: {'Saudável' if health_result['is_healthy'] else 'Problemas detectados'}",
        level="info" if health_result["is_healthy"] else "warning",
        data=health_result
    )
    db.add(log)
    db.commit()
    
    return {
        "success": True,
        "health": health_result,
        "uptime": round(target.uptime_percentage or 0, 2),
        "threats": threats,
        "vulnerabilities_found": vulnerabilities_found,
        "vulnerabilities": health_result.get("metadata", {}).get("vulnerabilities", [])
    }

@router.patch("/targets/{target_id}")
async def update_monitor_target(
    target_id: int,
    request: UpdateTargetRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza configurações de um alvo"""
    
    target = db.query(MonitorTarget).filter(
        MonitorTarget.id == target_id,
        MonitorTarget.user_id == current_user.id
    ).first()
    
    if not target:
        raise HTTPException(status_code=404, detail="Alvo não encontrado")
    
    update_data = request.dict(exclude_unset=True)
    for field, value in update_data.items():
        if field == "target_address" and value:
            value = normalize_target_address(target.target_type, value)
        setattr(target, field, value)
    
    target.updated_at = datetime.utcnow()
    db.commit()
    
    return {"success": True, "message": "Alvo atualizado com sucesso"}

@router.delete("/targets/{target_id}")
async def delete_monitor_target(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove um alvo de monitoramento"""
    
    target = db.query(MonitorTarget).filter(
        MonitorTarget.id == target_id,
        MonitorTarget.user_id == current_user.id
    ).first()
    
    if not target:
        raise HTTPException(status_code=404, detail="Alvo não encontrado")
    
    target.is_active = False
    target.status = "inactive"
    db.commit()
    
    return {"success": True, "message": "Alvo removido com sucesso"}

@router.get("/incidents")
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista incidentes detectados"""
    
    query = db.query(MonitorIncident).filter(
        MonitorIncident.user_id == current_user.id
    )
    
    if status:
        query = query.filter(MonitorIncident.status == status)
    if severity:
        query = query.filter(MonitorIncident.severity == severity)
    
    display_limit = VULNERABILITY_DISPLAY_LIMITS.get(current_user.subscription_plan, 3)
    total_found = query.count()
    ordered_query = query.order_by(MonitorIncident.detected_at.desc())
    incidents = ordered_query.all() if display_limit == -1 else ordered_query.limit(display_limit).all()
    
    return {
        "incidents": [
            {
                "id": inc.id,
                "target_id": inc.target_id,
                "type": inc.incident_type,
                "severity": inc.severity,
                "title": inc.title,
                "description": inc.description,
                "remediation": remediation_for_incident(inc),
                "cves": (inc.extra_data or {}).get("cves", []),
                "cwe": (inc.extra_data or {}).get("cwe"),
                "owasp": (inc.extra_data or {}).get("owasp"),
                "cvss": (inc.extra_data or {}).get("cvss"),
                "evidence": (inc.extra_data or {}).get("evidence"),
                "layer": (inc.extra_data or {}).get("layer"),
                "port": (inc.extra_data or {}).get("port"),
                "service": (inc.extra_data or {}).get("service"),
                "source_ip": inc.source_ip,
                "status": inc.status,
                "detected_at": inc.detected_at,
                "resolved_at": inc.resolved_at
            } for inc in incidents
        ],
        "total_found": total_found,
        "display_limit": display_limit
    }

@router.patch("/incidents/{incident_id}")
async def update_incident(
    incident_id: int,
    request: IncidentUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza status de um incidente"""
    
    incident = db.query(MonitorIncident).filter(
        MonitorIncident.id == incident_id,
        MonitorIncident.user_id == current_user.id
    ).first()
    
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    
    incident.status = request.status
    if request.notes:
        incident.notes = request.notes
    
    if request.status in ["resolved", "false_positive"]:
        incident.resolved_at = datetime.utcnow()
        incident.resolved_by = current_user.username
    
    db.commit()
    
    return {"success": True, "message": "Incidente atualizado"}

@router.post("/blocked-ips")
async def block_ip_address(
    request: BlockIPRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Bloqueia um endereço IP"""
    
    # Verifica se já está bloqueado
    existing = db.query(BlockedIP).filter(
        BlockedIP.ip_address == request.ip_address,
        BlockedIP.user_id == current_user.id,
        BlockedIP.is_active == True
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="IP já está bloqueado")
    
    expires_at = None
    is_permanent = request.duration_hours is None
    
    if not is_permanent:
        expires_at = datetime.utcnow() + timedelta(hours=request.duration_hours)
    
    blocked_ip = BlockedIP(
        user_id=current_user.id,
        ip_address=request.ip_address,
        reason=request.reason,
        expires_at=expires_at,
        is_permanent=is_permanent
    )
    
    db.add(blocked_ip)
    db.commit()
    
    return {
        "success": True,
        "message": f"IP {request.ip_address} bloqueado com sucesso",
        "expires_at": expires_at
    }

@router.get("/blocked-ips")
async def list_blocked_ips(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista IPs bloqueados"""
    deactivate_expired_blocks(db, current_user.id)
    db.commit()
    
    blocked_ips = db.query(BlockedIP).filter(
        BlockedIP.user_id == current_user.id,
        BlockedIP.is_active == True
    ).order_by(BlockedIP.blocked_at.desc()).all()
    
    return {
        "blocked_ips": [
            {
                "id": ip.id,
                "address": ip.ip_address,
                "reason": ip.reason,
                "blocked_at": ip.blocked_at,
                "expires_at": ip.expires_at,
                "is_permanent": ip.is_permanent,
                "country": ip.country
            } for ip in blocked_ips
        ]
    }

@router.delete("/blocked-ips/{ip_id}")
async def unblock_ip(
    ip_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Desbloqueia um IP"""
    
    blocked_ip = db.query(BlockedIP).filter(
        BlockedIP.id == ip_id,
        BlockedIP.user_id == current_user.id
    ).first()
    
    if not blocked_ip:
        raise HTTPException(status_code=404, detail="IP não encontrado")
    
    blocked_ip.is_active = False
    db.commit()
    
    return {"success": True, "message": "IP desbloqueado"}

@router.get("/dashboard")
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna estatísticas do dashboard Viggio Shield"""
    deactivate_expired_blocks(db, current_user.id)
    db.commit()
    
    # Total de alvos ativos
    total_targets = db.query(MonitorTarget).filter(
        MonitorTarget.user_id == current_user.id,
        MonitorTarget.is_active == True
    ).count()

    automations_this_month = db.query(MonitorTarget).filter(
        MonitorTarget.user_id == current_user.id,
        MonitorTarget.created_at >= current_month_start()
    ).count()
    automation_limit = AUTOMATION_MONTHLY_LIMITS.get(current_user.subscription_plan, 2)
    
    # Incidentes abertos
    open_incidents = db.query(MonitorIncident).filter(
        MonitorIncident.user_id == current_user.id,
        MonitorIncident.status == "open"
    ).count()
    
    # Incidentes críticos
    critical_incidents = db.query(MonitorIncident).filter(
        MonitorIncident.user_id == current_user.id,
        MonitorIncident.severity == "critical",
        MonitorIncident.status == "open"
    ).count()
    
    # IPs bloqueados ativos
    blocked_ips_count = db.query(BlockedIP).filter(
        BlockedIP.user_id == current_user.id,
        BlockedIP.is_active == True
    ).count()
    
    # Uptime médio
    targets = db.query(MonitorTarget).filter(
        MonitorTarget.user_id == current_user.id,
        MonitorTarget.is_active == True
    ).all()
    
    # Trata casos onde uptime_percentage pode ser None/NULL
    if targets:
        valid_uptimes = [t.uptime_percentage for t in targets if t.uptime_percentage is not None]
        avg_uptime = sum(valid_uptimes) / len(valid_uptimes) if valid_uptimes else 100.0
    else:
        avg_uptime = 100.0
    
    # Incidentes por tipo (últimos 7 dias)
    week_ago = datetime.utcnow() - timedelta(days=7)
    incidents_by_type = db.query(
        MonitorIncident.incident_type,
        func.count(MonitorIncident.id)
    ).filter(
        MonitorIncident.user_id == current_user.id,
        MonitorIncident.detected_at >= week_ago
    ).group_by(MonitorIncident.incident_type).all()
    
    return {
        "total_targets": total_targets,
        "open_incidents": open_incidents,
        "critical_incidents": critical_incidents,
        "blocked_ips": blocked_ips_count,
        "average_uptime": round(avg_uptime, 2),
        "automations_this_month": automations_this_month,
        "automation_monthly_limit": automation_limit,
        "incidents_by_type": {itype: count for itype, count in incidents_by_type}
    }
