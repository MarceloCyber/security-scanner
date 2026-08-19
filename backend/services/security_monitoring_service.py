"""Defensive detection and correlation for trusted web/WAF telemetry."""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import ipaddress
import re

from models.saas import SecurityEvent


SIGNALS = {
    "port_scan": ("high", "Varredura de portas detectada"),
    "web_scan": ("high", "Varredura web não autorizada detectada"),
    "reconnaissance": ("medium", "Reconhecimento automatizado detectado"),
    "brute_force": ("high", "Tentativa de força bruta detectada"),
    "credential_stuffing": ("critical", "Credential stuffing detectado"),
    "exploit_attempt": ("critical", "Tentativa de exploração detectada"),
    "path_traversal": ("critical", "Tentativa de path traversal detectada"),
    "sql_injection": ("critical", "Tentativa de SQL injection detectada"),
    "xss": ("high", "Tentativa de XSS detectada"),
    "ddos": ("critical", "Volume compatível com ataque de negação de serviço"),
    "unauthorized_access": ("high", "Acesso não autorizado repetido"),
    "malware": ("critical", "Atividade compatível com malware detectada"),
}

SCANNER_UA = re.compile(r"(?:nmap|nikto|sqlmap|masscan|nuclei|zgrab|gobuster|dirbuster|acunetix|nessus|openvas)", re.I)
SUSPICIOUS_PATH = re.compile(r"(?:/\.env|/\.git|wp-admin|phpmyadmin|\.\./|%2e%2e|etc/passwd|proc/self|cgi-bin|vendor/phpunit)", re.I)
SQLI_PATH = re.compile(r"(?:union(?:%20|\s)+select|sleep\(|benchmark\(|or(?:%20|\s)+1=1)", re.I)
XSS_PATH = re.compile(r"(?:<script|%3cscript|javascript:|onerror=|onload=)", re.I)

REMEDIATIONS = {
    "port_scan": "Bloqueie temporariamente o IP no WAF, restrinja portas públicas ao mínimo necessário e revise os logs do firewall para identificar outros destinos consultados.",
    "web_scan": "Bloqueie ou desafie o IP no WAF, aplique rate limiting e confirme nos logs se alguma rota sensível respondeu com sucesso.",
    "reconnaissance": "Aplique managed challenge ou rate limiting ao IP e reduza informações expostas em respostas, banners e páginas de erro.",
    "brute_force": "Bloqueie temporariamente o IP, imponha rate limiting no login, MFA e bloqueio progressivo de conta; revise logins bem-sucedidos no mesmo período.",
    "credential_stuffing": "Bloqueie o IP, force MFA, invalide sessões suspeitas e verifique contas acessadas; considere reset de senha quando houver sucesso anômalo.",
    "exploit_attempt": "Bloqueie o IP no WAF, preserve a evidência, revise respostas 2xx/3xx e logs da aplicação, corrija a rota afetada e rotacione credenciais se houver indício de sucesso.",
    "path_traversal": "Bloqueie o IP, normalize e valide caminhos no servidor, negue sequências de traversal no WAF e confira se arquivos sensíveis foram retornados.",
    "sql_injection": "Bloqueie o IP, use queries parametrizadas, ative regra WAF específica e revise banco e logs para consultas ou alterações inesperadas.",
    "xss": "Bloqueie ou desafie o IP, aplique encoding contextual, CSP e validação de entrada; revise se o payload foi persistido ou entregue a outros usuários.",
    "ddos": "Ative proteção DDoS e rate limiting no provedor, bloqueie a origem apenas quando útil e preserve capacidade do origin com cache e limites de conexão.",
    "unauthorized_access": "Bloqueie temporariamente a origem, revise autenticações bem-sucedidas, invalide sessões suspeitas e restrinja a rota por identidade e menor privilégio.",
    "malware": "Isole o ativo, bloqueie indicadores no WAF/EDR, preserve memória e logs, rotacione credenciais e execute resposta a incidente antes de restaurar o serviço.",
}


def safe_source_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def is_blockable_ip(value: str | None) -> bool:
    try:
        address = ipaddress.ip_address(value or "")
    except ValueError:
        return False
    return not any((address.is_private, address.is_loopback, address.is_link_local, address.is_reserved, address.is_multicast, address.is_unspecified))


def classify_telemetry(item: dict) -> dict | None:
    """Classify a sanitized aggregate emitted by a trusted reverse proxy/WAF."""
    signal = str(item.get("signal") or "").strip().lower()
    path = str(item.get("path") or "")[:2048]
    user_agent = str(item.get("user_agent") or "")[:512]
    count = max(1, int(item.get("request_count") or 1))
    window = max(1, int(item.get("window_seconds") or 60))
    status_code = item.get("status_code")

    if signal not in SIGNALS:
        rate = count / window
        if rate >= 30 or count >= 1000:
            signal = "ddos"
        elif SQLI_PATH.search(path):
            signal = "sql_injection"
        elif XSS_PATH.search(path):
            signal = "xss"
        elif SUSPICIOUS_PATH.search(path):
            signal = "path_traversal" if re.search(r"\.\./|%2e%2e|etc/passwd", path, re.I) else "exploit_attempt"
        elif status_code in (401, 403) and count >= 20:
            signal = "brute_force"
        elif SCANNER_UA.search(user_agent) or int(item.get("distinct_paths") or 0) >= 20:
            signal = "web_scan"
        else:
            return None

    severity, title = SIGNALS[signal]
    source_ip = safe_source_ip(item.get("source_ip"))
    description = f"{title} a partir de {source_ip or 'origem não informada'}"
    if path:
        description += f" contra {path}"
    description += f" ({count} requisição(ões) em {window}s)."
    return {
        "event_type": signal,
        "severity": severity,
        "title": title,
        "description": description[:8000],
        "remediation": REMEDIATIONS[signal],
        "source_ip": source_ip,
        "method": str(item.get("method") or "")[:12].upper() or None,
        "request_path": path or None,
        "status_code": status_code,
        "request_count": count,
        "evidence": {
            "window_seconds": window,
            "distinct_paths": int(item.get("distinct_paths") or 0),
            "user_agent": user_agent,
            "source": str(item.get("source") or "sensor")[:80],
        },
    }


def _fingerprint(organization_id: int, asset_id: int, detected: dict) -> str:
    correlated_path = "*" if detected["event_type"] in {"port_scan", "web_scan", "reconnaissance", "ddos"} else (detected.get("request_path") or "*")
    stable = "|".join([
        str(organization_id), str(asset_id), detected["event_type"],
        detected.get("source_ip") or "unknown", correlated_path,
    ])
    return hashlib.sha256(stable.encode()).hexdigest()


def correlate_event(db, organization_id: int, asset_id: int, sensor_id: int | None, detected: dict) -> SecurityEvent:
    now = datetime.utcnow()
    fingerprint = _fingerprint(organization_id, asset_id, detected)
    event = db.query(SecurityEvent).filter(
        SecurityEvent.organization_id == organization_id,
        SecurityEvent.fingerprint == fingerprint,
        SecurityEvent.status.in_(["open", "investigating"]),
        SecurityEvent.last_seen_at >= now - timedelta(hours=24),
    ).first()
    if event is None:
        event = SecurityEvent(
            organization_id=organization_id,
            asset_id=asset_id,
            sensor_id=sensor_id,
            fingerprint=fingerprint,
            event_type=detected["event_type"],
            severity=detected["severity"],
            title=detected["title"],
            description=detected["description"],
            remediation=detected["remediation"],
            source_ip=detected.get("source_ip"),
            method=detected.get("method"),
            request_path=detected.get("request_path"),
            status_code=detected.get("status_code"),
            request_count=detected["request_count"],
            evidence_json=detected.get("evidence"),
        )
        db.add(event)
    else:
        event.occurrence_count += 1
        event.request_count += detected["request_count"]
        event.last_seen_at = now
        event.description = detected["description"]
        event.evidence_json = detected.get("evidence")
        rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if rank.get(detected["severity"], 2) > rank.get(event.severity, 2):
            event.severity = detected["severity"]
    db.flush()
    return event
