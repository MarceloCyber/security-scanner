"""Analise passiva em camadas para alvos web monitorados pelo Viggio Shield."""

from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse
import socket
import ssl
import requests


SECURITY_HEADERS = {
    "content-security-policy": ("CWE-693", "A05:2021", 6.1, "Defina uma Content-Security-Policy restritiva, começando por default-src 'self'."),
    "strict-transport-security": ("CWE-319", "A02:2021", 6.5, "Ative HSTS com max-age, includeSubDomains e preload após validar HTTPS em todos os subdomínios."),
    "x-content-type-options": ("CWE-16", "A05:2021", 4.3, "Adicione X-Content-Type-Options: nosniff."),
    "x-frame-options": ("CWE-1021", "A05:2021", 4.3, "Adicione X-Frame-Options: DENY ou use frame-ancestors na CSP."),
    "referrer-policy": ("CWE-200", "A01:2021", 3.7, "Defina Referrer-Policy: strict-origin-when-cross-origin ou no-referrer."),
    "permissions-policy": ("CWE-16", "A05:2021", 3.1, "Defina Permissions-Policy bloqueando recursos de navegador não utilizados."),
}


def finding(finding_type: str, severity: str, description: str, recommendation: str,
            layer: str, cwe: str = None, owasp: str = None, cvss: float = None,
            evidence: str = None, cves: List[str] = None, port: int = 0) -> Dict[str, Any]:
    return {
        "type": finding_type,
        "severity": severity.upper(),
        "description": description,
        "recommendation": recommendation,
        "layer": layer,
        "cwe": cwe,
        "owasp": owasp,
        "cvss": cvss,
        "evidence": evidence,
        "cves": cves or [],
        "port": port,
    }


def inspect_tls(host: str, port: int = 443) -> Dict[str, Any]:
    result = {"enabled": False, "findings": []}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secured:
                cert = secured.getpeercert()
                result.update({
                    "enabled": True,
                    "protocol": secured.version(),
                    "cipher": secured.cipher()[0] if secured.cipher() else None,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "expires_at": cert.get("notAfter"),
                })
                expires = cert.get("notAfter")
                if expires:
                    expires_at = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (expires_at - datetime.now(timezone.utc)).days
                    result["days_to_expire"] = days
                    if days < 30:
                        severity = "HIGH" if days < 0 else "MEDIUM"
                        result["findings"].append(finding(
                            "TLS Certificate Expiration", severity,
                            f"O certificado TLS expira em {days} dia(s).",
                            "Renove o certificado e automatize a renovação antes de 30 dias do vencimento.",
                            "TLS", "CWE-295", "A07:2021", 7.4 if days < 0 else 5.3,
                            f"notAfter={expires}"
                        ))
    except ssl.SSLCertVerificationError as exc:
        result["findings"].append(finding(
            "Invalid TLS Certificate", "HIGH", "O certificado TLS não pôde ser validado.",
            "Instale um certificado válido, com cadeia completa e nome correspondente ao domínio.",
            "TLS", "CWE-295", "A07:2021", 7.4, str(exc)
        ))
    except Exception as exc:
        result["error"] = str(exc)
    return result


def deep_web_scan(url: str, target_type: str = "application") -> Dict[str, Any]:
    """Executa verificações passivas e seguras de configuração HTTP, API e TLS."""
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(url if "://" in url else f"https://{url}")
    normalized_url = parsed.geturl()
    response = requests.get(
        normalized_url, timeout=(3.05, 10), allow_redirects=True,
        headers={"User-Agent": "IronNet-ViggioShield-DeepScan/2.0"}
    )
    final_parsed = urlparse(response.url)
    headers = {k.lower(): v for k, v in response.headers.items()}

    for header, (cwe, owasp, cvss, recommendation) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(finding(
                "Missing Security Header", "MEDIUM" if cvss >= 4 else "LOW",
                f"Cabeçalho de segurança ausente: {header}.", recommendation,
                "HTTP Headers", cwe, owasp, cvss, f"GET {response.url}: {header} ausente"
            ))

    if final_parsed.scheme == "http":
        findings.append(finding(
            "Unencrypted HTTP", "HIGH", "A aplicação aceita comunicação HTTP sem criptografia.",
            "Redirecione todo o tráfego para HTTPS e desative conteúdo misto.",
            "Transport", "CWE-319", "A02:2021", 7.5, response.url, port=80
        ))

    server = response.headers.get("Server")
    powered_by = response.headers.get("X-Powered-By")
    if server or powered_by:
        evidence = "; ".join(x for x in [f"Server: {server}" if server else None, f"X-Powered-By: {powered_by}" if powered_by else None] if x)
        findings.append(finding(
            "Technology Version Disclosure", "LOW", "Cabeçalhos revelam tecnologia ou versão do servidor.",
            "Remova ou generalize Server e X-Powered-By na borda e na aplicação.",
            "Information Exposure", "CWE-200", "A05:2021", 3.7, evidence
        ))

    for cookie in response.cookies:
        missing = []
        if not cookie.secure: missing.append("Secure")
        if not cookie.has_nonstandard_attr("HttpOnly"): missing.append("HttpOnly")
        if missing:
            findings.append(finding(
                "Insecure Cookie", "MEDIUM", f"Cookie {cookie.name} sem {', '.join(missing)}.",
                "Configure cookies de sessão com Secure, HttpOnly e SameSite=Lax ou Strict.",
                "Session", "CWE-614", "A07:2021", 5.4, f"Set-Cookie: {cookie.name}; atributos ausentes: {', '.join(missing)}"
            ))

    cors = requests.get(normalized_url, timeout=(3.05, 10), headers={"Origin": "https://attacker.invalid", "User-Agent": "IronNet-ViggioShield-DeepScan/2.0"})
    allow_origin = cors.headers.get("Access-Control-Allow-Origin")
    allow_credentials = cors.headers.get("Access-Control-Allow-Credentials", "").lower()
    if allow_origin == "https://attacker.invalid" or (allow_origin == "*" and allow_credentials == "true"):
        findings.append(finding(
            "CORS Misconfiguration", "HIGH", "A política CORS aceita origem não confiável.",
            "Use uma lista explícita de origens confiáveis e nunca combine credenciais com origem curinga.",
            "API Security", "CWE-942", "A05:2021", 8.1, f"Access-Control-Allow-Origin: {allow_origin}"
        ))

    tls = inspect_tls(final_parsed.hostname, final_parsed.port or 443) if final_parsed.scheme == "https" and final_parsed.hostname else {"enabled": False, "findings": []}
    findings.extend(tls.pop("findings", []))
    counts = {s: sum(1 for item in findings if item["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    return {
        "url": response.url,
        "status_code": response.status_code,
        "layers": ["Transport", "TLS", "HTTP Headers", "Session", "Information Exposure", "API Security"],
        "findings": findings,
        "summary": {"total": len(findings), **{k.lower(): v for k, v in counts.items()}},
        "tls": tls,
        "response_headers": dict(response.headers),
    }
