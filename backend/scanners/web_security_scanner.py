"""Production-safe web posture scanner.

Only performs a small number of read-only HTTP requests plus DNS/TLS inspection.
It deliberately avoids injection payloads, brute force and port enumeration.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import socket
import ssl
import time
from urllib.parse import urljoin, urlparse

import requests


class WebScanError(ValueError):
    pass


def _finding(title: str, category: str, severity: str, evidence: str, remediation: str) -> dict:
    return {
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": "confirmed",
        "description": evidence,
        "evidence": evidence,
        "remediation": remediation,
        "location": "/",
    }


class WebSecurityScanner:
    USER_AGENT = "IronAI-Authorized-Security-Monitor/1.0"
    MAX_REDIRECTS = 5

    def __init__(self, target: str, timeout: int = 12, auth_headers: dict[str, str] | None = None):
        value = (target or "").strip()
        if not value:
            raise WebScanError("Target is required")
        if not value.startswith(("http://", "https://")):
            value = f"https://{value}"
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise WebScanError("Only valid HTTP/HTTPS targets are supported")
        self.target = value
        self.target_origin = (parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80))
        self.timeout = timeout
        self.auth_headers = dict(auth_headers or {})
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.USER_AGENT, "Accept": "text/html,application/xhtml+xml"})

    @staticmethod
    def _resolve_public(hostname: str) -> list[str]:
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)})
        except socket.gaierror as exc:
            raise WebScanError(f"DNS resolution failed for {hostname}: {exc}") from exc
        if not addresses:
            raise WebScanError(f"No IP address found for {hostname}")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise WebScanError("Private, local and reserved network targets are blocked")
        return addresses

    def _request(self, url: str) -> tuple[requests.Response, list[dict]]:
        redirects = []
        current = url
        for _ in range(self.MAX_REDIRECTS + 1):
            parsed = urlparse(current)
            self._resolve_public(parsed.hostname or "")
            current_origin = (parsed.scheme, (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme == "https" else 80))
            request_headers = self.auth_headers if current_origin == self.target_origin else {}
            started = time.perf_counter()
            response = self.session.get(current, headers=request_headers, timeout=self.timeout, allow_redirects=False, stream=True)
            response.elapsed_seconds = round(time.perf_counter() - started, 3)
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    return response, redirects
                next_url = urljoin(current, location)
                redirects.append({"status": response.status_code, "from": current, "to": next_url})
                current = next_url
                response.close()
                continue
            return response, redirects
        raise WebScanError("Target exceeded the redirect limit")

    def _tls(self, hostname: str, port: int = 443) -> dict:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=self.timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as secure:
                certificate = secure.getpeercert()
                expires = ssl.cert_time_to_seconds(certificate["notAfter"])
                issuer = dict(item[0] for item in certificate.get("issuer", []))
                subject = dict(item[0] for item in certificate.get("subject", []))
                return {
                    "version": secure.version(),
                    "cipher": secure.cipher()[0] if secure.cipher() else None,
                    "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat(),
                    "days_remaining": int((expires - time.time()) // 86400),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "subject": subject.get("commonName"),
                }

    @staticmethod
    def _technologies(headers: dict) -> list[str]:
        observed = []
        for name in ("Server", "X-Powered-By", "X-Generator", "Via"):
            if headers.get(name):
                observed.append(f"{name}: {headers[name]}")
        return observed

    def scan(self) -> dict:
        parsed = urlparse(self.target)
        hostname = parsed.hostname or ""
        addresses = self._resolve_public(hostname)
        response, redirects = self._request(self.target)
        raw_set_cookie = response.headers.get("Set-Cookie", "")
        headers = dict(response.headers)
        if "Set-Cookie" in headers:
            headers["Set-Cookie"] = "[redacted]"
        final_url = response.url
        findings = []

        required = {
            "Strict-Transport-Security": ("HSTS não configurado", "transport_security", "medium", "Ative Strict-Transport-Security com max-age adequado e includeSubDomains após validar HTTPS em todos os subdomínios."),
            "Content-Security-Policy": ("Content Security Policy ausente", "browser_security", "medium", "Defina uma Content-Security-Policy restritiva e evolua por report-only antes de aplicar bloqueio."),
            "X-Content-Type-Options": ("Proteção contra MIME sniffing ausente", "browser_security", "low", "Adicione X-Content-Type-Options: nosniff."),
            "X-Frame-Options": ("Proteção contra clickjacking ausente", "browser_security", "medium", "Use frame-ancestors na CSP ou X-Frame-Options conforme a compatibilidade necessária."),
            "Referrer-Policy": ("Referrer Policy não definida", "privacy", "low", "Defina Referrer-Policy, por exemplo strict-origin-when-cross-origin."),
            "Permissions-Policy": ("Permissions Policy não definida", "browser_security", "low", "Restrinja recursos do navegador não utilizados com Permissions-Policy."),
        }
        for header, (title, category, severity, remediation) in required.items():
            if not headers.get(header):
                findings.append(_finding(title, category, severity, f"O header {header} não foi observado em {final_url} (HTTP {response.status_code}).", remediation))

        if urlparse(final_url).scheme != "https":
            findings.append(_finding("Aplicação acessível sem HTTPS", "transport_security", "high", f"A URL final observada usa HTTP: {final_url}.", "Force HTTPS e redirecione todas as requisições HTTP antes de servir conteúdo."))

        set_cookie = raw_set_cookie
        if set_cookie and "secure" not in set_cookie.lower():
            findings.append(_finding("Cookie sem atributo Secure", "session_security", "medium", "Foi observado Set-Cookie sem o atributo Secure na resposta principal.", "Marque cookies de sessão como Secure, HttpOnly e SameSite."))
        if set_cookie and "httponly" not in set_cookie.lower():
            findings.append(_finding("Cookie sem atributo HttpOnly", "session_security", "medium", "Foi observado Set-Cookie sem o atributo HttpOnly na resposta principal.", "Aplique HttpOnly a cookies que não precisam ser lidos por JavaScript."))

        tls = None
        if urlparse(final_url).scheme == "https":
            try:
                tls = self._tls(urlparse(final_url).hostname or hostname, urlparse(final_url).port or 443)
                if tls["days_remaining"] < 30:
                    findings.append(_finding("Certificado TLS próximo do vencimento", "transport_security", "high" if tls["days_remaining"] < 7 else "medium", f"O certificado vence em {tls['days_remaining']} dias ({tls['expires_at']}).", "Renove e valide a cadeia do certificado antes do vencimento."))
            except (OSError, ssl.SSLError, KeyError) as exc:
                findings.append(_finding("Falha na validação TLS", "transport_security", "high", f"Não foi possível validar o certificado TLS: {exc}", "Corrija certificado, cadeia intermediária, hostname e configuração TLS."))

        probes = {}
        for path in ("/robots.txt", "/.well-known/security.txt"):
            try:
                probe, _ = self._request(urljoin(final_url, path))
                probes[path] = {"status": probe.status_code, "content_type": probe.headers.get("Content-Type")}
                probe.close()
            except (requests.RequestException, WebScanError) as exc:
                probes[path] = {"error": str(exc)}

        result = {
            "scanner": "web_security_scanner",
            "scan_mode": "authenticated_safe_read_only" if self.auth_headers else "safe_read_only",
            "target": self.target,
            "final_url": final_url,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "http": {"status": response.status_code, "response_time_ms": int(response.elapsed_seconds * 1000), "redirects": redirects, "headers": headers},
            "network": {"hostname": hostname, "ip_addresses": addresses},
            "tls": tls,
            "technologies": self._technologies(headers),
            "probes": probes,
            "findings": findings,
            "summary": {"findings_total": len(findings), "status": response.status_code, "reachable": True},
        }
        response.close()
        return result
