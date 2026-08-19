import ipaddress
import socket
from urllib.parse import urlparse


def public_https_base(value: str) -> str:
    base = (value or "").strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A URL da integração deve usar HTTPS e não pode conter credenciais")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, 443)}
    except socket.gaierror as exc:
        raise ValueError("Não foi possível resolver o host da integração") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("Hosts privados, locais ou reservados não são permitidos")
    return base
