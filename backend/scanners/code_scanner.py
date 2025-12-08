import re
from typing import List, Dict
from datetime import datetime

class SQLInjectionScanner:
    """Scanner para detectar vulnerabilidades de Injeção SQL (A03:2021)"""
    
    SQL_PATTERNS = [
        r"execute\s*\(\s*['\"].*?\+.*?['\"]\s*\)",
        r"\.query\s*\(\s*['\"].*?\+.*?['\"]\s*\)",
        r"\.raw\s*\(\s*['\"].*?\+.*?['\"]\s*\)",
        r"cursor\.execute\s*\(\s*['\"].*?%.*?['\"]\s*%",
        r"WHERE.*?=.*?\+",
        r"SELECT.*?FROM.*?\+",
        r"INSERT.*?INTO.*?\+",
        r"UPDATE.*?SET.*?\+",
        r"DELETE.*?FROM.*?\+",
        r"request\.(GET|POST|args|form)\[.*?\].*?INTO",
    ]
    
    def scan(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in self.SQL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'HIGH',
                        'line': i,
                        'code': line.strip(),
                        'description': 'Possível vulnerabilidade de SQL Injection detectada',
                        'recommendation': 'Use prepared statements ou ORM com parametrização'
                    })
        
        return vulnerabilities


class XSSScanner:
    """Scanner para detectar vulnerabilidades de Cross-Site Scripting (A03:2021)"""
    
    XSS_PATTERNS = [
        r"innerHTML\s*=",
        r"document\.write\s*\(",
        r"eval\s*\(",
        r"dangerouslySetInnerHTML",
        r"\.html\s*\(\s*.*?request",
        r"render_template_string\s*\(",
        r"<.*?>\s*\{\{.*?\}\}",  # Template injection
    ]
    
    def scan(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in self.XSS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'HIGH',
                        'line': i,
                        'code': line.strip(),
                        'description': 'Possível vulnerabilidade de XSS detectada',
                        'recommendation': 'Sanitize e escape todos os inputs do usuário'
                    })
        
        return vulnerabilities


class AuthenticationScanner:
    """Scanner para detectar falhas de autenticação (A07:2021)"""
    
    AUTH_PATTERNS = [
        r"password\s*=\s*['\"].*?['\"]",  # Senhas hardcoded
        r"api_key\s*=\s*['\"].*?['\"]",
        r"secret\s*=\s*['\"].*?['\"]",
        r"token\s*=\s*['\"].*?['\"]",
        r"md5\s*\(",  # Hash fraco
        r"sha1\s*\(",
        r"session\[.*?\]\s*=\s*request",  # Session fixation
    ]
    
    def scan(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in self.AUTH_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Broken Authentication',
                        'severity': 'CRITICAL',
                        'line': i,
                        'code': line.strip(),
                        'description': 'Possível falha de autenticação detectada',
                        'recommendation': 'Use bibliotecas de autenticação seguras e não armazene credenciais em código'
                    })
        
        return vulnerabilities


class SensitiveDataScanner:
    """Scanner para detectar exposição de dados sensíveis (A02:2021)"""
    
    SENSITIVE_PATTERNS = [
        r"['\"]?password['\"]?\s*:\s*['\"]",
        r"credit_card|card_number",
        r"ssn|social_security",
        r"api[_-]?key",
        r"private[_-]?key",
        r"access[_-]?token",
        r"SECRET|PRIVATE|CONFIDENTIAL",
    ]
    
    def scan(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in self.SENSITIVE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'severity': 'HIGH',
                        'line': i,
                        'code': line.strip()[:50] + '...',
                        'description': 'Possível exposição de dados sensíveis',
                        'recommendation': 'Criptografe dados sensíveis e use variáveis de ambiente'
                    })
        
        return vulnerabilities


class CSRFScanner:
    """Scanner para detectar vulnerabilidades CSRF (A01:2021)"""
    
    CSRF_PATTERNS = [
        r"@app\.route\(.*?methods=\[.*?POST.*?\]",
        r"def.*?\(.*?request.*?\)",
        r"<form",
    ]
    
    def scan(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split('\n')
        has_csrf_protection = 'csrf' in code.lower()
        
        for i, line in enumerate(lines, 1):
            if 'POST' in line and 'csrf' not in code.lower():
                for pattern in self.CSRF_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Cross-Site Request Forgery (CSRF)',
                            'severity': 'MEDIUM',
                            'line': i,
                            'code': line.strip(),
                            'description': 'Possível vulnerabilidade CSRF - sem proteção detectada',
                            'recommendation': 'Implemente tokens CSRF em todos os formulários'
                        })
        
        return vulnerabilities


class InsecureDesignScanner:
    """Scanner para detectar design inseguro (A04:2021)"""
    
    DESIGN_PATTERNS = [
        r"pickle\.loads",  # Desserialização insegura
        r"yaml\.load\(",  # YAML unsafe
        r"exec\s*\(",
        r"__import__\s*\(",
        r"os\.system\s*\(",
        r"subprocess\.(call|run|Popen).*?shell=True",
    ]
    
    def scan(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in self.DESIGN_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Insecure Design',
                        'severity': 'CRITICAL',
                        'line': i,
                        'code': line.strip(),
                        'description': 'Padrão de código inseguro detectado',
                        'recommendation': 'Evite desserialização insegura e execução de código dinâmico'
                    })
        
        return vulnerabilities


class SecurityMisconfigurationScanner:
    """Scanner para detectar configurações incorretas (A05:2021)"""
    
    CONFIG_PATTERNS = [
        r"DEBUG\s*=\s*True",
        r"debug\s*=\s*True",
        r"ALLOWED_HOSTS\s*=\s*\[\s*\*",
        r"verify=False",  # SSL verification disabled
        r"ssl_verify=False",
    ]
    
    def scan(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in self.CONFIG_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'MEDIUM',
                        'line': i,
                        'code': line.strip(),
                        'description': 'Configuração de segurança incorreta detectada',
                        'recommendation': 'Desabilite modo debug em produção e valide SSL'
                    })
        
        return vulnerabilities


class ComponentScanner:
    """Scanner para detectar componentes vulneráveis (A06:2021)"""
    
    VULNERABLE_IMPORTS = [
        r"import\s+pickle",
        r"from\s+pickle\s+import",
        r"import\s+marshal",
    ]
    
    def scan(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in self.VULNERABLE_IMPORTS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Vulnerable Components',
                        'severity': 'MEDIUM',
                        'line': i,
                        'code': line.strip(),
                        'description': 'Uso de componente potencialmente vulnerável',
                        'recommendation': 'Revise o uso de bibliotecas e mantenha dependências atualizadas'
                    })
        
        return vulnerabilities


class PathTraversalScanner:
    """Scanner para detectar Path Traversal (A01:2021)"""
    
    PATH_PATTERNS = [
        r"open\s*\(\s*.*?request",
        r"file_get_contents\s*\(\s*\$_",
        r"include\s*\(\s*\$_",
        r"require\s*\(\s*\$_",
        r"readFile\s*\(\s*.*?req\.",
    ]
    
    def scan(self, code: str) -> List[Dict]:
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            for pattern in self.PATH_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Path Traversal',
                        'severity': 'HIGH',
                        'line': i,
                        'code': line.strip(),
                        'description': 'Possível vulnerabilidade de Path Traversal',
                        'recommendation': 'Valide e sanitize todos os caminhos de arquivo'
                    })
        
        return vulnerabilities


def scan_code(code: str, options: Dict = None) -> Dict:
    """Executa scanners no código fornecido baseado nas opções selecionadas"""
    
    # Opções padrão (todos habilitados)
    if options is None:
        options = {
            "sql_injection": True,
            "xss": True,
            "command_injection": True,
            "path_traversal": True,
            "hardcoded_secrets": True,
            "insecure_functions": True
        }
    
    # Mapeamento de opções para scanners
    scanner_map = {
        "sql_injection": SQLInjectionScanner(),
        "xss": XSSScanner(),
        "hardcoded_secrets": AuthenticationScanner(),
        "insecure_functions": SensitiveDataScanner(),
        "command_injection": InsecureDesignScanner(),
        "path_traversal": PathTraversalScanner(),
    }
    
    # Adiciona scanners extras que sempre rodam
    extra_scanners = [
        CSRFScanner(),
        SecurityMisconfigurationScanner(),
        ComponentScanner(),
    ]
    
    all_vulnerabilities = []
    
    # Executa scanners baseado nas opções
    for option_key, scanner in scanner_map.items():
        if options.get(option_key, True):
            vulnerabilities = scanner.scan(code)
            all_vulnerabilities.extend(vulnerabilities)
    
    # Executa scanners extras
    for scanner in extra_scanners:
        vulnerabilities = scanner.scan(code)
        all_vulnerabilities.extend(vulnerabilities)
    
    # Estatísticas
    severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in all_vulnerabilities:
        severity_count[vuln['severity']] += 1
    
    return {
        'total_vulnerabilities': len(all_vulnerabilities),
        'vulnerabilities': all_vulnerabilities,
        'severity_count': severity_count,
        'scan_date': datetime.now().isoformat(),
        'scan_options': options
    }
