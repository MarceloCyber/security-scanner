"""
Docker Security Scanner
Analisa vulnerabilidades em containers e imagens Docker
"""

import re
from typing import Dict, List, Any, Optional


class DockerScanner:
    """Scanner de segurança para Docker"""
    
    def __init__(self):
        self.dockerfile_best_practices = self._load_best_practices()
    
    def _load_best_practices(self) -> Dict:
        """Carrega boas práticas de Dockerfile"""
        return {
            'base_image': [
                {'pattern': r'FROM\s+.*:latest', 'severity': 'MEDIUM',
                 'message': 'Evite usar :latest. Use tags específicas de versão'},
                {'pattern': r'FROM\s+(?!scratch)(?!alpine)(?!distroless)', 'severity': 'LOW',
                 'message': 'Considere usar imagens mínimas (alpine, distroless)'}
            ],
            'user': [
                {'pattern': r'^(?!.*USER)', 'severity': 'HIGH',
                 'message': 'Container rodará como root. Adicione USER non-root'},
            ],
            'secrets': [
                {'pattern': r'(ENV|ARG)\s+(PASSWORD|SECRET|KEY|TOKEN)\s*=', 'severity': 'CRITICAL',
                 'message': 'Não armazene segredos em ENV ou ARG. Use Docker secrets'},
                {'pattern': r'COPY.*\.(key|pem|p12|pfx)', 'severity': 'CRITICAL',
                 'message': 'Não copie certificados/chaves para imagem'},
            ],
            'updates': [
                {'pattern': r'apt-get install.*(?!.*apt-get upgrade)', 'severity': 'MEDIUM',
                 'message': 'Execute apt-get upgrade para obter patches de segurança'},
                {'pattern': r'yum install.*(?!.*yum update)', 'severity': 'MEDIUM',
                 'message': 'Execute yum update para obter patches de segurança'},
            ],
            'cleanup': [
                {'pattern': r'apt-get install.*(?!.*rm.*apt)', 'severity': 'LOW',
                 'message': 'Limpe cache do apt após instalação'},
                {'pattern': r'RUN.*wget.*(?!.*rm)', 'severity': 'LOW',
                 'message': 'Remova arquivos temporários após uso'},
            ],
            'ports': [
                {'pattern': r'EXPOSE\s+(22|23|3389)', 'severity': 'HIGH',
                 'message': 'Porta administrativa exposta (SSH/Telnet/RDP)'},
            ],
            'add_vs_copy': [
                {'pattern': r'ADD\s+(?!.*\.tar)', 'severity': 'LOW',
                 'message': 'Prefira COPY ao invés de ADD (exceto para .tar)'},
            ],
            'health_check': [
                {'pattern': r'^(?!.*HEALTHCHECK)', 'severity': 'MEDIUM',
                 'message': 'Adicione HEALTHCHECK para monitoramento'},
            ]
        }
    
    def scan_dockerfile(self, dockerfile_content: str) -> Dict[str, Any]:
        """Escaneia Dockerfile em busca de problemas de segurança"""
        
        lines = dockerfile_content.split('\n')
        vulnerabilities = []
        
        # Verificar cada categoria de best practices
        for category, rules in self.dockerfile_best_practices.items():
            for rule in rules:
                pattern = rule['pattern']
                severity = rule['severity']
                message = rule['message']
                
                # Verificar padrão linha por linha
                for line_num, line in enumerate(lines, 1):
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith('#'):
                        continue
                    
                    if re.search(pattern, line_clean, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': category.replace('_', ' ').title(),
                            'severity': severity,
                            'line': line_num,
                            'code': line_clean,
                            'description': message,
                            'recommendation': self._get_recommendation(category)
                        })
        
        # Verificações especiais
        vulnerabilities.extend(self._check_special_cases(dockerfile_content, lines))
        
        return self._format_results(vulnerabilities, 'Dockerfile')
    
    def scan_docker_compose(self, compose_content: str) -> Dict[str, Any]:
        """Escaneia docker-compose.yml"""
        
        vulnerabilities = []
        lines = compose_content.split('\n')
        
        security_checks = [
            {
                'pattern': r'privileged:\s*true',
                'severity': 'CRITICAL',
                'type': 'Privileged Mode',
                'message': 'Container em modo privilegiado tem acesso total ao host',
                'recommendation': 'Remova privileged: true a menos que absolutamente necessário'
            },
            {
                'pattern': r'network_mode:\s*host',
                'severity': 'HIGH',
                'type': 'Host Network',
                'message': 'Container compartilha namespace de rede do host',
                'recommendation': 'Use redes Docker isoladas'
            },
            {
                'pattern': r'cap_add:.*SYS_ADMIN',
                'severity': 'HIGH',
                'type': 'Excessive Capabilities',
                'message': 'SYS_ADMIN capability é muito permissiva',
                'recommendation': 'Use capabilities mínimas necessárias'
            },
            {
                'pattern': r'volumes:.*:/.*:rw',
                'severity': 'MEDIUM',
                'type': 'Writable Volume',
                'message': 'Volume montado com permissão de escrita',
                'recommendation': 'Use :ro (read-only) quando possível'
            },
            {
                'pattern': r'environment:.*PASSWORD',
                'severity': 'HIGH',
                'type': 'Hardcoded Password',
                'message': 'Senha em variável de ambiente',
                'recommendation': 'Use Docker secrets ou arquivo .env'
            }
        ]
        
        for check in security_checks:
            for line_num, line in enumerate(lines, 1):
                if re.search(check['pattern'], line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': check['type'],
                        'severity': check['severity'],
                        'line': line_num,
                        'code': line.strip(),
                        'description': check['message'],
                        'recommendation': check['recommendation']
                    })
        
        return self._format_results(vulnerabilities, 'Docker Compose')
    
    def analyze_image_config(self, image_name: str, config: Dict) -> Dict[str, Any]:
        """Analisa configuração de imagem Docker"""
        
        vulnerabilities = []
        
        # Verificar se roda como root
        if config.get('User') == 'root' or not config.get('User'):
            vulnerabilities.append({
                'type': 'Root User',
                'severity': 'HIGH',
                'description': 'Container configurado para rodar como root',
                'recommendation': 'Configure USER non-root no Dockerfile'
            })
        
        # Verificar portas expostas
        exposed_ports = config.get('ExposedPorts', {})
        for port in exposed_ports:
            port_num = int(port.split('/')[0])
            if port_num in [22, 23, 3389]:
                vulnerabilities.append({
                    'type': 'Administrative Port',
                    'severity': 'HIGH',
                    'port': port_num,
                    'description': f'Porta administrativa {port_num} exposta',
                    'recommendation': 'Remova exposição de portas administrativas'
                })
        
        # Verificar env vars suspeitas
        env_vars = config.get('Env', [])
        for env in env_vars:
            if any(secret in env.upper() for secret in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
                vulnerabilities.append({
                    'type': 'Environment Secret',
                    'severity': 'CRITICAL',
                    'description': f'Possível segredo em variável de ambiente: {env.split("=")[0]}',
                    'recommendation': 'Use Docker secrets ao invés de ENV'
                })
        
        return {
            'image': image_name,
            'vulnerabilities': vulnerabilities,
            'summary': self._generate_summary(vulnerabilities)
        }
    
    def _check_special_cases(self, content: str, lines: List[str]) -> List[Dict]:
        """Verificações especiais"""
        issues = []
        
        # Verificar camadas excessivas
        run_commands = len([l for l in lines if l.strip().startswith('RUN')])
        if run_commands > 10:
            issues.append({
                'type': 'Excessive Layers',
                'severity': 'LOW',
                'line': 0,
                'code': f'{run_commands} comandos RUN',
                'description': 'Muitos comandos RUN criam camadas desnecessárias',
                'recommendation': 'Combine comandos RUN com && para reduzir camadas'
            })
        
        # Verificar se há WORKDIR
        if 'WORKDIR' not in content:
            issues.append({
                'type': 'Missing Workdir',
                'severity': 'LOW',
                'line': 0,
                'code': '',
                'description': 'WORKDIR não definido',
                'recommendation': 'Defina WORKDIR para organização'
            })
        
        # Verificar curl/wget sem verificação SSL
        for line_num, line in enumerate(lines, 1):
            if 'curl' in line and ('-k' in line or '--insecure' in line):
                issues.append({
                    'type': 'Insecure Download',
                    'severity': 'HIGH',
                    'line': line_num,
                    'code': line.strip(),
                    'description': 'Download sem verificação de certificado SSL',
                    'recommendation': 'Remova -k/--insecure e verifique certificados'
                })
            
            if 'wget' in line and '--no-check-certificate' in line:
                issues.append({
                    'type': 'Insecure Download',
                    'severity': 'HIGH',
                    'line': line_num,
                    'code': line.strip(),
                    'description': 'Download sem verificação de certificado',
                    'recommendation': 'Remova --no-check-certificate'
                })
        
        return issues
    
    def _get_recommendation(self, category: str) -> str:
        """Recomendações por categoria"""
        recommendations = {
            'base_image': 'Use tags específicas e imagens mínimas',
            'user': 'Crie e use usuário non-root',
            'secrets': 'Use Docker secrets ou gerenciador de segredos',
            'updates': 'Mantenha pacotes atualizados',
            'cleanup': 'Limpe arquivos temporários e cache',
            'ports': 'Exponha apenas portas necessárias',
            'add_vs_copy': 'Use COPY para arquivos locais',
            'health_check': 'Adicione HEALTHCHECK para monitoramento'
        }
        return recommendations.get(category, 'Revise configuração Docker')
    
    def _format_results(self, vulnerabilities: List[Dict], scan_type: str) -> Dict[str, Any]:
        """Formata resultados"""
        return {
            'scan_type': scan_type,
            'vulnerabilities': vulnerabilities,
            'summary': self._generate_summary(vulnerabilities),
            'scanned_at': self._get_timestamp()
        }
    
    def _generate_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Gera resumo"""
        return {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v.get('severity') == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v.get('severity') == 'LOW')
        }
    
    def _get_timestamp(self) -> str:
        """Timestamp atual"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'


class GraphQLScanner:
    """Scanner de segurança para APIs GraphQL"""
    
    def __init__(self):
        self.test_queries = self._load_test_queries()
    
    def _load_test_queries(self) -> List[Dict]:
        """Carrega queries de teste"""
        return [
            {
                'name': 'Introspection Query',
                'severity': 'MEDIUM',
                'query': '{ __schema { types { name } } }',
                'description': 'Introspection habilitada expõe schema completo',
                'check': lambda r: '__schema' in str(r)
            },
            {
                'name': 'Depth Attack',
                'severity': 'HIGH',
                'query': '{ user { friends { friends { friends { friends { name } } } } } }',
                'description': 'Query com profundidade excessiva pode causar DoS',
                'check': lambda r: 'error' not in str(r).lower() or 'depth' not in str(r).lower()
            },
            {
                'name': 'Batch Attack',
                'severity': 'HIGH',
                'query': '[' + '{ __typename },' * 100 + ']',
                'description': 'Batching pode ser usado para DoS',
                'check': lambda r: 'error' not in str(r).lower()
            }
        ]
    
    def scan_endpoint(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """Escaneia endpoint GraphQL"""
        
        import requests
        
        vulnerabilities = []
        headers = headers or {}
        headers['Content-Type'] = 'application/json'
        
        # Teste de introspection
        introspection_query = {
            'query': '{ __schema { queryType { name } } }'
        }
        
        try:
            response = requests.post(url, json=introspection_query, headers=headers, timeout=10)
            if response.status_code == 200 and '__schema' in response.text:
                vulnerabilities.append({
                    'type': 'Introspection Enabled',
                    'severity': 'MEDIUM',
                    'description': 'GraphQL introspection está habilitada',
                    'recommendation': 'Desabilite introspection em produção',
                    'endpoint': url
                })
        except Exception as e:
            pass
        
        # Teste de query profunda
        deep_query = {
            'query': '{ user { posts { comments { author { posts { comments { id } } } } } } }'
        }
        
        try:
            response = requests.post(url, json=deep_query, headers=headers, timeout=10)
            if response.status_code == 200 and 'depth' not in response.text.lower():
                vulnerabilities.append({
                    'type': 'No Depth Limiting',
                    'severity': 'HIGH',
                    'description': 'Sem limitação de profundidade de query',
                    'recommendation': 'Implemente max query depth',
                    'endpoint': url
                })
        except Exception:
            pass
        
        # Teste de campo suggestions
        malformed_query = {
            'query': '{ usrrrr { id } }'
        }
        
        try:
            response = requests.post(url, json=malformed_query, headers=headers, timeout=10)
            if 'did you mean' in response.text.lower():
                vulnerabilities.append({
                    'type': 'Field Suggestions',
                    'severity': 'LOW',
                    'description': 'API retorna sugestões de campos, vazando informações do schema',
                    'recommendation': 'Desabilite field suggestions',
                    'endpoint': url
                })
        except Exception:
            pass
        
        return {
            'endpoint': url,
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
                'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
                'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
                'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
            },
            'scanned_at': self._get_timestamp()
        }
    
    def _get_timestamp(self) -> str:
        """Timestamp atual"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'


def scan_dockerfile(content: str) -> Dict[str, Any]:
    """Helper para scan de Dockerfile"""
    scanner = DockerScanner()
    return scanner.scan_dockerfile(content)


def scan_docker_compose(content: str) -> Dict[str, Any]:
    """Helper para scan de docker-compose"""
    scanner = DockerScanner()
    return scanner.scan_docker_compose(content)


def scan_graphql(url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
    """Helper para scan GraphQL"""
    scanner = GraphQLScanner()
    return scanner.scan_endpoint(url, headers)
