"""Motores locais do workspace AppSec do Viggio Shield."""

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Dict, List

from scanners.multilang_scanner import scan_code
from scanners.dependency_scanner import scan_dependencies
from scanners.docker_graphql_scanner import scan_dockerfile, scan_docker_compose, scan_graphql


IAC_RULES = [
    (r'0\.0\.0\.0/0', 'Public Network Exposure', 'HIGH', 'CWE-284', 'Restrinja o CIDR aos endereços estritamente necessários.'),
    (r'(?i)public[_-]?access\s*[:=]\s*(true|yes)', 'Public Resource', 'HIGH', 'CWE-284', 'Desative acesso público e use políticas privadas.'),
    (r'(?i)privileged\s*:\s*true', 'Privileged Container', 'CRITICAL', 'CWE-250', 'Remova privileged e conceda apenas capabilities necessárias.'),
    (r'(?i)runAsUser\s*:\s*0', 'Container Running as Root', 'HIGH', 'CWE-250', 'Configure runAsNonRoot e um UID sem privilégios.'),
    (r'(?i)allowPrivilegeEscalation\s*:\s*true', 'Privilege Escalation', 'HIGH', 'CWE-269', 'Defina allowPrivilegeEscalation como false.'),
    (r'(?i)(password|secret|token|access_key)\s*[:=]\s*["\'][^"\']+["\']', 'Hardcoded IaC Secret', 'CRITICAL', 'CWE-798', 'Use um secret manager e referências dinâmicas.'),
    (r'(?i)encrypted\s*[:=]\s*false', 'Encryption Disabled', 'HIGH', 'CWE-311', 'Ative criptografia em repouso com chave gerenciada.'),
    (r'(?i)versioning\s*[:=]\s*false', 'Versioning Disabled', 'MEDIUM', 'CWE-693', 'Ative versionamento para recuperação e auditoria.'),
]

SECRET_RULES = [
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'gh[pousr]_[A-Za-z0-9_]{20,}', 'GitHub Token'),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', 'Private Key'),
    (r'(?i)(api[_-]?key|client[_-]?secret|password|token)\s*[:=]\s*["\'][^"\']{8,}["\']', 'Hardcoded Credential'),
]


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        'total': len(findings),
        **{severity.lower(): sum(1 for item in findings if item.get('severity', '').upper() == severity)
           for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}
    }


def enrich(findings: List[Dict[str, Any]], scanner: str) -> List[Dict[str, Any]]:
    mapping = {
        'SQL Injection': ('CWE-89', 'A03:2021', 9.8),
        'Command Injection': ('CWE-78', 'A03:2021', 9.8),
        'Cross-Site Scripting (Xss)': ('CWE-79', 'A03:2021', 7.3),
        'Hardcoded Secrets': ('CWE-798', 'A07:2021', 9.1),
        'Path Traversal': ('CWE-22', 'A01:2021', 8.1),
        'Unsafe Deserialization': ('CWE-502', 'A08:2021', 9.8),
        'Weak Crypto': ('CWE-327', 'A02:2021', 7.5),
    }
    result = []
    for index, raw in enumerate(findings):
        item = dict(raw)
        cwe, owasp, cvss = mapping.get(item.get('type'), (item.get('cwe'), item.get('owasp'), None))
        item.update({
            'id': hashlib.sha1(f"{scanner}:{index}:{item}".encode()).hexdigest()[:12],
            'scanner': scanner,
            'cwe': item.get('cwe') or cwe,
            'owasp': item.get('owasp') or owasp,
            'cvss': item.get('cvss') or cvss,
            'status': 'open',
        })
        result.append(item)
    return result


def scan_sast(content: str, filename: str) -> Dict[str, Any]:
    result = scan_code(content, filename)
    findings = enrich(result.get('vulnerabilities', []), 'SAST')
    for line_number, line in enumerate(content.splitlines(), 1):
        for pattern, secret_type in SECRET_RULES:
            if re.search(pattern, line):
                findings.extend(enrich([{
                    'type': secret_type, 'severity': 'CRITICAL', 'line': line_number,
                    'code': '[REDACTED]', 'description': f'{secret_type} detectado no código.',
                    'recommendation': 'Revogue o segredo, remova-o do histórico e use um gerenciador de segredos.',
                    'cwe': 'CWE-798', 'owasp': 'A07:2021', 'cvss': 9.1
                }], 'Secrets'))
    return {'scanner': 'SAST + Secrets', 'language': result.get('language'), 'findings': findings, 'summary': summarize(findings)}


def scan_iac(content: str, filename: str) -> Dict[str, Any]:
    findings = []
    for line_number, line in enumerate(content.splitlines(), 1):
        for pattern, finding_type, severity, cwe, recommendation in IAC_RULES:
            if re.search(pattern, line):
                findings.append({
                    'type': finding_type, 'severity': severity, 'line': line_number,
                    'code': line.strip()[:240], 'description': f'Configuração insegura encontrada em {filename}.',
                    'recommendation': recommendation, 'cwe': cwe, 'owasp': 'A05:2021',
                    'cvss': 9.1 if severity == 'CRITICAL' else 7.5 if severity == 'HIGH' else 5.3
                })
    findings = enrich(findings, 'IaC Security')
    return {'scanner': 'IaC Security', 'findings': findings, 'summary': summarize(findings)}


def scan_sca(content: str, filename: str) -> Dict[str, Any]:
    result = scan_dependencies(content, filename)
    raw = result.get('vulnerabilities') or result.get('dependencies') or []
    findings = enrich(raw, 'SCA')
    ecosystem = result.get('ecosystem') or filename
    for item in findings:
        item['ecosystem'] = ecosystem
    return {'scanner': 'SCA', 'ecosystem': result.get('ecosystem'), 'findings': findings, 'summary': summarize(findings), 'raw_summary': result.get('summary')}


def generate_sbom(content: str, filename: str, project_name: str = 'viggio-project') -> Dict[str, Any]:
    components = []
    if filename == 'package.json':
        data = json.loads(content)
        for scope in ('dependencies', 'devDependencies'):
            for name, version in data.get(scope, {}).items():
                clean = str(version).lstrip('^~>=< ')
                components.append({'type': 'library', 'name': name, 'version': clean, 'purl': f'pkg:npm/{name}@{clean}', 'scope': scope})
    elif filename == 'requirements.txt':
        for line in content.splitlines():
            match = re.match(r'^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)', line.strip())
            if match:
                name, version = match.groups()
                components.append({'type': 'library', 'name': name, 'version': version, 'purl': f'pkg:pypi/{name}@{version}'})
    else:
        raise ValueError('SBOM suporta package.json e requirements.txt')
    return {
        'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'serialNumber': f'urn:uuid:{hashlib.md5(content.encode()).hexdigest()}',
        'version': 1, 'metadata': {'timestamp': datetime.utcnow().isoformat() + 'Z', 'component': {'type': 'application', 'name': project_name}},
        'components': components
    }


def discover_apis(content: str, filename: str) -> Dict[str, Any]:
    patterns = [
        ('GET', r'@(?:app|router)\.get\(["\']([^"\']+)'), ('POST', r'@(?:app|router)\.post\(["\']([^"\']+)'),
        ('ANY', r'(?:app|router)\.(?:use|route)\(["\']([^"\']+)'),
        ('ANY', r'\[(?:HttpGet|HttpPost|Route)\(["\']([^"\']+)'),
        ('ANY', r'@(RequestMapping|GetMapping|PostMapping)\(["\']([^"\']+)')
    ]
    endpoints = []
    for method, pattern in patterns:
        for match in re.finditer(pattern, content):
            path = match.groups()[-1]
            endpoints.append({'method': method, 'path': path, 'line': content[:match.start()].count('\n') + 1, 'documented': False})
    unique = list({f"{e['method']}:{e['path']}": e for e in endpoints}.values())
    return {'scanner': 'API Security', 'endpoints': unique, 'summary': {'total_endpoints': len(unique), 'undocumented': len(unique)}}


def run_appsec_scan(scan_type: str, content: str = '', filename: str = '', target_url: str = '') -> Dict[str, Any]:
    if scan_type == 'sast': return scan_sast(content, filename or 'source.py')
    if scan_type == 'sca': return scan_sca(content, filename)
    if scan_type == 'iac': return scan_iac(content, filename or 'infrastructure.tf')
    if scan_type == 'container':
        result = scan_docker_compose(content) if 'compose' in filename.lower() else scan_dockerfile(content)
        findings = enrich(result.get('vulnerabilities', []), 'Container Security')
        return {'scanner': 'Container Security', 'findings': findings, 'summary': summarize(findings)}
    if scan_type == 'api_inventory': return discover_apis(content, filename)
    if scan_type == 'graphql': return scan_graphql(target_url)
    if scan_type == 'sbom': return {'scanner': 'SBOM', 'sbom': generate_sbom(content, filename), 'summary': {'components': len(generate_sbom(content, filename)['components'])}}
    raise ValueError('Tipo de scan AppSec não suportado')


def fix_suggestion(finding: Dict[str, Any]) -> Dict[str, str]:
    """Sugestões determinísticas e revisáveis; nunca altera o código do cliente."""
    finding_type = str(finding.get('type', '')).lower()
    suggestions = [
        ('sql', 'Use parâmetros vinculados, nunca concatene entrada do usuário na query.', "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"),
        ('command', 'Evite shell=True; valide entradas com lista permitida e passe argumentos como lista.', "subprocess.run(['tool', validated_value], check=True, shell=False)"),
        ('secret', 'Revogue o segredo exposto e carregue a nova credencial de um cofre ou variável de ambiente.', "api_key = os.environ['API_KEY']"),
        ('xss', 'Use APIs de saída segura e sanitize HTML quando ele for realmente necessário.', "element.textContent = userSuppliedValue"),
        ('path', 'Resolva o caminho e valide que ele permanece dentro do diretório permitido.', "path = (BASE_DIR / filename).resolve(); assert path.is_relative_to(BASE_DIR)"),
        ('root', 'Execute o processo com usuário sem privilégios e aplique o princípio do menor privilégio.', 'USER appuser'),
        ('public', 'Restrinja a política de rede ao menor conjunto de IPs, serviços e contas possível.', 'cidr_blocks = ["10.0.0.0/16"]'),
    ]
    for term, guidance, template in suggestions:
        if term in finding_type:
            return {'guidance': guidance, 'patch_template': template, 'review_required': 'Revise e teste antes de aplicar em produção.'}
    package = finding.get('package')
    latest = finding.get('latest_version')
    ecosystem = str(finding.get('ecosystem') or '').lower()
    if package and latest:
        if 'npm' in ecosystem or 'node' in ecosystem:
            command = f'npm install {package}@{latest}'
            commands = {'macos': command, 'linux': command, 'windows': command}
        elif 'python' in ecosystem:
            commands = {'macos': f'python3 -m pip install --upgrade {package}=={latest}', 'linux': f'python3 -m pip install --upgrade {package}=={latest}', 'windows': f'py -m pip install --upgrade {package}=={latest}'}
        elif 'composer' in ecosystem or 'php' in ecosystem:
            command = f'composer require {package}:{latest}'
            commands = {'macos': command, 'linux': command, 'windows': command}
        elif 'ruby' in ecosystem:
            command = f'gem install {package} -v {latest}'
            commands = {'macos': command, 'linux': command, 'windows': command}
        else:
            commands = {'macos': f'# atualize {package} para {latest} no gerenciador do projeto', 'linux': f'# atualize {package} para {latest} no gerenciador do projeto', 'windows': f'# atualize {package} para {latest} no gerenciador do projeto'}
        return {'guidance': finding.get('recommendation', f'Atualize {package} para {latest}.'), 'patch_template': '', 'review_required': 'Execute os testes e valide o lockfile antes do deploy.', 'terminal_commands': commands}
    return {'guidance': finding.get('recommendation', 'Revise o achado e aplique uma correção compatível com o contexto.'), 'patch_template': '', 'review_required': 'Revise e teste antes de aplicar em produção.'}


def add_governance(result: Dict[str, Any], policy: Dict[str, Any] = None, filename: str = '') -> Dict[str, Any]:
    policy = policy or {}
    findings = result.get('findings', [])
    for item in findings:
        item['fix'] = fix_suggestion(item)
    max_severity = str(policy.get('fail_on') or 'critical').upper()
    order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    threshold = order.get(max_severity, 4)
    blocking = [item for item in findings if order.get(str(item.get('severity', '')).upper(), 0) >= threshold]
    result['quality_gate'] = {
        'policy': policy.get('name') or f'Bloquear {max_severity} e superiores',
        'fail_on': max_severity,
        'passed': not blocking,
        'blocking_findings': len(blocking),
        'message': 'Pipeline aprovado.' if not blocking else f'Pipeline bloqueado por {len(blocking)} achado(s) {max_severity}+.'
    }
    result['sarif'] = {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0',
        'runs': [{'tool': {'driver': {'name': 'Viggio Shield AppSec', 'rules': []}}, 'results': [
            {'ruleId': item.get('cwe') or item.get('type', 'VIGGIO'), 'level': str(item.get('severity', 'warning')).lower().replace('critical', 'error').replace('high', 'error').replace('medium', 'warning').replace('low', 'note'),
             'message': {'text': item.get('description') or item.get('type', 'Finding')},
             'locations': [{'physicalLocation': {'artifactLocation': {'uri': filename or 'source'}, 'region': {'startLine': int(item.get('line') or 1)}}}]}
            for item in findings
        ]}]}
    return result
