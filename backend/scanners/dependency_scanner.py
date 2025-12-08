"""
Dependency and CVE Scanner
Analisa dependências e busca vulnerabilidades conhecidas (CVEs)
"""

import re
import json
import requests
from typing import Dict, List, Any, Optional
from packaging import version
import subprocess


class DependencyScanner:
    """Scanner de dependências e CVEs"""
    
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.pypi_api = "https://pypi.org/pypi/{}/json"
        self.npm_api = "https://registry.npmjs.org/{}"
    
    def scan_python_dependencies(self, requirements_content: str) -> Dict[str, Any]:
        """Escaneia dependências Python"""
        
        dependencies = self._parse_requirements(requirements_content)
        results = []
        
        for dep in dependencies:
            vuln_info = self._check_python_package(dep['name'], dep.get('version'))
            if vuln_info:
                results.append(vuln_info)
        
        return self._format_results(results, 'Python')
    
    def scan_npm_dependencies(self, package_json_content: str) -> Dict[str, Any]:
        """Escaneia dependências Node.js/npm"""
        
        try:
            package_data = json.loads(package_json_content)
            dependencies = package_data.get('dependencies', {})
            dev_dependencies = package_data.get('devDependencies', {})
            
            all_deps = {**dependencies, **dev_dependencies}
            results = []
            
            for name, ver in all_deps.items():
                vuln_info = self._check_npm_package(name, ver)
                if vuln_info:
                    results.append(vuln_info)
            
            return self._format_results(results, 'Node.js/npm')
        
        except json.JSONDecodeError:
            return {'error': 'Invalid package.json format'}
    
    def scan_composer_dependencies(self, composer_json_content: str) -> Dict[str, Any]:
        """Escaneia dependências PHP/Composer"""
        
        try:
            composer_data = json.loads(composer_json_content)
            dependencies = composer_data.get('require', {})
            results = []
            
            for name, ver in dependencies.items():
                if name == 'php':
                    continue
                vuln_info = self._check_packagist_package(name, ver)
                if vuln_info:
                    results.append(vuln_info)
            
            return self._format_results(results, 'PHP/Composer')
        
        except json.JSONDecodeError:
            return {'error': 'Invalid composer.json format'}
    
    def scan_gemfile_dependencies(self, gemfile_content: str) -> Dict[str, Any]:
        """Escaneia dependências Ruby/Bundler"""
        
        dependencies = self._parse_gemfile(gemfile_content)
        results = []
        
        for dep in dependencies:
            vuln_info = self._check_ruby_gem(dep['name'], dep.get('version'))
            if vuln_info:
                results.append(vuln_info)
        
        return self._format_results(results, 'Ruby/Bundler')
    
    def scan_maven_dependencies(self, pom_xml_content: str) -> Dict[str, Any]:
        """Escaneia dependências Java/Maven"""
        
        dependencies = self._parse_pom_xml(pom_xml_content)
        results = []
        
        for dep in dependencies:
            vuln_info = self._check_maven_package(dep['group'], dep['artifact'], dep.get('version'))
            if vuln_info:
                results.append(vuln_info)
        
        return self._format_results(results, 'Java/Maven')
    
    def _parse_requirements(self, content: str) -> List[Dict[str, str]]:
        """Parse arquivo requirements.txt"""
        dependencies = []
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Remove extras e comentários
            line = re.sub(r'\[.*?\]', '', line)
            line = line.split('#')[0].strip()
            
            # Parse nome e versão
            match = re.match(r'([a-zA-Z0-9\-_.]+)\s*([><=!~]+)?\s*([0-9.]+)?', line)
            if match:
                name, operator, ver = match.groups()
                dependencies.append({
                    'name': name.lower(),
                    'version': ver,
                    'operator': operator or '=='
                })
        
        return dependencies
    
    def _parse_gemfile(self, content: str) -> List[Dict[str, str]]:
        """Parse Gemfile"""
        dependencies = []
        
        for line in content.split('\n'):
            line = line.strip()
            match = re.match(r"gem\s+['\"]([^'\"]+)['\"]\s*,?\s*['\"]?([~>=<]*\s*[0-9.]*)?", line)
            if match:
                name, ver = match.groups()
                dependencies.append({
                    'name': name,
                    'version': ver.strip() if ver else None
                })
        
        return dependencies
    
    def _parse_pom_xml(self, content: str) -> List[Dict[str, str]]:
        """Parse pom.xml"""
        dependencies = []
        
        # Regex simples para extrair dependências
        dep_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?(?:<version>(.*?)</version>)?.*?</dependency>'
        matches = re.finditer(dep_pattern, content, re.DOTALL)
        
        for match in matches:
            group, artifact, ver = match.groups()
            dependencies.append({
                'group': group,
                'artifact': artifact,
                'version': ver
            })
        
        return dependencies
    
    def _check_python_package(self, package_name: str, package_version: Optional[str]) -> Optional[Dict[str, Any]]:
        """Verifica vulnerabilidades em pacote Python"""
        
        # Banco de dados simples de vulnerabilidades conhecidas
        known_vulns = {
            'django': {
                '3.0': ['CVE-2020-9402', 'CVE-2020-13254'],
                '2.2': ['CVE-2019-19844', 'CVE-2019-14234']
            },
            'flask': {
                '0.12': ['CVE-2018-1000656']
            },
            'requests': {
                '2.19': ['CVE-2018-18074']
            },
            'pyyaml': {
                '5.3': ['CVE-2020-1747']
            }
        }
        
        if package_name in known_vulns and package_version:
            for vuln_version, cves in known_vulns[package_name].items():
                if package_version.startswith(vuln_version):
                    return {
                        'package': package_name,
                        'version': package_version,
                        'severity': 'HIGH',
                        'cves': cves,
                        'description': f'Vulnerabilidades conhecidas encontradas em {package_name} {package_version}',
                        'recommendation': f'Atualize para a versão mais recente de {package_name}'
                    }
        
        # Verificar se existe versão mais recente
        try:
            response = requests.get(self.pypi_api.format(package_name), timeout=5)
            if response.status_code == 200:
                data = response.json()
                latest_version = data['info']['version']
                
                if package_version and version.parse(latest_version) > version.parse(package_version):
                    return {
                        'package': package_name,
                        'version': package_version,
                        'severity': 'MEDIUM',
                        'cves': [],
                        'description': f'Versão desatualizada. Versão atual: {package_version}, Última: {latest_version}',
                        'recommendation': f'Considere atualizar para {latest_version}'
                    }
        except Exception:
            pass
        
        return None
    
    def _check_npm_package(self, package_name: str, package_version: str) -> Optional[Dict[str, Any]]:
        """Verifica vulnerabilidades em pacote npm"""
        
        known_vulns = {
            'lodash': {
                '4.17.15': ['CVE-2019-10744'],
                '4.17.11': ['CVE-2019-1010266']
            },
            'axios': {
                '0.18.0': ['CVE-2019-10742']
            },
            'jquery': {
                '3.3.1': ['CVE-2019-11358'],
                '2.2.0': ['CVE-2015-9251']
            }
        }
        
        clean_version = package_version.replace('^', '').replace('~', '').replace('>=', '').replace('>', '')
        
        if package_name in known_vulns:
            for vuln_version, cves in known_vulns[package_name].items():
                if clean_version.startswith(vuln_version):
                    return {
                        'package': package_name,
                        'version': clean_version,
                        'severity': 'HIGH',
                        'cves': cves,
                        'description': f'Vulnerabilidades conhecidas em {package_name} {clean_version}',
                        'recommendation': f'Atualize {package_name} para a versão mais recente'
                    }
        
        return None
    
    def _check_packagist_package(self, package_name: str, package_version: str) -> Optional[Dict[str, Any]]:
        """Verifica vulnerabilidades em pacote PHP/Composer"""
        
        # Vulnerabilidades conhecidas em pacotes PHP populares
        known_vulns = {
            'symfony/symfony': {
                '4.4': ['CVE-2020-15094', 'CVE-2020-5275']
            },
            'laravel/framework': {
                '7.0': ['CVE-2021-21263']
            }
        }
        
        clean_version = package_version.replace('^', '').replace('~', '')
        
        if package_name in known_vulns:
            for vuln_version, cves in known_vulns[package_name].items():
                if clean_version.startswith(vuln_version):
                    return {
                        'package': package_name,
                        'version': clean_version,
                        'severity': 'HIGH',
                        'cves': cves,
                        'description': f'Vulnerabilidades em {package_name}',
                        'recommendation': 'Atualize para versão corrigida'
                    }
        
        return None
    
    def _check_ruby_gem(self, gem_name: str, gem_version: Optional[str]) -> Optional[Dict[str, Any]]:
        """Verifica vulnerabilidades em Ruby gem"""
        
        known_vulns = {
            'rails': {
                '5.2': ['CVE-2020-8164', 'CVE-2020-8165']
            },
            'devise': {
                '4.7': ['CVE-2019-16109']
            }
        }
        
        if gem_name in known_vulns and gem_version:
            clean_version = gem_version.replace('~>', '').replace('>=', '').strip()
            for vuln_version, cves in known_vulns[gem_name].items():
                if clean_version.startswith(vuln_version):
                    return {
                        'package': gem_name,
                        'version': clean_version,
                        'severity': 'HIGH',
                        'cves': cves,
                        'description': f'Vulnerabilidades em {gem_name}',
                        'recommendation': 'Atualize a gem'
                    }
        
        return None
    
    def _check_maven_package(self, group: str, artifact: str, ver: Optional[str]) -> Optional[Dict[str, Any]]:
        """Verifica vulnerabilidades em dependência Maven"""
        
        full_name = f"{group}:{artifact}"
        
        known_vulns = {
            'org.springframework:spring-core': {
                '5.2': ['CVE-2020-5421']
            },
            'com.fasterxml.jackson.core:jackson-databind': {
                '2.9': ['CVE-2020-36518']
            }
        }
        
        if full_name in known_vulns and ver:
            for vuln_version, cves in known_vulns[full_name].items():
                if ver.startswith(vuln_version):
                    return {
                        'package': full_name,
                        'version': ver,
                        'severity': 'HIGH',
                        'cves': cves,
                        'description': f'Vulnerabilidades em {full_name}',
                        'recommendation': 'Atualize a dependência'
                    }
        
        return None
    
    def _format_results(self, vulnerabilities: List[Dict], ecosystem: str) -> Dict[str, Any]:
        """Formata resultados do scan"""
        
        summary = {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
        }
        
        return {
            'ecosystem': ecosystem,
            'vulnerabilities': vulnerabilities,
            'summary': summary,
            'scanned_at': self._get_timestamp()
        }
    
    def _get_timestamp(self) -> str:
        """Retorna timestamp atual"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'


def scan_dependencies(content: str, file_type: str) -> Dict[str, Any]:
    """Função helper para scan de dependências"""
    scanner = DependencyScanner()
    
    if file_type == 'requirements.txt':
        return scanner.scan_python_dependencies(content)
    elif file_type == 'package.json':
        return scanner.scan_npm_dependencies(content)
    elif file_type == 'composer.json':
        return scanner.scan_composer_dependencies(content)
    elif file_type == 'Gemfile':
        return scanner.scan_gemfile_dependencies(content)
    elif file_type == 'pom.xml':
        return scanner.scan_maven_dependencies(content)
    else:
        return {'error': 'Unsupported file type'}
