"""
Network and Port Scanner
Escaneia portas e serviços em hosts
"""

import socket
import subprocess
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import re


class PortScanner:
    """Scanner de portas e serviços de rede"""
    
    # Portas comuns e seus serviços
    COMMON_PORTS = {
        20: 'FTP Data',
        21: 'FTP Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP Proxy',
        8443: 'HTTPS Alt',
        9200: 'Elasticsearch',
        27017: 'MongoDB'
    }
    
    # Portas conhecidas por problemas de segurança
    VULNERABLE_PORTS = {
        23: 'Telnet sem criptografia',
        21: 'FTP sem criptografia',
        445: 'SMB - vulnerável a EternalBlue',
        3389: 'RDP - alvo de ataques brute force',
        5900: 'VNC - frequentemente sem senha',
        6379: 'Redis - frequentemente sem autenticação'
    }
    
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
    
    def scan_host(self, host: str, ports: Optional[List[int]] = None, 
                  max_workers: int = 100) -> Dict[str, Any]:
        """Escaneia um host para portas abertas"""
        
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(self._check_port, host, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        service = self.COMMON_PORTS.get(port, 'Unknown')
                        is_vulnerable = port in self.VULNERABLE_PORTS
                        vulnerability = self.VULNERABLE_PORTS.get(port, '')
                        
                        port_info = {
                            'port': port,
                            'state': 'open',
                            'service': service,
                            'is_vulnerable': is_vulnerable,
                            'vulnerability': vulnerability,
                            'severity': 'HIGH' if is_vulnerable else 'MEDIUM'
                        }
                        
                        # Tentar detectar versão/banner
                        banner = self._grab_banner(host, port)
                        if banner:
                            port_info['banner'] = banner
                            port_info['version_info'] = self._parse_banner(banner)
                        
                        open_ports.append(port_info)
                except Exception:
                    pass
        
        # Análise de segurança
        vulnerabilities = self._analyze_security(open_ports)
        
        return {
            'host': host,
            'scan_time': self._get_timestamp(),
            'total_ports_scanned': len(ports),
            'open_ports': len(open_ports),
            'ports': sorted(open_ports, key=lambda x: x['port']),
            'vulnerabilities': vulnerabilities,
            'summary': self._generate_summary(open_ports, vulnerabilities)
        }
    
    def scan_range(self, network: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """Escaneia uma faixa de IPs"""
        
        # Parse network (ex: 192.168.1.0/24 ou 192.168.1.1-254)
        hosts = self._parse_network_range(network)
        results = []
        
        for host in hosts:
            try:
                result = self.scan_host(host, ports)
                if result['open_ports'] > 0:
                    results.append(result)
            except Exception:
                continue
        
        return {
            'network': network,
            'hosts_scanned': len(hosts),
            'hosts_with_open_ports': len(results),
            'results': results
        }
    
    def _check_port(self, host: str, port: int) -> bool:
        """Verifica se uma porta está aberta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Tenta capturar banner do serviço"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            # Enviar requisição básica para alguns serviços
            if port == 80 or port == 8080:
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
            elif port == 21:
                pass  # FTP envia banner automaticamente
            elif port == 25:
                pass  # SMTP envia banner automaticamente
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
        except Exception:
            return None
    
    def _parse_banner(self, banner: str) -> Dict[str, str]:
        """Parse banner para extrair informações de versão"""
        info = {}
        
        # Apache
        if 'Apache' in banner:
            match = re.search(r'Apache/([\d.]+)', banner)
            if match:
                info['server'] = 'Apache'
                info['version'] = match.group(1)
        
        # Nginx
        elif 'nginx' in banner:
            match = re.search(r'nginx/([\d.]+)', banner)
            if match:
                info['server'] = 'nginx'
                info['version'] = match.group(1)
        
        # OpenSSH
        elif 'OpenSSH' in banner:
            match = re.search(r'OpenSSH_([\d.p]+)', banner)
            if match:
                info['service'] = 'OpenSSH'
                info['version'] = match.group(1)
        
        # FTP
        elif 'FTP' in banner:
            info['service'] = 'FTP'
            if 'vsftpd' in banner:
                match = re.search(r'vsftpd ([\d.]+)', banner)
                if match:
                    info['version'] = match.group(1)
        
        return info
    
    def _analyze_security(self, open_ports: List[Dict]) -> List[Dict]:
        """Analisa riscos de segurança"""
        vulnerabilities = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            # Serviços sem criptografia
            if port in [21, 23, 80]:
                vulnerabilities.append({
                    'type': 'Unencrypted Service',
                    'severity': 'HIGH',
                    'port': port,
                    'service': service,
                    'description': f'{service} não usa criptografia. Dados trafegam em texto claro.',
                    'recommendation': f'Use alternativas seguras (SFTP, SSH, HTTPS)'
                })
            
            # Serviços de banco de dados expostos
            if port in [3306, 5432, 27017, 6379, 9200]:
                vulnerabilities.append({
                    'type': 'Database Exposed',
                    'severity': 'CRITICAL',
                    'port': port,
                    'service': service,
                    'description': f'Banco de dados {service} acessível externamente',
                    'recommendation': 'Restrinja acesso via firewall. Use VPN ou túnel SSH.'
                })
            
            # RDP exposto
            if port == 3389:
                vulnerabilities.append({
                    'type': 'RDP Exposed',
                    'severity': 'CRITICAL',
                    'port': port,
                    'service': service,
                    'description': 'RDP exposto é alvo frequente de ataques brute force',
                    'recommendation': 'Use VPN, implemente MFA, restrinja IPs permitidos'
                })
            
            # SMB exposto
            if port == 445:
                vulnerabilities.append({
                    'type': 'SMB Exposed',
                    'severity': 'CRITICAL',
                    'port': port,
                    'service': service,
                    'description': 'SMB vulnerável a exploits como EternalBlue',
                    'recommendation': 'Atualize Windows, desabilite SMBv1, use firewall'
                })
            
            # Versões desatualizadas
            if 'version_info' in port_info:
                version_info = port_info['version_info']
                if 'version' in version_info:
                    vuln = self._check_version_vulnerabilities(
                        version_info.get('server', version_info.get('service')),
                        version_info['version'],
                        port
                    )
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_version_vulnerabilities(self, software: str, version: str, port: int) -> Optional[Dict]:
        """Verifica vulnerabilidades conhecidas de versões"""
        
        vulnerable_versions = {
            'Apache': {
                '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
                '2.4.48': ['CVE-2021-40438']
            },
            'nginx': {
                '1.20.0': ['CVE-2021-23017']
            },
            'OpenSSH': {
                '7.4': ['CVE-2018-15473'],
                '7.7': ['CVE-2018-20685']
            }
        }
        
        if software in vulnerable_versions:
            for vuln_version, cves in vulnerable_versions[software].items():
                if version.startswith(vuln_version):
                    return {
                        'type': 'Vulnerable Version',
                        'severity': 'HIGH',
                        'port': port,
                        'service': software,
                        'version': version,
                        'cves': cves,
                        'description': f'{software} {version} possui vulnerabilidades conhecidas',
                        'recommendation': f'Atualize {software} para versão mais recente'
                    }
        
        return None
    
    def _parse_network_range(self, network: str) -> List[str]:
        """Parse range de rede"""
        hosts = []
        
        # CIDR notation (ex: 192.168.1.0/24)
        if '/' in network:
            # Implementação simplificada - apenas /24
            base = network.split('/')[0]
            base_parts = base.split('.')
            base_parts[-1] = '0'
            
            for i in range(1, 255):
                base_parts[-1] = str(i)
                hosts.append('.'.join(base_parts))
        
        # Range notation (ex: 192.168.1.1-254)
        elif '-' in network:
            base, range_part = network.rsplit('.', 1)
            start, end = map(int, range_part.split('-'))
            
            for i in range(start, end + 1):
                hosts.append(f"{base}.{i}")
        
        # Single host
        else:
            hosts.append(network)
        
        return hosts
    
    def _generate_summary(self, open_ports: List[Dict], vulnerabilities: List[Dict]) -> Dict:
        """Gera resumo do scan"""
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW'),
            'services_without_encryption': sum(1 for p in open_ports if p['port'] in [21, 23, 80]),
            'databases_exposed': sum(1 for p in open_ports if p['port'] in [3306, 5432, 27017, 6379, 9200])
        }
    
    def _get_timestamp(self) -> str:
        """Retorna timestamp atual"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'


def scan_ports(target: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
    """Função helper para scan de portas"""
    scanner = PortScanner()
    
    # Detectar se é um único host ou range
    if '/' in target or '-' in target.split('.')[-1]:
        return scanner.scan_range(target, ports)
    else:
        return scanner.scan_host(target, ports)
