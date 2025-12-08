"""
Multi-Language Code Scanner
Suporta análise de vulnerabilidades em múltiplas linguagens de programação
"""

import re
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class LanguagePattern:
    """Padrões de vulnerabilidade por linguagem"""
    name: str
    extensions: List[str]
    patterns: Dict[str, List[Dict[str, str]]]


class MultiLanguageScanner:
    """Scanner avançado para múltiplas linguagens"""
    
    def __init__(self):
        self.languages = self._initialize_language_patterns()
    
    def _initialize_language_patterns(self) -> Dict[str, LanguagePattern]:
        """Inicializa padrões de vulnerabilidade para cada linguagem"""
        
        return {
            'python': LanguagePattern(
                name='Python',
                extensions=['.py'],
                patterns={
                    'sql_injection': [
                        {'pattern': r'execute\([^)]*%s', 'severity': 'CRITICAL'},
                        {'pattern': r'cursor\.execute\([^)]*\+', 'severity': 'CRITICAL'},
                        {'pattern': r'raw\([^)]*%s', 'severity': 'HIGH'},
                    ],
                    'command_injection': [
                        {'pattern': r'os\.system\([^)]*\+', 'severity': 'CRITICAL'},
                        {'pattern': r'subprocess\.call\([^)]*shell=True', 'severity': 'CRITICAL'},
                        {'pattern': r'eval\(', 'severity': 'CRITICAL'},
                        {'pattern': r'exec\(', 'severity': 'CRITICAL'},
                    ],
                    'path_traversal': [
                        {'pattern': r'open\([^)]*\+', 'severity': 'HIGH'},
                        {'pattern': r'os\.path\.join\([^)]*user', 'severity': 'MEDIUM'},
                    ],
                    'unsafe_deserialization': [
                        {'pattern': r'pickle\.loads?\(', 'severity': 'CRITICAL'},
                        {'pattern': r'yaml\.load\(', 'severity': 'HIGH'},
                    ],
                    'hardcoded_secrets': [
                        {'pattern': r'password\s*=\s*["\'][^"\']{8,}["\']', 'severity': 'CRITICAL'},
                        {'pattern': r'api_key\s*=\s*["\'][^"\']+["\']', 'severity': 'CRITICAL'},
                        {'pattern': r'secret\s*=\s*["\'][^"\']+["\']', 'severity': 'HIGH'},
                    ]
                }
            ),
            
            'javascript': LanguagePattern(
                name='JavaScript/TypeScript',
                extensions=['.js', '.jsx', '.ts', '.tsx'],
                patterns={
                    'xss': [
                        {'pattern': r'innerHTML\s*=', 'severity': 'HIGH'},
                        {'pattern': r'document\.write\(', 'severity': 'HIGH'},
                        {'pattern': r'dangerouslySetInnerHTML', 'severity': 'MEDIUM'},
                    ],
                    'sql_injection': [
                        {'pattern': r'query\([^)]*\+', 'severity': 'CRITICAL'},
                        {'pattern': r'execute\([^)]*`\$\{', 'severity': 'CRITICAL'},
                    ],
                    'command_injection': [
                        {'pattern': r'eval\(', 'severity': 'CRITICAL'},
                        {'pattern': r'Function\(', 'severity': 'HIGH'},
                        {'pattern': r'exec\(', 'severity': 'CRITICAL'},
                        {'pattern': r'child_process', 'severity': 'MEDIUM'},
                    ],
                    'insecure_random': [
                        {'pattern': r'Math\.random\(\)', 'severity': 'MEDIUM'},
                    ],
                    'prototype_pollution': [
                        {'pattern': r'__proto__', 'severity': 'HIGH'},
                        {'pattern': r'constructor\.prototype', 'severity': 'MEDIUM'},
                    ]
                }
            ),
            
            'php': LanguagePattern(
                name='PHP',
                extensions=['.php'],
                patterns={
                    'sql_injection': [
                        {'pattern': r'mysql_query\([^)]*\$_', 'severity': 'CRITICAL'},
                        {'pattern': r'mysqli_query\([^)]*\$_', 'severity': 'CRITICAL'},
                        {'pattern': r'\$wpdb->query\([^)]*\$_', 'severity': 'CRITICAL'},
                    ],
                    'command_injection': [
                        {'pattern': r'exec\([^)]*\$_', 'severity': 'CRITICAL'},
                        {'pattern': r'system\([^)]*\$_', 'severity': 'CRITICAL'},
                        {'pattern': r'shell_exec\([^)]*\$_', 'severity': 'CRITICAL'},
                        {'pattern': r'passthru\([^)]*\$_', 'severity': 'CRITICAL'},
                    ],
                    'file_inclusion': [
                        {'pattern': r'include\([^)]*\$_', 'severity': 'CRITICAL'},
                        {'pattern': r'require\([^)]*\$_', 'severity': 'CRITICAL'},
                        {'pattern': r'include_once\([^)]*\$_', 'severity': 'CRITICAL'},
                    ],
                    'xss': [
                        {'pattern': r'echo\s+\$_(?!.*htmlspecialchars)', 'severity': 'HIGH'},
                        {'pattern': r'print\s+\$_(?!.*htmlspecialchars)', 'severity': 'HIGH'},
                    ],
                    'unsafe_deserialization': [
                        {'pattern': r'unserialize\([^)]*\$_', 'severity': 'CRITICAL'},
                    ]
                }
            ),
            
            'java': LanguagePattern(
                name='Java',
                extensions=['.java'],
                patterns={
                    'sql_injection': [
                        {'pattern': r'Statement\.execute\([^)]*\+', 'severity': 'CRITICAL'},
                        {'pattern': r'createQuery\([^)]*\+', 'severity': 'CRITICAL'},
                    ],
                    'command_injection': [
                        {'pattern': r'Runtime\.exec\(', 'severity': 'HIGH'},
                        {'pattern': r'ProcessBuilder\(', 'severity': 'MEDIUM'},
                    ],
                    'path_traversal': [
                        {'pattern': r'new File\([^)]*\+', 'severity': 'HIGH'},
                    ],
                    'xxe': [
                        {'pattern': r'DocumentBuilderFactory(?!.*setFeature)', 'severity': 'HIGH'},
                        {'pattern': r'SAXParserFactory(?!.*setFeature)', 'severity': 'HIGH'},
                    ],
                    'weak_crypto': [
                        {'pattern': r'Cipher\.getInstance\("DES', 'severity': 'HIGH'},
                        {'pattern': r'Cipher\.getInstance\("RC4', 'severity': 'HIGH'},
                        {'pattern': r'MessageDigest\.getInstance\("MD5', 'severity': 'MEDIUM'},
                    ]
                }
            ),
            
            'csharp': LanguagePattern(
                name='C#',
                extensions=['.cs'],
                patterns={
                    'sql_injection': [
                        {'pattern': r'SqlCommand\([^)]*\+', 'severity': 'CRITICAL'},
                        {'pattern': r'ExecuteNonQuery\([^)]*\+', 'severity': 'CRITICAL'},
                    ],
                    'command_injection': [
                        {'pattern': r'Process\.Start\([^)]*\+', 'severity': 'HIGH'},
                    ],
                    'xxe': [
                        {'pattern': r'XmlReader(?!.*DtdProcessing\.Prohibit)', 'severity': 'HIGH'},
                    ],
                    'weak_crypto': [
                        {'pattern': r'DESCryptoServiceProvider', 'severity': 'HIGH'},
                        {'pattern': r'MD5CryptoServiceProvider', 'severity': 'MEDIUM'},
                    ],
                    'ldap_injection': [
                        {'pattern': r'DirectorySearcher.*Filter.*\+', 'severity': 'HIGH'},
                    ]
                }
            ),
            
            'ruby': LanguagePattern(
                name='Ruby',
                extensions=['.rb'],
                patterns={
                    'sql_injection': [
                        {'pattern': r'find_by_sql\([^)]*\+', 'severity': 'CRITICAL'},
                        {'pattern': r'where\([^)]*\#{', 'severity': 'CRITICAL'},
                    ],
                    'command_injection': [
                        {'pattern': r'system\([^)]*\#{', 'severity': 'CRITICAL'},
                        {'pattern': r'exec\([^)]*\#{', 'severity': 'CRITICAL'},
                        {'pattern': r'`[^`]*\#{', 'severity': 'CRITICAL'},
                    ],
                    'unsafe_deserialization': [
                        {'pattern': r'Marshal\.load', 'severity': 'CRITICAL'},
                        {'pattern': r'YAML\.load(?!.*safe)', 'severity': 'HIGH'},
                    ],
                    'mass_assignment': [
                        {'pattern': r'attr_accessible', 'severity': 'MEDIUM'},
                    ]
                }
            ),
            
            'go': LanguagePattern(
                name='Go',
                extensions=['.go'],
                patterns={
                    'sql_injection': [
                        {'pattern': r'db\.Exec\([^)]*\+', 'severity': 'CRITICAL'},
                        {'pattern': r'db\.Query\([^)]*fmt\.Sprintf', 'severity': 'CRITICAL'},
                    ],
                    'command_injection': [
                        {'pattern': r'exec\.Command\([^)]*\+', 'severity': 'HIGH'},
                    ],
                    'path_traversal': [
                        {'pattern': r'os\.Open\([^)]*\+', 'severity': 'HIGH'},
                    ],
                    'weak_crypto': [
                        {'pattern': r'md5\.New\(\)', 'severity': 'MEDIUM'},
                        {'pattern': r'sha1\.New\(\)', 'severity': 'MEDIUM'},
                    ],
                    'race_condition': [
                        {'pattern': r'go\s+func\([^)]*\)\s*{[^}]*(?!.*sync\.)', 'severity': 'MEDIUM'},
                    ]
                }
            )
        }
    
    def detect_language(self, filename: str, code: str) -> str:
        """Detecta a linguagem de programação do código"""
        
        # Por extensão
        for lang_id, lang in self.languages.items():
            for ext in lang.extensions:
                if filename.endswith(ext):
                    return lang_id
        
        # Por conteúdo (fallback)
        if 'def ' in code and 'import ' in code:
            return 'python'
        elif 'function ' in code or 'const ' in code or 'let ' in code:
            return 'javascript'
        elif '<?php' in code:
            return 'php'
        elif 'public class' in code or 'private class' in code:
            return 'java'
        elif 'namespace ' in code and 'using ' in code:
            return 'csharp'
        elif 'def ' in code and 'end' in code:
            return 'ruby'
        elif 'package main' in code and 'func ' in code:
            return 'go'
        
        return 'unknown'
    
    def scan(self, code: str, filename: str = "unknown.txt") -> Dict[str, Any]:
        """Realiza scan de segurança no código"""
        
        language = self.detect_language(filename, code)
        
        if language == 'unknown':
            return {
                'language': 'Unknown',
                'vulnerabilities': [],
                'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }
        
        lang_config = self.languages[language]
        vulnerabilities = []
        lines = code.split('\n')
        
        # Procurar vulnerabilidades
        for vuln_type, patterns in lang_config.patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                severity = pattern_info['severity']
                
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': vuln_type.replace('_', ' ').title(),
                            'severity': severity,
                            'line': line_num,
                            'code': line.strip(),
                            'description': self._get_description(vuln_type, language),
                            'recommendation': self._get_recommendation(vuln_type, language)
                        })
        
        # Calcular resumo
        summary = {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
        }
        
        return {
            'language': lang_config.name,
            'vulnerabilities': vulnerabilities,
            'summary': summary
        }
    
    def _get_description(self, vuln_type: str, language: str) -> str:
        """Retorna descrição da vulnerabilidade"""
        descriptions = {
            'sql_injection': 'Possível SQL Injection - entrada do usuário concatenada em query SQL',
            'command_injection': 'Possível Command Injection - execução de comandos do sistema com entrada não sanitizada',
            'xss': 'Possível Cross-Site Scripting - saída não sanitizada pode executar scripts maliciosos',
            'path_traversal': 'Possível Path Traversal - acesso a arquivos fora do diretório permitido',
            'xxe': 'Possível XML External Entity - parser XML configurado de forma insegura',
            'unsafe_deserialization': 'Desserialização insegura - pode levar a execução remota de código',
            'weak_crypto': 'Criptografia fraca - algoritmo obsoleto ou inseguro',
            'hardcoded_secrets': 'Segredos hardcoded - credenciais ou chaves expostas no código',
            'insecure_random': 'Gerador de números aleatórios inseguro - não deve ser usado para segurança',
            'prototype_pollution': 'Possível Prototype Pollution - pode levar a execução de código',
            'file_inclusion': 'Possível File Inclusion - inclusão dinâmica de arquivos',
            'ldap_injection': 'Possível LDAP Injection - query LDAP com entrada não sanitizada',
            'race_condition': 'Possível Race Condition - goroutine sem sincronização adequada',
            'mass_assignment': 'Possível Mass Assignment - atribuição em massa não controlada'
        }
        return descriptions.get(vuln_type, 'Vulnerabilidade de segurança detectada')
    
    def _get_recommendation(self, vuln_type: str, language: str) -> str:
        """Retorna recomendação de correção"""
        recommendations = {
            'sql_injection': 'Use prepared statements ou parametrized queries',
            'command_injection': 'Evite executar comandos do sistema. Se necessário, valide e sanitize toda entrada',
            'xss': 'Use funções de escape apropriadas (htmlspecialchars, textContent, etc.)',
            'path_traversal': 'Valide e sanitize caminhos de arquivo, use whitelist de diretórios permitidos',
            'xxe': 'Desabilite external entities no parser XML',
            'unsafe_deserialization': 'Evite desserializar dados não confiáveis ou use formatos seguros como JSON',
            'weak_crypto': 'Use algoritmos modernos: AES-256, SHA-256 ou superior',
            'hardcoded_secrets': 'Use variáveis de ambiente ou gerenciadores de segredos',
            'insecure_random': 'Use crypto.randomBytes() ou secrets module',
            'prototype_pollution': 'Valide chaves de objetos e evite acesso a __proto__',
            'file_inclusion': 'Use whitelist de arquivos permitidos e valide paths',
            'ldap_injection': 'Escape caracteres especiais em queries LDAP',
            'race_condition': 'Use sync.Mutex ou channels para sincronização',
            'mass_assignment': 'Use strong_parameters ou whitelist de atributos permitidos'
        }
        return recommendations.get(vuln_type, 'Revise o código e aplique práticas seguras')


def scan_code(code: str, filename: str = "unknown.txt") -> Dict[str, Any]:
    """Função helper para scan de código"""
    scanner = MultiLanguageScanner()
    return scanner.scan(code, filename)
