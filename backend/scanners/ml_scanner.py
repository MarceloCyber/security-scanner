"""
Machine Learning Enhanced Scanner
Usa ML para detectar padrões de vulnerabilidades e reduzir falsos positivos
"""

import re
import json
from typing import Dict, List, Any, Tuple
from collections import Counter
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
import joblib
import os


class MLVulnerabilityDetector:
    """Detector de vulnerabilidades com Machine Learning"""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            token_pattern=r'\b\w+\b'
        )
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.is_trained = False
        self.vulnerability_patterns = self._load_training_data()
    
    def _load_training_data(self) -> Dict[str, List[str]]:
        """Carrega dados de treinamento"""
        return {
            'sql_injection': [
                "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
                "query = 'DELETE FROM users WHERE name = %s' % name",
                "db.raw('UPDATE products SET price = ' + price)",
                "execute('INSERT INTO logs VALUES (' + data + ')')",
                "mysqli_query($conn, 'SELECT * FROM ' . $table)",
            ],
            'xss': [
                "document.write(userInput)",
                "innerHTML = '<div>' + userData + '</div>'",
                "echo $_GET['name']",
                "$('#result').html(userComment)",
                "response.write('<p>' + params.text + '</p>')",
            ],
            'command_injection': [
                "os.system('ping ' + host)",
                "exec('rm -rf ' + path)",
                "subprocess.call('tar -xf ' + filename, shell=True)",
                "Runtime.getRuntime().exec('ls ' + directory)",
                "system('cat ' + $file)",
            ],
            'path_traversal': [
                "open('/var/www/' + user_file)",
                "File(basePath + '/' + filename)",
                "readFile(dir + user_path)",
                "include($_GET['page'] + '.php')",
                "res.sendFile(path.join(__dirname, req.params.file))",
            ],
            'hardcoded_secrets': [
                "password = 'admin123'",
                "API_KEY = 'sk_live_51234567890'",
                "db_password = 'P@ssw0rd!'",
                "const token = 'ghp_1234567890abcdef'",
                "secret_key = 'my-secret-key-12345'",
            ],
            'safe_code': [
                "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                "element.textContent = userInput",
                "password = os.environ.get('DB_PASSWORD')",
                "subprocess.call(['ls', directory])",
                "with open(safe_path, 'r') as f: data = f.read()",
            ]
        }
    
    def train(self):
        """Treina o modelo com dados de exemplo"""
        
        X_train = []
        y_train = []
        
        # Preparar dados de treinamento
        for vuln_type, examples in self.vulnerability_patterns.items():
            for example in examples:
                X_train.append(example)
                y_train.append(vuln_type)
        
        # Vetorizar
        X_vectorized = self.vectorizer.fit_transform(X_train)
        
        # Treinar
        self.classifier.fit(X_vectorized, y_train)
        self.is_trained = True
    
    def predict_vulnerability(self, code: str) -> Tuple[str, float]:
        """Prediz tipo de vulnerabilidade e confiança"""
        
        if not self.is_trained:
            self.train()
        
        # Vetorizar código
        X = self.vectorizer.transform([code])
        
        # Predição
        prediction = self.classifier.predict(X)[0]
        probabilities = self.classifier.predict_proba(X)[0]
        confidence = max(probabilities)
        
        return prediction, confidence
    
    def analyze_code_patterns(self, code: str) -> Dict[str, Any]:
        """Analisa padrões no código usando ML"""
        
        lines = code.split('\n')
        detections = []
        
        for line_num, line in enumerate(lines, 1):
            line_clean = line.strip()
            
            if not line_clean or line_clean.startswith('#') or line_clean.startswith('//'):
                continue
            
            # ML prediction
            vuln_type, confidence = self.predict_vulnerability(line_clean)
            
            # Só reportar se confiança > 60% e não for safe_code
            if confidence > 0.6 and vuln_type != 'safe_code':
                severity = self._calculate_severity(vuln_type, confidence)
                
                detections.append({
                    'line': line_num,
                    'code': line_clean,
                    'type': vuln_type.replace('_', ' ').title(),
                    'severity': severity,
                    'confidence': float(confidence),
                    'ml_detected': True,
                    'description': self._get_ml_description(vuln_type, confidence),
                    'recommendation': self._get_ml_recommendation(vuln_type)
                })
        
        return {
            'detections': detections,
            'summary': self._generate_ml_summary(detections),
            'analysis_type': 'Machine Learning Enhanced'
        }
    
    def reduce_false_positives(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Usa ML para filtrar falsos positivos"""
        
        filtered = []
        
        for vuln in vulnerabilities:
            code = vuln.get('code', '')
            
            # Features para detectar falsos positivos
            false_positive_indicators = [
                'test' in code.lower(),
                'mock' in code.lower(),
                'example' in code.lower(),
                'TODO' in code,
                'FIXME' in code,
                code.strip().startswith('#'),
                code.strip().startswith('//'),
                len(code.strip()) < 10
            ]
            
            # Se tiver muitos indicadores de falso positivo, reduzir severidade
            if sum(false_positive_indicators) >= 2:
                vuln['confidence'] = vuln.get('confidence', 1.0) * 0.5
                vuln['possible_false_positive'] = True
            
            # Manter se confiança ainda for razoável
            if vuln.get('confidence', 1.0) >= 0.3:
                filtered.append(vuln)
        
        return filtered
    
    def extract_security_metrics(self, code: str) -> Dict[str, Any]:
        """Extrai métricas de segurança do código"""
        
        metrics = {
            'lines_of_code': len(code.split('\n')),
            'complexity_score': self._calculate_complexity(code),
            'security_score': self._calculate_security_score(code),
            'risk_level': 'LOW',
            'patterns_found': {}
        }
        
        # Padrões de segurança
        security_patterns = {
            'input_validation': len(re.findall(r'validate|sanitize|escape|filter', code, re.I)),
            'authentication': len(re.findall(r'auth|login|verify|check', code, re.I)),
            'encryption': len(re.findall(r'encrypt|hash|cipher|crypto', code, re.I)),
            'error_handling': len(re.findall(r'try|except|catch|error', code, re.I)),
            'logging': len(re.findall(r'log|audit|track', code, re.I)),
        }
        
        metrics['patterns_found'] = security_patterns
        
        # Calcular nível de risco
        security_score = metrics['security_score']
        if security_score < 30:
            metrics['risk_level'] = 'CRITICAL'
        elif security_score < 50:
            metrics['risk_level'] = 'HIGH'
        elif security_score < 70:
            metrics['risk_level'] = 'MEDIUM'
        else:
            metrics['risk_level'] = 'LOW'
        
        return metrics
    
    def _calculate_complexity(self, code: str) -> int:
        """Calcula complexidade ciclomática simplificada"""
        
        complexity = 1  # Base
        
        # Conta estruturas de controle
        complexity += len(re.findall(r'\bif\b', code))
        complexity += len(re.findall(r'\bfor\b', code))
        complexity += len(re.findall(r'\bwhile\b', code))
        complexity += len(re.findall(r'\bcase\b', code))
        complexity += len(re.findall(r'\bcatch\b', code))
        complexity += len(re.findall(r'\b&&\b|\b\|\|\b', code))
        
        return complexity
    
    def _calculate_security_score(self, code: str) -> float:
        """Calcula score de segurança (0-100)"""
        
        score = 100.0
        
        # Penalidades
        penalties = {
            'hardcoded_password': len(re.findall(r'password\s*=\s*["\'][^"\']+["\']', code, re.I)) * 15,
            'sql_concat': len(re.findall(r'SELECT.*\+|INSERT.*\+|UPDATE.*\+', code)) * 10,
            'eval_exec': len(re.findall(r'\beval\(|\bexec\(', code)) * 20,
            'shell_true': len(re.findall(r'shell\s*=\s*True', code)) * 15,
            'no_validation': 5 if 'validate' not in code.lower() else 0,
        }
        
        # Bônus
        bonuses = {
            'input_validation': 10 if 'validate' in code.lower() else 0,
            'parameterized': 10 if '?' in code and 'execute' in code else 0,
            'env_vars': 10 if 'environ' in code or 'getenv' in code else 0,
            'try_except': 5 if 'try:' in code else 0,
        }
        
        total_penalty = sum(penalties.values())
        total_bonus = sum(bonuses.values())
        
        score = max(0, min(100, score - total_penalty + total_bonus))
        
        return score
    
    def _calculate_severity(self, vuln_type: str, confidence: float) -> str:
        """Calcula severidade baseada em tipo e confiança"""
        
        base_severity = {
            'sql_injection': 'CRITICAL',
            'command_injection': 'CRITICAL',
            'xss': 'HIGH',
            'path_traversal': 'HIGH',
            'hardcoded_secrets': 'CRITICAL',
        }
        
        severity = base_severity.get(vuln_type, 'MEDIUM')
        
        # Ajustar baseado em confiança
        if confidence < 0.7:
            severity_map = {
                'CRITICAL': 'HIGH',
                'HIGH': 'MEDIUM',
                'MEDIUM': 'LOW'
            }
            severity = severity_map.get(severity, severity)
        
        return severity
    
    def _get_ml_description(self, vuln_type: str, confidence: float) -> str:
        """Descrição da detecção ML"""
        descriptions = {
            'sql_injection': f'ML detectou padrão de SQL Injection (confiança: {confidence:.1%})',
            'xss': f'ML detectou padrão de XSS (confiança: {confidence:.1%})',
            'command_injection': f'ML detectou execução insegura de comandos (confiança: {confidence:.1%})',
            'path_traversal': f'ML detectou manipulação insegura de paths (confiança: {confidence:.1%})',
            'hardcoded_secrets': f'ML detectou possível segredo hardcoded (confiança: {confidence:.1%})',
        }
        return descriptions.get(vuln_type, f'Vulnerabilidade detectada por ML (confiança: {confidence:.1%})')
    
    def _get_ml_recommendation(self, vuln_type: str) -> str:
        """Recomendação baseada em ML"""
        recommendations = {
            'sql_injection': 'Use prepared statements ou ORM',
            'xss': 'Sanitize output com escaping apropriado',
            'command_injection': 'Use APIs nativas ao invés de shell commands',
            'path_traversal': 'Valide e normalize paths de arquivos',
            'hardcoded_secrets': 'Use variáveis de ambiente ou vault',
        }
        return recommendations.get(vuln_type, 'Revise o código e aplique best practices')
    
    def _generate_ml_summary(self, detections: List[Dict]) -> Dict:
        """Gera resumo das detecções ML"""
        return {
            'total_detections': len(detections),
            'high_confidence': sum(1 for d in detections if d.get('confidence', 0) > 0.8),
            'medium_confidence': sum(1 for d in detections if 0.6 < d.get('confidence', 0) <= 0.8),
            'average_confidence': np.mean([d.get('confidence', 0) for d in detections]) if detections else 0,
            'critical': sum(1 for d in detections if d.get('severity') == 'CRITICAL'),
            'high': sum(1 for d in detections if d.get('severity') == 'HIGH'),
            'medium': sum(1 for d in detections if d.get('severity') == 'MEDIUM'),
            'low': sum(1 for d in detections if d.get('severity') == 'LOW'),
        }


def analyze_with_ml(code: str) -> Dict[str, Any]:
    """Helper para análise com ML"""
    detector = MLVulnerabilityDetector()
    return detector.analyze_code_patterns(code)


def get_security_metrics(code: str) -> Dict[str, Any]:
    """Helper para métricas de segurança"""
    detector = MLVulnerabilityDetector()
    return detector.extract_security_metrics(code)
