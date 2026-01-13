"""
CI/CD Integration Module
Webhooks e integrações para Jenkins, GitLab CI, GitHub Actions
"""

from typing import Dict, Any, Optional
from datetime import datetime
import json
import hmac
import hashlib


class CICDIntegration:
    """Integração com sistemas de CI/CD"""
    
    def __init__(self):
        self.supported_platforms = ['github', 'gitlab', 'jenkins', 'azure-devops', 'bitbucket']
    
    def generate_webhook_config(self, platform: str, scan_type: str = 'code') -> Dict[str, Any]:
        """Gera configuração de webhook para plataforma"""
        
        configs = {
            'github': self._github_action_config(scan_type),
            'gitlab': self._gitlab_ci_config(scan_type),
            'jenkins': self._jenkins_pipeline_config(scan_type),
            'azure-devops': self._azure_pipeline_config(scan_type),
            'bitbucket': self._bitbucket_pipeline_config(scan_type)
        }
        
        return configs.get(platform, {})
    
    def _github_action_config(self, scan_type: str) -> Dict[str, Any]:
        """Configuração para GitHub Actions"""
        
        workflow = """
name: Iron Net

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Run Iron Net
      run: |
        curl -X POST ${{ secrets.SCANNER_API_URL }}/api/scan/code \\
          -H "Authorization: Bearer ${{ secrets.SCANNER_API_TOKEN }}" \\
          -H "Content-Type: application/json" \\
          -d '{
            "code": "$(cat **/*.py | base64)",
            "filename": "repository_scan"
          }'
    
    - name: Check Results
      run: |
        # Buscar resultados do scan
        SCAN_ID=$(curl -s ${{ secrets.SCANNER_API_URL }}/api/scans/latest \\
          -H "Authorization: Bearer ${{ secrets.SCANNER_API_TOKEN }}" \\
          | jq -r '.scan_id')
        
        # Verificar se há vulnerabilidades críticas
        CRITICAL=$(curl -s ${{ secrets.SCANNER_API_URL }}/api/scans/$SCAN_ID \\
          -H "Authorization: Bearer ${{ secrets.SCANNER_API_TOKEN }}" \\
          | jq -r '.summary.critical')
        
        if [ "$CRITICAL" -gt "0" ]; then
          echo "❌ Critical vulnerabilities found!"
          exit 1
        fi
        
        echo "✅ No critical vulnerabilities found"
"""
        
        return {
            'platform': 'GitHub Actions',
            'file': '.github/workflows/security-scanner.yml',
            'content': workflow,
            'setup_instructions': [
                '1. Crie arquivo .github/workflows/security-scanner.yml',
                '2. Adicione secrets: SCANNER_API_URL e SCANNER_API_TOKEN',
                '3. Commit e push para ativar workflow'
            ]
        }
    
    def _gitlab_ci_config(self, scan_type: str) -> Dict[str, Any]:
        """Configuração para GitLab CI"""
        
        config = """
stages:
  - security

security_scan:
  stage: security
  image: python:3.9
  script:
    - |
      # Install dependencies
      pip install requests
      
      # Run security scan
      python - <<EOF
      import requests
      import json
      import os
      import sys
      
      api_url = os.environ['SCANNER_API_URL']
      api_token = os.environ['SCANNER_API_TOKEN']
      
      headers = {
          'Authorization': f'Bearer {api_token}',
          'Content-Type': 'application/json'
      }
      
      # Scan code
      with open('main.py', 'r') as f:
          code = f.read()
      
      response = requests.post(
          f'{api_url}/api/scan/code',
          headers=headers,
          json={'code': code, 'filename': 'main.py'}
      )
      
      result = response.json()
      critical = result.get('summary', {}).get('critical', 0)
      
      if critical > 0:
          print(f'❌ {critical} critical vulnerabilities found!')
          sys.exit(1)
      
      print('✅ Security scan passed')
      EOF
  
  only:
    - main
    - merge_requests
  
  variables:
    SCANNER_API_URL: $SCANNER_API_URL
    SCANNER_API_TOKEN: $SCANNER_API_TOKEN
"""
        
        return {
            'platform': 'GitLab CI',
            'file': '.gitlab-ci.yml',
            'content': config,
            'setup_instructions': [
                '1. Crie arquivo .gitlab-ci.yml',
                '2. Configure variáveis: SCANNER_API_URL, SCANNER_API_TOKEN',
                '3. Pipeline será executado automaticamente'
            ]
        }
    
    def _jenkins_pipeline_config(self, scan_type: str) -> Dict[str, Any]:
        """Configuração para Jenkins"""
        
        pipeline = """
pipeline {
    agent any
    
    environment {
        SCANNER_API_URL = credentials('scanner-api-url')
        SCANNER_API_TOKEN = credentials('scanner-api-token')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Run security scanner
                    def response = sh(
                        script: '''
                            curl -X POST ${SCANNER_API_URL}/api/scan/code \\
                                -H "Authorization: Bearer ${SCANNER_API_TOKEN}" \\
                                -H "Content-Type: application/json" \\
                                -d '{
                                    "code": "'$(cat src/**/*.py | base64)'",
                                    "filename": "jenkins_scan"
                                }'
                        ''',
                        returnStdout: true
                    )
                    
                    def result = readJSON text: response
                    def critical = result.summary.critical
                    
                    if (critical > 0) {
                        error("❌ ${critical} critical vulnerabilities found!")
                    }
                    
                    echo "✅ Security scan passed"
                }
            }
        }
    }
    
    post {
        always {
            // Generate and archive report
            sh '''
                curl -X GET ${SCANNER_API_URL}/api/scans/latest/report \\
                    -H "Authorization: Bearer ${SCANNER_API_TOKEN}" \\
                    -o security-report.pdf
            '''
            archiveArtifacts artifacts: 'security-report.pdf'
        }
    }
}
"""
        
        return {
            'platform': 'Jenkins',
            'file': 'Jenkinsfile',
            'content': pipeline,
            'setup_instructions': [
                '1. Crie Jenkinsfile na raiz do projeto',
                '2. Configure credentials: scanner-api-url, scanner-api-token',
                '3. Crie pipeline job apontando para o Jenkinsfile'
            ]
        }
    
    def _azure_pipeline_config(self, scan_type: str) -> Dict[str, Any]:
        """Configuração para Azure DevOps"""
        
        config = """
trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: security-scanner-vars

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.9'
  
- script: |
    pip install requests
  displayName: 'Install dependencies'

- script: |
    python -c "
    import requests
    import sys
    
    response = requests.post(
        '$(SCANNER_API_URL)/api/scan/code',
        headers={
            'Authorization': 'Bearer $(SCANNER_API_TOKEN)',
            'Content-Type': 'application/json'
        },
        json={
            'code': open('main.py').read(),
            'filename': 'azure_scan'
        }
    )
    
    result = response.json()
    critical = result.get('summary', {}).get('critical', 0)
    
    if critical > 0:
        print(f'##vso[task.logissue type=error]{critical} critical vulnerabilities!')
        sys.exit(1)
    
    print('##vso[task.complete result=Succeeded]Security scan passed')
    "
  displayName: 'Run Iron Net'
  
- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'security-report.pdf'
    artifactName: 'SecurityReport'
"""
        
        return {
            'platform': 'Azure DevOps',
            'file': 'azure-pipelines.yml',
            'content': config,
            'setup_instructions': [
                '1. Crie azure-pipelines.yml',
                '2. Crie variable group "security-scanner-vars"',
                '3. Adicione variáveis: SCANNER_API_URL, SCANNER_API_TOKEN',
                '4. Configure pipeline no Azure DevOps'
            ]
        }
    
    def _bitbucket_pipeline_config(self, scan_type: str) -> Dict[str, Any]:
        """Configuração para Bitbucket Pipelines"""
        
        config = """
pipelines:
  default:
    - step:
        name: Security Scan
        image: python:3.9
        script:
          - pip install requests
          - |
            python - <<EOF
            import requests
            import sys
            
            response = requests.post(
                '$SCANNER_API_URL/api/scan/code',
                headers={
                    'Authorization': 'Bearer $SCANNER_API_TOKEN',
                    'Content-Type': 'application/json'
                },
                json={
                    'code': open('main.py').read(),
                    'filename': 'bitbucket_scan'
                }
            )
            
            result = response.json()
            critical = result.get('summary', {}).get('critical', 0)
            
            if critical > 0:
                print(f'❌ {critical} critical vulnerabilities found!')
                sys.exit(1)
            
            print('✅ Security scan passed')
            EOF
  
  branches:
    main:
      - step:
          name: Security Scan
          image: python:3.9
          script:
            - pip install requests
            - python scan.py
"""
        
        return {
            'platform': 'Bitbucket Pipelines',
            'file': 'bitbucket-pipelines.yml',
            'content': config,
            'setup_instructions': [
                '1. Crie bitbucket-pipelines.yml',
                '2. Configure repository variables: SCANNER_API_URL, SCANNER_API_TOKEN',
                '3. Habilite Pipelines no repositório'
            ]
        }
    
    def validate_webhook_signature(self, payload: bytes, signature: str, secret: str, platform: str) -> bool:
        """Valida assinatura de webhook"""
        
        if platform == 'github':
            expected = 'sha256=' + hmac.new(
                secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, signature)
        
        elif platform == 'gitlab':
            return signature == secret
        
        elif platform == 'bitbucket':
            expected = hmac.new(
                secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, signature)
        
        return False
    
    def parse_webhook_payload(self, payload: Dict, platform: str) -> Dict[str, Any]:
        """Parse payload do webhook"""
        
        parsers = {
            'github': self._parse_github_webhook,
            'gitlab': self._parse_gitlab_webhook,
            'bitbucket': self._parse_bitbucket_webhook
        }
        
        parser = parsers.get(platform)
        return parser(payload) if parser else {}
    
    def _parse_github_webhook(self, payload: Dict) -> Dict[str, Any]:
        """Parse GitHub webhook"""
        return {
            'event': payload.get('action'),
            'repository': payload.get('repository', {}).get('full_name'),
            'branch': payload.get('ref', '').split('/')[-1],
            'commit': payload.get('head_commit', {}).get('id'),
            'author': payload.get('head_commit', {}).get('author', {}).get('name'),
            'message': payload.get('head_commit', {}).get('message')
        }
    
    def _parse_gitlab_webhook(self, payload: Dict) -> Dict[str, Any]:
        """Parse GitLab webhook"""
        return {
            'event': payload.get('object_kind'),
            'repository': payload.get('project', {}).get('path_with_namespace'),
            'branch': payload.get('ref', '').split('/')[-1],
            'commit': payload.get('checkout_sha'),
            'author': payload.get('user_name'),
            'message': payload.get('commits', [{}])[0].get('message') if payload.get('commits') else None
        }
    
    def _parse_bitbucket_webhook(self, payload: Dict) -> Dict[str, Any]:
        """Parse Bitbucket webhook"""
        push = payload.get('push', {})
        changes = push.get('changes', [{}])[0] if push.get('changes') else {}
        
        return {
            'event': 'push',
            'repository': payload.get('repository', {}).get('full_name'),
            'branch': changes.get('new', {}).get('name'),
            'commit': changes.get('new', {}).get('target', {}).get('hash'),
            'author': payload.get('actor', {}).get('display_name'),
            'message': changes.get('new', {}).get('target', {}).get('message')
        }


def get_cicd_config(platform: str, scan_type: str = 'code') -> Dict[str, Any]:
    """Helper para obter configuração CI/CD"""
    integration = CICDIntegration()
    return integration.generate_webhook_config(platform, scan_type)
