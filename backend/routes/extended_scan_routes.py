"""
Extended Scan Routes - Rotas adicionais com novas funcionalidades
"""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from typing import Optional, List
import json
from datetime import datetime
from database import get_db
from auth import get_current_user
from models.user import User
from models.scan import Scan
from pydantic import BaseModel
from middleware.subscription import increment_scan_count, check_subscription_status, check_tool_access

# Import novos scanners
from scanners.multilang_scanner import scan_code as multilang_scan
from scanners.dependency_scanner import scan_dependencies
from scanners.pdf_generator import generate_pdf_report
from scanners.port_scanner import scan_ports
from scanners.docker_graphql_scanner import scan_dockerfile, scan_docker_compose, scan_graphql
from scanners.ml_scanner import analyze_with_ml, get_security_metrics
from integrations.cicd import get_cicd_config
from routes.tools_routes import list_phishing_captures, list_generated_pages

router = APIRouter()


# ========== DEPENDENCY SCANNING ==========

class DependencyScanRequest(BaseModel):
    content: str
    file_type: str  # requirements.txt, package.json, composer.json, Gemfile, pom.xml


@router.post("/scan/dependencies")
async def scan_dependencies_endpoint(
    request: DependencyScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escaneia dependências em busca de CVEs"""
    try:
        if not check_tool_access("vulnerability_scanner", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "vulnerability_scanner",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        results = scan_dependencies(request.content, request.file_type)
        
        scan = Scan(
            user_id=current_user.id,
            scan_type="dependencies",
            target=request.file_type,
            status="completed",
            results=json.dumps(results),
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        return {
            "scan_id": scan.id,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== NETWORK/PORT SCANNING ==========

class PortScanRequest(BaseModel):
    target: str  # IP, hostname ou range (192.168.1.0/24)
    ports: Optional[list] = None


@router.post("/scan/ports")
async def scan_ports_endpoint(
    request: PortScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escaneia portas e serviços de rede"""
    try:
        # Verificar limite de scans
        check_result = check_subscription_status(current_user)
        if not check_result["active"]:
            raise HTTPException(status_code=403, detail=check_result["message"])
        if not check_tool_access("port_scanner", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "port_scanner",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        
        results = scan_ports(request.target, request.ports)
        
        scan = Scan(
            user_id=current_user.id,
            scan_type="network",
            target=request.target,
            status="completed",
            results=json.dumps(results),
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Incrementar contador de scans
        increment_scan_count(current_user, db)
        
        return {
            "scan_id": scan.id,
            "results": results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== DOCKER SCANNING ==========

class DockerScanRequest(BaseModel):
    content: str
    scan_type: str  # dockerfile, docker-compose


@router.post("/scan/docker")
async def scan_docker_endpoint(
    request: DockerScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escaneia Dockerfile ou docker-compose.yml"""
    try:
        if not check_tool_access("container_scanner", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "container_scanner",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        if request.scan_type == "dockerfile":
            results = scan_dockerfile(request.content)
        elif request.scan_type == "docker-compose":
            results = scan_docker_compose(request.content)
        else:
            raise HTTPException(status_code=400, detail="Invalid scan_type")
        
        scan = Scan(
            user_id=current_user.id,
            scan_type="docker",
            target=request.scan_type,
            status="completed",
            results=json.dumps(results),
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        return {
            "scan_id": scan.id,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== GRAPHQL SCANNING ==========

class GraphQLScanRequest(BaseModel):
    url: str
    headers: Optional[dict] = None


@router.post("/scan/graphql")
async def scan_graphql_endpoint(
    request: GraphQLScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escaneia API GraphQL"""
    try:
        if not check_tool_access("api_security_tester", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "api_security_tester",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        results = scan_graphql(request.url, request.headers)
        
        scan = Scan(
            user_id=current_user.id,
            scan_type="graphql",
            target=request.url,
            status="completed",
            results=json.dumps(results),
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        return {
            "scan_id": scan.id,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== ML-ENHANCED SCANNING ==========

class MLScanRequest(BaseModel):
    code: str


@router.post("/scan/ml")
async def scan_with_ml_endpoint(
    request: MLScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escaneia código com Machine Learning"""
    try:
        if not check_tool_access("vulnerability_scanner", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "vulnerability_scanner",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        results = analyze_with_ml(request.code)
        metrics = get_security_metrics(request.code)
        
        combined_results = {
            **results,
            "metrics": metrics
        }
        
        scan = Scan(
            user_id=current_user.id,
            scan_type="ml_analysis",
            target="ml_scan",
            status="completed",
            results=json.dumps(combined_results),
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        return {
            "scan_id": scan.id,
            "results": combined_results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== PDF REPORT GENERATION ==========

@router.get("/scans/{scan_id}/report")
async def generate_report_endpoint(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Gera relatório PDF do scan"""
    try:
        scan = db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == current_user.id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        selected = json.loads(scan.results) if scan.results else {}

        def extract_vulns(res: dict) -> List[dict]:
            vulns = []
            if isinstance(res, dict):
                if res.get('vulnerabilities'):
                    vulns = res['vulnerabilities']
                elif res.get('endpoint_results'):
                    for er in res['endpoint_results']:
                        for v in er.get('vulnerabilities', []):
                            vulns.append(v)
            return vulns

        def extract_summary(res: dict) -> dict:
            def to_int(x):
                try:
                    return int(x)
                except Exception:
                    return 0
            if not isinstance(res, dict):
                return {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            if res.get('summary'):
                s = res['summary']
                return {
                    'total': to_int(s.get('total', s.get('total_vulnerabilities', 0))),
                    'critical': to_int(s.get('critical', 0)),
                    'high': to_int(s.get('high', 0)),
                    'medium': to_int(s.get('medium', 0)),
                    'low': to_int(s.get('low', 0))
                }
            if res.get('severity_count'):
                sc = res['severity_count']
                return {
                    'total': to_int(res.get('total_vulnerabilities', sum(to_int(v) for v in sc.values()))),
                    'critical': to_int(sc.get('CRITICAL', 0)),
                    'high': to_int(sc.get('HIGH', 0)),
                    'medium': to_int(sc.get('MEDIUM', 0)),
                    'low': to_int(sc.get('LOW', 0))
                }
            vulns = extract_vulns(res)
            return {
                'total': to_int(len(vulns)),
                'critical': to_int(sum(1 for v in vulns if v.get('severity') == 'CRITICAL')),
                'high': to_int(sum(1 for v in vulns if v.get('severity') == 'HIGH')),
                'medium': to_int(sum(1 for v in vulns if v.get('severity') == 'MEDIUM')),
                'low': to_int(sum(1 for v in vulns if v.get('severity') == 'LOW'))
            }

        selected_vulns = extract_vulns(selected)
        selected_summary = extract_summary(selected)

        scan_data = {
            "scan_id": scan.id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "created_at": scan.created_at.isoformat(),
            "summary": selected_summary,
            "vulnerabilities": selected_vulns
        }

        scans_all = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).all()
        agg_sc = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        agg_total = 0
        tools_map = {
            'code': 'Code Scanner',
            'api': 'API Scanner',
            'dependencies': 'Dependency Scanner',
            'docker': 'Docker Scanner',
            'graphql': 'GraphQL Scanner',
            'network': 'Port Scanner'
        }
        tools_summary = {}
        scans_details = []
        for s in scans_all:
            res = {}
            try:
                res = json.loads(s.results) if s.results else {}
            except Exception:
                res = {}
            vulns = extract_vulns(res)
            summ = extract_summary(res)
            agg_total += summ.get('total', 0)
            agg_sc['CRITICAL'] += summ.get('critical', 0)
            agg_sc['HIGH'] += summ.get('high', 0)
            agg_sc['MEDIUM'] += summ.get('medium', 0)
            agg_sc['LOW'] += summ.get('low', 0)
            tname = tools_map.get(s.scan_type, s.scan_type)
            if tname not in tools_summary:
                tools_summary[tname] = {'tool': tname, 'scans': 0, 'vulnerabilities': 0}
            tools_summary[tname]['scans'] += 1
            tools_summary[tname]['vulnerabilities'] += summ.get('total', 0)
            try:
                raw_json = json.dumps(res, ensure_ascii=False, indent=2)
            except Exception:
                raw_json = str(res)
            lines_limit = 40
            max_len = 800
            lines = raw_json.splitlines()
            if len(lines) > lines_limit:
                raw_excerpt = "\n".join(lines[:lines_limit]) + "\n... (conteúdo truncado)"
            else:
                raw_excerpt = raw_json[:max_len] + ("\n... (conteúdo truncado)" if len(raw_json) > max_len else "")
            scans_details.append({
                'id': s.id,
                'tool': tname,
                'scan_type': s.scan_type,
                'target': s.target,
                'created_at': s.created_at.isoformat(),
                'total_vulnerabilities': summ.get('total', 0),
                'severity_count': {
                    'CRITICAL': summ.get('critical', 0),
                    'HIGH': summ.get('high', 0),
                    'MEDIUM': summ.get('medium', 0),
                    'LOW': summ.get('low', 0)
                },
                'raw_excerpt': raw_excerpt
            })

        try:
            phishing_captures = await list_phishing_captures(current_user)
        except Exception:
            phishing_captures = {"captures": []}
        for capture in phishing_captures.get('captures', []):
            try:
                raw_json = json.dumps(capture, ensure_ascii=False, indent=2)
            except Exception:
                raw_json = str(capture)
            lines_limit = 40
            max_len = 800
            lines = raw_json.splitlines()
            if len(lines) > lines_limit:
                raw_excerpt = "\n".join(lines[:lines_limit]) + "\n... (conteúdo truncado)"
            else:
                raw_excerpt = raw_json[:max_len] + ("\n... (conteúdo truncado)" if len(raw_json) > max_len else "")
            if 'Phishing Generator' not in tools_summary:
                tools_summary['Phishing Generator'] = {'tool': 'Phishing Generator', 'scans': 0, 'vulnerabilities': 0}
            tools_summary['Phishing Generator']['scans'] += 1
            scans_details.append({
                'id': capture.get('capture_id', 'N/A'),
                'tool': 'Phishing Generator',
                'scan_type': 'phishing_capture',
                'target': capture.get('page_id', 'N/A'),
                'created_at': capture.get('timestamp', 'N/A'),
                'total_vulnerabilities': 0,
                'severity_count': {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                },
                'raw_excerpt': raw_excerpt
            })

        try:
            generated_pages = await list_generated_pages(current_user)
        except Exception:
            generated_pages = {"pages": []}
        for page in generated_pages.get('pages', []):
            try:
                raw_json = json.dumps(page, ensure_ascii=False, indent=2)
            except Exception:
                raw_json = str(page)
            lines_limit = 40
            max_len = 800
            lines = raw_json.splitlines()
            if len(lines) > lines_limit:
                raw_excerpt = "\n".join(lines[:lines_limit]) + "\n... (conteúdo truncado)"
            else:
                raw_excerpt = raw_json[:max_len] + ("\n... (conteúdo truncado)" if len(raw_json) > max_len else "")
            if 'Phishing Generator' not in tools_summary:
                tools_summary['Phishing Generator'] = {'tool': 'Phishing Generator', 'scans': 0, 'vulnerabilities': 0}
            tools_summary['Phishing Generator']['scans'] += 1
            scans_details.append({
                'id': page.get('filename', 'N/A'),
                'tool': 'Phishing Generator',
                'scan_type': 'phishing_page',
                'target': page.get('short_url') or page.get('url') or 'N/A',
                'created_at': page.get('created_at', 'N/A'),
                'total_vulnerabilities': 0,
                'severity_count': {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                },
                'raw_excerpt': raw_excerpt
            })

        scan_data['user_overview'] = {
            'total_scans': len(scans_all),
            'total_vulnerabilities': agg_total,
            'severity_count': agg_sc
        }
        scan_data['tools_summary'] = list(tools_summary.values())
        scan_data['scans_details'] = scans_details
        
        pdf_bytes = generate_pdf_report(scan_data)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=security-report-{scan_id}.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/report/full")
async def generate_full_report(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        def extract_vulns(res: dict) -> List[dict]:
            vulns = []
            if isinstance(res, dict):
                if res.get('vulnerabilities'):
                    vulns = res['vulnerabilities']
                elif res.get('endpoint_results'):
                    for er in res['endpoint_results']:
                        for v in er.get('vulnerabilities', []):
                            vulns.append(v)
            return vulns

        def extract_summary(res: dict) -> dict:
            def to_int(x):
                try:
                    return int(x)
                except Exception:
                    return 0
            if not isinstance(res, dict):
                return {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            if res.get('summary'):
                s = res['summary']
                return {
                    'total': to_int(s.get('total', s.get('total_vulnerabilities', 0))),
                    'critical': to_int(s.get('critical', 0)),
                    'high': to_int(s.get('high', 0)),
                    'medium': to_int(s.get('medium', 0)),
                    'low': to_int(s.get('low', 0))
                }
            if res.get('severity_count'):
                sc = res['severity_count']
                return {
                    'total': to_int(res.get('total_vulnerabilities', sum(to_int(v) for v in sc.values()))),
                    'critical': to_int(sc.get('CRITICAL', 0)),
                    'high': to_int(sc.get('HIGH', 0)),
                    'medium': to_int(sc.get('MEDIUM', 0)),
                    'low': to_int(sc.get('LOW', 0))
                }
            vulns = extract_vulns(res)
            return {
                'total': to_int(len(vulns)),
                'critical': to_int(sum(1 for v in vulns if v.get('severity') == 'CRITICAL')),
                'high': to_int(sum(1 for v in vulns if v.get('severity') == 'HIGH')),
                'medium': to_int(sum(1 for v in vulns if v.get('severity') == 'MEDIUM')),
                'low': to_int(sum(1 for v in vulns if v.get('severity') == 'LOW'))
            }

        scans_all = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).all()
        agg_sc = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        agg_total = 0
        tools_map = {
            'code': 'Code Scanner',
            'api': 'API Scanner',
            'dependencies': 'Dependency Scanner',
            'docker': 'Docker Scanner',
            'graphql': 'GraphQL Scanner',
            'network': 'Port Scanner'
        }
        tools_summary = {}
        scans_details = []

        for s in scans_all:
            res = {}
            try:
                res = json.loads(s.results) if s.results else {}
            except Exception:
                res = {}
            vulns = extract_vulns(res)
            summ = extract_summary(res)
            agg_total += summ.get('total', 0)
            agg_sc['CRITICAL'] += summ.get('critical', 0)
            agg_sc['HIGH'] += summ.get('high', 0)
            agg_sc['MEDIUM'] += summ.get('medium', 0)
            agg_sc['LOW'] += summ.get('low', 0)
            tname = tools_map.get(s.scan_type, s.scan_type)
            if tname not in tools_summary:
                tools_summary[tname] = {'tool': tname, 'scans': 0, 'vulnerabilities': 0}
            tools_summary[tname]['scans'] += 1
            tools_summary[tname]['vulnerabilities'] += summ.get('total', 0)
            try:
                raw_json = json.dumps(res, ensure_ascii=False, indent=2)
            except Exception:
                raw_json = str(res)
            max_len = 3000
            raw_excerpt = (raw_json[:max_len] + ('\n... (conteúdo truncado)' if len(raw_json) > max_len else ''))
            scans_details.append({
                'id': s.id,
                'tool': tname,
                'scan_type': s.scan_type,
                'target': s.target,
                'created_at': s.created_at.isoformat(),
                'total_vulnerabilities': summ.get('total', 0),
                'severity_count': {
                    'CRITICAL': summ.get('critical', 0),
                    'HIGH': summ.get('high', 0),
                    'MEDIUM': summ.get('medium', 0),
                    'LOW': summ.get('low', 0)
                },
                'raw_excerpt': raw_excerpt
            })

        try:
            phishing_captures = await list_phishing_captures(current_user)
        except Exception:
            phishing_captures = {"captures": []}
        for capture in phishing_captures.get('captures', []):
            try:
                raw_json = json.dumps(capture, ensure_ascii=False, indent=2)
            except Exception:
                raw_json = str(capture)
            max_len = 3000
            raw_excerpt = (raw_json[:max_len] + ('\n... (conteúdo truncado)' if len(raw_json) > max_len else ''))
            if 'Phishing Generator' not in tools_summary:
                tools_summary['Phishing Generator'] = {'tool': 'Phishing Generator', 'scans': 0, 'vulnerabilities': 0}
            tools_summary['Phishing Generator']['scans'] += 1
            scans_details.append({
                'id': capture.get('capture_id', 'N/A'),
                'tool': 'Phishing Generator',
                'scan_type': 'phishing_capture',
                'target': capture.get('page_id', 'N/A'),
                'created_at': capture.get('timestamp', 'N/A'),
                'total_vulnerabilities': 0,
                'severity_count': {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                },
                'raw_excerpt': raw_excerpt
            })

        try:
            generated_pages = await list_generated_pages(current_user)
        except Exception:
            generated_pages = {"pages": []}
        for page in generated_pages.get('pages', []):
            try:
                raw_json = json.dumps(page, ensure_ascii=False, indent=2)
            except Exception:
                raw_json = str(page)
            max_len = 3000
            raw_excerpt = (raw_json[:max_len] + ('\n... (conteúdo truncado)' if len(raw_json) > max_len else ''))
            if 'Phishing Generator' not in tools_summary:
                tools_summary['Phishing Generator'] = {'tool': 'Phishing Generator', 'scans': 0, 'vulnerabilities': 0}
            tools_summary['Phishing Generator']['scans'] += 1
            scans_details.append({
                'id': page.get('filename', 'N/A'),
                'tool': 'Phishing Generator',
                'scan_type': 'phishing_page',
                'target': page.get('short_url') or page.get('url') or 'N/A',
                'created_at': page.get('created_at', 'N/A'),
                'total_vulnerabilities': 0,
                'severity_count': {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                },
                'raw_excerpt': raw_excerpt
            })

        overall_summary = {
            'total': agg_total,
            'critical': agg_sc['CRITICAL'],
            'high': agg_sc['HIGH'],
            'medium': agg_sc['MEDIUM'],
            'low': agg_sc['LOW']
        }

        scan_data = {
            'scan_id': 'ALL',
            'scan_type': 'full',
            'target': 'Todos',
            'created_at': datetime.utcnow().isoformat(),
            'summary': overall_summary,
            'vulnerabilities': [],
            'user_overview': {
                'total_scans': len(scans_all),
                'total_vulnerabilities': agg_total,
                'severity_count': agg_sc
            },
            'tools_summary': list(tools_summary.values()),
            'scans_details': scans_details
        }

        pdf_bytes = generate_pdf_report(scan_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=security-report-full.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== CI/CD INTEGRATION ==========

class CICDConfigRequest(BaseModel):
    platform: str  # github, gitlab, jenkins, azure-devops, bitbucket
    scan_type: str = "code"


@router.post("/cicd/config")
async def get_cicd_config_endpoint(
    request: CICDConfigRequest,
    current_user: User = Depends(get_current_user)
):
    """Retorna configuração de CI/CD para plataforma"""
    try:
        config = get_cicd_config(request.platform, request.scan_type)
        
        if not config:
            raise HTTPException(status_code=400, detail="Unsupported platform")
        
        return config
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cicd/platforms")
async def list_cicd_platforms(current_user: User = Depends(get_current_user)):
    """Lista plataformas de CI/CD suportadas"""
    return {
        "platforms": [
            {
                "id": "github",
                "name": "GitHub Actions",
                "description": "Integração com GitHub Actions workflows"
            },
            {
                "id": "gitlab",
                "name": "GitLab CI/CD",
                "description": "Integração com GitLab CI/CD pipelines"
            },
            {
                "id": "jenkins",
                "name": "Jenkins",
                "description": "Integração com Jenkins pipelines"
            },
            {
                "id": "azure-devops",
                "name": "Azure DevOps",
                "description": "Integração com Azure Pipelines"
            },
            {
                "id": "bitbucket",
                "name": "Bitbucket Pipelines",
                "description": "Integração com Bitbucket Pipelines"
            }
        ]
    }


# ========== MULTI-LANGUAGE SUPPORT ==========

class MultiLangScanRequest(BaseModel):
    code: str
    filename: str


@router.post("/scan/multilang")
async def scan_multilang_endpoint(
    request: MultiLangScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escaneia código em múltiplas linguagens"""
    try:
        if not check_tool_access("code_scanner", current_user):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tool_locked",
                    "message": "Esta ferramenta não está disponível no seu plano atual",
                    "tool": "code_scanner",
                    "current_plan": current_user.subscription_plan,
                    "upgrade_url": "/pricing"
                }
            )
        results = multilang_scan(request.code, request.filename)
        
        scan = Scan(
            user_id=current_user.id,
            scan_type="multilang",
            target=request.filename,
            status="completed",
            results=json.dumps(results),
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        return {
            "scan_id": scan.id,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========== SUPPORTED LANGUAGES ==========

@router.get("/languages")
async def get_supported_languages(current_user: User = Depends(get_current_user)):
    """Lista linguagens de programação suportadas"""
    return {
        "languages": [
            {
                "name": "Python",
                "extensions": [".py"],
                "scanners": ["code", "dependencies", "ml"]
            },
            {
                "name": "JavaScript/TypeScript",
                "extensions": [".js", ".jsx", ".ts", ".tsx"],
                "scanners": ["code", "dependencies"]
            },
            {
                "name": "PHP",
                "extensions": [".php"],
                "scanners": ["code", "dependencies"]
            },
            {
                "name": "Java",
                "extensions": [".java"],
                "scanners": ["code", "dependencies"]
            },
            {
                "name": "C#",
                "extensions": [".cs"],
                "scanners": ["code"]
            },
            {
                "name": "Ruby",
                "extensions": [".rb"],
                "scanners": ["code", "dependencies"]
            },
            {
                "name": "Go",
                "extensions": [".go"],
                "scanners": ["code"]
            }
        ]
    }


# ========== ANALYTICS ==========

@router.get("/analytics/overview")
async def get_analytics_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna overview analítico dos scans"""
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).all()
    
    # Estatísticas por tipo de scan
    scan_types = {}
    total_vulns_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    vulnerabilities_trend = []
    
    for scan in scans:
        scan_type = scan.scan_type
        scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        
        if scan.results:
            results = json.loads(scan.results)
            summary = results.get('summary', {})
            
            for severity in ['critical', 'high', 'medium', 'low']:
                count = summary.get(severity, 0)
                total_vulns_by_severity[severity.upper()] += count
    
    return {
        "total_scans": len(scans),
        "scans_by_type": scan_types,
        "vulnerabilities_by_severity": total_vulns_by_severity,
        "average_vulnerabilities_per_scan": sum(total_vulns_by_severity.values()) / len(scans) if scans else 0,
        "most_common_scan_type": max(scan_types.items(), key=lambda x: x[1])[0] if scan_types else None
    }
