from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import Optional
import json
from datetime import datetime
from database import get_db
from auth import get_current_user
from models.user import User
from models.scan import Scan
from scanners.code_scanner import scan_code
from scanners.api_scanner import APISecurityScanner
from pydantic import BaseModel
from middleware.subscription import increment_scan_count, check_subscription_status

router = APIRouter()

class ScanOptions(BaseModel):
    sql_injection: bool = True
    xss: bool = True
    command_injection: bool = True
    path_traversal: bool = True
    hardcoded_secrets: bool = True
    insecure_functions: bool = True

class CodeScanRequest(BaseModel):
    code: str
    filename: Optional[str] = "unknown"
    language: Optional[str] = "auto"
    scan_options: Optional[ScanOptions] = None

class APIScanRequest(BaseModel):
    base_url: str
    endpoints: list
    headers: Optional[dict] = None

@router.post("/scan/code")
async def scan_code_endpoint(
    request: CodeScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escaneia código fonte em busca de vulnerabilidades"""
    try:
        # Verificar limite de scans
        check_result = check_subscription_status(current_user)
        if not check_result["active"]:
            raise HTTPException(status_code=403, detail=check_result["message"])
        
        # Prepara opções de scan
        scan_options = request.scan_options.dict() if request.scan_options else {
            "sql_injection": True,
            "xss": True,
            "command_injection": True,
            "path_traversal": True,
            "hardcoded_secrets": True,
            "insecure_functions": True
        }
        
        # Executa scan com opções
        results = scan_code(request.code, options=scan_options)
        
        # Salva no banco
        scan = Scan(
            user_id=current_user.id,
            scan_type="code",
            target=request.filename,
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/api")
async def scan_api_endpoint(
    request: APIScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escaneia API em busca de vulnerabilidades"""
    try:
        # Cria scanner
        scanner = APISecurityScanner(
            base_url=request.base_url,
            headers=request.headers or {}
        )
        
        # Executa scan
        results = scanner.full_scan(request.endpoints)
        
        # Salva no banco
        scan = Scan(
            user_id=current_user.id,
            scan_type="api",
            target=request.base_url,
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

@router.post("/scan/upload")
async def upload_file_scan(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload e escaneia arquivo de código"""
    try:
        # Lê conteúdo do arquivo
        content = await file.read()
        code = content.decode('utf-8')
        
        # Executa scan
        results = scan_code(code)
        
        # Salva no banco
        scan = Scan(
            user_id=current_user.id,
            scan_type="code",
            target=file.filename,
            status="completed",
            results=json.dumps(results),
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        return {
            "scan_id": scan.id,
            "filename": file.filename,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scans")
async def get_user_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna todos os scans do usuário"""
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).all()
    
    scans_list = []
    for scan in scans:
        scan_data = {
            "id": scan.id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "status": scan.status,
            "created_at": scan.created_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        }
        
        # Adiciona results para cálculo de vulnerabilidades
        if scan.results:
            try:
                scan_data["results"] = json.loads(scan.results)
            except:
                scan_data["results"] = {}
        
        scans_list.append(scan_data)
    
    return {
        "total": len(scans_list),
        "scans": scans_list
    }

@router.get("/scans/{scan_id}")
async def get_scan_details(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna detalhes de um scan específico"""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "status": scan.status,
        "results": json.loads(scan.results) if scan.results else None,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
    }

@router.get("/dashboard/stats")
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna estatísticas para o dashboard"""
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).all()
    
    total_scans = len(scans)
    total_vulnerabilities = 0
    severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    for scan in scans:
        if scan.results:
            results = json.loads(scan.results)
            if 'total_vulnerabilities' in results:
                total_vulnerabilities += results['total_vulnerabilities']
            if 'severity_count' in results:
                for severity, count in results['severity_count'].items():
                    if severity in severity_count:
                        severity_count[severity] += count
    
    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulnerabilities,
        "severity_count": severity_count,
        "recent_scans": [{
            "id": scan.id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "created_at": scan.created_at.isoformat()
        } for scan in scans[:5]]
    }

@router.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta um scan específico"""
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id
    ).first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    db.delete(scan)
    db.commit()
    
    return {
        "success": True,
        "message": "Scan deletado com sucesso",
        "scan_id": scan_id
    }
