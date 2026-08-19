const API_URL = '/api';
const CHECKOUT_PLAN_KEY = 'iron_ai_pending_checkout_plan';
const VALID_CHECKOUT_PLANS = ['starter', 'professional', 'enterprise'];

function pendingCheckoutPlan() {
    const requested = new URLSearchParams(window.location.search).get('checkout_plan');
    if (VALID_CHECKOUT_PLANS.includes(requested)) {
        sessionStorage.setItem(CHECKOUT_PLAN_KEY, requested);
        return requested;
    }
    const stored = sessionStorage.getItem(CHECKOUT_PLAN_KEY);
    return VALID_CHECKOUT_PLANS.includes(stored) ? stored : '';
}

function destinationAfterLogin() {
    const plan = pendingCheckoutPlan();
    return plan
        ? `pricing.html?resume_checkout=1&checkout_plan=${encodeURIComponent(plan)}`
        : 'platform.html';
}

// Force clear any old redirects
console.log('Auth.js loaded - version 2.0');

let pendingRenewalToken = '';

function openRenewalModal(detail) {
    pendingRenewalToken = detail.renewal_token || '';
    const modal = document.getElementById('renewalModal');
    const message = document.getElementById('renewalMessage');
    const planLabel = detail.plan === 'enterprise' ? 'Enterprise' : 'Professional';
    const duration = detail.plan === 'enterprise' ? '1 ano' : '4 meses';
    message.textContent = `O acesso do plano ${planLabel} terminou. Ao renovar no Stripe, a plataforma será reativada por mais ${duration}.`;
    modal.style.display = 'flex';
}

async function continueRenewal() {
    const button = document.getElementById('renewalContinue');
    const error = document.getElementById('renewalError');
    button.disabled = true;
    error.textContent = '';
    try {
        const response = await fetch(`${API_URL}/payments/renewal-checkout`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({renewal_token: pendingRenewalToken})
        });
        const data = await response.json();
        if (!response.ok || !data.checkout_url) throw new Error(typeof data.detail === 'string' ? data.detail : data.detail?.message || 'Não foi possível iniciar a renovação.');
        window.showTransitionLoading?.('Abrindo renovação segura...', 'Você será direcionado ao checkout do Stripe.');
        window.location.href = data.checkout_url;
    } catch (renewalError) {
        error.textContent = renewalError.message;
        error.className = 'message error';
        button.disabled = false;
    }
}

window.addEventListener('DOMContentLoaded', () => {
    document.getElementById('renewalContinue')?.addEventListener('click', continueRenewal);
    document.getElementById('renewalCancel')?.addEventListener('click', () => {
        pendingRenewalToken = '';
        document.getElementById('renewalModal').style.display = 'none';
        ['access_token', 'token', 'username'].forEach(key => localStorage.removeItem(key));
        window.location.href = 'index.html';
    });
});

// Toggle between login and register forms
document.getElementById('showRegister').addEventListener('click', (e) => {
    e.preventDefault();
    document.querySelector('.login-box:not(.register-box)').style.display = 'none';
    document.querySelector('.register-box').style.display = 'block';
});

document.getElementById('showLogin').addEventListener('click', (e) => {
    e.preventDefault();
    document.querySelector('.register-box').style.display = 'none';
    document.querySelector('.login-box:not(.register-box)').style.display = 'block';
});

document.getElementById('sso-login-button').addEventListener('click', () => {
    const slug = document.getElementById('sso-organization').value.trim().toLowerCase();
    const messageEl = document.getElementById('message');
    if (!/^[a-z0-9-]{2,160}$/.test(slug)) {
        messageEl.textContent = 'Informe o identificador da organização fornecido pelo administrador.';
        messageEl.className = 'message error';
        return;
    }
    window.showTransitionLoading?.('Conectando ao SSO...', 'Abrindo o provedor de identidade da sua organização.');
    window.location.href = `${API_URL}/auth/sso/${encodeURIComponent(slug)}/start`;
});

// Login form submission
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const accessKey = document.getElementById('access_key')?.value.trim() || '';
    const mfaCode = document.getElementById('mfa_code')?.value.trim() || '';
    const messageEl = document.getElementById('message');
    const submitBtn = document.querySelector('#loginForm button[type="submit"]');
    const originalBtnHTML = submitBtn ? submitBtn.innerHTML : '';
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Entrando...';
    }
    
    try {
        // Create form data for OAuth2
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);
        formData.append('access_key', accessKey);
        formData.append('mfa_code', mfaCode);
        const activeToken = localStorage.getItem('access_token');
        
        let response = await fetch(`${API_URL}/auth/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                ...(activeToken ? { 'Authorization': `Bearer ${activeToken}` } : {}),
            },
            body: formData
        });
        
        let data = await response.json();
        
        if (!response.ok && response.status === 409) {
            const recover = await showConfirmDialog({
                variant: 'warning',
                icon: 'fa-display',
                title: 'Substituir sessão ativa?',
                message: data.detail || 'Esta conta já está conectada em outro dispositivo.',
                details: 'Ao continuar, a sessão anterior será encerrada com segurança.',
                confirmText: 'Entrar neste dispositivo',
                confirmIcon: 'fa-right-to-bracket'
            });
            if (recover) {
                formData.append('force_session', 'true');
                response = await fetch(`${API_URL}/auth/token`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: formData
                });
                data = await response.json();
            }
        }
        
        if (response.ok) {
            // Store token and username
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('username', username);
            
            const checkoutPlan = pendingCheckoutPlan();
            messageEl.textContent = checkoutPlan
                ? 'Login realizado. Preparando o pagamento...'
                : 'Login realizado com sucesso!';
            messageEl.className = 'message success';
            window.showTransitionLoading?.(
                checkoutPlan ? 'Preparando pagamento seguro...' : 'Preparando seu acesso...',
                checkoutPlan ? 'Você será direcionado ao checkout.' : 'Carregando sua organização.'
            );
            window.location.replace(destinationAfterLogin());
        } else if (response.status === 402 && data.detail?.error === 'subscription_renewal_required') {
            openRenewalModal(data.detail);
            messageEl.textContent = data.detail.message;
            messageEl.className = 'message error';
        } else {
            messageEl.textContent = typeof data.detail === 'string' ? data.detail : data.detail?.message || 'Erro ao fazer login';
            messageEl.className = 'message error';
        }
    } catch (error) {
        console.error('Error:', error);
        messageEl.textContent = 'Erro ao conectar com o servidor';
        messageEl.className = 'message error';
    }
    finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnHTML;
        }
    }
});

// Register form submission
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('reg_username').value;
    const email = document.getElementById('reg_email').value;
    const password = document.getElementById('reg_password').value;
    const messageEl = document.getElementById('registerMessage');
    
    try {
        const response = await fetch(`${API_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            messageEl.textContent = 'Conta criada com sucesso! Redirecionando...';
            messageEl.className = 'message success';
            
            // Switch to login form
            setTimeout(() => {
                document.getElementById('reg_username').value = '';
                document.getElementById('reg_email').value = '';
                document.getElementById('reg_password').value = '';
                document.querySelector('.register-box').style.display = 'none';
                document.querySelector('.login-box:not(.register-box)').style.display = 'block';
                document.getElementById('username').value = username;
            }, 1500);
        } else {
            messageEl.textContent = data.detail || 'Erro ao criar conta';
            messageEl.className = 'message error';
        }
    } catch (error) {
        console.error('Error:', error);
        messageEl.textContent = 'Erro ao conectar com o servidor';
        messageEl.className = 'message error';
    }
});

// Só redireciona quando a sessão armazenada ainda é válida. Isso evita loop
// de login ao alternar entre o banco local e o banco de produção.
async function validateStoredSession() {
    const storedToken = localStorage.getItem('access_token');
    if (!storedToken) return;
    window.showPageProgress?.();
    try {
        const response = await fetch(`${API_URL}/auth/refresh`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${storedToken}` }
        });
        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('access_token', data.access_token);
            window.showTransitionLoading?.('Restaurando sua sessão...', 'Carregando sua organização.');
            window.location.replace(destinationAfterLogin());
            return;
        }
    } catch (_) {
        // Mantém a tela de login quando o servidor ainda está inicializando.
    } finally {
        window.hidePageProgress?.();
    }
    ['access_token', 'token', 'username'].forEach(key => localStorage.removeItem(key));
    ['access_token', 'token'].forEach(key => sessionStorage.removeItem(key));
}

async function handleSSOReturn() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('sso_code');
    const error = params.get('sso_error');
    if (error) {
        history.replaceState({}, '', window.location.pathname);
        const messageEl = document.getElementById('message');
        messageEl.textContent = error === 'expired' ? 'A tentativa de SSO expirou. Tente novamente.' : 'O provedor corporativo recusou o login ou não comprovou os requisitos de segurança.';
        messageEl.className = 'message error';
        return true;
    }
    if (!code) return false;
    history.replaceState({}, '', window.location.pathname);
    try {
        const response = await fetch(`${API_URL}/auth/sso/exchange`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
        const data = await response.json();
        if (response.status === 402 && data.detail?.error === 'subscription_renewal_required') {
            openRenewalModal(data.detail);
            return true;
        }
        if (!response.ok) throw new Error(data.detail || 'Código SSO inválido.');
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('username', data.username || 'SSO');
        window.showTransitionLoading?.('Validando acesso corporativo...', 'Carregando sua organização.');
        window.location.replace(destinationAfterLogin());
        return true;
    } catch (error) {
        const messageEl = document.getElementById('message');
        messageEl.textContent = error.message;
        messageEl.className = 'message error';
        return true;
    }
}

handleSSOReturn().then(handled => { if (!handled) validateStoredSession(); });

document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const flash = localStorage.getItem('flash_success');
    const msg = flash;
    if (msg) {
        const messageEl = document.getElementById('message');
        if (messageEl) {
            messageEl.textContent = msg;
            messageEl.className = 'message success';
        }
        localStorage.removeItem('flash_success');
    }
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;
            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';
            const icon = btn.querySelector('i');
            if (icon) {
                icon.className = isPassword ? 'fas fa-eye-slash' : 'fas fa-eye';
            }
        });
    });
});
