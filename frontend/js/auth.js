const API_URL = '/api';

// Force clear any old redirects
console.log('Auth.js loaded - version 2.0');

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

// Login form submission
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
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
        
        const response = await fetch(`${API_URL}/auth/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Store token and username
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('username', username);
            
            // Show success message
            messageEl.textContent = 'Login realizado com sucesso!';
            messageEl.className = 'message success';
            
            // Redirect to dashboard
            console.log('Redirecting to dashboard.html');
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1000);
        } else {
            messageEl.textContent = data.detail || 'Erro ao fazer login';
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

// Check if already logged in
if (localStorage.getItem('access_token')) {
    console.log('Already logged in, redirecting to dashboard.html');
    window.location.href = 'dashboard.html';
}

document.addEventListener('DOMContentLoaded', () => {
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
