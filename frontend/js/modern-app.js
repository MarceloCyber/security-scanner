// Modern Security Scanner Pro - JavaScript

const API_URL = '/api';

// Get token function to always have fresh token
function getToken() {
    return (
        localStorage.getItem('access_token') ||
        sessionStorage.getItem('access_token') ||
        localStorage.getItem('token') ||
        sessionStorage.getItem('token')
    );
}

// ==================== MOBILE SIDEBAR FUNCTIONS ====================
function toggleSidebarMobile() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        sidebar.classList.toggle('active');
        overlay.classList.toggle('active');
    }
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    
    if (sidebar && overlay) {
        sidebar.classList.remove('active');
        overlay.classList.remove('active');
    }
}

// Fechar sidebar ao clicar em um item de navegação (mobile)
function setupMobileSidebar() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            // Não fechar sidebar para links externos
            if (item.hasAttribute('target') || !item.dataset.page || item.classList.contains('nav-external')) {
                return; // Permite navegação normal
            }
            if (window.innerWidth <= 768) {
                closeSidebar();
            }
        });
    });
}

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    // Check authentication
    if (!getToken()) {
        window.location.href = '/index.html';
        return;
    }
    prelockTools();
    prelockToolCards();
    prepopulateSubscriptionCard();
    prepopulateDashboardStats();
    updateSidebarUsername();
    prepopulateToolResults();
    initializeApp();
    setupEventListeners();
    loadDashboardStats();
    loadNotifications();
    setupNotificationsDropdown();
    checkSubscription();
    
    setInterval(loadNotifications, 30000);
});

async function checkSubscription() {
    try {
        const response = await apiRequest('/user/subscription-info');
        const plan = response.subscription_plan;
        
        // Mostrar link admin se for administrador
        if (response.is_admin) {
            const adminLink = document.getElementById('adminLink');
            if (adminLink) {
                adminLink.style.display = 'flex';
            }
        }
        
        // Update Subscription Card
        const card = document.getElementById('subscriptionCard');
        if (card) {
            card.style.display = 'block';
            document.getElementById('planBadge').textContent = plan.toUpperCase();
            const statusBanner = document.getElementById('subscriptionStatusBanner');
            if (statusBanner) {
                const status = (response.subscription_status || 'active').toLowerCase();
                const messages = {
                    'active': '',
                    'pending': 'Pagamento pendente. Conclua o pagamento para ativar sua assinatura.',
                    'expired': 'Assinatura expirada. Renove para continuar usando os recursos premium.',
                    'cancelled': 'Assinatura cancelada. Você está no plano Free.',
                    'rejected': 'Pagamento rejeitado. Verifique seus dados e tente novamente.',
                    'payment_failed': 'Pagamento falhou. Atualize seu método de pagamento.'
                };
                const ctas = {
                    'pending': { text: 'Verificar status', href: 'pricing.html' },
                    'expired': { text: 'Renovar assinatura', href: 'pricing.html' },
                    'cancelled': { text: 'Escolher plano', href: 'pricing.html' },
                    'rejected': { text: 'Atualizar pagamento', href: 'pricing.html' },
                    'payment_failed': { text: 'Atualizar pagamento', href: 'pricing.html' }
                };
                if (status !== 'active') {
                    statusBanner.style.display = 'block';
                    const msg = messages[status] || `Status: ${status}`;
                    const cta = ctas[status];
                    statusBanner.innerHTML = cta ? `${msg} <a href="${cta.href}" style="color:#667eea; text-decoration:underline; margin-left:8px;">${cta.text}</a>` : msg;
                } else {
                    statusBanner.style.display = 'none';
                    statusBanner.textContent = '';
                }
            }
            
            if (response.scans_limit > 0) {
                const percentage = Math.min((response.scans_this_month / response.scans_limit) * 100, 100);
                document.getElementById('usageFill').style.width = percentage + '%';
                document.getElementById('usageText').textContent = 
                    `${response.scans_this_month} / ${response.scans_limit}`;
                
                // Color coding
                const fill = document.getElementById('usageFill');
                if (percentage >= 90) fill.style.background = '#f56565';
                else if (percentage >= 70) fill.style.background = '#ed8936';
                else fill.style.background = '#48bb78';
                if (response.scans_this_month >= response.scans_limit) {
                    showToast('Você atingiu seu limite mensal de scans no seu plano.', 'warning');
                }
            } else {
                document.getElementById('usageText').textContent = 'Ilimitado';
                document.getElementById('usageFill').style.width = '0%';
            }
        }

        // Lock Tools - Define quais ferramentas cada plano pode acessar
        const toolAccess = {
            'free': ['port-scan'], // Free só tem Port Scanner (10 scans/mês)
            'starter': ['port-scan', 'scanner', 'encoder', 'subdomain', 'hash-analyzer', 'password-strength'],
            'professional': ['port-scan', 'scanner', 'encoder', 'phishing', 'payloads', 'subdomain', 'sql-injection', 'xss-tester', 'brute-force', 'log-analyzer', 'threat-intel', 'hash-analyzer', 'password-strength', 'reports'],
            'enterprise': ['port-scan', 'scanner', 'encoder', 'phishing', 'payloads', 'subdomain', 'sql-injection', 'xss-tester', 'brute-force', 'log-analyzer', 'threat-intel', 'hash-analyzer', 'password-strength', 'reports']
        };

        const allowedTools = toolAccess[plan] || [];
        
        // Bloquear todas as ferramentas que não estão na lista permitida
        const allTools = ['dashboard', 'phishing', 'payloads', 'encoder', 'scanner', 'port-scan', 
                         'sql-injection', 'xss-tester', 'brute-force', 'subdomain', 
                         'log-analyzer', 'threat-intel', 'hash-analyzer', 'password-strength', 'reports'];
        
        allTools.forEach(toolId => {
            if (toolId === 'dashboard') return; // Dashboard sempre acessível
            
            if (!allowedTools.includes(toolId)) {
                const navItem = document.querySelector(`.nav-item[data-page="${toolId}"]`);
                if (navItem) {
                    navItem.classList.add('locked');
                    navItem.title = 'Upgrade necessário para acessar esta ferramenta';
                    
                    // Remove existing listeners and add lock listener
                    const newNavItem = navItem.cloneNode(true);
                    navItem.parentNode.replaceChild(newNavItem, navItem);
                    
                    newNavItem.addEventListener('click', (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        showToast('Esta ferramenta requer um plano superior. Faça upgrade!', 'info');
                        setTimeout(() => window.location.href = 'pricing.html', 1500);
                    });
                }
            }
        });

        // Bloquear cards do dashboard que não estão na lista permitida
        const toolCards = document.querySelectorAll('.tool-card');
        toolCards.forEach(card => {
            const button = card.querySelector('button');
            if (!button) return;
            
            const onclickAttr = button.getAttribute('onclick');
            if (!onclickAttr) return;
            
            // Extrair o nome da ferramenta do onclick (ex: "navigateTo('phishing')")
            const match = onclickAttr.match(/navigateTo\('([^']+)'\)/);
            if (!match) return;
            
            const toolId = match[1];
            
            if (!allowedTools.includes(toolId)) {
                card.classList.add('locked');
                card.style.opacity = '0.6';
                card.style.position = 'relative';
                
                // Adicionar overlay de bloqueio
                if (!card.querySelector('.lock-overlay')) {
                    const overlay = document.createElement('div');
                    overlay.className = 'lock-overlay';
                    overlay.innerHTML = '<i class="fas fa-lock"></i><br><span>Upgrade Necessário</span>';
                    overlay.style.cssText = `
                        position: absolute;
                        top: 0;
                        left: 0;
                        right: 0;
                        bottom: 0;
                        background: rgba(0,0,0,0.7);
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        color: #fff;
                        font-size: 1.5em;
                        border-radius: 15px;
                        cursor: pointer;
                    `;
                    
                    overlay.addEventListener('click', (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        showToast('Esta ferramenta requer um plano superior. Faça upgrade!', 'info');
                        setTimeout(() => window.location.href = 'pricing.html', 1500);
                    });
                    
                    card.appendChild(overlay);
                }
                
                // Desabilitar botão original
                button.style.pointerEvents = 'none';
            }
        });

        // Store plan and subscription info for other checks e detectar mudança de plano
        const prevPlan = localStorage.getItem('userPlan');
        localStorage.setItem('userPlan', plan);
        localStorage.setItem('scansThisMonth', response.scans_this_month || 0);
        localStorage.setItem('scansLimit', response.scans_limit || 0);

        // Feedback visual adicional em mudança de plano
        if (prevPlan && prevPlan !== plan) {
            const banner = document.createElement('div');
            banner.style.cssText = 'position:fixed;bottom:20px;left:20px;right:20px;background:#1f2937;color:#e5e7eb;border:1px solid #374151;padding:12px 16px;border-radius:10px;z-index:9999;box-shadow:0 10px 25px rgba(0,0,0,0.25);display:flex;justify-content:space-between;align-items:center;';
            banner.innerHTML = `<span>Seu plano foi alterado de ${prevPlan.toUpperCase()} para ${plan.toUpperCase()}.</span><a href="pricing.html" style="color:#667eea; text-decoration:none; font-weight:600;">Ver benefícios</a>`;
            document.body.appendChild(banner);
            setTimeout(() => { banner.remove(); }, 6000);
        }

    } catch (error) {
        console.error('Error checking subscription:', error);
    }
}

function prelockTools() {
    const plan = (localStorage.getItem('userPlan') || 'free').toLowerCase();
    const toolAccess = {
        'free': ['port-scan'],
        'starter': ['port-scan', 'scanner', 'encoder', 'subdomain', 'hash-analyzer', 'password-strength'],
        'professional': ['port-scan', 'scanner', 'encoder', 'phishing', 'payloads', 'subdomain', 'directory-enum', 'sql-injection', 'xss-tester', 'brute-force', 'log-analyzer', 'ioc-analyzer', 'threat-intel', 'hash-analyzer', 'password-strength', 'reports'],
        'enterprise': ['port-scan', 'scanner', 'encoder', 'phishing', 'payloads', 'subdomain', 'directory-enum', 'sql-injection', 'xss-tester', 'brute-force', 'log-analyzer', 'ioc-analyzer', 'threat-intel', 'hash-analyzer', 'password-strength', 'reports']
    };
    const allowedTools = toolAccess[plan] || [];
    const allTools = ['dashboard', 'phishing', 'payloads', 'encoder', 'scanner', 'port-scan', 'sql-injection', 'xss-tester', 'brute-force', 'subdomain', 'directory-enum', 'log-analyzer', 'ioc-analyzer', 'threat-intel', 'hash-analyzer', 'password-strength', 'reports'];
    allTools.forEach(toolId => {
        if (toolId === 'dashboard') return;
        if (!allowedTools.includes(toolId)) {
            const navItem = document.querySelector(`.nav-item[data-page="${toolId}"]`);
            if (navItem) {
                navItem.classList.add('locked');
                navItem.title = 'Upgrade necessário para acessar esta ferramenta';
            }
        }
    });
}

function prelockToolCards() {
    const plan = (localStorage.getItem('userPlan') || 'free').toLowerCase();
    const toolAccess = {
        'free': ['port-scan'],
        'starter': ['port-scan', 'scanner', 'encoder', 'subdomain', 'hash-analyzer', 'password-strength'],
        'professional': ['port-scan', 'scanner', 'encoder', 'phishing', 'payloads', 'subdomain', 'sql-injection', 'xss-tester', 'brute-force', 'log-analyzer', 'threat-intel', 'hash-analyzer', 'password-strength', 'reports'],
        'enterprise': ['port-scan', 'scanner', 'encoder', 'phishing', 'payloads', 'subdomain', 'sql-injection', 'xss-tester', 'brute-force', 'log-analyzer', 'threat-intel', 'hash-analyzer', 'password-strength', 'reports']
    };
    const allowedTools = toolAccess[plan] || [];
    const toolCards = document.querySelectorAll('.tool-card');
    toolCards.forEach(card => {
        const button = card.querySelector('button');
        if (!button) return;
        const onclickAttr = button.getAttribute('onclick');
        if (!onclickAttr) return;
        const match = onclickAttr.match(/navigateTo\('([^']+)'\)/);
        if (!match) return;
        const toolId = match[1];
        if (!allowedTools.includes(toolId)) {
            card.classList.add('locked');
            card.style.opacity = '0.6';
            card.style.position = 'relative';
            if (!card.querySelector('.lock-overlay')) {
                const overlay = document.createElement('div');
                overlay.className = 'lock-overlay';
                overlay.innerHTML = '<i class="fas fa-lock"></i><br><span>Upgrade Necessário</span>';
                overlay.style.cssText = 'position:absolute;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;flex-direction:column;align-items:center;justify-content:center;color:#fff;font-size:1.5em;border-radius:15px;cursor:pointer;';
                overlay.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    showToast('Esta ferramenta requer um plano superior. Faça upgrade!', 'info');
                    setTimeout(() => window.location.href = 'pricing.html', 1500);
                });
                card.appendChild(overlay);
            }
            button.style.pointerEvents = 'none';
        }
    });
}

function prepopulateSubscriptionCard() {
    const plan = (localStorage.getItem('userPlan') || 'free').toLowerCase();
    const scansThisMonth = parseInt(localStorage.getItem('scansThisMonth') || '0', 10);
    const scansLimit = parseInt(localStorage.getItem('scansLimit') || '10', 10);
    const card = document.getElementById('subscriptionCard');
    if (!card) return;
    card.style.display = 'block';
    const planBadge = document.getElementById('planBadge');
    if (planBadge) planBadge.textContent = plan.toUpperCase();
    const usageFill = document.getElementById('usageFill');
    const usageText = document.getElementById('usageText');
    if (usageFill && usageText) {
        if (scansLimit > 0) {
            const percentage = Math.min((scansThisMonth / scansLimit) * 100, 100);
            usageFill.style.width = percentage + '%';
            usageText.textContent = `${scansThisMonth} / ${scansLimit}`;
            if (percentage >= 90) usageFill.style.background = '#f56565';
            else if (percentage >= 70) usageFill.style.background = '#ed8936';
            else usageFill.style.background = '#48bb78';
        } else {
            usageText.textContent = 'Ilimitado';
            usageFill.style.width = '0%';
        }
    }
}

function prepopulateDashboardStats() {
    const ts = localStorage.getItem('dashboard.totalScans');
    if (ts !== null) {
        const el = document.getElementById('total-scans');
        if (el) el.textContent = ts;
    }
    const tp = localStorage.getItem('dashboard.totalPhishing');
    if (tp !== null) {
        const el = document.getElementById('total-phishing');
        if (el) el.textContent = tp;
    }
    const tv = localStorage.getItem('dashboard.totalVulns');
    if (tv !== null) {
        const el = document.getElementById('total-vulns');
        if (el) el.textContent = tv;
    }
    const tr = localStorage.getItem('dashboard.totalReports');
    if (tr !== null) {
        const el = document.getElementById('total-reports');
        if (el) el.textContent = tr;
    }
}

function updateSidebarUsername() {
    const el = document.getElementById('username');
    if (el) el.textContent = localStorage.getItem('username') || 'Usuário';
}

function prepopulateToolResults() {
    try {
        const sqliHtml = localStorage.getItem('tool.sqli.resultsHtml');
        if (sqliHtml) {
            const el = document.getElementById('sqli-results');
            if (el) el.innerHTML = sqliHtml;
            const count = localStorage.getItem('tool.sqli.vulnCount');
            const badge = document.getElementById('sqli-vuln-count');
            if (badge && count !== null) badge.textContent = count;
        }

        const xssHtml = localStorage.getItem('tool.xss.resultsHtml');
        if (xssHtml) {
            const el = document.getElementById('xss-results');
            if (el) el.innerHTML = xssHtml;
            const count = localStorage.getItem('tool.xss.vulnCount');
            const badge = document.getElementById('xss-vuln-count');
            if (badge && count !== null) badge.textContent = count;
        }

        const bruteHtml = localStorage.getItem('tool.brute.resultsHtml');
        if (bruteHtml) {
            const el = document.getElementById('bf-results');
            if (el) el.innerHTML = bruteHtml;
            const prog = localStorage.getItem('tool.brute.progress');
            const pEl = document.getElementById('bf-progress');
            if (pEl && prog !== null) pEl.textContent = `${prog}%`;
        }

        const subHtml = localStorage.getItem('tool.subdomain.resultsHtml');
        if (subHtml) {
            const el = document.getElementById('subdomain-results');
            if (el) el.innerHTML = subHtml;
            const count = localStorage.getItem('tool.subdomain.count');
            const badge = document.getElementById('subdomain-count');
            if (badge && count !== null) badge.textContent = count;
        }

        const logHtml = localStorage.getItem('tool.log.resultsHtml');
        if (logHtml) {
            const el = document.getElementById('log-results');
            if (el) el.innerHTML = logHtml;
            const threats = localStorage.getItem('tool.log.threats');
            const badge = document.getElementById('log-threats');
            if (badge && threats !== null) badge.textContent = threats;
        }

        const thHtml = localStorage.getItem('tool.threat.resultsHtml');
        if (thHtml) {
            const el = document.getElementById('threat-results');
            if (el) el.innerHTML = thHtml;
            const score = localStorage.getItem('tool.threat.score');
            const mal = localStorage.getItem('tool.threat.malicious');
            const badge = document.getElementById('threat-score');
            if (badge && score !== null) {
                badge.textContent = `Score: ${score}`;
                const isMal = mal === 'true';
                badge.className = `badge badge-${isMal ? 'danger' : 'success'}`;
            }
        }

        const hashHtml = localStorage.getItem('tool.hash.resultsHtml');
        if (hashHtml) {
            const el = document.getElementById('hash-results');
            if (el) el.innerHTML = hashHtml;
        }

        const pwdHtml = localStorage.getItem('tool.password.resultsHtml');
        if (pwdHtml) {
            const el = document.getElementById('password-results');
            if (el) el.innerHTML = pwdHtml;
        }

        const dirHtml = localStorage.getItem('tool.direnum.resultsHtml');
        if (dirHtml) {
            const el = document.getElementById('direnum-results');
            if (el) el.innerHTML = dirHtml;
            const count = localStorage.getItem('tool.direnum.count');
            const badge = document.getElementById('direnum-count');
            if (badge && count !== null) badge.textContent = count;
        }

        const iocHtml = localStorage.getItem('tool.ioc.resultsHtml');
        if (iocHtml) {
            const el = document.getElementById('ioc-results');
            if (el) el.innerHTML = iocHtml;
            const count = localStorage.getItem('tool.ioc.count');
            const badge = document.getElementById('ioc-count');
            if (badge && count !== null) badge.textContent = count;
        }
    } catch (e) {}
}

function clearAllSQLiResults() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do SQL Injection Tester?')) return;
    try {
        localStorage.removeItem('tool.sqli.resultsHtml');
        localStorage.removeItem('tool.sqli.vulnCount');
    } catch (_) {}
    const el = document.getElementById('sqli-results');
    if (el) el.innerHTML = '<p class="text-muted">Configure o teste e clique em "Iniciar Teste"</p>';
    const badge = document.getElementById('sqli-vuln-count');
    if (badge) badge.textContent = '0';
    showToast('Resultados limpos com sucesso', 'success');
}

function clearAllXSSResults() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do XSS Tester?')) return;
    try {
        localStorage.removeItem('tool.xss.resultsHtml');
        localStorage.removeItem('tool.xss.vulnCount');
    } catch (_) {}
    const el = document.getElementById('xss-results');
    if (el) el.innerHTML = '<p class="text-muted">Configure e inicie o teste</p>';
    const badge = document.getElementById('xss-vuln-count');
    if (badge) badge.textContent = '0';
    showToast('Resultados limpos com sucesso', 'success');
}

function clearAllBruteForceResults() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do Brute Force Tool?')) return;
    try {
        localStorage.removeItem('tool.brute.resultsHtml');
        localStorage.removeItem('tool.brute.progress');
    } catch (_) {}
    const el = document.getElementById('bf-results');
    if (el) el.innerHTML = '<p class="text-muted">Configure e inicie o ataque</p>';
    const pEl = document.getElementById('bf-progress');
    if (pEl) pEl.textContent = '0%';
    showToast('Resultados limpos com sucesso', 'success');
}

function clearAllSubdomainResults() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do Subdomain Enumeration?')) return;
    try {
        localStorage.removeItem('tool.subdomain.resultsHtml');
        localStorage.removeItem('tool.subdomain.count');
    } catch (_) {}
    const el = document.getElementById('subdomain-results');
    if (el) el.innerHTML = '<p class="text-muted">Inicie a enumeração</p>';
    const badge = document.getElementById('subdomain-count');
    if (badge) badge.textContent = '0';
    showToast('Resultados limpos com sucesso', 'success');
}

function clearAllLogAnalysis() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do Log Analyzer?')) return;
    try {
        localStorage.removeItem('tool.log.resultsHtml');
        localStorage.removeItem('tool.log.threats');
    } catch (_) {}
    const el = document.getElementById('log-results');
    if (el) el.innerHTML = '<p class="text-muted">Faça upload de um log para análise</p>';
    const badge = document.getElementById('log-threats');
    if (badge) badge.textContent = '0';
    showToast('Resultados limpos com sucesso', 'success');
}

function clearAllThreatIntel() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do Threat Intelligence?')) return;
    try {
        localStorage.removeItem('tool.threat.resultsHtml');
        localStorage.removeItem('tool.threat.score');
        localStorage.removeItem('tool.threat.malicious');
    } catch (_) {}
    const el = document.getElementById('threat-results');
    if (el) el.innerHTML = '<p class="text-muted">Configure e faça uma consulta</p>';
    const badge = document.getElementById('threat-score');
    if (badge) {
        badge.textContent = 'N/A';
        badge.className = 'badge';
    }
    showToast('Resultados limpos com sucesso', 'success');
}

function clearAllDirEnum() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do Directory Enumerator?')) return;
    try {
        localStorage.removeItem('tool.direnum.resultsHtml');
        localStorage.removeItem('tool.direnum.count');
    } catch (_) {}
    const el = document.getElementById('direnum-results');
    if (el) el.innerHTML = '<p class="text-muted">Inicie a enumeração de diretórios</p>';
    const badge = document.getElementById('direnum-count');
    if (badge) badge.textContent = '0';
    showToast('Resultados limpos com sucesso', 'success');
}

function clearAllIOCAnalyzer() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do IOC Analyzer?')) return;
    try {
        localStorage.removeItem('tool.ioc.resultsHtml');
        localStorage.removeItem('tool.ioc.count');
    } catch (_) {}
    const el = document.getElementById('ioc-results');
    if (el) el.innerHTML = '<p class="text-muted">Cole IOCs para análise</p>';
    const badge = document.getElementById('ioc-count');
    if (badge) badge.textContent = '0';
    showToast('Resultados limpos com sucesso', 'success');
}

function clearAllHashAnalysis() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do Hash Analyzer?')) return;
    try {
        localStorage.removeItem('tool.hash.resultsHtml');
    } catch (_) {}
    const el = document.getElementById('hash-results');
    if (el) el.innerHTML = '<p class="text-muted">Insira hashes para análise</p>';
    showToast('Resultados limpos com sucesso', 'success');
}

function clearAllPasswordAnalysis() {
    if (!confirm('Tem certeza que deseja limpar todos os resultados do Password Strength Checker?')) return;
    try {
        localStorage.removeItem('tool.password.resultsHtml');
    } catch (_) {}
    const el = document.getElementById('password-results');
    if (el) el.innerHTML = '<p class="text-muted">Digite uma senha para análise</p>';
    showToast('Resultados limpos com sucesso', 'success');
}

function initializeApp() {
    // Setup mobile sidebar
    setupMobileSidebar();
    
    // Setup navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function(e) {
            // Não bloquear links externos (target="_blank"), sem data-page, ou com classe nav-external
            if (this.hasAttribute('target') || !this.dataset.page || this.classList.contains('nav-external')) {
                return; // Deixa o link funcionar normalmente
            }
            e.preventDefault();
            if (this.classList.contains('locked')) {
                showToast('Esta ferramenta requer um plano superior. Faça upgrade!', 'info');
                setTimeout(() => window.location.href = 'pricing.html', 1500);
                return;
            }
            const page = this.dataset.page;
            navigateTo(page);
        });
    });

    // Setup tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const tabId = this.dataset.tab;
            switchTab(tabId);
        });
    });

    // Load initial data
    loadPhishingTemplates();
    loadPayloadCategories();
    loadEncodingTypes();
    
    // Load reports when page is navigated to
    if (window.location.hash === '#reports') {
        loadAvailableScans();
    }

    // Setup payload encoding checkbox
    document.getElementById('encode-payload')?.addEventListener('change', function() {
        document.getElementById('encoding-type-group').style.display = this.checked ? 'block' : 'none';
    });
}

function setupEventListeners() {
    // Add any additional event listeners here
}

// Navigation
function navigateTo(pageName) {
    const navItem = document.querySelector(`.nav-item[data-page="${pageName}"]`);
    if (navItem && navItem.classList.contains('locked')) {
        showToast('Esta ferramenta requer um plano superior. Faça upgrade!', 'info');
        setTimeout(() => window.location.href = 'pricing.html', 1500);
        return;
    }
    const plan = (localStorage.getItem('userPlan') || 'free').toLowerCase();
    if (plan === 'free') {
        const allowed = ['dashboard', 'port-scan'];
        if (!allowed.includes(pageName)) {
            showToast('Esta ferramenta requer um plano superior. Faça upgrade!', 'info');
            setTimeout(() => window.location.href = 'pricing.html', 1500);
            return;
        }
    }
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.page === pageName) {
            item.classList.add('active');
        }
    });

    // Update pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    document.getElementById(pageName + '-page').classList.add('active');

    // Load page-specific data
    if (pageName === 'phishing') {
        loadPhishingTemplates(); // Reload templates when opening page
        loadPhishingPages();
        loadPhishingCaptures(); // Load captures
    } else if (pageName === 'reports') {
        loadAvailableScans();
    } else if (pageName === 'profile') {
        loadProfile();
    }
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === tabId) {
            btn.classList.add('active');
        }
    });

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(tabId).classList.add('active');
}

async function loadProfile() {
    try {
        const me = await apiRequest('/user/me');
        const sub = await apiRequest('/user/subscription-info');
        const emailEl = document.getElementById('profileEmail');
        const userEl = document.getElementById('profileUsername');
        const planEl = document.getElementById('profilePlan');
        const statusEl = document.getElementById('profileStatus');
        const cancelBtn = document.getElementById('cancelSubscriptionBtn');
        const hint = document.getElementById('profileHint');
        if (emailEl) emailEl.value = me.email || '';
        if (userEl) userEl.value = me.username || '';
        const plan = (sub.subscription_plan || 'free').toLowerCase();
        const status = (sub.subscription_status || 'active').toLowerCase();
        if (planEl) planEl.value = plan.toUpperCase();
        if (statusEl) statusEl.value = status.toUpperCase();
        if (cancelBtn) {
            const canCancel = plan !== 'free' && status !== 'cancelled';
            cancelBtn.disabled = !canCancel;
            const reason = !canCancel
                ? (plan === 'free' ? 'Disponível apenas para planos pagos'
                   : status === 'cancelled' ? 'Assinatura já cancelada'
                   : 'Indisponível')
                : 'Cancelar assinatura';
            cancelBtn.title = reason;
            cancelBtn.style.opacity = canCancel ? '' : '0.6';
            cancelBtn.style.cursor = canCancel ? '' : 'not-allowed';
            cancelBtn.setAttribute('aria-disabled', String(!canCancel));
        }
        if (hint) {
            if (plan === 'free') hint.textContent = 'Plano Free não possui assinatura a cancelar.';
            else if (status === 'cancelled') hint.textContent = 'Sua assinatura já está cancelada.';
            else hint.textContent = '';
        }
    } catch (e) {
        showToast('Erro ao carregar perfil', 'error');
    }
}

async function cancelSubscription() {
    try {
        showLoading('Cancelando assinatura...');
        const sub = await apiRequest('/user/subscription-info');
        const plan = (sub.subscription_plan || 'free').toLowerCase();
        if (plan === 'free') {
            hideLoading();
            showToast('Seu plano é Free. Não há assinatura para cancelar.', 'info');
            return;
        }
        await apiRequest('/payments/cancel-subscription', { method: 'POST' });
        hideLoading();
        showToast('Assinatura cancelada com sucesso', 'success');
        await checkSubscription();
        await loadProfile();
    } catch (e) {
        hideLoading();
        showToast('Erro ao cancelar. Tente novamente.', 'error');
    }
}

function upgradeFromProfile() {
    window.location.href = 'pricing.html';
}

// Expose profile functions globally for inline onclick handlers
window.loadProfile = loadProfile;
window.cancelSubscription = cancelSubscription;
window.upgradeFromProfile = upgradeFromProfile;

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('active');
    
    // Add/remove overlay for mobile
    let overlay = document.querySelector('.sidebar-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.className = 'sidebar-overlay';
        overlay.addEventListener('click', toggleSidebar);
        document.body.appendChild(overlay);
    }
    overlay.classList.toggle('active');
    
    // Close sidebar when clicking nav items on mobile
    if (window.innerWidth <= 992) {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                // Não fechar sidebar para links externos
                if (item.hasAttribute('target') || !item.dataset.page || item.classList.contains('nav-external')) {
                    return; // Permite navegação normal
                }
                if (sidebar.classList.contains('active')) {
                    toggleSidebar();
                }
            });
        });
    }
}

// Theme toggle removed - Dark mode is now permanent
function toggleTheme() {
    // Dark mode only - no theme switching
    return;
}

function logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('username');
    window.location.href = '/index.html';
}

// API Helpers
async function refreshAccessToken() {
    const t = getToken();
    if (!t) return null;
    try {
        const r = await fetch(`${API_URL}/auth/refresh`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${t}`
            }
        });
        const d = await r.json();
        if (r.ok && d.access_token) {
            localStorage.setItem('access_token', d.access_token);
            return d.access_token;
        }
        return null;
    } catch (_) {
        return null;
    }
}

async function apiRequest(endpoint, options = {}) {
    const currentToken = getToken();
    
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    if (currentToken) {
        headers['Authorization'] = `Bearer ${currentToken}`;
    }

    try {
        let response = await fetch(`${API_URL}${endpoint}`, {
            ...options,
            headers
        });
        let data = await response.json();
        if (!response.ok && response.status === 401) {
            const newToken = await refreshAccessToken();
            if (newToken) {
                const retryHeaders = { ...headers, 'Authorization': `Bearer ${newToken}` };
                response = await fetch(`${API_URL}${endpoint}`, { ...options, headers: retryHeaders });
                data = await response.json();
            }
        }
        if (!response.ok) {
            if (response.status === 401) {
                localStorage.removeItem('access_token');
                localStorage.removeItem('username');
                window.location.href = '/index.html';
                return;
            }
            throw new Error(data.detail || 'Erro na requisição');
        }
        return data;
    } catch (error) {
        throw error;
    }
}

// Dashboard
async function loadDashboardStats() {
    try {
        // Carregar informações de assinatura para obter scans deste mês
        const subscriptionInfo = await apiRequest('/user/subscription-info');
        
        // Atualizar total de scans do mês atual
        const scansThisMonth = subscriptionInfo.scans_this_month || 0;
        document.getElementById('total-scans').textContent = scansThisMonth;
        localStorage.setItem('dashboard.totalScans', String(scansThisMonth));
        
        // Carregar estatísticas de phishing
        try {
            const stats = await apiRequest('/tools/stats');
            const phishingTotal = stats.phishing && stats.phishing.generated_pages ? stats.phishing.generated_pages : 0;
            document.getElementById('total-phishing').textContent = phishingTotal;
            localStorage.setItem('dashboard.totalPhishing', String(phishingTotal));
        } catch (error) {
            const cachedPh = localStorage.getItem('dashboard.totalPhishing');
            if (cachedPh !== null) {
                document.getElementById('total-phishing').textContent = cachedPh;
            }
        }
        
        // Load scan stats para vulnerabilidades e relatórios
        try {
            const scansResponse = await apiRequest('/scans');
            
            const totalReports = scansResponse.total || 0;
            document.getElementById('total-reports').textContent = totalReports;
            localStorage.setItem('dashboard.totalReports', String(totalReports));
            
            let totalVulns = 0;
            if (scansResponse.scans) {
                scansResponse.scans.forEach(scan => {
                    if (scan.results && scan.results.vulnerabilities) {
                        totalVulns += scan.results.vulnerabilities.length;
                    }
                });
            }
            document.getElementById('total-vulns').textContent = totalVulns;
            localStorage.setItem('dashboard.totalVulns', String(totalVulns));
        } catch (error) {
            const cachedReports = localStorage.getItem('dashboard.totalReports');
            if (cachedReports !== null) {
                document.getElementById('total-reports').textContent = cachedReports;
            }
            const cachedVulns = localStorage.getItem('dashboard.totalVulns');
            if (cachedVulns !== null) {
                document.getElementById('total-vulns').textContent = cachedVulns;
            }
        }
    } catch (error) {
        console.error('Error loading dashboard stats:', error);
        const ts = localStorage.getItem('dashboard.totalScans');
        if (ts !== null) document.getElementById('total-scans').textContent = ts;
        const tp = localStorage.getItem('dashboard.totalPhishing');
        if (tp !== null) document.getElementById('total-phishing').textContent = tp;
        const tv = localStorage.getItem('dashboard.totalVulns');
        if (tv !== null) document.getElementById('total-vulns').textContent = tv;
        const tr = localStorage.getItem('dashboard.totalReports');
        if (tr !== null) document.getElementById('total-reports').textContent = tr;
    }
}

// Phishing Generator
async function loadPhishingTemplates() {
    const select = document.getElementById('phishing-template');
    if (!select) return; // Element doesn't exist yet
    
    try {
        const response = await apiRequest('/tools/phishing/templates');
        select.innerHTML = '<option value="">Selecione um template</option>';
        
        if (response && response.templates && response.templates.length > 0) {
            response.templates.forEach(template => {
                const option = document.createElement('option');
                option.value = template.id;
                option.textContent = `${template.name} - ${template.description}`;
                select.appendChild(option);
            });
        } else {
            select.innerHTML = '<option value="">Nenhum template disponível</option>';
        }
    } catch (error) {
        console.error('Error loading templates:', error);
        select.innerHTML = '<option value="">Erro ao carregar templates</option>';
    }
}

async function generatePhishingPage() {
    const template = document.getElementById('phishing-template').value;
    const redirectUrl = document.getElementById('redirect-url').value;
    const captureWebhook = document.getElementById('capture-webhook').value;
    const customTitle = document.getElementById('custom-title').value;
    const expirationHours = parseInt(document.getElementById('expiration-time').value);

    if (!template) {
        showToast('Selecione um template', 'error');
        return;
    }

    try {
        const response = await apiRequest('/tools/phishing/generate', {
            method: 'POST',
            body: JSON.stringify({
                template,
                redirect_url: redirectUrl,
                capture_webhook: captureWebhook || null,
                custom_title: customTitle || null,
                expiration_hours: expirationHours
})
        });

        let message = 'Página gerada com sucesso!';
        if (response.expires_at) {
            const expiresAt = new Date(response.expires_at).toLocaleString('pt-BR');
            message += ` Expira em: ${expiresAt}`;
        } else {
            message += ' (Nunca expira)';
        }
        
        showToast(message, 'success');
        
        // Show URLs based on configuration
        if (response.masked_url && !response.masked_url.includes('⚠️')) {
            showToast(`🎭 URL Pública Mascarada: ${response.masked_url}`, 'success');
        } else if (response.setup_instructions) {
            showToast(`⚠️ URL local: ${response.local_url}\n\nPara usar externamente, configure ngrok`, 'warning');
        }
        
        loadPhishingPages();
    } catch (error) {
        console.error('Error generating phishing page:', error);
    }
}

async function loadPhishingPages() {
    try {
        const response = await apiRequest('/tools/phishing/pages');
        const container = document.getElementById('phishing-pages-list');
        
        if (response.pages.length === 0) {
            container.innerHTML = '<p class="text-muted">Nenhuma página gerada ainda</p>';
            return;
        }

        const fullUrl = window.location.origin;
        container.innerHTML = response.pages.map(page => {
            const expiresAt = page.expires_at ? new Date(page.expires_at) : null;
            const isExpired = expiresAt && new Date() > expiresAt;
            const timeLeft = expiresAt ? Math.ceil((expiresAt - new Date()) / 1000 / 60 / 60) : null; // hours
            
            const realUrl = `${fullUrl}${page.url}`;
            const shortUrl = page.short_url || realUrl;
            const maskedUrl = page.masked_url || shortUrl;
            
            // Verifica se tem URL pública mascarada válida
            const hasPublicUrl = maskedUrl && !maskedUrl.includes('⚠️') && !maskedUrl.includes('Configure');
            
            return `
            <div class="payload-item ${isExpired ? 'expired' : ''}">
                <div class="payload-item-header">
                    <strong>${page.filename}</strong>
                    ${isExpired ? '<span class="badge badge-danger">Expirado</span>' : ''}
                    ${timeLeft && timeLeft <= 24 && !isExpired ? `<span class="badge badge-warning">Expira em ${timeLeft}h</span>` : ''}
                </div>
                
                ${hasPublicUrl ? `
                <div style="margin: 10px 0;">
                    <strong style="color: #10b981;">� URL PÚBLICA (usar esta!):</strong>
                    <div class="payload-code" id="masked-${page.filename}" style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(5, 150, 105, 0.1)); border-left: 3px solid #10b981; font-size: 13px; word-wrap: break-word; word-break: break-all; white-space: normal; overflow-wrap: break-word;">
                        ${maskedUrl}
                    </div>
                    <button class="btn-sm" onclick="copyToClipboard('masked-${page.filename}')" style="margin-top: 5px; background: #10b981;">
                        <i class="fas fa-copy"></i> Copiar URL Pública
                    </button>
                    <a href="${maskedUrl}" target="_blank" class="btn-sm btn-success" style="margin-top: 5px; margin-left: 5px;">
                        <i class="fas fa-external-link-alt"></i> Abrir em Nova Aba
                    </a>
                </div>
                ` : ''}
                
                <div style="margin: 10px 0;">
                    <strong style="color: #667eea;">🔗 URL Curta ${hasPublicUrl ? '(local)' : '(compartilhar)'}:</strong>
                    <div class="payload-code" id="short-${page.filename}" style="background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1)); border-left: 3px solid #667eea; font-size: 12px; word-wrap: break-word; word-break: break-all; white-space: normal;">
                        ${shortUrl}
                    </div>
                    <button class="btn-sm" onclick="copyToClipboard('short-${page.filename}')" style="margin-top: 5px;">
                        <i class="fas fa-copy"></i> Copiar URL Curta
                    </button>
                    <a href="${shortUrl}" target="_blank" class="btn-sm btn-success" style="margin-top: 5px; margin-left: 5px;">
                        <i class="fas fa-external-link-alt"></i> Testar
                    </a>
                </div>
                
                <div style="margin: 10px 0;">
                    <strong style="color: #888;">� URL Completa (debug):</strong>
                    <div class="payload-code" id="url-${page.filename}" style="font-size: 11px; opacity: 0.7;">${realUrl}</div>
                    <button class="btn-sm" onclick="copyToClipboard('url-${page.filename}')" style="margin-top: 5px;">
                        <i class="fas fa-copy"></i> Copiar URL Completa
                    </button>
                </div>
                
                <small>📅 Criado: ${page.created_at ? new Date(page.created_at).toLocaleString('pt-BR') : 'N/A'}</small>
                ${page.expires_at ? `<br><small>⏱️ Expira: ${new Date(page.expires_at).toLocaleString('pt-BR')}</small>` : '<br><small>♾️ Nunca expira</small>'}
            </div>
        `}).join('');
    } catch (error) {
        console.error('Error loading phishing pages:', error);
    }
}

async function clearAllPhishingPages() {
    if (!confirm('⚠️ Tem certeza que deseja APAGAR TODOS os links de phishing gerados?\n\nEsta ação não pode ser desfeita!')) {
        return;
    }
    
    try {
        const response = await apiRequest('/tools/phishing/pages/clear-all', {
            method: 'DELETE'
        });
        
        showToast(`✅ ${response.message}`, 'success');
        loadPhishingPages(); // Reload the list
    } catch (error) {
        console.error('Error clearing phishing pages:', error);
        showToast('❌ Erro ao limpar histórico', 'error');
    }
}

async function loadPhishingCaptures() {
    const token = getToken();
    if (!token) {
        // Se não tiver token, não tenta carregar e deixa o apiRequest redirecionar ou o usuário fazer login
        return;
    }

    try {
        const response = await apiRequest('/tools/phishing/captures');
        const container = document.getElementById('phishing-captures-list');
        
        if (!response.captures || response.captures.length === 0) {
            container.innerHTML = '<p class="text-muted">Nenhuma captura encontrada no servidor.</p>';
            return;
        }

        container.innerHTML = '<div class="captures-grid">' + response.captures.map(capture => {
            // Normalize location data
            let lat = capture.latitude;
            let lon = capture.longitude;
            if (capture.location) {
                lat = capture.location.latitude || lat;
                lon = capture.location.longitude || lon;
            }
            
            const hasLocation = (typeof lat === 'number' && typeof lon === 'number');
            const hasPhoto = !!(capture.photo_base64 || capture.photo_file);
            const locationDetails = capture.location_details;
            const isGPS = (capture.location_type === 'GPS') || (capture.location && capture.location.type === 'GPS') || (capture.gps_status === 'success');

            // Fallbacks de endereço quando não houver location_details
            const displayCity = (locationDetails && locationDetails.city) || capture.city || '';
            const displayState = (locationDetails && locationDetails.state) || capture.region || '';
            const displayCountry = (locationDetails && locationDetails.country) || capture.country || '';
            const fullAddress = (locationDetails && locationDetails.full_address) || (displayCity || displayState || displayCountry ? `${displayCity}${displayCity && displayState ? ', ' : ''}${displayState}${(displayCity || displayState) && displayCountry ? ' - ' : ''}${displayCountry}` : '');
            
            return `
                <div class="capture-card">
                    <div class="capture-header">
                        <div class="capture-icon">
                            <i class="fas fa-user-secret"></i>
                        </div>
                        <div class="capture-info">
                            <strong>Page ID: ${capture.page_id}</strong>
                            <small>${new Date(capture.timestamp).toLocaleString('pt-BR')}</small>
                        </div>
                        <div class="capture-actions">
                            <button class="btn-icon" onclick="shareCapture('${capture.capture_id || capture.page_id}', ${hasPhoto}, ${hasLocation})" title="Compartilhar">
                                <i class="fas fa-share-alt"></i>
                            </button>
                            <button class="btn-icon btn-danger" onclick="deleteCapture('${capture.capture_id || capture.page_id}')" title="Deletar">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                    <div class="capture-body">
                        ${capture.form_data ? `
                            <div class="capture-credentials" style="background: #fff3cd; padding: 10px; border-radius: 4px; border-left: 4px solid #ffc107; margin-bottom: 15px;">
                                <h4 style="margin: 0 0 10px 0; color: #856404; font-size: 1.1em;"><i class="fas fa-key"></i> Credenciais Capturadas</h4>
                                ${Object.entries(capture.form_data).map(([key, value]) => 
                                    `<div style="margin-bottom: 5px; color: #333;"><strong>${key}:</strong> <span style="font-family: monospace; background: rgba(0,0,0,0.05); padding: 2px 4px; border-radius: 3px;">${value}</span></div>`
                                ).join('')}
                            </div>
                        ` : ''}

                        ${hasPhoto ? `
                            <div class="capture-photo">
                                <img src="data:image/jpeg;base64,${capture.photo_base64 || ''}" 
                                     alt="Captured photo" 
                                     onerror="this.onerror=null; this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22200%22 height=%22200%22><text x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 dy=%22.3em%22 fill=%22%23999%22>Foto não disponível</text></svg>';"
                                     onclick="window.open(this.src, '_blank')" 
                                     style="max-width: 100%; border-radius: 8px; cursor: pointer;">
                                <small style="display:block; margin-top:5px; color:#666;"><i class="fas fa-camera"></i> Foto capturada</small>
                            </div>
                        ` : '<p style="color:#666; margin-bottom: 15px;"><i class="fas fa-camera-slash"></i> Sem foto</p>'}
                        
                        <div class="capture-details">
                            ${hasLocation ? `
                                <div class="capture-location" style="margin-bottom: 15px;">
                                    <p style="color: ${isGPS ? '#28a745' : '#ffc107'}; font-weight: bold; margin-bottom: 5px;">
                                        <i class="fas fa-map-marker-alt"></i> Localização (${isGPS ? 'GPS - Precisa' : 'IP - Aproximada'})
                                    </p>
                                    ${(fullAddress || displayCity || displayState || displayCountry) ? `
                                        <div style="background: #f8f9fa; padding: 10px; border-radius: 4px; margin-bottom: 5px;">
                                            ${fullAddress ? `<p style="color:#333; margin-bottom: 5px;"><strong>Endereço:</strong> ${fullAddress}</p>` : ''}
                                            ${(displayCity || displayState || displayCountry) ? `<p style="color:#666; font-size: 0.9em;">${displayCity || ''}${displayCity && displayState ? ', ' : ''}${displayState || ''}${(displayCity || displayState) && displayCountry ? ' - ' : ''}${displayCountry || ''}</p>` : ''}
                                        </div>
                                    ` : ''}
                                    <p style="color:#666; font-family: monospace; margin-bottom: 5px;">
                                        <i class="fas fa-compass"></i> ${lat.toFixed(6)}, ${lon.toFixed(6)}
                                    </p>
                                    <a href="https://www.google.com/maps?q=${lat},${lon}" target="_blank" class="btn-sm" style="display: inline-block;">
                                        <i class="fas fa-external-link-alt"></i> Ver no Maps
                                    </a>
                                    <div class="capture-map" style="margin-top: 10px;">
                                        <iframe src="https://www.google.com/maps?q=${lat},${lon}&z=15&output=embed" width="100%" height="200" style="border:0;border-radius:8px;" allowfullscreen="" loading="lazy" referrerpolicy="no-referrer-when-downgrade"></iframe>
                                    </div>
                                </div>
                            ` : !locationDetails && !capture.ip_address ? '<p style="color:#a0aec0"><i class="fas fa-map-marker-slash"></i> Sem localização</p>' : ''}

                            ${capture.keystrokes && capture.keystrokes.length > 0 ? `
                                <div class="capture-keystrokes" style="margin-bottom: 15px;">
                                    <h5 style="margin: 0 0 5px 0; color: #333;"><i class="fas fa-keyboard"></i> Keylogger (${capture.keystrokes.length} teclas)</h5>
                                    <div style="font-family: monospace; background: #2d3748; color: #48bb78; padding: 10px; border-radius: 4px; font-size: 12px; max-height: 150px; overflow-y: auto; word-break: break-all;">
                                        ${capture.keystrokes.map(k => k.key === 'Enter' ? '<br><span style="color:#cbd5e0">[ENTER]</span><br>' : (k.key === 'Backspace' ? '<span style="color:#fc8181">[BS]</span>' : k.key)).join('')}
                                    </div>
                                </div>
                            ` : ''}

                            <div class="capture-meta" style="font-size: 0.85em; color: #666; border-top: 1px solid #eee; padding-top: 10px;">
                                ${capture.battery_info ? `
                                    <span style="margin-right: 15px;">
                                        <i class="fas fa-battery-three-quarters"></i> ${(capture.battery_info.level * 100).toFixed(0)}% ${capture.battery_info.charging ? '⚡' : ''}
                                    </span>
                                ` : ''}
                                ${capture.ip_address ? `
                                    <span style="margin-right: 15px;"><i class="fas fa-network-wired"></i> ${capture.ip_address}</span>
                                ` : ''}
                                <span><i class="fas fa-desktop"></i> ${capture.user_agent ? capture.user_agent.split(')')[0] + ')' : 'N/A'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('') + '</div>';
        
    } catch (error) {
        console.error('Error loading captures:', error);
        document.getElementById('phishing-captures-list').innerHTML = 
            '<p class="text-muted">Erro ao carregar capturas</p>';
    }
}

async function deleteCapture(captureId) {
    if (!confirm('Tem certeza que deseja deletar esta captura? Esta ação não pode ser desfeita.')) {
        return;
    }
    
    try {
        await apiRequest(`/tools/phishing/captures/${captureId}`, {
            method: 'DELETE'
        });
        showToast('Captura deletada com sucesso!', 'success');
        loadPhishingCaptures(); // Reload captures list
    } catch (error) {
        console.error('Error deleting capture:', error);
        showToast('Erro ao deletar captura', 'error');
    }
}

async function clearPhishingCaptures() {
    if (!confirm('Tem certeza que deseja limpar TODAS as capturas de phishing? Esta ação não pode ser desfeita.')) {
        return;
    }
    
    try {
        showLoading();
        
        // Get all captures
        const response = await apiRequest('/tools/phishing/captures');
        const captures = response.captures || [];
        
        if (captures.length === 0) {
            showToast('Não há capturas para deletar', 'info');
            hideLoading();
            return;
        }
        
        // Delete each capture
        for (const capture of captures) {
            await apiRequest(`/tools/phishing/captures/${capture.capture_id || capture.page_id}`, {
                method: 'DELETE'
            });
        }
        
        showToast(`${captures.length} captura(s) deletada(s) com sucesso!`, 'success');
        loadPhishingCaptures();
        
    } catch (error) {
        console.error('Error clearing captures:', error);
        showToast('Erro ao limpar capturas', 'error');
    } finally {
        hideLoading();
    }
}

async function shareCapture(captureId, hasPhoto, hasLocation) {
    try {
        console.log('shareCapture called with:', { captureId, hasPhoto, hasLocation });
        
        const captures = (await apiRequest('/tools/phishing/captures')).captures;
        const capture = captures.find(c => (c.page_id === captureId) || (c.capture_id === captureId));
        
        if (!capture) {
            showToast('Captura não encontrada', 'error');
            return;
        }
        
        console.log('Capture found:', capture);
        
        // Build share message
        let message = `🎣 Captura de Phishing - ${capture.page_id}\n\n`;
        message += `📅 Data: ${new Date(capture.timestamp).toLocaleString('pt-BR')}\n`;
        
        if (capture.ip_address) {
            message += `🌐 IP: ${capture.ip_address}\n`;
        }
        
        if (hasLocation && capture.location) {
            message += `\n📍 Localização:\n`;
            if (capture.location_details) {
                message += `País: ${capture.location_details.country || 'N/A'}\n`;
                message += `Cidade: ${capture.location_details.city || 'N/A'}\n`;
                message += `Região: ${capture.location_details.state || 'N/A'}\n`;
            }
            message += `Coordenadas: ${capture.location.latitude.toFixed(6)}, ${capture.location.longitude.toFixed(6)}\n`;
            message += `Google Maps: https://www.google.com/maps?q=${capture.location.latitude},${capture.location.longitude}\n`;
        }
        
        if (capture.form_data) {
            message += `\n🔑 Credenciais:\n`;
            if (capture.form_data.email) message += `Email: ${capture.form_data.email}\n`;
            if (capture.form_data.password) message += `Senha: ${capture.form_data.password}\n`;
        }

        if (capture.user_agent) {
            message += `\n💻 User Agent: ${capture.user_agent}\n`;
        }
        
        if (capture.screen_resolution) {
            message += `📐 Resolução: ${capture.screen_resolution}\n`;
        }
        
        console.log('Share message built:', message);
        
        // Store message in a global variable
        window.currentShareMessage = message;
        
        // Create modal using DOM (safer than innerHTML with special characters)
        const modal = document.createElement('div');
        modal.className = 'share-modal';
        
        const modalContent = document.createElement('div');
        modalContent.className = 'share-modal-content';
        
        // Header
        const header = document.createElement('div');
        header.className = 'share-modal-header';
        header.innerHTML = '<h3>Compartilhar Captura</h3>';
        
        const closeBtn = document.createElement('button');
        closeBtn.className = 'close-btn';
        closeBtn.innerHTML = '<i class="fas fa-times"></i>';
        closeBtn.onclick = () => modal.remove();
        header.appendChild(closeBtn);
        
        // Body
        const body = document.createElement('div');
        body.className = 'share-modal-body';
        
        const textarea = document.createElement('textarea');
        textarea.className = 'share-text';
        textarea.readOnly = true;
        textarea.value = message;
        body.appendChild(textarea);
        
        // Photo if available
        if (hasPhoto && capture.photo_base64) {
            const photoDiv = document.createElement('div');
            photoDiv.className = 'share-photo';
            photoDiv.innerHTML = '<p><strong>Foto capturada:</strong></p>';
            
            const img = document.createElement('img');
            img.src = `data:image/jpeg;base64,${capture.photo_base64}`;
            img.alt = 'Captura';
            img.style.cssText = 'max-width: 100%; border-radius: 8px; margin-top: 10px;';
            photoDiv.appendChild(img);
            body.appendChild(photoDiv);
        }
        
        // Footer with buttons
        const footer = document.createElement('div');
        footer.className = 'share-modal-footer';
        
        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn';
        copyBtn.innerHTML = '<i class="fas fa-copy"></i> Copiar Texto';
        copyBtn.onclick = () => copyToClipboard(window.currentShareMessage);
        
        const whatsappBtn = document.createElement('button');
        whatsappBtn.className = 'btn btn-success';
        whatsappBtn.innerHTML = '<i class="fab fa-whatsapp"></i> WhatsApp';
        whatsappBtn.onclick = () => shareViaWhatsApp(window.currentShareMessage);
        
        const emailBtn = document.createElement('button');
        emailBtn.className = 'btn btn-primary';
        emailBtn.innerHTML = '<i class="fas fa-envelope"></i> Email';
        emailBtn.onclick = () => shareViaEmail(window.currentShareMessage);
        
        footer.appendChild(copyBtn);
        footer.appendChild(whatsappBtn);
        footer.appendChild(emailBtn);
        
        // Assemble modal
        modalContent.appendChild(header);
        modalContent.appendChild(body);
        modalContent.appendChild(footer);
        modal.appendChild(modalContent);
        document.body.appendChild(modal);
        
        console.log('Modal created and added to DOM');
        
        // Close on outside click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
        
    } catch (error) {
        console.error('Error in shareCapture:', error);
        showToast('Erro ao compartilhar captura: ' + error.message, 'error');
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Texto copiado para área de transferência!', 'success');
    }).catch(err => {
        showToast('Erro ao copiar texto', 'error');
    });
}

function shareViaWhatsApp(message) {
    try {
        const encodedMessage = encodeURIComponent(message);
        const whatsappUrl = `https://wa.me/?text=${encodedMessage}`;
        console.log('Opening WhatsApp with URL:', whatsappUrl);
        window.open(whatsappUrl, '_blank');
        showToast('Abrindo WhatsApp...', 'info');
    } catch (error) {
        console.error('Error sharing via WhatsApp:', error);
        showToast('Erro ao compartilhar no WhatsApp', 'error');
    }
}

function shareViaEmail(message) {
    try {
        const encodedMessage = encodeURIComponent(message);
        const subject = encodeURIComponent('Captura de Phishing');
        const mailtoUrl = `mailto:?subject=${subject}&body=${encodedMessage}`;
        console.log('Opening email client with mailto URL');
        window.location.href = mailtoUrl;
        showToast('Abrindo cliente de email...', 'info');
    } catch (error) {
        console.error('Error sharing via email:', error);
        showToast('Erro ao compartilhar por email', 'error');
    }
}

// Payload Generator
async function loadPayloadCategories() {
    const select = document.getElementById('payload-category');
    if (!select) return; // Element doesn't exist yet
    
    try {
        const response = await apiRequest('/tools/payloads/categories');
        select.innerHTML = '<option value="">Selecione uma categoria</option>';
        
        if (response && response.categories && response.categories.length > 0) {
            response.categories.forEach(category => {
                const option = document.createElement('option');
                option.value = category.id;
                option.textContent = `${category.name} (${category.count} payloads)`;
                select.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error loading payload categories:', error);
        if (select) {
            select.innerHTML = '<option value="">Erro ao carregar categorias</option>';
        }
    }
}

async function generatePayloads() {
    const category = document.getElementById('payload-category').value;
    const encode = document.getElementById('encode-payload').checked;
    const encodeType = document.getElementById('encoding-type').value;

    if (!category) {
        showToast('Selecione uma categoria', 'error');
        return;
    }

    try {
        const response = await apiRequest('/tools/payloads/generate', {
            method: 'POST',
            body: JSON.stringify({
                category,
                encode,
                encode_type: encodeType
            })
        });

        displayPayloads(response.payloads);
        document.getElementById('payload-count').textContent = response.total;
        showToast(`${response.total} payloads gerados!`, 'success');
    } catch (error) {
        console.error('Error generating payloads:', error);
    }
}

function displayPayloads(payloads) {
    const container = document.getElementById('payloads-list');
    
    container.innerHTML = payloads.map(payload => `
        <div class="payload-item">
            <div class="payload-item-header">
                <span>${payload.description}</span>
                <span class="severity-badge severity-${payload.severity}">${payload.severity}</span>
            </div>
            <div class="payload-code">${escapeHtml(payload.encoded || payload.payload)}</div>
            ${payload.encoded ? `
                <small style="color: #666;">Original: ${escapeHtml(payload.payload)}</small>
            ` : ''}
            <button class="btn-sm" style="margin-top: 8px;" onclick="copyPayload('${escapeHtml(payload.encoded || payload.payload)}')">
                <i class="fas fa-copy"></i> Copiar
            </button>
        </div>
    `).join('');
}

function copyPayload(payload) {
    const textarea = document.createElement('textarea');
    textarea.value = payload.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#x27;/g, "'");
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showToast('Payload copiado!', 'success');
}

// Encoder/Decoder
async function loadEncodingTypes() {
    const encodeSelect = document.getElementById('encode-type');
    const decodeSelect = document.getElementById('decode-type');
    const hashSelect = document.getElementById('hash-type');
    
    // Check if elements exist
    if (!encodeSelect || !decodeSelect || !hashSelect) return;
    
    try {
        const response = await apiRequest('/tools/encoder/types');
        
        // Load encodings
        if (response && response.encodings) {
            encodeSelect.innerHTML = '<option value="">Selecione o tipo</option>';
            decodeSelect.innerHTML = '<option value="">Selecione o tipo</option>';
            
            response.encodings.forEach(enc => {
                const option = document.createElement('option');
                option.value = enc.id;
                option.textContent = `${enc.name} - ${enc.description}`;
                encodeSelect.appendChild(option);
                
                const option2 = option.cloneNode(true);
                decodeSelect.appendChild(option2);
            });
        }
        
        // Load hash types
        if (response && response.hashes) {
            hashSelect.innerHTML = '<option value="">Selecione o algoritmo</option>';
            response.hashes.forEach(hash => {
                const option = document.createElement('option');
                option.value = hash.id;
                option.textContent = `${hash.name} - ${hash.description}`;
                hashSelect.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error loading encoding types:', error);
        encodeSelect.innerHTML = '<option value="">Erro ao carregar tipos</option>';
        decodeSelect.innerHTML = '<option value="">Erro ao carregar tipos</option>';
        hashSelect.innerHTML = '<option value="">Erro ao carregar algoritmos</option>';
    }
}

async function encodeText() {
    const text = document.getElementById('encode-input').value;
    const encodingType = document.getElementById('encode-type').value;

    if (!text || !encodingType) {
        showToast('Preencha todos os campos', 'error');
        return;
    }

    try {
        const response = await apiRequest('/tools/encoder/encode', {
            method: 'POST',
            body: JSON.stringify({ text, encoding_type: encodingType })
        });

        document.getElementById('encode-output').value = response.result.encoded;
        showToast('Texto codificado!', 'success');
    } catch (error) {
        console.error('Error encoding text:', error);
    }
}

async function decodeText() {
    const text = document.getElementById('decode-input').value;
    const encodingType = document.getElementById('decode-type').value;

    if (!text || !encodingType) {
        showToast('Preencha todos os campos', 'error');
        return;
    }

    try {
        const response = await apiRequest('/tools/encoder/decode', {
            method: 'POST',
            body: JSON.stringify({ text, encoding_type: encodingType })
        });

        if (response.result.success) {
            document.getElementById('decode-output').value = response.result.decoded;
            showToast('Texto decodificado!', 'success');
        } else {
            showToast('Erro ao decodificar: ' + response.result.error, 'error');
        }
    } catch (error) {
        console.error('Error decoding text:', error);
    }
}

async function hashText() {
    const text = document.getElementById('hash-input').value;
    const hashType = document.getElementById('hash-type').value;

    if (!text || !hashType) {
        showToast('Preencha todos os campos', 'error');
        return;
    }

    try {
        const response = await apiRequest('/tools/encoder/hash', {
            method: 'POST',
            body: JSON.stringify({ text, hash_type: hashType })
        });

        document.getElementById('hash-output').value = response.result.hash;
        showToast(`Hash ${hashType.toUpperCase()} gerado!`, 'success');
    } catch (error) {
        console.error('Error hashing text:', error);
    }
}

// Utility Functions
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.value || element.textContent;
    
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    showToast('Copiado para a área de transferência!', 'success');
}

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function showLoading(message = 'Carregando...') {
    const loadingElement = document.getElementById('loading');
    if (loadingElement) {
        const textElement = loadingElement.querySelector('.loading-text') || loadingElement;
        if (textElement.classList && textElement.classList.contains('loading-text')) {
            textElement.textContent = message;
        }
        loadingElement.classList.add('active');
    }
}

function hideLoading() {
    const loadingElement = document.getElementById('loading');
    if (loadingElement) {
        loadingElement.classList.remove('active');
    }
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Dark mode is now permanent - no theme initialization needed
// Removed theme toggle functionality

// ==================== CODE SCANNER ====================

function toggleCodeSource() {
    const sourceType = document.getElementById('code-source-type').value;
    const fileGroup = document.getElementById('file-source-group');
    const textGroup = document.getElementById('text-source-group');
    const urlGroup = document.getElementById('url-source-group');
    
    fileGroup.style.display = sourceType === 'file' ? 'block' : 'none';
    textGroup.style.display = sourceType === 'text' ? 'block' : 'none';
    urlGroup.style.display = sourceType === 'url' ? 'block' : 'none';
}

async function scanCode() {
    const sourceType = document.getElementById('code-source-type').value;
    const fileInput = document.getElementById('code-file');
    const codeTextarea = document.getElementById('code-content');
    const codeUrlInput = document.getElementById('code-url');
    const languageSelect = document.getElementById('code-language');
    
    let code = '';
    let filename = 'unknown';
    let url = '';
    
    // Get enabled scan options
    const scanOptions = {
        sql_injection: document.getElementById('scan-sql-injection')?.checked || false,
        xss: document.getElementById('scan-xss')?.checked || false,
        command_injection: document.getElementById('scan-command-injection')?.checked || false,
        path_traversal: document.getElementById('scan-path-traversal')?.checked || false,
        hardcoded_secrets: document.getElementById('scan-hardcoded-secrets')?.checked || false,
        insecure_functions: document.getElementById('scan-insecure-functions')?.checked || false
    };
    
    try {
        if (sourceType === 'file') {
            if (fileInput.files.length === 0) {
                showToast('Por favor, selecione um arquivo', 'error');
                return;
            }
            const file = fileInput.files[0];
            filename = file.name;
            code = await file.text();
            
        } else if (sourceType === 'text') {
            code = codeTextarea.value;
            filename = 'pasted_code.' + (languageSelect.value === 'auto' ? 'txt' : languageSelect.value);
            
        } else if (sourceType === 'url') {
            url = codeUrlInput.value.trim();
            if (!url) {
                showToast('Por favor, forneça uma URL', 'error');
                return;
            }
            
            // Validate URL
            try {
                new URL(url);
            } catch (e) {
                showToast('URL inválida', 'error');
                return;
            }
            
            showLoading('Baixando código da URL...');
            
            // Fetch code from URL
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                code = await response.text();
                
                // Extract filename from URL
                const urlPath = new URL(url).pathname;
                filename = urlPath.split('/').pop() || 'downloaded_code';
                
                showToast('Código baixado com sucesso!', 'success');
            } catch (fetchError) {
                hideLoading();
                showToast('Erro ao baixar código da URL: ' + fetchError.message, 'error');
                return;
            }
        }
        
        if (!code.trim()) {
            showToast('Por favor, forneça código para análise', 'error');
            return;
        }
        
        showLoading('Analisando código...');
        
        const response = await apiRequest('/scan/code', {
            method: 'POST',
            body: JSON.stringify({
                code: code,
                filename: filename,
                language: languageSelect.value,
                scan_options: scanOptions
            })
        });
        
        displayScanResults(response.results);
        showToast('Análise concluída!', 'success');
        
        // Atualiza dashboard stats
        loadDashboardStats();
        
    } catch (error) {
        console.error('Error scanning code:', error);
        showToast('Erro ao analisar código: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

function displayScanResults(results) {
    const container = document.getElementById('scan-results');
    const countBadge = document.getElementById('vuln-count');
    
    if (!results || !results.vulnerabilities || results.vulnerabilities.length === 0) {
        container.innerHTML = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <strong>Nenhuma vulnerabilidade encontrada!</strong>
                <p>O código parece estar seguro de acordo com nossa análise.</p>
            </div>
        `;
        countBadge.textContent = '0';
        return;
    }
    
    const vulns = results.vulnerabilities;
    countBadge.textContent = vulns.length;
    
    // Group by severity
    const critical = vulns.filter(v => v.severity === 'CRITICAL');
    const high = vulns.filter(v => v.severity === 'HIGH');
    const medium = vulns.filter(v => v.severity === 'MEDIUM');
    const low = vulns.filter(v => v.severity === 'LOW');
    
    let html = `
        <div class="scan-summary">
            <div class="severity-stats">
                ${critical.length > 0 ? `<span class="severity-badge critical">${critical.length} Críticas</span>` : ''}
                ${high.length > 0 ? `<span class="severity-badge high">${high.length} Altas</span>` : ''}
                ${medium.length > 0 ? `<span class="severity-badge medium">${medium.length} Médias</span>` : ''}
                ${low.length > 0 ? `<span class="severity-badge low">${low.length} Baixas</span>` : ''}
            </div>
            <button class="btn-primary" onclick="generateCodeScanReport()" style="margin-top: 15px;">
                <i class="fas fa-file-alt"></i> Gerar Relatório
            </button>
        </div>
        <div class="vulnerabilities-list">
    `;
    
    // Armazenar resultados globalmente para geração de relatório
    window.lastScanResults = results;
    
    vulns.forEach((vuln, index) => {
        html += `
            <div class="vulnerability-item severity-${vuln.severity.toLowerCase()}">
                <div class="vuln-header">
                    <span class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                    <h4>${vuln.type || 'Vulnerabilidade'}</h4>
                </div>
                <div class="vuln-body">
                    <p><strong>Descrição:</strong> ${vuln.description || 'Vulnerabilidade detectada'}</p>
                    <p><strong>Linha:</strong> ${vuln.line || 'N/A'}</p>
                    ${vuln.code ? `<pre><code>${escapeHtml(vuln.code)}</code></pre>` : ''}
                    ${vuln.recommendation ? `<p><strong>Recomendação:</strong> ${vuln.recommendation}</p>` : ''}
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

// Setup file input handler
document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('code-file');
    if (fileInput) {
        fileInput.addEventListener('change', async function() {
            if (this.files.length > 0) {
                const file = this.files[0];
                const code = await file.text();
                document.getElementById('code-content').value = code;
            }
        });
    }
    
    // Setup port scan type selector
    const portScanType = document.getElementById('port-scan-type');
    if (portScanType) {
        portScanType.addEventListener('change', function() {
            document.getElementById('custom-ports-group').style.display = 
                this.value === 'custom' ? 'block' : 'none';
            document.getElementById('port-range-group').style.display = 
                this.value === 'range' ? 'block' : 'none';
        });
    }
});

// ==================== PORT SCANNER ====================

async function startPortScan() {
    const target = document.getElementById('port-target').value.trim();
    const scanType = document.getElementById('port-scan-type').value;
    
    if (!target) {
        showToast('Por favor, informe um alvo (IP ou hostname)', 'error');
        return;
    }
    
    let ports = null;
    
    if (scanType === 'custom') {
        const customPorts = document.getElementById('custom-ports').value.trim();
        if (!customPorts) {
            showToast('Por favor, informe as portas', 'error');
            return;
        }
        ports = customPorts.split(',').map(p => parseInt(p.trim())).filter(p => p > 0 && p <= 65535);
    } else if (scanType === 'range') {
        const start = parseInt(document.getElementById('port-start').value);
        const end = parseInt(document.getElementById('port-end').value);
        if (start > end || start < 1 || end > 65535) {
            showToast('Range de portas inválido', 'error');
            return;
        }
        ports = [];
        for (let i = start; i <= end; i++) {
            ports.push(i);
        }
    }
    
    try {
        showLoading();
        const response = await apiRequest('/scan/ports', {
            method: 'POST',
            body: JSON.stringify({
                target: target,
                ports: ports
            })
        });
        
        displayPortScanResults(response.results);
        showToast('Scan concluído!', 'success');
        
        // Atualiza dashboard stats e subscription card
        loadDashboardStats();
        checkSubscription();
        
    } catch (error) {
        console.error('Port scan error:', error);
        
        // Verificar se é erro de limite de scans
        if (error.message && error.message.includes('limite')) {
            showToast('Limite de scans atingido! Faça upgrade para continuar.', 'warning');
            
            // Mostrar modal de upgrade
            if (confirm('Você atingiu o limite de scans do seu plano. Deseja fazer upgrade agora?')) {
                window.location.href = 'pricing.html';
            }
        } else {
            showToast('Erro ao escanear portas: ' + error.message, 'error');
        }
    } finally {
        hideLoading();
    }
}

function displayPortScanResults(results) {
    const container = document.getElementById('port-scan-results');
    const countBadge = document.getElementById('open-ports-count');
    
    console.log('Port scan results:', results);
    
    if (!results || !results.ports || results.ports.length === 0) {
        container.innerHTML = `
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i>
                <strong>Nenhuma porta aberta encontrada</strong>
                <p>Todas as portas escaneadas estão fechadas ou filtradas.</p>
            </div>
        `;
        countBadge.textContent = '0';
        return;
    }
    
    const openPorts = results.ports.filter(p => p.state === 'open');
    countBadge.textContent = results.open_ports || openPorts.length;
    
    // Group by severity
    const critical = openPorts.filter(p => p.severity === 'CRITICAL');
    const high = openPorts.filter(p => p.severity === 'HIGH');
    const medium = openPorts.filter(p => p.severity === 'MEDIUM');
    const low = openPorts.filter(p => p.severity === 'LOW' || !p.severity);
    
    let html = `
        <div class="port-scan-summary">
            <div class="severity-stats">
                ${critical.length > 0 ? `<span class="severity-badge critical">${critical.length} Críticas</span>` : ''}
                ${high.length > 0 ? `<span class="severity-badge high">${high.length} Alto Risco</span>` : ''}
                ${medium.length > 0 ? `<span class="severity-badge medium">${medium.length} Médio Risco</span>` : ''}
                ${low.length > 0 ? `<span class="severity-badge low">${low.length} Baixo Risco</span>` : ''}
            </div>
            <button class="btn-primary" onclick="generatePortScanReport()" style="margin-top: 15px;">
                <i class="fas fa-file-alt"></i> Gerar Relatório
            </button>
        </div>
        <div class="ports-grid">
    `;
    
    // Armazenar resultados globalmente para geração de relatório
    window.lastPortScanResults = results;
    
    openPorts.forEach(port => {
        const severityClass = (port.severity || 'MEDIUM').toLowerCase();
        const isVulnerable = port.is_vulnerable || false;
        
        html += `
            <div class="port-item risk-${severityClass}">
                <div class="port-header">
                    <div class="port-number">
                        <i class="fas fa-network-wired"></i> Porta ${port.port}
                    </div>
                    <span class="badge badge-${severityClass}">${port.severity || 'MEDIUM'}</span>
                </div>
                <div class="port-info">
                    <p><strong>Serviço:</strong> ${port.service || 'Unknown'}</p>
                    ${port.banner ? `<p><strong>Banner:</strong> <code>${port.banner.substring(0, 100)}...</code></p>` : ''}
                    ${port.version_info && Object.keys(port.version_info).length > 0 ? `<p><strong>Versão:</strong> ${JSON.stringify(port.version_info)}</p>` : ''}
                    ${isVulnerable ? `<p class="text-danger"><i class="fas fa-exclamation-triangle"></i> <strong>Vulnerável:</strong> ${port.vulnerability || 'Serviço exposto'}</p>` : ''}
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    
    // Vulnerabilities section
    if (results.vulnerabilities && results.vulnerabilities.length > 0) {
        html += `
            <div class="vulnerabilities-section">
                <h3><i class="fas fa-bug"></i> Vulnerabilidades Encontradas</h3>
                <div class="vulnerabilities-list">
        `;
        
        results.vulnerabilities.forEach(vuln => {
            html += `
                <div class="vulnerability-item severity-${vuln.severity.toLowerCase()}">
                    <div class="vuln-header">
                        <span class="badge badge-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                        <strong>${vuln.type}</strong>
                    </div>
                    <p><strong>Porta:</strong> ${vuln.port} (${vuln.service})</p>
                    <p><strong>Descrição:</strong> ${vuln.description}</p>
                    <p><strong>Recomendação:</strong> ${vuln.recommendation}</p>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
    }
    
    // Summary section
    if (results.summary) {
        html += `
            <div class="scan-summary">
                <h3><i class="fas fa-chart-bar"></i> Resumo do Scan</h3>
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="summary-number">${results.total_ports_scanned || 0}</div>
                        <div class="summary-label">Portas Escaneadas</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">${results.open_ports || 0}</div>
                        <div class="summary-label">Portas Abertas</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number text-danger">${results.summary.total_vulnerabilities || 0}</div>
                        <div class="summary-label">Vulnerabilidades</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number text-warning">${results.summary.services_without_encryption || 0}</div>
                        <div class="summary-label">Sem Criptografia</div>
                    </div>
                </div>
                <p style="margin-top: 15px;"><strong>Host:</strong> ${results.host || 'N/A'}</p>
                <p><strong>Tempo do Scan:</strong> ${results.scan_time ? new Date(results.scan_time).toLocaleString('pt-BR') : 'N/A'}</p>
            </div>
        `;
    }
    
    container.innerHTML = html;
}

// ==================== REPORTS ====================

async function loadAvailableScans() {
    const container = document.getElementById('available-scans');
    
    try {
        const response = await apiRequest('/scans');
        const scans = response.scans || [];
        
        if (scans.length === 0) {
            container.innerHTML = `
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    <strong>Nenhum scan disponível</strong>
                    <p>Execute alguns scans primeiro para gerar relatórios.</p>
                </div>
            `;
            return;
        }
        
        let html = '<div class="scans-list">';
        
        scans.forEach(scan => {
            const date = new Date(scan.created_at || scan.completed_at).toLocaleString('pt-BR');
            const scanType = scan.scan_type || 'code';
            const scanTypeLabel = {
                'code': 'Código',
                'network': 'Rede/Portas',
                'api': 'API',
                'dependency': 'Dependências',
                'docker': 'Docker',
                'graphql': 'GraphQL'
            }[scanType] || scanType;
            
            html += `
                <div class="scan-item">
                    <div class="scan-info">
                        <div class="scan-icon ${scanType}">
                            <i class="fas fa-${getScanIcon(scanType)}"></i>
                        </div>
                        <div class="scan-details">
                            <h4>${scanTypeLabel} - ${scan.target || 'Sem alvo'}</h4>
                            <p class="scan-date">${date}</p>
                            <span class="scan-status ${scan.status}">${scan.status}</span>
                        </div>
                    </div>
                    <div class="scan-actions">
                        <button class="btn-sm" onclick="generateReport(${scan.id})">
                            <i class="fas fa-file-pdf"></i>
                            Gerar PDF
                        </button>
                        <button class="btn-sm btn-danger" onclick="deleteScan(${scan.id})" style="background: #dc3545;">
                            <i class="fas fa-trash"></i>
                            Deletar
                        </button>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
        
    } catch (error) {
        container.innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                Erro ao carregar scans: ${error.message}
            </div>
        `;
    }
}

function getScanIcon(scanType) {
    const icons = {
        'code': 'code',
        'network': 'network-wired',
        'api': 'plug',
        'dependency': 'cube',
        'docker': 'docker',
        'graphql': 'project-diagram'
    };
    return icons[scanType] || 'search';
}

async function generateReport(scanId) {
    try {
        showLoading();
        showToast('Gerando relatório PDF...', 'info');
        
        // Download PDF
        const response = await fetch(`${API_URL}/scans/${scanId}/report`, {
            headers: {
                'Authorization': `Bearer ${getToken()}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Erro ao gerar relatório');
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-report-${scanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showToast('Relatório gerado com sucesso!', 'success');
        
    } catch (error) {
        showToast('Erro ao gerar relatório: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function deleteScan(scanId) {
    if (!confirm('Tem certeza que deseja deletar este scan? Esta ação não pode ser desfeita.')) {
        return;
    }
    
    try {
        showLoading();
        
        await apiRequest(`/scans/${scanId}`, {
            method: 'DELETE'
        });
        
        showToast('Scan deletado com sucesso!', 'success');
        
        // Recarrega a lista de scans
        loadAvailableScans();
        
        // Atualiza dashboard stats
        loadDashboardStats();
        
    } catch (error) {
        showToast('Erro ao deletar scan: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

// ==================== GENERIC REPORT GENERATOR ====================

// Função genérica para gerar relatórios de qualquer ferramenta
async function generateToolReport(toolName, toolData, resultData) {
    try {
        showLoading();
        showToast('Gerando relatório...', 'info');
        
        const reportData = {
            tool_name: toolName,
            tool_data: toolData,
            result_data: resultData,
            generated_at: new Date().toISOString(),
            user: localStorage.getItem('username') || 'Usuário'
        };
        
        const response = await apiRequest('/tools/generate-report', {
            method: 'POST',
            body: JSON.stringify(reportData)
        });
        
        if (response.report_html) {
            // Criar modal para preview do relatório
            createReportPreviewModal(response.report_html, toolName);
            showToast('Relatório gerado com sucesso!', 'success');
        }
        
    } catch (error) {
        showToast('Erro ao gerar relatório: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

// Cria modal de preview do relatório
function createReportPreviewModal(reportHtml, toolName) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal-content" style="max-width: 900px; max-height: 90vh; overflow-y: auto;">
            <div class="modal-header">
                <h2><i class="fas fa-file-alt"></i> Relatório - ${toolName}</h2>
                <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="report-actions" style="margin-bottom: 20px; display: flex; gap: 10px; justify-content: flex-end;">
                    <button class="btn-primary" onclick="printReport()">
                        <i class="fas fa-print"></i> Imprimir
                    </button>
                    <button class="btn-primary" onclick="downloadReportPDF('${toolName}')">
                        <i class="fas fa-file-pdf"></i> Baixar PDF
                    </button>
                    <button class="btn-secondary" onclick="copyReportHTML()">
                        <i class="fas fa-copy"></i> Copiar HTML
                    </button>
                </div>
                <div id="report-content" class="report-preview" style="background: white; color: #000; padding: 30px; border-radius: 8px;">
                    ${reportHtml}
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Fechar ao clicar fora
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

// Imprime o relatório
function printReport() {
    const reportContent = document.getElementById('report-content');
    if (!reportContent) return;
    
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
        <html>
            <head>
                <title>Relatório de Segurança</title>
                <style>
                    body { font-family: Arial, sans-serif; padding: 20px; }
                    table { border-collapse: collapse; width: 100%; margin: 20px 0; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #7c3aed; color: white; }
                    h1, h2, h3 { color: #333; }
                    .info-box { background: #f0f0f0; padding: 15px; margin: 10px 0; border-radius: 5px; }
                </style>
            </head>
            <body>
                ${reportContent.innerHTML}
            </body>
        </html>
    `);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
        printWindow.print();
        printWindow.close();
    }, 250);
}

// Download relatório como PDF
async function downloadReportPDF(toolName) {
    const reportContent = document.getElementById('report-content');
    if (!reportContent) return;
    
    try {
        showToast('Preparando PDF...', 'info');
        
        // Usar html2pdf se estiver disponível, senão usar print
        if (typeof html2pdf !== 'undefined') {
            const opt = {
                margin: 1,
                filename: `relatorio-${toolName.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}.pdf`,
                image: { type: 'jpeg', quality: 0.98 },
                html2canvas: { scale: 2 },
                jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' }
            };
            
            await html2pdf().set(opt).from(reportContent).save();
            showToast('PDF baixado com sucesso!', 'success');
        } else {
            // Fallback: usar print
            showToast('Use o botão Imprimir e escolha "Salvar como PDF"', 'info');
            printReport();
        }
    } catch (error) {
        showToast('Erro ao gerar PDF. Use o botão Imprimir.', 'error');
        console.error('PDF generation error:', error);
    }
}

// Copia HTML do relatório
function copyReportHTML() {
    const reportContent = document.getElementById('report-content');
    if (!reportContent) return;
    
    const htmlContent = reportContent.innerHTML;
    navigator.clipboard.writeText(htmlContent).then(() => {
        showToast('HTML copiado para área de transferência!', 'success');
    }).catch(err => {
        showToast('Erro ao copiar HTML', 'error');
    });
}

// ==================== SPECIFIC REPORT GENERATORS ====================

// Relatório de Code Scanner
function generateCodeScanReport() {
    if (!window.lastScanResults) {
        showToast('Nenhum resultado de scan disponível', 'error');
        return;
    }
    
    const results = window.lastScanResults;
    const vulns = results.vulnerabilities || [];
    
    const critical = vulns.filter(v => v.severity === 'CRITICAL');
    const high = vulns.filter(v => v.severity === 'HIGH');
    const medium = vulns.filter(v => v.severity === 'MEDIUM');
    const low = vulns.filter(v => v.severity === 'LOW');
    
    const reportHtml = `
        <div style="font-family: Arial, sans-serif;">
            <h1 style="color: #7c3aed; border-bottom: 3px solid #7c3aed; padding-bottom: 10px;">
                Relatório de Análise de Código
            </h1>
            <div style="background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px;">
                <p><strong>Data:</strong> ${new Date().toLocaleString('pt-BR')}</p>
                <p><strong>Analista:</strong> ${localStorage.getItem('username') || 'Usuário'}</p>
                <p><strong>Total de Vulnerabilidades:</strong> ${vulns.length}</p>
            </div>
            
            <h2 style="color: #333; margin-top: 30px;">Resumo por Severidade</h2>
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="background: #7c3aed; color: white;">
                    <th style="padding: 10px; text-align: left;">Severidade</th>
                    <th style="padding: 10px; text-align: center;">Quantidade</th>
                </tr>
                <tr style="background: #ffe6e6;">
                    <td style="padding: 10px;"><strong>Crítica</strong></td>
                    <td style="padding: 10px; text-align: center;">${critical.length}</td>
                </tr>
                <tr style="background: #fff3e6;">
                    <td style="padding: 10px;"><strong>Alta</strong></td>
                    <td style="padding: 10px; text-align: center;">${high.length}</td>
                </tr>
                <tr style="background: #fff9e6;">
                    <td style="padding: 10px;"><strong>Média</strong></td>
                    <td style="padding: 10px; text-align: center;">${medium.length}</td>
                </tr>
                <tr style="background: #e6f7ff;">
                    <td style="padding: 10px;"><strong>Baixa</strong></td>
                    <td style="padding: 10px; text-align: center;">${low.length}</td>
                </tr>
            </table>
            
            <h2 style="color: #333; margin-top: 30px;">Detalhes das Vulnerabilidades</h2>
            ${vulns.map((v, i) => `
                <div style="border: 2px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 5px solid ${getSeverityColor(v.severity)};">
                    <h3 style="margin: 0 0 10px 0; color: ${getSeverityColor(v.severity)};">
                        ${i + 1}. ${v.type || 'Vulnerabilidade'}
                    </h3>
                    <p><strong>Severidade:</strong> <span style="color: ${getSeverityColor(v.severity)};">${v.severity}</span></p>
                    <p><strong>Descrição:</strong> ${v.description || 'N/A'}</p>
                    <p><strong>Linha:</strong> ${v.line || 'N/A'}</p>
                    ${v.code ? `<pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto;"><code>${escapeHtml(v.code)}</code></pre>` : ''}
                    ${v.recommendation ? `<p><strong>Recomendação:</strong> ${v.recommendation}</p>` : ''}
                </div>
            `).join('')}
            
            <div style="margin-top: 40px; padding: 20px; background: #f0f0f0; border-radius: 5px;">
                <h3>Conclusão</h3>
                <p>
                    ${vulns.length === 0 ? 
                        'Nenhuma vulnerabilidade foi encontrada. O código analisado parece estar seguro.' :
                        `Foram identificadas ${vulns.length} vulnerabilidade(s). Recomenda-se revisar e corrigir as questões apontadas, priorizando as de maior severidade.`
                    }
                </p>
            </div>
        </div>
    `;
    
    createReportPreviewModal(reportHtml, 'Code Scanner');
}

// Relatório de Port Scanner
function generatePortScanReport() {
    if (!window.lastPortScanResults) {
        showToast('Nenhum resultado de scan de portas disponível', 'error');
        return;
    }
    
    const results = window.lastPortScanResults;
    const ports = results.ports || [];
    const openPorts = ports.filter(p => p.state === 'open');
    
    const reportHtml = `
        <div style="font-family: Arial, sans-serif;">
            <h1 style="color: #7c3aed; border-bottom: 3px solid #7c3aed; padding-bottom: 10px;">
                Relatório de Scan de Portas
            </h1>
            <div style="background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px;">
                <p><strong>Data:</strong> ${new Date().toLocaleString('pt-BR')}</p>
                <p><strong>Analista:</strong> ${localStorage.getItem('username') || 'Usuário'}</p>
                <p><strong>Alvo:</strong> ${results.target || 'N/A'}</p>
                <p><strong>Portas Abertas:</strong> ${openPorts.length}</p>
                <p><strong>Portas Escaneadas:</strong> ${ports.length}</p>
            </div>
            
            <h2 style="color: #333; margin-top: 30px;">Portas Abertas Encontradas</h2>
            ${openPorts.length === 0 ? 
                '<p>Nenhuma porta aberta foi encontrada.</p>' :
                `<table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                    <tr style="background: #7c3aed; color: white;">
                        <th style="padding: 10px; text-align: left;">Porta</th>
                        <th style="padding: 10px; text-align: left;">Serviço</th>
                        <th style="padding: 10px; text-align: left;">Estado</th>
                        <th style="padding: 10px; text-align: left;">Severidade</th>
                    </tr>
                    ${openPorts.map(p => `
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 10px;"><strong>${p.port}</strong></td>
                            <td style="padding: 10px;">${p.service || 'Desconhecido'}</td>
                            <td style="padding: 10px;">${p.state}</td>
                            <td style="padding: 10px; color: ${getSeverityColor(p.severity || 'MEDIUM')};">
                                ${p.severity || 'MEDIUM'}
                            </td>
                        </tr>
                    `).join('')}
                </table>`
            }
            
            <div style="margin-top: 40px; padding: 20px; background: #f0f0f0; border-radius: 5px;">
                <h3>Recomendações</h3>
                <ul>
                    <li>Verifique se todas as portas abertas são necessárias para o funcionamento do sistema</li>
                    <li>Considere fechar portas não utilizadas ou aplicar regras de firewall</li>
                    <li>Mantenha os serviços atualizados para evitar vulnerabilidades conhecidas</li>
                    <li>Implemente autenticação forte em serviços expostos</li>
                </ul>
            </div>
        </div>
    `;
    
    createReportPreviewModal(reportHtml, 'Port Scanner');
}

// Helper: Obter cor por severidade
function getSeverityColor(severity) {
    const colors = {
        'CRITICAL': '#d32f2f',
        'HIGH': '#f57c00',
        'MEDIUM': '#fbc02d',
        'LOW': '#388e3c'
    };
    return colors[severity] || '#757575';
}

// Relatório de SQL Injection
function generateSQLInjectionReport() {
    if (!window.lastSQLInjectionResults) {
        showToast('Nenhum resultado de teste disponível', 'error');
        return;
    }
    
    const results = window.lastSQLInjectionResults;
    const vulnerableResults = results.results.filter(r => r.vulnerable);
    
    const reportHtml = `
        <div style="font-family: Arial, sans-serif;">
            <h1 style="color: #7c3aed; border-bottom: 3px solid #7c3aed; padding-bottom: 10px;">
                Relatório de Teste SQL Injection
            </h1>
            <div style="background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px;">
                <p><strong>Data:</strong> ${new Date().toLocaleString('pt-BR')}</p>
                <p><strong>Analista:</strong> ${localStorage.getItem('username') || 'Usuário'}</p>
                <p><strong>URL Testada:</strong> ${results.target || 'N/A'}</p>
                <p><strong>Parâmetros Testados:</strong> ${results.parameters_tested}</p>
                <p><strong>Payloads Testados:</strong> ${results.payloads_tested}</p>
                <p><strong>Vulnerabilidades Encontradas:</strong> ${results.vulnerabilities_found}</p>
            </div>
            
            <h2 style="color: #333; margin-top: 30px;">Resumo do Teste</h2>
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr style="background: #7c3aed; color: white;">
                    <th style="padding: 10px; text-align: left;">Métrica</th>
                    <th style="padding: 10px; text-align: center;">Valor</th>
                </tr>
                <tr style="border-bottom: 1px solid #ddd;">
                    <td style="padding: 10px;">Parâmetros Testados</td>
                    <td style="padding: 10px; text-align: center;"><strong>${results.parameters_tested}</strong></td>
                </tr>
                <tr style="border-bottom: 1px solid #ddd;">
                    <td style="padding: 10px;">Payloads Testados</td>
                    <td style="padding: 10px; text-align: center;"><strong>${results.payloads_tested}</strong></td>
                </tr>
                <tr style="border-bottom: 1px solid #ddd; background: ${results.vulnerabilities_found > 0 ? '#ffe6e6' : '#e6ffe6'};">
                    <td style="padding: 10px;">Vulnerabilidades Encontradas</td>
                    <td style="padding: 10px; text-align: center;"><strong style="color: ${results.vulnerabilities_found > 0 ? '#d32f2f' : '#388e3c'};">${results.vulnerabilities_found}</strong></td>
                </tr>
            </table>
            
            ${vulnerableResults.length > 0 ? `
                <h2 style="color: #d32f2f; margin-top: 30px;">⚠️ Vulnerabilidades Detectadas</h2>
                ${vulnerableResults.map((v, i) => `
                    <div style="border: 2px solid #d32f2f; padding: 15px; margin: 15px 0; border-radius: 5px; background: #ffe6e6;">
                        <h3 style="margin: 0 0 10px 0; color: #d32f2f;">
                            Vulnerabilidade ${i + 1} - Parâmetro: ${v.parameter}
                        </h3>
                        <p><strong>Payload:</strong></p>
                        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto;"><code>${escapeHtml(v.payload)}</code></pre>
                        ${v.error_message ? `<p><strong>Mensagem de Erro:</strong> ${v.error_message}</p>` : ''}
                    </div>
                `).join('')}
            ` : `
                <div style="margin-top: 30px; padding: 20px; background: #e6ffe6; border-radius: 5px; border: 2px solid #388e3c;">
                    <h3 style="color: #388e3c;">✓ Nenhuma vulnerabilidade SQL Injection detectada</h3>
                    <p>O sistema testado parece estar protegido contra ataques SQL Injection.</p>
                </div>
            `}
            
            <div style="margin-top: 40px; padding: 20px; background: #f0f0f0; border-radius: 5px;">
                <h3>Recomendações de Segurança</h3>
                <ul>
                    <li>Utilize prepared statements ou consultas parametrizadas</li>
                    <li>Implemente validação de entrada rigorosa</li>
                    <li>Aplique sanitização adequada de dados</li>
                    <li>Utilize ORMs com proteção integrada contra SQL Injection</li>
                    <li>Mantenha logs de tentativas de SQL Injection</li>
                    <li>Configure mensagens de erro genéricas em produção</li>
                </ul>
            </div>
        </div>
    `;
    
    createReportPreviewModal(reportHtml, 'SQL Injection Tester');
}

// Relatório de XSS
function generateXSSReport() {
    if (!window.lastXSSResults) {
        showToast('Nenhum resultado de teste XSS disponível', 'error');
        return;
    }
    
    const results = window.lastXSSResults;
    const vulnerableResults = results.results.filter(r => r.vulnerable);
    
    const reportHtml = `
        <div style="font-family: Arial, sans-serif;">
            <h1 style="color: #7c3aed; border-bottom: 3px solid #7c3aed; padding-bottom: 10px;">
                Relatório de Teste XSS (Cross-Site Scripting)
            </h1>
            <div style="background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px;">
                <p><strong>Data:</strong> ${new Date().toLocaleString('pt-BR')}</p>
                <p><strong>Analista:</strong> ${localStorage.getItem('username') || 'Usuário'}</p>
                <p><strong>URL Testada:</strong> ${results.target || 'N/A'}</p>
                <p><strong>Vulnerabilidades Encontradas:</strong> ${results.vulnerabilities_found}</p>
            </div>
            
            ${vulnerableResults.length > 0 ? `
                <h2 style="color: #f57c00; margin-top: 30px;">⚠️ Vulnerabilidades XSS Detectadas</h2>
                ${vulnerableResults.map((v, i) => `
                    <div style="border: 2px solid #f57c00; padding: 15px; margin: 15px 0; border-radius: 5px; background: #fff3e6;">
                        <h3 style="margin: 0 0 10px 0; color: #f57c00;">
                            ${v.type.toUpperCase()} XSS - Parâmetro: ${v.parameter}
                        </h3>
                        <p><strong>Severidade:</strong> <span style="color: ${getSeverityColor(v.severity.toUpperCase())};">${v.severity.toUpperCase()}</span></p>
                        <p><strong>Payload:</strong></p>
                        <pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto;"><code>${escapeHtml(v.payload)}</code></pre>
                    </div>
                `).join('')}
            ` : `
                <div style="margin-top: 30px; padding: 20px; background: #e6ffe6; border-radius: 5px; border: 2px solid #388e3c;">
                    <h3 style="color: #388e3c;">✓ Nenhuma vulnerabilidade XSS detectada</h3>
                    <p>O sistema testado parece estar protegido contra ataques XSS.</p>
                </div>
            `}
            
            <div style="margin-top: 40px; padding: 20px; background: #f0f0f0; border-radius: 5px;">
                <h3>Tipos de XSS</h3>
                <ul>
                    <li><strong>Reflected XSS:</strong> O payload é refletido imediatamente na resposta</li>
                    <li><strong>Stored XSS:</strong> O payload é armazenado no servidor e executado posteriormente</li>
                    <li><strong>DOM-based XSS:</strong> A vulnerabilidade existe no código JavaScript do cliente</li>
                </ul>
                <h3>Recomendações de Segurança</h3>
                <ul>
                    <li>Sanitize e escape todos os dados de entrada antes de exibi-los</li>
                    <li>Implemente Content Security Policy (CSP)</li>
                    <li>Use bibliotecas de sanitização como DOMPurify</li>
                    <li>Valide e codifique saídas baseadas no contexto (HTML, JavaScript, CSS)</li>
                    <li>Configure HttpOnly e Secure flags em cookies</li>
                </ul>
            </div>
        </div>
    `;
    
    createReportPreviewModal(reportHtml, 'XSS Tester');
}

// Relatório genérico para outras ferramentas Red/Blue Team
function generateGenericToolReport(toolName, resultsData) {
    const reportHtml = `
        <div style="font-family: Arial, sans-serif;">
            <h1 style="color: #7c3aed; border-bottom: 3px solid #7c3aed; padding-bottom: 10px;">
                Relatório - ${toolName}
            </h1>
            <div style="background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px;">
                <p><strong>Data:</strong> ${new Date().toLocaleString('pt-BR')}</p>
                <p><strong>Analista:</strong> ${localStorage.getItem('username') || 'Usuário'}</p>
                <p><strong>Ferramenta:</strong> ${toolName}</p>
            </div>
            
            <h2 style="color: #333; margin-top: 30px;">Resultados</h2>
            <div style="background: white; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                <pre style="white-space: pre-wrap; word-wrap: break-word;">${JSON.stringify(resultsData, null, 2)}</pre>
            </div>
            
            <div style="margin-top: 40px; padding: 20px; background: #f0f0f0; border-radius: 5px;">
                <h3>Observações</h3>
                <p>Este relatório foi gerado automaticamente. Revise os resultados e tome as ações necessárias.</p>
            </div>
        </div>
    `;
    
    createReportPreviewModal(reportHtml, toolName);
}

// ==================== NOTIFICATIONS ====================

async function loadNotifications() {
    try {
        const response = await apiRequest('/tools/notifications');
        const { notifications, unread_count } = response;
        
        // Update badge
        const badge = document.querySelector('.header-actions .badge');
        if (badge) {
            badge.textContent = unread_count;
            badge.style.display = unread_count > 0 ? 'block' : 'none';
        }
        
        // Store notifications for dropdown (we'll add dropdown UI later)
        window.currentNotifications = notifications;
        
    } catch (error) {
        console.error('Error loading notifications:', error);
    }
}

function setupNotificationsDropdown() {
    const bellBtn = document.getElementById('notification-icon');
    if (!bellBtn) return;
    
    // Remover listeners antigos para evitar duplicação
    const newBtn = bellBtn.cloneNode(true);
    bellBtn.parentNode.replaceChild(newBtn, bellBtn);
    
    newBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        showNotificationsPanel();
    });
}

async function showNotificationsPanel() {
    // Remove existing panel
    const existingPanel = document.querySelector('.notifications-panel');
    if (existingPanel) {
        existingPanel.remove();
        return;
    }
    
    // Se não houver notificações carregadas, tenta carregar
    if (!window.currentNotifications) {
        await loadNotifications();
    }
    
    // Filtrar apenas não lidas para exibição, conforme solicitado
    // "depois que eu clicar e ver elas podem sumir"
    // Mostraremos todas agora, mas ao fechar e abrir de novo, as lidas sumirão se filtrarmos aqui?
    // Melhor: mostrar todas aqui, mas o comportamento de "sumir" será natural se filtrarmos as lidas.
    // Vamos filtrar para mostrar apenas as não lidas OU as que acabaram de chegar.
    // Mas se o usuário quiser ver o histórico? O pedido foi "podem sumir".
    // Então vamos mostrar apenas as não lidas.
    
    const allNotifications = window.currentNotifications || [];
    // Mostra apenas notificações não lidas
    const notifications = allNotifications.filter(n => !n.read);
    
    // Se não houver não lidas, mas houver notificações recentes (ex: últimas 5), mostramos para não ficar vazio?
    // O usuário disse "podem sumir", então se não tiver não lidas, mostra vazio.
    
    const panel = document.createElement('div');
    panel.className = 'notifications-panel';
    panel.innerHTML = `
        <div class="notifications-header">
            <h3>Notificações</h3>
            <div>
                <span class="badge">${notifications.filter(n => !n.read).length}</span>
                ${notifications.length > 0 ? `<button class="btn-sm" onclick="clearAllNotifications()" style="background: #dc3545; margin-left: 10px; font-size: 12px;"><i class="fas fa-trash"></i></button>` : ''}
            </div>
        </div>
        <div class="notifications-list">
            ${notifications.length > 0 ? notifications.map(n => `
                <div class="notification-item ${n.read ? 'read' : 'unread'}" data-id="${n.id}">
                    <div class="notification-icon ${n.type}">
                        <i class="fas fa-${getNotificationIcon(n.type)}"></i>
                    </div>
                    <div class="notification-content">
                        <div class="notification-message">${n.message}</div>
                        <div class="notification-time">${formatTime(n.timestamp)}</div>
                    </div>
                    <button class="notification-close" onclick="deleteNotification('${n.id}')">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `).join('') : '<div class="no-notifications">Nenhuma notificação</div>'}
        </div>
    `;
    
    document.body.appendChild(panel);
    
    // Close when clicking outside
    setTimeout(() => {
        document.addEventListener('click', function closePanel(e) {
            if (!panel.contains(e.target)) {
                panel.remove();
                document.removeEventListener('click', closePanel);
            }
        });
    }, 100);
    
    // Mark notifications as read when opened
    notifications.filter(n => !n.read).forEach(n => {
        markNotificationRead(n.id);
    });
}

function getNotificationIcon(type) {
    const icons = {
        'phishing_capture': 'camera',
        'scan_complete': 'check-circle',
        'vulnerability_found': 'exclamation-triangle',
        'system': 'info-circle'
    };
    return icons[type] || 'bell';
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000); // seconds
    
    if (diff < 60) return 'Agora';
    if (diff < 3600) return `${Math.floor(diff / 60)}m atrás`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h atrás`;
    return `${Math.floor(diff / 86400)}d atrás`;
}

async function markNotificationRead(notificationId) {
    try {
        await apiRequest(`/tools/notifications/${notificationId}/read`, {
            method: 'POST'
        });
        loadNotifications();
    } catch (error) {
        console.error('Error marking notification as read:', error);
    }
}

async function deleteNotification(notificationId) {
    try {
        await apiRequest(`/tools/notifications/${notificationId}`, {
            method: 'DELETE'
        });
        loadNotifications();
        showNotificationsPanel(); // Refresh panel
    } catch (error) {
        console.error('Error deleting notification:', error);
    }
}

async function clearAllNotifications() {
    if (!confirm('Tem certeza que deseja limpar todas as notificações?')) {
        return;
    }
    
    try {
        const notifications = window.currentNotifications || [];
        
        for (const notification of notifications) {
            await apiRequest(`/tools/notifications/${notification.id}`, {
                method: 'DELETE'
            });
        }
        
        showToast('Todas as notificações foram deletadas!', 'success');
        loadNotifications();
        
        // Fechar o painel
        const panel = document.querySelector('.notifications-panel');
        if (panel) panel.remove();
        
    } catch (error) {
        console.error('Error clearing notifications:', error);
        showToast('Erro ao limpar notificações', 'error');
    }
}

// Setup notifications dropdown on init
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupNotificationsDropdown);
} else {
    setupNotificationsDropdown();
}

// ==================== RED TEAM TOOLS ====================

async function startSQLiTest() {
    const url = document.getElementById('sqli-url').value;
    const method = document.getElementById('sqli-method').value;
    const params = document.getElementById('sqli-params').value.split(',').map(p => p.trim());
    const payloadType = document.getElementById('sqli-payload-type').value;
    
    if (!url) {
        showToast('Digite uma URL', 'error');
        return;
    }
    
    showLoading();
    
    try {
        const response = await apiRequest('/redteam/sqli/test', {
            method: 'POST',
            body: JSON.stringify({
                url,
                method,
                parameters: params,
                payload_type: payloadType
            })
        });
        
        document.getElementById('sqli-vuln-count').textContent = response.vulnerabilities_found;
        
        // Armazenar resultados para relatório
        window.lastSQLInjectionResults = response;
        
        const resultsHtml = `
            <div class="alert alert-${response.vulnerabilities_found > 0 ? 'danger' : 'success'}">
                <i class="fas fa-${response.vulnerabilities_found > 0 ? 'exclamation-triangle' : 'check-circle'}"></i>
                <strong>${response.vulnerabilities_found > 0 ? 'Vulnerabilidades encontradas!' : 'Nenhuma vulnerabilidade detectada'}</strong>
            </div>
            <div style="text-align: right; margin-bottom: 15px;">
                <button class="btn-primary" onclick="generateSQLInjectionReport()">
                    <i class="fas fa-file-alt"></i> Gerar Relatório
                </button>
            </div>
            <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 20px;">
                <div class="stat-card">
                    <div class="stat-content">
                        <h3>${response.parameters_tested}</h3>
                        <p>Parâmetros Testados</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <h3>${response.payloads_tested}</h3>
                        <p>Payloads Testados</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <h3>${response.vulnerabilities_found}</h3>
                        <p>Vulnerabilidades</p>
                    </div>
                </div>
            </div>
            ${response.results.filter(r => r.vulnerable).map(r => `
                <div class="vulnerability-item">
                    <div class="vulnerability-header">
                        <span class="vuln-severity HIGH">SQL INJECTION</span>
                        <span class="vuln-location">${r.parameter}</span>
                    </div>
                    <div class="vuln-description">
                        Payload vulnerável detectado
                    </div>
                    <div class="vuln-code">${escapeHtml(r.payload)}</div>
                </div>
            `).join('')}
        `;
        
        document.getElementById('sqli-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.sqli.resultsHtml', resultsHtml);
            localStorage.setItem('tool.sqli.vulnCount', String(response.vulnerabilities_found));
        } catch (_) {}
        hideLoading();
        showToast('Teste SQL Injection concluído', 'success');
        
        // Atualiza dashboard stats
        loadDashboardStats();
    } catch (error) {
        hideLoading();
        showToast('Erro ao testar SQL Injection', 'error');
    }
}

async function startXSSTest() {
    const url = document.getElementById('xss-url').value;
    const params = document.getElementById('xss-params').value.split(',').map(p => p.trim());
    const payloadType = document.getElementById('xss-payload-type').value;
    
    if (!url) {
        showToast('Digite uma URL', 'error');
        return;
    }
    
    showLoading();
    
    try {
        const response = await apiRequest('/redteam/xss/test', {
            method: 'POST',
            body: JSON.stringify({
                url,
                parameters: params,
                payload_type: payloadType
            })
        });
        
        document.getElementById('xss-vuln-count').textContent = response.vulnerabilities_found;
        
        // Armazenar resultados para relatório
        window.lastXSSResults = response;
        
        const resultsHtml = `
            <div class="alert alert-${response.vulnerabilities_found > 0 ? 'warning' : 'success'}">
                <i class="fas fa-${response.vulnerabilities_found > 0 ? 'exclamation-triangle' : 'check-circle'}"></i>
                <strong>${response.vulnerabilities_found > 0 ? 'XSS detectado!' : 'Nenhuma vulnerabilidade XSS'}</strong>
            </div>
            <div style="text-align: right; margin-bottom: 15px;">
                <button class="btn-primary" onclick="generateXSSReport()">
                    <i class="fas fa-file-alt"></i> Gerar Relatório
                </button>
            </div>
            ${response.results.filter(r => r.vulnerable).map(r => `
                <div class="vulnerability-item">
                    <div class="vulnerability-header">
                        <span class="vuln-severity ${r.severity.toUpperCase()}">${r.type.toUpperCase()} XSS</span>
                        <span class="vuln-location">${r.parameter}</span>
                    </div>
                    <div class="vuln-code">${escapeHtml(r.payload)}</div>
                </div>
            `).join('')}
        `;
        
        document.getElementById('xss-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.xss.resultsHtml', resultsHtml);
            localStorage.setItem('tool.xss.vulnCount', String(response.vulnerabilities_found));
        } catch (_) {}
        hideLoading();
        showToast('Teste XSS concluído', 'success');
        
        // Atualiza dashboard stats
        loadDashboardStats();
    } catch (error) {
        hideLoading();
        showToast('Erro ao testar XSS', 'error');
    }
}

async function startBruteForce() {
    const url = document.getElementById('bf-url').value;
    const userField = document.getElementById('bf-user-field').value;
    const passField = document.getElementById('bf-pass-field').value;
    const userlist = document.getElementById('bf-userlist').value.split('\n').map(u => u.trim()).filter(u => u);
    const wordlist = document.getElementById('bf-wordlist').value;
    
    if (!url || userlist.length === 0) {
        showToast('Preencha todos os campos', 'error');
        return;
    }
    
    showLoading();
    
    try {
        const response = await apiRequest('/redteam/bruteforce/start', {
            method: 'POST',
            body: JSON.stringify({
                url,
                user_field: userField,
                pass_field: passField,
                userlist,
                wordlist
            })
        });
        
        document.getElementById('bf-progress').textContent = `${response.progress}%`;
        
        const resultsHtml = `
            <div class="alert alert-${response.successful_attempts > 0 ? 'success' : 'info'}">
                <i class="fas fa-info-circle"></i>
                <strong>Operação concluída</strong>
            </div>
            <div class="stats-grid" style="grid-template-columns: repeat(2, 1fr); margin-bottom: 20px;">
                <div class="stat-card">
                    <div class="stat-content">
                        <h3>${response.total_attempts}</h3>
                        <p>Total de Tentativas</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <h3>${response.successful_attempts}</h3>
                        <p>Credenciais Encontradas</p>
                    </div>
                </div>
            </div>
            ${response.credentials_found.length > 0 ? `
                <h3 style="margin-bottom: 15px;">Credenciais Válidas:</h3>
                ${response.credentials_found.map(cred => `
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <strong>Username:</strong> ${cred.username} | <strong>Password:</strong> ${cred.password}
                    </div>
                `).join('')}
            ` : '<p class="text-muted">Nenhuma credencial encontrada</p>'}
        `;
        
        document.getElementById('bf-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.brute.resultsHtml', resultsHtml);
            localStorage.setItem('tool.brute.progress', String(response.progress));
        } catch (_) {}
        hideLoading();
        showToast('Brute force concluído', 'success');
    } catch (error) {
        hideLoading();
        showToast('Erro no brute force', 'error');
    }
}

async function startSubdomainEnum() {
    const domain = document.getElementById('subdomain-target').value;
    const method = document.getElementById('subdomain-method').value;
    const wordlist = document.getElementById('subdomain-wordlist').value;
    
    if (!domain) {
        showToast('Digite um domínio', 'error');
        return;
    }
    
    showLoading();
    
    try {
        const response = await apiRequest('/redteam/subdomain/enumerate', {
            method: 'POST',
            body: JSON.stringify({
                domain,
                method,
                wordlist_size: wordlist
            })
        });
        
        document.getElementById('subdomain-count').textContent = response.subdomains_found;
        
        const resultsHtml = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <strong>${response.subdomains_found} subdomínios encontrados</strong>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>Subdomínio</th>
                        <th>IP</th>
                        <th>Status</th>
                        <th>Server</th>
                    </tr>
                </thead>
                <tbody>
                    ${response.results.map(sub => `
                        <tr>
                            <td>${sub.subdomain}</td>
                            <td>${sub.ip}</td>
                            <td><span class="badge badge-success">${sub.status}</span></td>
                            <td>${sub.server}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        
        document.getElementById('subdomain-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.subdomain.resultsHtml', resultsHtml);
            localStorage.setItem('tool.subdomain.count', String(response.subdomains_found));
        } catch (_) {}
        hideLoading();
        showToast('Enumeração concluída', 'success');
    } catch (error) {
        hideLoading();
        showToast('Erro na enumeração', 'error');
    }
}

async function startDirEnum() {
    const baseUrl = document.getElementById('dir-base-url').value;
    const wordlist = document.getElementById('dir-wordlist').value;
    const statusText = document.getElementById('dir-status-filter').value.trim();
    const status_filter = statusText ? statusText.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)) : [];
    if (!baseUrl) {
        showToast('Digite a URL base', 'error');
        return;
    }
    showLoading();
    try {
        const response = await apiRequest('/redteam/directory/enumerate', {
            method: 'POST',
            body: JSON.stringify({ base_url: baseUrl, wordlist_size: wordlist, status_filter })
        });
        document.getElementById('direnum-count').textContent = response.dirs_found;
        const resultsHtml = `
            <div class="alert alert-${response.dirs_found > 0 ? 'success' : 'info'}">
                <i class="fas fa-${response.dirs_found > 0 ? 'check-circle' : 'info-circle'}"></i>
                <strong>${response.dirs_found} diretório(s) encontrados</strong>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Status</th>
                        <th>Tamanho</th>
                        <th>Fingerprint</th>
                    </tr>
                </thead>
                <tbody>
                    ${response.results.map(r => `
                        <tr>
                            <td>${r.path}</td>
                            <td><span class="badge badge-${r.status_code === 200 ? 'success' : r.status_code === 403 ? 'warning' : 'secondary'}">${r.status_code}</span></td>
                            <td>${r.length}</td>
                            <td>${r.fingerprint}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        document.getElementById('direnum-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.direnum.resultsHtml', resultsHtml);
            localStorage.setItem('tool.direnum.count', String(response.dirs_found));
        } catch (_) {}
        hideLoading();
        showToast('Enumeração de diretórios concluída', 'success');
    } catch (error) {
        hideLoading();
        showToast('Erro na enumeração de diretórios', 'error');
    }
}

async function analyzeIOC() {
    const raw = document.getElementById('ioc-input').value;
    const indicators = raw.split('\n').map(s => s.trim()).filter(s => s);
    const sources = [];
    if (document.getElementById('ioc-source-virustotal').checked) sources.push('virustotal');
    if (document.getElementById('ioc-source-alienvault').checked) sources.push('alienvault');
    if (indicators.length === 0) {
        showToast('Cole pelo menos um IOC', 'error');
        return;
    }
    showLoading();
    try {
        const response = await apiRequest('/blueteam/ioc/analyze', {
            method: 'POST',
            body: JSON.stringify({ indicators, sources })
        });
        document.getElementById('ioc-count').textContent = response.total;
        const resultsHtml = `
            <div class="stats-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 20px;">
                <div class="stat-card"><div class="stat-content"><h3>${response.summary.ips}</h3><p>IPs</p></div></div>
                <div class="stat-card"><div class="stat-content"><h3>${response.summary.domains}</h3><p>Domínios</p></div></div>
                <div class="stat-card"><div class="stat-content"><h3>${response.summary.urls}</h3><p>URLs</p></div></div>
                <div class="stat-card"><div class="stat-content"><h3>${response.summary.hashes}</h3><p>Hashes</p></div></div>
            </div>
            ${response.results.map(item => `
                <div class="card" style="margin-bottom: 10px;">
                    <div class="card-header">
                        <h3>${item.indicator}</h3>
                        <span class="badge badge-${item.is_malicious ? 'danger' : 'success'}">${item.is_malicious ? 'MALICIOUS' : 'CLEAN'}</span>
                    </div>
                    <div class="card-body">
                        <p><strong>Tipo:</strong> ${item.type.toUpperCase()}</p>
                        ${item.details ? `<pre>${JSON.stringify(item.details, null, 2)}</pre>` : ''}
                    </div>
                </div>
            `).join('')}
        `;
        document.getElementById('ioc-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.ioc.resultsHtml', resultsHtml);
            localStorage.setItem('tool.ioc.count', String(response.total));
        } catch (_) {}
        hideLoading();
        showToast('Análise de IOCs concluída', 'success');
    } catch (error) {
        hideLoading();
        showToast('Erro na análise de IOCs', 'error');
    }
}

// ==================== BLUE TEAM TOOLS ====================

async function analyzeLog() {
    const logType = document.getElementById('log-type').value;
    const fileInput = document.getElementById('log-file');
    
    if (!fileInput.files[0]) {
        showToast('Selecione um arquivo de log', 'error');
        return;
    }
    
    showLoading();
    
    try {
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('log_type', logType);
        
        const token = getToken();
        const response = await fetch(`${API_URL}/blueteam/logs/analyze?log_type=${logType}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });
        
        const data = await response.json();
        
        document.getElementById('log-threats').textContent = data.threats_found;
        
        const resultsHtml = `
            <div class="alert alert-${data.threats_found > 0 ? 'danger' : 'success'}">
                <i class="fas fa-${data.threats_found > 0 ? 'exclamation-triangle' : 'check-circle'}"></i>
                <strong>${data.threats_found > 0 ? 'Ameaças detectadas!' : 'Log limpo'}</strong>
            </div>
            <div class="stats-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 20px;">
                <div class="stat-card">
                    <div class="stat-content">
                        <h3 style="color: var(--danger)">${data.summary.critical}</h3>
                        <p>Críticos</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <h3 style="color: var(--warning)">${data.summary.high}</h3>
                        <p>Altos</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <h3 style="color: var(--info)">${data.summary.medium}</h3>
                        <p>Médios</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <h3>${data.lines_analyzed}</h3>
                        <p>Linhas</p>
                    </div>
                </div>
            </div>
            <h3 style="margin: 20px 0;">Ameaças Detectadas:</h3>
            ${data.threats.failed_logins.length > 0 ? `
                <h4>Failed Logins (${data.threats.failed_logins.length})</h4>
                ${data.threats.failed_logins.slice(0, 5).map(t => `
                    <div class="alert alert-warning">
                        <strong>Linha ${t.line}:</strong> ${escapeHtml(t.content.substring(0, 100))}...
                    </div>
                `).join('')}
            ` : ''}
            ${data.threats.sql_injection_attempts.length > 0 ? `
                <h4>SQL Injection Attempts (${data.threats.sql_injection_attempts.length})</h4>
                ${data.threats.sql_injection_attempts.slice(0, 5).map(t => `
                    <div class="alert alert-danger">
                        <strong>Linha ${t.line}:</strong> ${escapeHtml(t.content.substring(0, 100))}...
                    </div>
                `).join('')}
            ` : ''}
        `;
        
        document.getElementById('log-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.log.resultsHtml', resultsHtml);
            localStorage.setItem('tool.log.threats', String(data.threats_found));
        } catch (_) {}
        hideLoading();
        showToast('Análise de log concluída', 'success');
    } catch (error) {
        hideLoading();
        showToast('Erro ao analisar log', 'error');
    }
}

async function queryThreatIntel() {
    const target = document.getElementById('threat-target').value;
    const targetType = document.getElementById('threat-type').value;
    
    const sources = [];
    if (document.getElementById('source-virustotal').checked) sources.push('virustotal');
    if (document.getElementById('source-abuseipdb').checked) sources.push('abuseipdb');
    if (document.getElementById('source-shodan').checked) sources.push('shodan');
    if (document.getElementById('source-alienvault').checked) sources.push('alienvault');
    
    if (!target) {
        showToast('Digite um alvo', 'error');
        return;
    }
    
    showLoading();
    
    try {
        const response = await apiRequest('/blueteam/threat-intel/query', {
            method: 'POST',
            body: JSON.stringify({
                target,
                target_type: targetType,
                sources
            })
        });
        
        document.getElementById('threat-score').textContent = `Score: ${response.reputation_score}`;
        document.getElementById('threat-score').className = `badge badge-${response.is_malicious ? 'danger' : 'success'}`;
        
        const resultsHtml = `
            <div class="alert alert-${response.is_malicious ? 'danger' : 'success'}">
                <i class="fas fa-${response.is_malicious ? 'skull-crossbones' : 'check-circle'}"></i>
                <strong>${response.is_malicious ? 'AMEAÇA DETECTADA' : 'Sem ameaças conhecidas'}</strong>
            </div>
            <div class="card" style="margin-bottom: 20px;">
                <div class="card-header"><h3>Detalhes</h3></div>
                <div class="card-body">
                    <p><strong>Nível de Risco:</strong> <span class="badge badge-${response.details.risk_level === 'high' ? 'danger' : response.details.risk_level === 'medium' ? 'warning' : 'success'}">${response.details.risk_level.toUpperCase()}</span></p>
                    <p><strong>Recomendação:</strong> ${response.details.recommendation}</p>
                    <p><strong>Confiança:</strong> ${response.details.confidence}</p>
                </div>
            </div>
            ${Object.entries(response.sources).map(([source, data]) => `
                <div class="card" style="margin-bottom: 15px;">
                    <div class="card-header">
                        <h3><i class="fas fa-database"></i> ${source.toUpperCase()}</h3>
                    </div>
                    <div class="card-body">
                        <pre>${JSON.stringify(data, null, 2)}</pre>
                    </div>
                </div>
            `).join('')}
        `;
        
        document.getElementById('threat-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.threat.resultsHtml', resultsHtml);
            localStorage.setItem('tool.threat.score', String(response.reputation_score));
            localStorage.setItem('tool.threat.malicious', String(!!response.is_malicious));
        } catch (_) {}
        hideLoading();
        showToast('Consulta concluída', 'success');
    } catch (error) {
        hideLoading();
        showToast('Erro na consulta', 'error');
    }
}

async function analyzeHash() {
    const hashInput = document.getElementById('hash-input').value;
    const hashType = document.getElementById('hash-type').value;
    
    const hashes = hashInput.split('\n').map(h => h.trim()).filter(h => h);
    
    if (hashes.length === 0) {
        showToast('Digite pelo menos um hash', 'error');
        return;
    }
    
    showLoading();
    
    try {
        const response = await apiRequest('/blueteam/hash/analyze', {
            method: 'POST',
            body: JSON.stringify({
                hashes,
                hash_type: hashType
            })
        });
        
        const resultsHtml = `
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i>
                <strong>${response.hashes_analyzed} hashes analisados</strong>
            </div>
            <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 20px;">
                <div class="stat-card">
                    <div class="stat-content">
                        <h3>${response.known_hashes}</h3>
                        <p>Hashes Conhecidos</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <h3>${response.malware_detected}</h3>
                        <p>Malware Detectado</p>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-content">
                        <h3>${response.hashes_analyzed - response.known_hashes}</h3>
                        <p>Desconhecidos</p>
                    </div>
                </div>
            </div>
            ${response.results.map(r => `
                <div class="card" style="margin-bottom: 15px;">
                    <div class="card-header">
                        <h3>${r.type} Hash</h3>
                        ${r.malware_associated ? '<span class="badge badge-danger">MALWARE</span>' : ''}
                        ${r.is_known ? '<span class="badge badge-success">CONHECIDO</span>' : ''}
                    </div>
                    <div class="card-body">
                        <p><strong>Hash:</strong> <code>${r.hash}</code></p>
                        <p><strong>Tamanho:</strong> ${r.length} caracteres</p>
                        ${r.plaintext ? `<p><strong>Plaintext:</strong> <code>${r.plaintext}</code></p>` : ''}
                        ${r.file_info ? `
                            <div class="alert alert-danger" style="margin-top: 10px;">
                                <strong>Malware Detectado:</strong>
                                <p>Família: ${r.file_info.malware_family}</p>
                                <p>Nível: ${r.file_info.threat_level}</p>
                            </div>
                        ` : ''}
                    </div>
                </div>
            `).join('')}
        `;
        
        document.getElementById('hash-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.hash.resultsHtml', resultsHtml);
        } catch (_) {}
        hideLoading();
        showToast('Análise concluída', 'success');
    } catch (error) {
        hideLoading();
        showToast('Erro ao analisar hashes', 'error');
    }
}

async function checkPasswordStrength() {
    const password = document.getElementById('password-input').value;
    
    if (!password) {
        showToast('Digite uma senha', 'error');
        return;
    }
    
    try {
        const response = await apiRequest('/blueteam/password/check', {
            method: 'POST',
            body: JSON.stringify({ password })
        });
        
        const resultsHtml = `
            <div class="card" style="margin-bottom: 20px;">
                <div class="card-body" style="text-align: center;">
                    <h2 style="color: ${response.color}; margin-bottom: 10px;">${response.strength}</h2>
                    <div style="background: #ddd; height: 30px; border-radius: 15px; overflow: hidden; margin: 20px 0;">
                        <div style="width: ${response.score}%; height: 100%; background: ${response.color}; transition: width 0.3s;"></div>
                    </div>
                    <p><strong>Score:</strong> ${response.score}/100</p>
                    <p><strong>Tempo para quebrar:</strong> ${response.crack_time}</p>
                </div>
            </div>
            <div class="card">
                <div class="card-header"><h3>Características</h3></div>
                <div class="card-body">
                    <p><i class="fas fa-${response.has_lowercase ? 'check' : 'times'}"></i> Letras minúsculas</p>
                    <p><i class="fas fa-${response.has_uppercase ? 'check' : 'times'}"></i> Letras maiúsculas</p>
                    <p><i class="fas fa-${response.has_numbers ? 'check' : 'times'}"></i> Números</p>
                    <p><i class="fas fa-${response.has_symbols ? 'check' : 'times'}"></i> Símbolos</p>
                    <p><strong>Comprimento:</strong> ${response.password_length} caracteres</p>
                </div>
            </div>
            ${response.feedback.length > 0 ? `
                <div class="alert alert-warning" style="margin-top: 20px;">
                    <strong>Recomendações:</strong>
                    <ul>${response.feedback.map(f => `<li>${f}</li>`).join('')}</ul>
                </div>
            ` : ''}
        `;
        
        document.getElementById('password-results').innerHTML = resultsHtml;
        try {
            localStorage.setItem('tool.password.resultsHtml', resultsHtml);
        } catch (_) {}
        showToast('Análise concluída', 'success');
    } catch (error) {
        showToast('Erro ao verificar senha', 'error');
    }
}

async function generatePassword() {
    const length = parseInt(document.getElementById('pwd-length').value);
    const uppercase = document.getElementById('pwd-uppercase').checked;
    const lowercase = document.getElementById('pwd-lowercase').checked;
    const numbers = document.getElementById('pwd-numbers').checked;
    const symbols = document.getElementById('pwd-symbols').checked;
    
    if (!uppercase && !lowercase && !numbers && !symbols) {
        showToast('Selecione pelo menos uma opção', 'error');
        return;
    }
    
    try {
        const response = await apiRequest('/blueteam/password/generate', {
            method: 'POST',
            body: JSON.stringify({
                length,
                uppercase,
                lowercase,
                numbers,
                symbols
            })
        });
        
        const resultsHtml = `
            <div class="card">
                <div class="card-header"><h3>Senha Gerada</h3></div>
                <div class="card-body" style="text-align: center;">
                    <h2 style="background: var(--bg-tertiary); padding: 20px; border-radius: 10px; font-family: monospace; word-break: break-all;">${response.password}</h2>
                    <button class="btn-primary" onclick="navigator.clipboard.writeText('${response.password}'); showToast('Senha copiada!', 'success');" style="margin-top: 20px;">
                        <i class="fas fa-copy"></i> Copiar Senha
                    </button>
                    <p style="margin-top: 20px;"><strong>Entropia:</strong> ${response.entropy} bits</p>
                    <p><strong>Tamanho do charset:</strong> ${response.charset_size} caracteres</p>
                </div>
            </div>
        `;
        
        document.getElementById('password-results').innerHTML = resultsHtml;
        document.getElementById('password-input').value = response.password;
        showToast('Senha gerada com sucesso', 'success');
    } catch (error) {
        showToast('Erro ao gerar senha', 'error');
    }
}

// Update password length display
document.addEventListener('DOMContentLoaded', () => {
    const lengthInput = document.getElementById('pwd-length');
    const lengthDisplay = document.getElementById('pwd-length-display');
    
    if (lengthInput && lengthDisplay) {
        lengthInput.addEventListener('input', () => {
            lengthDisplay.textContent = lengthInput.value;
        });
    }
});

// ==================== GLOBAL SEARCH ====================

// Database de ferramentas para pesquisa
const searchDatabase = [
    {
        id: 'phishing',
        title: 'Gerador de Phishing',
        description: 'Crie páginas de phishing personalizadas',
        icon: 'fa-fish',
        keywords: ['phishing', 'fake', 'página', 'login', 'clone']
    },
    {
        id: 'payloads',
        title: 'Gerador de Payload',
        description: 'Gere payloads para testes de segurança',
        icon: 'fa-bomb',
        keywords: ['payload', 'exploit', 'reverse', 'shell', 'meterpreter']
    },
    {
        id: 'encoder',
        title: 'Encoder/Decoder',
        description: 'Codifique e decodifique dados',
        icon: 'fa-code',
        keywords: ['encode', 'decode', 'base64', 'url', 'hex']
    },
    {
        id: 'scanner',
        title: 'Code Scanner',
        description: 'Analise código em busca de vulnerabilidades',
        icon: 'fa-bug',
        keywords: ['scanner', 'código', 'vulnerabilidade', 'análise', 'scan']
    },
    {
        id: 'port-scan',
        title: 'Port Scanner',
        description: 'Escaneie portas de servidores',
        icon: 'fa-network-wired',
        keywords: ['port', 'porta', 'scan', 'network', 'nmap']
    },
    {
        id: 'sql-injection',
        title: 'SQL Injection Tester',
        description: 'Teste vulnerabilidades SQL Injection',
        icon: 'fa-database',
        keywords: ['sql', 'injection', 'database', 'sqli', 'union']
    },
    {
        id: 'xss-tester',
        title: 'XSS Tester',
        description: 'Teste vulnerabilidades XSS',
        icon: 'fa-code',
        keywords: ['xss', 'cross', 'site', 'scripting', 'javascript']
    },
    {
        id: 'brute-force',
        title: 'Brute Force Tool',
        description: 'Ferramenta de força bruta',
        icon: 'fa-unlock-alt',
        keywords: ['brute', 'force', 'password', 'crack', 'login']
    },
    {
        id: 'subdomain',
        title: 'Subdomain Enumeration',
        description: 'Enumere subdomínios de um domínio',
        icon: 'fa-sitemap',
        keywords: ['subdomain', 'enum', 'dns', 'domain', 'reconnaissance']
    },
    {
        id: 'directory-enum',
        title: 'Directory Enumerator',
        description: 'Enumere diretórios e caminhos ocultos',
        icon: 'fa-folder-open',
        keywords: ['directory', 'enum', 'dirb', 'gobuster', 'paths']
    },
    {
        id: 'log-analyzer',
        title: 'Log Analyzer',
        description: 'Analise logs em busca de ameaças',
        icon: 'fa-file-alt',
        keywords: ['log', 'analysis', 'threat', 'security', 'siem']
    },
    {
        id: 'threat-intel',
        title: 'Threat Intelligence',
        description: 'Consulte informações de ameaças',
        icon: 'fa-shield-alt',
        keywords: ['threat', 'intelligence', 'ioc', 'malware', 'reputation']
    },
    {
        id: 'ioc-analyzer',
        title: 'IOC Analyzer',
        description: 'Analise indicators of compromise (IOCs)',
        icon: 'fa-list-check',
        keywords: ['ioc', 'indicator', 'compromise', 'malware', 'threat']
    },
    {
        id: 'hash-analyzer',
        title: 'Hash Analyzer',
        description: 'Analise e identifique hashes',
        icon: 'fa-fingerprint',
        keywords: ['hash', 'md5', 'sha', 'crack', 'decrypt']
    },
    {
        id: 'password-strength',
        title: 'Password Strength Checker',
        description: 'Verifique força de senhas',
        icon: 'fa-lock',
        keywords: ['password', 'strength', 'security', 'generator', 'check']
    },
    {
        id: 'reports',
        title: 'Relatórios',
        description: 'Visualize relatórios de scans',
        icon: 'fa-file-alt',
        keywords: ['report', 'relatório', 'resultado', 'histórico']
    }
];

let searchTimeout;

function performSearch(query) {
    clearTimeout(searchTimeout);
    
    const searchResults = document.getElementById('search-results');
    
    if (!query || query.length < 2) {
        searchResults.style.display = 'none';
        return;
    }
    
    searchTimeout = setTimeout(() => {
        const results = searchInDatabase(query.toLowerCase());
        displaySearchResults(results);
    }, 300);
}

function searchInDatabase(query) {
    return searchDatabase.filter(tool => {
        // Pesquisa no título
        if (tool.title.toLowerCase().includes(query)) return true;
        
        // Pesquisa na descrição
        if (tool.description.toLowerCase().includes(query)) return true;
        
        // Pesquisa nas keywords
        if (tool.keywords.some(keyword => keyword.includes(query))) return true;
        
        return false;
    });
}

function displaySearchResults(results) {
    const searchResults = document.getElementById('search-results');
    
    if (results.length === 0) {
        searchResults.innerHTML = `
            <div class="search-no-results">
                <i class="fas fa-search"></i>
                <p>Nenhuma ferramenta encontrada</p>
            </div>
        `;
        searchResults.style.display = 'block';
        return;
    }
    
    searchResults.innerHTML = results.map(tool => `
        <div class="search-result-item" onclick="navigateToTool('${tool.id}')">
            <div class="search-result-icon">
                <i class="fas ${tool.icon}"></i>
            </div>
            <div class="search-result-content">
                <div class="search-result-title">${tool.title}</div>
                <div class="search-result-description">${tool.description}</div>
            </div>
        </div>
    `).join('');
    
    searchResults.style.display = 'block';
}

function navigateToTool(toolId) {
    // Fecha os resultados da pesquisa
    document.getElementById('search-results').style.display = 'none';
    document.getElementById('global-search').value = '';
    
    // Navega para a ferramenta
    navigateTo(toolId);
    
    // Scroll para o topo
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Fecha resultados ao clicar fora
document.addEventListener('click', (e) => {
    const searchContainer = document.querySelector('.header-search');
    const searchResults = document.getElementById('search-results');
    
    if (searchContainer && !searchContainer.contains(e.target) && !searchResults.contains(e.target)) {
        searchResults.style.display = 'none';
    }
});

// Previne fechar ao clicar no input de pesquisa
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('global-search');
    if (searchInput) {
        searchInput.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    }
});
