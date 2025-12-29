// =============================================
// Admin Panel - Security Scanner
// Gerenciamento completo do painel administrativo
// =============================================

const API_URL = 'http://localhost:8000';
let currentPage = 1;
let currentSearch = '';
let currentPlanFilter = '';
let currentUserId = null;
let currentUsername = '';

// ============ Inicialização ============
document.addEventListener('DOMContentLoaded', () => {
    checkAdminAuth();
    initNavigation();
    initModals();
    loadDashboard();
    
    // Event Listeners - com verificação de existência
    const userSearch = document.getElementById('userSearch');
    if (userSearch) {
        userSearch.addEventListener('input', debounce(handleSearch, 500));
    }
    
    const planFilter = document.getElementById('planFilter');
    if (planFilter) {
        planFilter.addEventListener('change', handleFilter);
    }
    
    const prevPage = document.getElementById('prevPage');
    if (prevPage) {
        prevPage.addEventListener('click', () => changePage(currentPage - 1));
    }
    
    const nextPage = document.getElementById('nextPage');
    if (nextPage) {
        nextPage.addEventListener('click', () => changePage(currentPage + 1));
    }
    
    // Nota: refreshActivity, saveUserBtn e confirmDeleteBtn usam onclick direto no HTML
});

// ============ Autenticação ============
function checkAdminAuth() {
    const token = localStorage.getItem('token') || sessionStorage.getItem('token');
    if (!token) {
        window.location.href = 'admin-login.html';
        return;
    }

    // Verifica se é admin
    fetch(`${API_URL}/api/user/subscription-info`, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        if (!response.ok) throw new Error('Não autorizado');
        return response.json();
    })
    .then(data => {
        if (!data.is_admin) {
            showToast('Acesso negado. Apenas administradores.', 'error');
            setTimeout(() => {
                window.location.href = 'admin-login.html';
            }, 2000);
            return;
        }
        document.getElementById('adminUsername').textContent = data.username || 'Admin';
    })
    .catch(error => {
        console.error('Erro de autenticação:', error);
        localStorage.removeItem('token');
        sessionStorage.removeItem('token');
        window.location.href = 'admin-login.html';
    });
}

function logout() {
    localStorage.removeItem('token');
    sessionStorage.removeItem('token');
    showToast('Logout realizado com sucesso', 'success');
    setTimeout(() => {
        window.location.href = 'admin-login.html';
    }, 1000);
}

// ============ Navegação ============
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const pageId = item.getAttribute('data-page');
            if (pageId) {
                showPage(pageId);
                updateActiveNav(item);
                
                // Carrega dados da página
                if (pageId === 'dashboard') loadDashboard();
                else if (pageId === 'users') loadUsers();
                else if (pageId === 'payments') loadPayments();
                else if (pageId === 'cancelled') loadCancelled();
                else if (pageId === 'activity') loadActivity();
                else if (pageId === 'system') loadSystemInfo();
            }
        });
    });
}

function showPage(pageId) {
    document.querySelectorAll('.admin-page').forEach(page => {
        page.classList.remove('active');
    });
    const targetPage = document.getElementById(pageId + '-page');
    if (targetPage) {
        targetPage.classList.add('active');
    }
}

function updateActiveNav(activeItem) {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    activeItem.classList.add('active');
}

function toggleSidebar() {
    const sidebar = document.querySelector('.admin-sidebar');
    sidebar.classList.toggle('active');
}

// ============ Dashboard ============
async function loadDashboard() {
    try {
        const response = await fetchAPI('/api/admin/stats');
        const data = await response.json();
        
        // Atualiza cards de estatísticas - com verificação
        const totalUsers = document.getElementById('totalUsers');
        if (totalUsers) totalUsers.textContent = data.total_users || 0;
        
        const activeUsers = document.getElementById('activeUsers');
        if (activeUsers) activeUsers.textContent = data.active_users || 0;
        
        const totalScans = document.getElementById('totalScans');
        if (totalScans) totalScans.textContent = data.total_scans || 0;
        
        const monthlyRevenue = document.getElementById('monthlyRevenue');
        if (monthlyRevenue) monthlyRevenue.textContent = `R$ ${(data.monthly_revenue || 0).toLocaleString()}`;
        
        // Atualiza badge de scans hoje
        const scansToday = document.getElementById('scansToday');
        if (scansToday) scansToday.textContent = `${data.scans_today || 0} hoje`;
        
        // Atualiza planos
        updatePlanStats(data.users_by_plan || {});
        
        // Atualiza atividades recentes - com verificação
        const scans7Days = document.getElementById('scans7Days');
        if (scans7Days) scans7Days.textContent = data.scans_last_7_days || 0;
        
        const newUsers7Days = document.getElementById('newUsers7Days');
        if (newUsers7Days) newUsers7Days.textContent = data.new_users_last_7_days || 0;
        
    } catch (error) {
        console.error('Erro ao carregar dashboard:', error);
        showToast('Erro ao carregar estatísticas', 'error');
    }
}

function updatePlanStats(plans) {
    const totalUsers = Object.values(plans).reduce((sum, count) => sum + count, 0) || 1;
    
    const planData = [
        { id: 'free', count: plans.free || 0, label: 'Gratuito' },
        { id: 'starter', count: plans.starter || 0, label: 'Starter' },
        { id: 'professional', count: plans.professional || 0, label: 'Professional' },
        { id: 'enterprise', count: plans.enterprise || 0, label: 'Enterprise' }
    ];
    
    planData.forEach(plan => {
        const percentage = totalUsers > 0 ? (plan.count / totalUsers * 100) : 0;
        
        // IDs corretos do HTML: planFree, planStarter, planProfessional, planEnterprise
        const planName = plan.id.charAt(0).toUpperCase() + plan.id.slice(1); // Capitaliza primeira letra
        const countElem = document.getElementById(`plan${planName}`);
        if (countElem) countElem.textContent = plan.count;
        
        const barElem = document.getElementById(`planBar${planName}`);
        if (barElem) barElem.style.width = `${percentage}%`;
    });
}

// ============ Usuários ============
async function loadUsers(page = 1) {
    try {
        const params = new URLSearchParams({
            page: page,
            limit: 10,
            ...(currentSearch && { search: currentSearch }),
            ...(currentPlanFilter && { plan: currentPlanFilter })
        });
        
        const response = await fetchAPI(`/api/admin/users?${params}`);
        const data = await response.json();
        
        renderUsersTable(data.users || []);
        updatePagination(data.page || 1, data.pages || 1);
        
    } catch (error) {
        console.error('Erro ao carregar usuários:', error);
        showToast('Erro ao carregar usuários', 'error');
    }
}

function renderUsersTable(users) {
    const tbody = document.getElementById('usersTableBody');
    if (!tbody) {
        console.error('Elemento usersTableBody não encontrado');
        return;
    }
    
    if (!Array.isArray(users) || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="loading-cell">Nenhum usuário encontrado</td></tr>';
        return;
    }
    
    tbody.innerHTML = users.map(user => `
        <tr>
            <td>${user.id}</td>
            <td>${escapeHtml(user.username)}</td>
            <td>${escapeHtml(user.email)}</td>
            <td>
                <span class="plan-badge ${(user.subscription_plan || 'free').toLowerCase()}">
                    ${getPlanLabel(user.subscription_plan)}
                </span>
            </td>
            <td>${user.scans_this_month || 0}/${user.scans_limit || 0}</td>
            <td>
                <span class="status-badge ${(user.subscription_status || 'active').toLowerCase()}">
                    ${getStatusLabel(user.subscription_status)}
                </span>
            </td>
            <td>${formatDate(user.created_at)}</td>
            <td class="table-actions">
                <button class="btn-icon btn-edit" onclick="openEditModal(${user.id})" title="Editar">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="btn-icon btn-reset" onclick="resetUserScans(${user.id})" title="Resetar Scans">
                    <i class="fas fa-redo"></i>
                </button>
                <button class="btn-icon btn-delete" onclick="openDeleteModal(${user.id}, '${escapeHtml(user.username)}')" title="Excluir">
                    <i class="fas fa-trash"></i>
                </button>
                <button class="btn-icon" onclick="promptChangePlan(${user.id})" title="Trocar Plano">
                    <i class="fas fa-exchange-alt"></i>
                </button>
                <button class="btn-icon" onclick="cancelSubscriptionAdmin(${user.id})" title="Cancelar Assinatura">
                    <i class="fas fa-ban"></i>
                </button>
                <button class="btn-icon" onclick="refundLastInvoice(${user.id})" title="Reembolso (Stripe)">
                    <i class="fas fa-undo"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

function handleSearch(e) {
    currentSearch = e.target.value;
    currentPage = 1;
    loadUsers(currentPage);
}

function handleFilter(e) {
    currentPlanFilter = e.target.value;
    currentPage = 1;
    loadUsers(currentPage);
}

function changePage(page) {
    currentPage = page;
    loadUsers(currentPage);
}

function updatePagination(page, totalPages) {
    const currentPageElem = document.getElementById('currentPage');
    if (currentPageElem) currentPageElem.textContent = page;
    
    const totalPagesElem = document.getElementById('totalPages');
    if (totalPagesElem) totalPagesElem.textContent = totalPages;
    
    const prevPage = document.getElementById('prevPage');
    if (prevPage) prevPage.disabled = page <= 1;
    
    const nextPage = document.getElementById('nextPage');
    if (nextPage) nextPage.disabled = page >= totalPages;
}

// ============ Editar Usuário ============
async function openEditModal(userId) {
    try {
        const response = await fetchAPI(`/api/admin/users/${userId}`);
        const user = await response.json();
        
        currentUserId = userId;
        
        const editEmail = document.getElementById('editUserEmail');
        if (editEmail) editEmail.value = user.email || '';
        
        const editPlan = document.getElementById('editUserPlan');
        if (editPlan) editPlan.value = user.subscription_plan || 'free';
        
        const editStatus = document.getElementById('editUserStatus');
        if (editStatus) editStatus.value = user.subscription_status || 'active';
        
        const editScansLimit = document.getElementById('editUserScansLimit');
        if (editScansLimit) editScansLimit.value = user.scans_limit || 0;
        
        const editIsAdmin = document.getElementById('editUserIsAdmin');
        if (editIsAdmin) editIsAdmin.checked = user.is_admin || false;
        
        const modal = document.getElementById('editUserModal');
        if (modal) modal.classList.add('active');
    } catch (error) {
        console.error('Erro ao carregar usuário:', error);
        showToast('Erro ao carregar dados do usuário', 'error');
    }
}

function closeEditModal() {
    const modal = document.getElementById('editUserModal');
    if (modal) modal.classList.remove('active');
}

async function saveUserChanges() {
    if (!currentUserId) return;
    
    const emailElem = document.getElementById('editUserEmail');
    const planElem = document.getElementById('editUserPlan');
    const statusElem = document.getElementById('editUserStatus');
    const scansLimitElem = document.getElementById('editUserScansLimit');
    const isAdminElem = document.getElementById('editUserIsAdmin');
    
    if (!emailElem || !planElem || !statusElem || !scansLimitElem || !isAdminElem) {
        console.error('Elementos do formulário não encontrados');
        return;
    }
    
    const updateData = {
        email: emailElem.value,
        subscription_plan: planElem.value,
        subscription_status: statusElem.value,
        scans_limit: parseInt(scansLimitElem.value) || 0,
        is_admin: isAdminElem.checked
    };
    
    try {
        await fetchAPI(`/api/admin/users/${currentUserId}`, {
            method: 'PUT',
            body: JSON.stringify(updateData)
        });
        
        showToast('Usuário atualizado com sucesso', 'success');
        closeEditModal();
        loadUsers(currentPage);
        
    } catch (error) {
        console.error('Erro ao atualizar usuário:', error);
        showToast('Erro ao atualizar usuário', 'error');
    }
}

// ============ Deletar Usuário ============
function openDeleteModal(userId, username) {
    currentUserId = userId;
    currentUsername = username;
    
    const deleteUsernameElem = document.getElementById('deleteUsername');
    if (deleteUsernameElem) deleteUsernameElem.textContent = username;
    
    const modal = document.getElementById('deleteUserModal');
    if (modal) modal.classList.add('active');
}

function closeDeleteModal() {
    const modal = document.getElementById('deleteUserModal');
    if (modal) modal.classList.remove('active');
}

async function confirmDeleteUser() {
    if (!currentUserId) return;
    
    try {
        await fetchAPI(`/api/admin/users/${currentUserId}`, {
            method: 'DELETE'
        });
        
        showToast('Usuário excluído com sucesso', 'success');
        closeDeleteModal();
        loadUsers(currentPage);
        
    } catch (error) {
        console.error('Erro ao excluir usuário:', error);
        showToast(error.message || 'Erro ao excluir usuário', 'error');
    }
}

async function promptChangePlan(userId) {
    const plan = prompt('Informe o novo plano: free | starter | professional | enterprise');
    if (!plan) return;
    try {
        await fetchAPI(`/api/admin/subscriptions/${userId}/change-plan?new_plan=${encodeURIComponent(plan)}`, { method: 'POST' });
        showToast('Plano atualizado', 'success');
        loadUsers(currentPage);
    } catch (error) {
        showToast('Erro ao atualizar plano', 'error');
    }
}

async function changePlanAction(plan) {
    if (!currentUserId) return;
    try {
        await fetchAPI(`/api/admin/subscriptions/${currentUserId}/change-plan?new_plan=${encodeURIComponent(plan)}`, { method: 'POST' });
        const editPlan = document.getElementById('editUserPlan');
        if (editPlan) editPlan.value = plan;
        showToast('Plano atualizado', 'success');
        loadUsers(currentPage);
    } catch (error) {
        showToast('Erro ao atualizar plano', 'error');
    }
}

window.changePlanAction = changePlanAction;

async function cancelSubscriptionAdmin(userId) {
    if (!confirm('Confirmar cancelamento da assinatura?')) return;
    try {
        await fetchAPI(`/api/admin/subscriptions/${userId}/cancel`, { method: 'POST' });
        showToast('Assinatura cancelada', 'success');
        loadUsers(currentPage);
    } catch (error) {
        showToast('Erro ao cancelar assinatura', 'error');
    }
}

async function refundLastInvoice(userId) {
    if (!confirm('Confirmar reembolso da última fatura (Stripe)?')) return;
    try {
        await fetchAPI(`/api/admin/subscriptions/${userId}/refund`, { method: 'POST' });
        showToast('Reembolso solicitado', 'success');
    } catch (error) {
        showToast('Erro ao solicitar reembolso', 'error');
    }
}

// ============ Reset Scans ============
async function resetUserScans(userId) {
    if (!confirm('Deseja realmente resetar os scans deste usuário?')) return;
    
    try {
        await fetchAPI(`/api/admin/users/${userId}/reset-scans`, {
            method: 'POST'
        });
        
        showToast('Scans resetados com sucesso', 'success');
        loadUsers(currentPage);
        
    } catch (error) {
        console.error('Erro ao resetar scans:', error);
        showToast('Erro ao resetar scans', 'error');
    }
}

// ============ Atividades ============
async function loadActivity() {
    try {
        const response = await fetchAPI('/api/admin/activity');
        const data = await response.json();
        const activityList = document.getElementById('activityList');
        if (!activityList) return;

        const activities = Array.isArray(data.activities) ? data.activities : [];
        if (activities.length === 0) {
            activityList.innerHTML = '<div class="loading-state">Nenhuma atividade recente</div>';
            return;
        }

        const groups = {};
        for (const a of activities) {
            const key = a.user_id || a.username || 'desconhecido';
            if (!groups[key]) groups[key] = { username: a.username || 'Usuário desconhecido', user_id: a.user_id || null, items: [] };
            groups[key].items.push(a);
        }

        const html = Object.values(groups).map(group => {
            const count = group.items.length;
            const itemsHtml = group.items.map(activity => `
                <div class="activity-item-detail">
                    <div class="aid-type">${escapeHtml(activity.scan_type || 'Desconhecido')}</div>
                    <div class="aid-target">${escapeHtml(activity.target || 'N/A')}</div>
                    <div class="aid-time">${formatDateTime(activity.created_at)}</div>
                </div>
            `).join('');
            return `
                <div class="activity-group">
                    <div class="activity-group-header">
                        <div class="agh-left">
                            <strong>${escapeHtml(group.username)}</strong>
                            ${group.user_id ? `<span class="agh-id">ID ${group.user_id}</span>` : ''}
                            <span class="agh-count">${count} atividades</span>
                        </div>
                        <div class="agh-right">
                            <button class="btn-refresh" onclick="loadActivity()"><i class="fas fa-sync-alt"></i> Atualizar</button>
                            <button class="btn-danger" onclick="clearActivity()"><i class="fas fa-trash"></i> Apagar histórico</button>
                        </div>
                    </div>
                    <div class="activity-group-body">${itemsHtml}</div>
                </div>
            `;
        }).join('');

        activityList.innerHTML = html;
    } catch (error) {
        console.error('Erro ao carregar atividades:', error);
        const activityList = document.getElementById('activityList');
        if (activityList) activityList.innerHTML = '<div class="loading-state">Erro ao carregar atividades</div>';
        showToast('Erro ao carregar atividades', 'error');
    }
}

async function clearActivity() {
    if (!confirm('Deseja apagar todo o histórico de atividades?')) return;
    try {
        await fetchAPI('/api/admin/activity', { method: 'DELETE' });
        showToast('Histórico de atividades apagado', 'success');
        loadActivity();
    } catch (error) {
        showToast('Erro ao apagar histórico', 'error');
    }
}

window.clearActivity = clearActivity;

// ============ Sistema ============
async function loadSystemInfo() {
    try {
        const response = await fetchAPI('/api/admin/system');
        const data = await response.json();
        
        // A API retorna {system: {...}, resources: {...}, database: {...}}
        const system = data.system || {};
        const resources = data.resources || {};
        const database = data.database || {};
        
        // OS Info - com verificação
        const osPlatform = document.getElementById('osPlatform');
        if (osPlatform) osPlatform.textContent = system.platform || 'N/A';
        
        const pythonVersion = document.getElementById('pythonVersion');
        if (pythonVersion) pythonVersion.textContent = system.python_version || 'N/A';
        
        const hostname = document.getElementById('hostname');
        if (hostname) hostname.textContent = system.hostname || 'N/A';
        
        // Resources - com verificação
        const cpuUsage = document.getElementById('cpuUsage');
        if (cpuUsage) cpuUsage.textContent = `${resources.cpu_percent || 0}%`;
        
        const memoryUsage = document.getElementById('memoryUsage');
        if (memoryUsage) memoryUsage.textContent = `${resources.memory_percent || 0}%`;
        
        const diskUsage = document.getElementById('diskUsage');
        if (diskUsage) diskUsage.textContent = `${resources.disk_percent || 0}%`;
        
        // Database - com verificação
        const dbTotalUsers = document.getElementById('dbTotalUsers');
        if (dbTotalUsers) dbTotalUsers.textContent = database.total_users || 0;
        
        const dbTotalScans = document.getElementById('dbTotalScans');
        if (dbTotalScans) dbTotalScans.textContent = database.total_scans || 0;
        
        const dbSize = document.getElementById('dbSize');
        if (dbSize) dbSize.textContent = database.database_size || 'N/A';
        
    } catch (error) {
        console.error('Erro ao carregar informações do sistema:', error);
        showToast('Erro ao carregar informações do sistema', 'error');
    }
}

// ============ Modais ============
function initModals() {
    // Fechar ao clicar no X
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            const modal = btn.closest('.modal');
            modal.classList.remove('active');
        });
    });
    
    // Fechar ao clicar fora
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    });
    
    // Botões cancelar
    document.querySelectorAll('[data-action="cancel"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const modal = btn.closest('.modal');
            modal.classList.remove('active');
        });
    });
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

// ============ Utilitários ============
async function fetchAPI(endpoint, options = {}) {
    const token = localStorage.getItem('token');
    const defaultOptions = {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    };
    
    const response = await fetch(`${API_URL}${endpoint}`, {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers
        }
    });
    
    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Erro desconhecido' }));
        throw new Error(error.detail || `Erro HTTP: ${response.status}`);
    }
    
    return response;
}

function showToast(message, type = 'success') {
    // Criar container se não existir
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.style.position = 'fixed';
        container.style.top = '20px';
        container.style.right = '20px';
        container.style.zIndex = '10000';
        document.body.appendChild(container);
    }
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.style.cssText = `
        background: ${type === 'success' ? '#d4edda' : type === 'error' ? '#f8d7da' : '#fff3cd'};
        color: ${type === 'success' ? '#155724' : type === 'error' ? '#721c24' : '#856404'};
        border: 1px solid ${type === 'success' ? '#c3e6cb' : type === 'error' ? '#f5c6cb' : '#ffeaa7'};
        border-radius: 8px;
        padding: 12px 20px;
        margin-bottom: 10px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        display: flex;
        align-items: center;
        gap: 10px;
        min-width: 250px;
        animation: slideIn 0.3s ease;
        transition: opacity 0.3s ease;
    `;
    
    const icon = type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'exclamation-triangle';
    
    toast.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR');
}

function formatDateTime(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('pt-BR');
}

function getPlanLabel(plan) {
    const labels = {
        'free': 'Gratuito',
        'starter': 'Starter',
        'professional': 'Professional',
        'enterprise': 'Enterprise'
    };
    return labels[plan?.toLowerCase()] || 'Gratuito';
}

function getStatusLabel(status) {
    const labels = {
        'active': 'Ativo',
        'cancelled': 'Cancelado',
        'expired': 'Expirado'
    };
    return labels[status?.toLowerCase()] || 'Ativo';
}

function getPaymentStatusLabel(session) {
    const ps = (session.payment_status || '').toLowerCase();
    const st = (session.status || '').toLowerCase();
    if (ps === 'paid' || ps === 'no_payment_required') return 'Pago';
    if (st === 'expired' || st === 'canceled') return 'Falhou';
    return 'Pendente';
}

function getPaymentStatusClass(session) {
    const ps = (session.payment_status || '').toLowerCase();
    const st = (session.status || '').toLowerCase();
    if (ps === 'paid' || ps === 'no_payment_required') return 'paid';
    if (st === 'expired' || st === 'canceled') return 'failed';
    return 'pending';
}

// ============ Funções globais (para onclick no HTML) ============
window.openEditModal = openEditModal;
window.openDeleteModal = openDeleteModal;
window.resetUserScans = resetUserScans;

async function loadPayments() {
    try {
        const response = await fetchAPI('/api/admin/payments/sessions');
        const data = await response.json();
        const tbody = document.getElementById('paymentsTableBody');
        if (!tbody) return;
    const rows = (data.sessions || []).map(s => {
        const user = s.user || {};
        const url = s.url ? `<a href="${s.url}" target="_blank" rel="noopener">Abrir</a>` : '-';
        const amount = typeof s.amount_total === 'number' ? `R$ ${(s.amount_total / 100).toLocaleString('pt-BR', { minimumFractionDigits: 2 })}` : '-';
        const methods = (s.payment_methods && s.payment_methods.length) ? s.payment_methods.join(', ') : '-';
        const paymentLabel = getPaymentStatusLabel(s);
        const paymentClass = getPaymentStatusClass(s);
        return `
            <tr>
                <td>${s.id}</td>
                <td>${escapeHtml(user.username || '-')}</td>
                <td>${escapeHtml(user.email || '-')}</td>
                <td>${getPlanLabel(s.plan || user.plan)}</td>
                <td>${amount}</td>
                <td>${escapeHtml(methods)}</td>
                <td>${escapeHtml(s.status || '-')}</td>
                <td><span class="status-badge ${paymentClass}">${paymentLabel}</span></td>
                <td>${formatDateTime(s.created)}</td>
                <td>${url}</td>
            </tr>
        `;
    }).join('');
    tbody.innerHTML = rows || '<tr><td colspan="10" class="loading-cell">Nenhuma sessão encontrada</td></tr>';
    } catch (error) {
        console.error('Erro ao carregar pagamentos:', error);
        const tbody = document.getElementById('paymentsTableBody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="10" class="loading-cell">Erro ao carregar pagamentos</td></tr>';
        }
        showToast('Erro ao carregar pagamentos', 'error');
    }
}

async function loadCancelled(page = 1) {
    try {
        const response = await fetchAPI(`/api/admin/users?page=${page}&limit=200`);
        const data = await response.json();
        const tbody = document.getElementById('cancelledTableBody');
        if (!tbody) return;
        const users = Array.isArray(data.users) ? data.users : [];
        const cancelled = users.filter(u => (u.subscription_status || '').toLowerCase() === 'cancelled');
        const rows = cancelled.map(user => `
            <tr>
                <td>${user.id}</td>
                <td>${escapeHtml(user.username || '-')}</td>
                <td>${escapeHtml(user.email || '-')}</td>
                <td>${getPlanLabel(user.subscription_plan)}</td>
                <td><span class="status-badge cancelled">Cancelado</span></td>
                <td>${formatDateTime(user.created_at)}</td>
            </tr>
        `).join('');
        tbody.innerHTML = rows || '<tr><td colspan="6" class="loading-cell">Nenhum usuário cancelado</td></tr>';
    } catch (error) {
        const tbody = document.getElementById('cancelledTableBody');
        if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">Erro ao carregar cancelados</td></tr>';
        showToast('Erro ao carregar cancelados', 'error');
    }
}
