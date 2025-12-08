// Manual de Uso - JavaScript
// Funcionalidades: Navegação suave, menu ativo, scroll spy

document.addEventListener('DOMContentLoaded', function() {
    initScrollSpy();
    initSmoothScroll();
    initMobileMenu();
});

// Scroll Spy - Atualiza link ativo baseado na posição do scroll
function initScrollSpy() {
    const sections = document.querySelectorAll('.content-section');
    const navLinks = document.querySelectorAll('.nav-link');
    
    function updateActiveLink() {
        let currentSection = '';
        const scrollPosition = window.scrollY + 200;
        
        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            const sectionHeight = section.clientHeight;
            
            if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
                currentSection = section.getAttribute('id');
            }
        });
        
        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${currentSection}`) {
                link.classList.add('active');
            }
        });
    }
    
    window.addEventListener('scroll', updateActiveLink);
    updateActiveLink(); // Executar uma vez no carregamento
}

// Smooth Scroll - Rolagem suave ao clicar nos links
function initSmoothScroll() {
    const links = document.querySelectorAll('a[href^="#"]');
    
    links.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                const headerOffset = 100;
                const elementPosition = targetElement.offsetTop;
                const offsetPosition = elementPosition - headerOffset;
                
                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// Mobile Menu - Scroll horizontal suave para navegação mobile
function initMobileMenu() {
    const navList = document.querySelector('.nav-list');
    
    if (!navList) return;
    
    // Centralizar link ativo em telas pequenas
    function centerActiveLink() {
        const activeLink = navList.querySelector('.nav-link.active');
        
        if (activeLink && window.innerWidth < 768) {
            const navListWidth = navList.clientWidth;
            const linkOffset = activeLink.offsetLeft;
            const linkWidth = activeLink.clientWidth;
            
            navList.scrollTo({
                left: linkOffset - (navListWidth / 2) + (linkWidth / 2),
                behavior: 'smooth'
            });
        }
    }
    
    // Centralizar ao carregar e ao redimensionar
    window.addEventListener('load', centerActiveLink);
    window.addEventListener('resize', centerActiveLink);
    
    // Centralizar quando um link for clicado
    const navLinks = navList.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            setTimeout(centerActiveLink, 100);
        });
    });
}

// Adicionar animações ao scroll
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observar cards para animação
document.querySelectorAll('.tool-card, .content-card, .plan-card, .support-card').forEach(card => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(20px)';
    card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(card);
});

// Copiar código para clipboard (se houver exemplos de código)
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Mostrar feedback visual
        const toast = document.createElement('div');
        toast.textContent = 'Código copiado!';
        toast.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #10b981;
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 10000;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 2000);
    });
}

// Adicionar animações CSS via JavaScript
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Rastrear tempo de leitura (opcional)
let readingTime = 0;
const trackingInterval = setInterval(() => {
    readingTime++;
}, 1000);

// Parar rastreamento ao sair da página
window.addEventListener('beforeunload', () => {
    clearInterval(trackingInterval);
    console.log(`Tempo de leitura: ${Math.floor(readingTime / 60)} minutos`);
});

// Destacar texto ao copiar (opcional)
document.addEventListener('copy', (e) => {
    const selection = document.getSelection().toString();
    if (selection.length > 0) {
        console.log('Texto copiado do manual:', selection.substring(0, 50) + '...');
    }
});

// Função para imprimir o manual
function printManual() {
    window.print();
}

// Busca rápida no manual (feature extra)
function searchManual(query) {
    if (!query) return;
    
    const content = document.querySelector('.manual-content');
    const text = content.textContent.toLowerCase();
    
    if (text.includes(query.toLowerCase())) {
        // Destacar resultado (implementação básica)
        console.log(`Encontrado: "${query}" no manual`);
        // Aqui você pode adicionar lógica para destacar o texto
    }
}

console.log('Manual de Uso carregado com sucesso! 📚');