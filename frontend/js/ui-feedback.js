(function () {
    'use strict';

    function ensureStyles() {
        if (document.getElementById('iron-ai-feedback-styles')) return;
        const style = document.createElement('style');
        style.id = 'iron-ai-feedback-styles';
        style.textContent = `
            .iron-transition-overlay{position:fixed;inset:0;z-index:23000;display:flex;align-items:center;justify-content:center;padding:24px;background:rgba(6,4,12,.78);backdrop-filter:blur(12px);opacity:0;visibility:hidden;transition:opacity .18s ease,visibility .18s ease}
            .iron-transition-overlay.active{opacity:1;visibility:visible}
            .iron-transition-card{min-width:min(330px,90vw);display:flex;align-items:center;gap:16px;padding:20px 22px;border:1px solid rgba(204,170,255,.2);border-radius:17px;background:linear-gradient(145deg,rgba(27,20,42,.98),rgba(12,9,20,.98));color:#f7f2ff;box-shadow:0 26px 90px rgba(0,0,0,.48)}
            .iron-transition-logo{width:48px;height:48px;flex:0 0 48px;border-radius:14px;background:#0b0812 url('/assets/ironnet-logo.jpeg') center/cover no-repeat;box-shadow:0 10px 34px rgba(139,92,246,.3);position:relative}
            .iron-transition-logo::after{content:"";position:absolute;inset:-5px;border:2px solid transparent;border-top-color:#b56cff;border-right-color:rgba(181,108,255,.3);border-radius:18px;animation:ironFeedbackSpin .85s linear infinite}
            .iron-transition-copy{display:flex;flex-direction:column;min-width:0}.iron-transition-copy strong{font-size:14px}.iron-transition-copy span{margin-top:3px;color:#a99db7;font-size:11px}
            .iron-page-progress{position:fixed;z-index:22000;top:0;left:0;right:0;height:3px;opacity:0;visibility:hidden;background:rgba(181,108,255,.08);transition:opacity .15s}.iron-page-progress.active{opacity:1;visibility:visible}.iron-page-progress::after{content:"";display:block;width:34%;height:100%;background:linear-gradient(90deg,#b56cff,#62d4ad);box-shadow:0 0 14px rgba(181,108,255,.55);animation:ironFeedbackProgress 1s ease-in-out infinite}
            @keyframes ironFeedbackSpin{to{transform:rotate(360deg)}}@keyframes ironFeedbackProgress{from{transform:translateX(-110%)}to{transform:translateX(400%)}}
            @media(prefers-reduced-motion:reduce){.iron-transition-logo::after,.iron-page-progress::after{animation-duration:2s}}
        `;
        document.head.appendChild(style);
    }

    function ensureOverlay() {
        ensureStyles();
        let overlay = document.getElementById('iron-transition-overlay');
        if (overlay) return overlay;
        overlay = document.createElement('div');
        overlay.id = 'iron-transition-overlay';
        overlay.className = 'iron-transition-overlay';
        overlay.setAttribute('role', 'status');
        overlay.setAttribute('aria-live', 'polite');
        overlay.innerHTML = '<div class="iron-transition-card"><div class="iron-transition-logo"></div><div class="iron-transition-copy"><strong>Processando...</strong><span>Aguarde um instante.</span></div></div>';
        document.body.appendChild(overlay);
        return overlay;
    }

    window.showTransitionLoading = function (message = 'Processando...', detail = 'Aguarde um instante.') {
        const overlay = ensureOverlay();
        overlay.querySelector('strong').textContent = message;
        overlay.querySelector('span').textContent = detail;
        overlay.setAttribute('aria-hidden', 'false');
        requestAnimationFrame(() => overlay.classList.add('active'));
    };

    window.hideTransitionLoading = function () {
        const overlay = document.getElementById('iron-transition-overlay');
        if (!overlay) return;
        overlay.classList.remove('active');
        overlay.setAttribute('aria-hidden', 'true');
    };

    window.withTransitionLoading = async function (message, operation, detail) {
        window.showTransitionLoading(message, detail);
        try { return await operation(); }
        finally { window.hideTransitionLoading(); }
    };

    window.showPageProgress = function () {
        ensureStyles();
        let bar = document.getElementById('iron-page-progress');
        if (!bar) {
            bar = document.createElement('div');
            bar.id = 'iron-page-progress';
            bar.className = 'iron-page-progress';
            document.body.appendChild(bar);
        }
        requestAnimationFrame(() => bar.classList.add('active'));
    };

    window.hidePageProgress = function () {
        document.getElementById('iron-page-progress')?.classList.remove('active');
    };

    document.addEventListener('click', event => {
        const link = event.target.closest('a[href]');
        if (!link || event.defaultPrevented || link.target === '_blank' || link.hasAttribute('download') || link.dataset.noTransition !== undefined) return;
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        const raw = link.getAttribute('href') || '';
        if (!raw || raw.startsWith('#') || raw.startsWith('javascript:') || raw.startsWith('mailto:') || raw.startsWith('tel:')) return;
        try {
            const target = new URL(link.href, window.location.href);
            if (target.origin !== window.location.origin) return;
            window.showTransitionLoading('Abrindo página...', 'Preparando a próxima etapa da Iron AI.');
        } catch (_) {}
    });

    window.addEventListener('pageshow', window.hideTransitionLoading);
})();
