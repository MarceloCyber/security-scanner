(function () {
    'use strict';

    function ensureStyles() {
        if (document.getElementById('platform-confirm-styles')) return;
        const style = document.createElement('style');
        style.id = 'platform-confirm-styles';
        style.textContent = `
            .platform-confirm-overlay{position:fixed;inset:0;z-index:20000;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(2,6,23,.72);backdrop-filter:blur(8px);opacity:0;transition:opacity .2s ease}
            .platform-confirm-overlay.active{opacity:1}
            .platform-confirm-dialog{width:min(460px,100%);overflow:hidden;border:1px solid var(--border,#334155);border-radius:18px;background:var(--bg-secondary,#111827);color:var(--text,#f8fafc);box-shadow:0 24px 80px rgba(0,0,0,.48);transform:translateY(14px) scale(.97);transition:transform .2s ease}
            .platform-confirm-overlay.active .platform-confirm-dialog{transform:translateY(0) scale(1)}
            .platform-confirm-main{padding:28px 28px 20px}
            .platform-confirm-heading{display:flex;align-items:flex-start;gap:15px;margin-bottom:18px}
            .platform-confirm-icon{width:48px;height:48px;flex:0 0 48px;display:flex;align-items:center;justify-content:center;border-radius:14px;background:rgba(239,68,68,.14);color:#ef4444;font-size:21px}
            .platform-confirm-title{margin:2px 0 5px;font-size:20px;line-height:1.25;font-weight:700;color:var(--text,#f8fafc)}
            .platform-confirm-kicker{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#ef4444}
            .platform-confirm-message{margin:0;color:var(--text-secondary,#cbd5e1);font-size:14px;line-height:1.65}
            .platform-confirm-note{display:flex;gap:9px;margin-top:16px;padding:12px 14px;border:1px solid rgba(245,158,11,.28);border-radius:10px;background:rgba(245,158,11,.08);color:var(--text-secondary,#cbd5e1);font-size:12px;line-height:1.5}
            .platform-confirm-actions{display:flex;justify-content:flex-end;gap:10px;padding:18px 28px;border-top:1px solid var(--border,#334155);background:var(--bg-tertiary,rgba(15,23,42,.55))}
            .platform-confirm-button{min-height:42px;padding:0 20px;border-radius:9px;border:1px solid transparent;font:600 14px/1 inherit;cursor:pointer;transition:transform .15s ease,background .15s ease,box-shadow .15s ease}
            .platform-confirm-cancel{border-color:var(--border,#475569);background:var(--bg-secondary,#1e293b);color:var(--text-secondary,#e2e8f0)}
            .platform-confirm-cancel:hover{background:var(--bg-elevated,#334155);color:var(--text,#fff)}
            .platform-confirm-submit{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff;box-shadow:0 6px 18px rgba(239,68,68,.25)}
            .platform-confirm-submit:hover{transform:translateY(-1px);box-shadow:0 9px 24px rgba(239,68,68,.35)}
            .platform-confirm-button:focus-visible{outline:3px solid rgba(59,130,246,.4);outline-offset:2px}
            @media(max-width:520px){.platform-confirm-main{padding:22px 20px 17px}.platform-confirm-actions{padding:15px 20px}.platform-confirm-actions{flex-direction:column-reverse}.platform-confirm-button{width:100%}}
            @media(prefers-reduced-motion:reduce){.platform-confirm-overlay,.platform-confirm-dialog,.platform-confirm-button{transition:none}}
        `;
        document.head.appendChild(style);
    }

    window.showConfirmDialog = function (options) {
        const config = typeof options === 'string' ? { message: options } : (options || {});
        ensureStyles();
        return new Promise(resolve => {
            const overlay = document.createElement('div');
            overlay.className = 'platform-confirm-overlay';
            overlay.setAttribute('role', 'presentation');

            const dialog = document.createElement('div');
            dialog.className = 'platform-confirm-dialog';
            dialog.setAttribute('role', 'alertdialog');
            dialog.setAttribute('aria-modal', 'true');

            const main = document.createElement('div');
            main.className = 'platform-confirm-main';
            const heading = document.createElement('div');
            heading.className = 'platform-confirm-heading';
            const icon = document.createElement('div');
            icon.className = 'platform-confirm-icon';
            icon.innerHTML = '<i class="fas fa-trash-alt" aria-hidden="true"></i>';
            const headingText = document.createElement('div');
            const kicker = document.createElement('div');
            kicker.className = 'platform-confirm-kicker';
            kicker.textContent = config.kicker || 'Confirmação necessária';
            const title = document.createElement('h2');
            title.className = 'platform-confirm-title';
            title.textContent = config.title || 'Confirmar exclusão';
            const message = document.createElement('p');
            message.className = 'platform-confirm-message';
            message.textContent = config.message || 'Confirme se deseja continuar com esta ação.';
            headingText.append(kicker, title);
            heading.append(icon, headingText);
            main.append(heading, message);

            if (config.details !== false) {
                const note = document.createElement('div');
                note.className = 'platform-confirm-note';
                note.innerHTML = '<i class="fas fa-exclamation-triangle" aria-hidden="true"></i>';
                const noteText = document.createElement('span');
                noteText.textContent = config.details || 'Esta ação não pode ser desfeita.';
                note.appendChild(noteText);
                main.appendChild(note);
            }

            const actions = document.createElement('div');
            actions.className = 'platform-confirm-actions';
            const cancel = document.createElement('button');
            cancel.type = 'button';
            cancel.className = 'platform-confirm-button platform-confirm-cancel';
            cancel.textContent = config.cancelText || 'Cancelar';
            const submit = document.createElement('button');
            submit.type = 'button';
            submit.className = 'platform-confirm-button platform-confirm-submit';
            submit.innerHTML = '<i class="fas fa-trash-alt" aria-hidden="true"></i> ';
            submit.appendChild(document.createTextNode(config.confirmText || 'Sim, excluir'));
            actions.append(cancel, submit);
            dialog.append(main, actions);
            overlay.appendChild(dialog);
            document.body.appendChild(overlay);

            let finished = false;
            const close = value => {
                if (finished) return;
                finished = true;
                document.removeEventListener('keydown', onKeydown);
                overlay.classList.remove('active');
                setTimeout(() => overlay.remove(), 180);
                resolve(value);
            };
            const onKeydown = event => {
                if (event.key === 'Escape') close(false);
                if (event.key === 'Tab') {
                    const next = document.activeElement === submit && !event.shiftKey ? cancel :
                        document.activeElement === cancel && event.shiftKey ? submit : null;
                    if (next) { event.preventDefault(); next.focus(); }
                }
            };
            cancel.addEventListener('click', () => close(false));
            submit.addEventListener('click', () => close(true));
            overlay.addEventListener('click', event => { if (event.target === overlay) close(false); });
            document.addEventListener('keydown', onKeydown);
            requestAnimationFrame(() => { overlay.classList.add('active'); cancel.focus(); });
        });
    };
})();
