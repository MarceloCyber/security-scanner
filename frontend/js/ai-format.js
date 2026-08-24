(function () {
    'use strict';

    function ensureStyles() {
        if (document.getElementById('iron-ai-answer-styles')) return;
        const style = document.createElement('style');
        style.id = 'iron-ai-answer-styles';
        style.textContent = `
            .ai-rich-answer{width:min(100%,780px);max-width:92%!important;white-space:normal!important;line-height:1.65!important;overflow-wrap:anywhere}
            .ai-rich-answer h2,.ai-rich-answer h3,.ai-rich-answer h4{margin:16px 0 7px;color:#f5f2ff;line-height:1.3}
            .ai-rich-answer h2:first-child,.ai-rich-answer h3:first-child{margin-top:2px}
            .ai-rich-answer h2{font-size:1.18em}.ai-rich-answer h3{font-size:1.08em}.ai-rich-answer h4{font-size:1em}
            .ai-rich-answer p{margin:7px 0}.ai-rich-answer ul,.ai-rich-answer ol{margin:8px 0;padding-left:22px}
            .ai-rich-answer li{margin:5px 0}.ai-rich-answer strong{color:#fff;font-weight:750}
            .ai-rich-answer code{padding:2px 5px;border-radius:5px;background:rgba(0,0,0,.28);color:#bdebd8;font:inherit;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
            .ai-rich-answer pre{margin:12px 0;padding:13px 14px;overflow:auto;border:1px solid rgba(185,156,255,.18);border-radius:10px;background:#08110f;color:#cfe9df;font:11px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre;tab-size:2}
            .ai-rich-answer pre code{padding:0;background:transparent;color:inherit;font:inherit;white-space:inherit}
            .ai-rich-answer blockquote{margin:11px 0;padding:9px 12px;border-left:3px solid #aa91f4;border-radius:0 8px 8px 0;background:rgba(170,145,244,.07);color:#cfc7e6}
            .ai-rich-answer hr{margin:15px 0;border:0;border-top:1px solid rgba(255,255,255,.1)}
            .ai-rich-answer a{color:#8fdcbd;text-decoration:underline;text-decoration-color:rgba(143,220,189,.4);overflow-wrap:anywhere}
            .ai-table-wrap{max-width:100%;overflow:auto;margin:12px 0;border:1px solid rgba(255,255,255,.12);border-radius:10px}
            .ai-rich-answer table{width:100%;min-width:560px;border-collapse:collapse;background:rgba(0,0,0,.12)}
            .ai-rich-answer th,.ai-rich-answer td{padding:9px 11px;border-right:1px solid rgba(255,255,255,.08);border-bottom:1px solid rgba(255,255,255,.08);text-align:left;vertical-align:top;font-size:.94em;text-transform:none;letter-spacing:0}
            .ai-rich-answer th{color:#d8cbff;background:rgba(151,117,255,.1)}.ai-rich-answer tr:last-child td{border-bottom:0}
            .ai-source{margin-top:14px!important;padding-top:9px;border-top:1px solid rgba(255,255,255,.1);color:#9f91ca;font-size:.88em}
            .ai-thinking{display:inline-flex;align-items:center;gap:11px;color:#c7badb;min-height:48px}
            .ai-thinking-logo{position:relative;width:38px;height:38px;flex:0 0 38px;border-radius:12px;padding:3px;background:linear-gradient(145deg,rgba(185,156,255,.32),rgba(70,219,167,.16));box-shadow:0 0 20px rgba(151,117,255,.18)}
            .ai-thinking-logo img{display:block;width:100%;height:100%;object-fit:cover;border-radius:9px;animation:ironAiLogoPulse 1.45s ease-in-out infinite}
            .ai-thinking-logo::after{content:"";position:absolute;inset:-4px;border:1.5px solid transparent;border-top-color:#b99cff;border-right-color:rgba(87,225,171,.75);border-radius:15px;animation:ironAiLogoOrbit 1.4s linear infinite}
            .ai-thinking-copy{display:flex;flex-direction:column;gap:2px}.ai-thinking-copy strong{font-size:11px;color:#eee8ff}.ai-thinking-copy small{font-size:9px;color:#8f829f;letter-spacing:.15px}
            @keyframes ironAiLogoPulse{0%,100%{opacity:.48;filter:saturate(.75);transform:scale(.94)}50%{opacity:1;filter:saturate(1.2) drop-shadow(0 0 8px rgba(185,156,255,.7));transform:scale(1)}}
            @keyframes ironAiLogoOrbit{to{transform:rotate(360deg)}}
            @media(prefers-reduced-motion:reduce){.ai-thinking-logo img,.ai-thinking-logo::after{animation:none}.ai-thinking-logo img{opacity:1}}
        `;
        document.head.appendChild(style);
    }

    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>"']/g, char => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[char]);
    }

    function inline(value) {
        return escapeHtml(value)
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
            .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/__([^_]+)__/g, '<strong>$1</strong>')
            .replace(/(^|\s)\*([^*]+)\*(?=\s|$)/g, '$1<em>$2</em>')
            .replace(/(^|\s)_([^_]+)_(?=\s|$)/g, '$1<em>$2</em>');
    }

    function tableCells(line) {
        return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(cell => cell.trim());
    }

    function isTableDivider(line) {
        const cells = tableCells(line);
        return cells.length > 1 && cells.every(cell => /^:?-{3,}:?$/.test(cell));
    }

    function render(markdown) {
        ensureStyles();
        const lines = String(markdown ?? '').replace(/\r\n?/g, '\n').split('\n');
        const output = [];
        let list = null;
        let paragraph = [];
        let code = null;
        const closeList = () => {
            if (list) output.push(`</${list}>`);
            list = null;
        };
        const closeParagraph = () => {
            if (!paragraph.length) return;
            const sourceClass = /^fonte\s*:/i.test(paragraph[0]) ? ' class="ai-source"' : '';
            output.push(`<p${sourceClass}>${inline(paragraph.join(' '))}</p>`);
            paragraph = [];
        };
        const closeCode = () => {
            if (!code) return;
            output.push(`<pre><code>${escapeHtml(code.lines.join('\n'))}</code></pre>`);
            code = null;
        };

        for (let index = 0; index < lines.length; index += 1) {
            const rawLine = lines[index];
            const line = rawLine.trim();

            if (code) {
                if (/^```/.test(line)) closeCode();
                else code.lines.push(rawLine);
                continue;
            }

            const fence = line.match(/^```\s*([\w+-]*)?\s*$/);
            if (fence) {
                closeParagraph();
                closeList();
                code = { language: fence[1] || '', lines: [] };
                continue;
            }

            if (!line) {
                closeParagraph();
                closeList();
                continue;
            }

            if (line.includes('|') && index + 1 < lines.length && isTableDivider(lines[index + 1])) {
                closeParagraph();
                closeList();
                const headers = tableCells(line);
                index += 2;
                const rows = [];
                while (index < lines.length && lines[index].includes('|') && lines[index].trim()) {
                    rows.push(tableCells(lines[index]));
                    index += 1;
                }
                index -= 1;
                output.push('<div class="ai-table-wrap"><table><thead><tr>');
                headers.forEach(cell => output.push(`<th>${inline(cell)}</th>`));
                output.push('</tr></thead><tbody>');
                rows.forEach(row => {
                    output.push('<tr>');
                    headers.forEach((_, cellIndex) => output.push(`<td>${inline(row[cellIndex] || '')}</td>`));
                    output.push('</tr>');
                });
                output.push('</tbody></table></div>');
                continue;
            }

            const heading = line.match(/^(#{1,4})\s+(.+)$/);
            if (heading) {
                closeParagraph();
                closeList();
                const level = Math.min(heading[1].length + 1, 4);
                output.push(`<h${level}>${inline(heading[2])}</h${level}>`);
                continue;
            }

            const unordered = line.match(/^[-*]\s+(.+)$/);
            const ordered = line.match(/^\d+[.)]\s+(.+)$/);
            if (unordered || ordered) {
                closeParagraph();
                const desired = ordered ? 'ol' : 'ul';
                if (list !== desired) {
                    closeList();
                    list = desired;
                    output.push(`<${list}>`);
                }
                output.push(`<li>${inline((ordered || unordered)[1])}</li>`);
                continue;
            }

            if (/^[-*_]{3,}$/.test(line)) {
                closeParagraph();
                closeList();
                output.push('<hr>');
                continue;
            }

            const quote = line.match(/^>\s?(.*)$/);
            if (quote) {
                closeParagraph();
                closeList();
                output.push(`<blockquote>${inline(quote[1])}</blockquote>`);
                continue;
            }

            closeList();
            paragraph.push(line);
        }
        closeCode();
        closeParagraph();
        closeList();
        return output.join('');
    }

    function renderInto(element, markdown) {
        if (!element) return;
        element.classList.remove('ai-thinking');
        element.classList.add('ai-rich-answer');
        element.innerHTML = render(markdown);
    }

    function showThinking(element, label = 'Analisando seus dados') {
        if (!element) return;
        ensureStyles();
        element.classList.remove('ai-rich-answer');
        element.classList.add('ai-thinking');
        element.innerHTML = `<span class="ai-thinking-logo" aria-hidden="true"><img src="/assets/ironnet-logo.jpeg" alt=""></span><span class="ai-thinking-copy"><strong>${escapeHtml(label)}</strong><small>Iron AI está preparando a resposta</small></span>`;
    }

    window.IronAIFormat = { render, renderInto, showThinking };
})();
