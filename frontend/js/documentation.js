(() => {
  'use strict';

  const body = document.body;
  const sections = [...document.querySelectorAll('.docs-section[id]')];
  const navLinks = [...document.querySelectorAll('.docs-nav a[href^="#"]')];
  const menuButton = document.getElementById('docs-menu');
  const mobileOverlay = document.getElementById('docs-mobile-overlay');
  const searchModal = document.getElementById('search-modal');
  const searchInput = document.getElementById('docs-search-modal');
  const sidebarSearch = document.getElementById('docs-search-sidebar');
  const searchResults = document.getElementById('search-results');
  const toast = document.getElementById('docs-toast');
  let toastTimer;

  const normalize = (value) => String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();

  const showToast = (message) => {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('show');
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => toast.classList.remove('show'), 2200);
  };

  const copyText = async (text) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const helper = document.createElement('textarea');
        helper.value = text;
        helper.setAttribute('readonly', '');
        helper.style.position = 'fixed';
        helper.style.opacity = '0';
        document.body.appendChild(helper);
        helper.select();
        const copied = document.execCommand('copy');
        helper.remove();
        if (!copied) throw new Error('copy command unavailable');
      }
      showToast('Copiado para a área de transferência');
    } catch (_) {
      showToast('Não foi possível copiar automaticamente');
    }
  };

  document.querySelectorAll('[data-copy-code]').forEach((button) => {
    button.addEventListener('click', () => {
      const code = button.closest('.code-block')?.querySelector('pre code');
      if (code) copyText(code.textContent.trim());
    });
  });

  document.querySelectorAll('[data-copy-prompt]').forEach((button) => {
    button.addEventListener('click', () => {
      const text = button.cloneNode(true);
      text.querySelectorAll('i').forEach((icon) => icon.remove());
      copyText(text.textContent.trim().replace(/^“|”$/g, ''));
    });
  });

  const closeMenu = () => body.classList.remove('menu-open');
  menuButton?.addEventListener('click', () => body.classList.toggle('menu-open'));
  mobileOverlay?.addEventListener('click', closeMenu);
  navLinks.forEach((link) => link.addEventListener('click', closeMenu));

  const searchIndex = sections.map((section) => {
    const heading = section.querySelector('h1, h2');
    const paragraph = section.querySelector('p');
    return {
      id: section.id,
      title: heading?.textContent.trim() || section.id,
      excerpt: paragraph?.textContent.trim() || '',
      haystack: normalize(`${heading?.textContent || ''} ${section.dataset.search || ''} ${section.textContent}`)
    };
  });

  const emptySearch = (query = '') => {
    if (!searchResults) return;
    searchResults.innerHTML = query
      ? '<div class="search-empty"><i class="fa-solid fa-magnifying-glass"></i><strong>Nenhum resultado encontrado</strong><p>Tente um termo mais amplo, como “scan”, “MFA”, “relatório” ou “Cloudflare”.</p></div>'
      : '<div class="search-empty"><i class="fa-solid fa-compass"></i><strong>O que você precisa fazer?</strong><p>Pesquise por uma funcionalidade, erro ou procedimento.</p></div>';
  };

  const goToSection = (id) => {
    const section = document.getElementById(id);
    if (!section) return;
    closeSearch();
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    section.classList.remove('search-highlight');
    window.setTimeout(() => section.classList.add('search-highlight'), 250);
    window.setTimeout(() => section.classList.remove('search-highlight'), 1800);
    history.replaceState(null, '', `#${id}`);
  };

  const renderSearch = (rawQuery) => {
    const query = normalize(rawQuery);
    if (!query) {
      emptySearch();
      return;
    }
    const terms = query.split(' ').filter(Boolean);
    const matches = searchIndex
      .map((item) => ({ item, score: terms.reduce((score, term) => score + (item.haystack.includes(term) ? 1 : 0), 0) }))
      .filter(({ score }) => score > 0)
      .sort((a, b) => b.score - a.score || a.item.title.localeCompare(b.item.title, 'pt-BR'))
      .slice(0, 10);

    if (!matches.length) {
      emptySearch(query);
      return;
    }

    searchResults.innerHTML = '';
    matches.forEach(({ item }) => {
      const result = document.createElement('button');
      result.type = 'button';
      result.className = 'search-result';
      result.innerHTML = '<i class="fa-regular fa-file-lines"></i><span><b></b><small></small></span>';
      result.querySelector('b').textContent = item.title;
      result.querySelector('small').textContent = item.excerpt.length > 110
        ? `${item.excerpt.slice(0, 107)}...`
        : item.excerpt;
      result.addEventListener('click', () => goToSection(item.id));
      searchResults.appendChild(result);
    });
  };

  function openSearch(query = '') {
    if (!searchModal || !searchInput) return;
    searchModal.hidden = false;
    body.style.overflow = 'hidden';
    searchInput.value = query;
    renderSearch(query);
    window.setTimeout(() => searchInput.focus(), 20);
  }

  function closeSearch() {
    if (!searchModal) return;
    searchModal.hidden = true;
    body.style.overflow = '';
  }

  document.getElementById('docs-search-trigger')?.addEventListener('click', () => openSearch());
  document.querySelectorAll('[data-open-search]').forEach((button) => button.addEventListener('click', () => openSearch()));
  document.getElementById('close-search')?.addEventListener('click', closeSearch);
  searchModal?.addEventListener('click', (event) => {
    if (event.target === searchModal) closeSearch();
  });
  searchInput?.addEventListener('input', () => renderSearch(searchInput.value));
  sidebarSearch?.addEventListener('focus', () => openSearch(sidebarSearch.value));
  sidebarSearch?.addEventListener('input', () => {
    openSearch(sidebarSearch.value);
    sidebarSearch.value = '';
  });
  document.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openSearch();
    }
    if (event.key === 'Escape') {
      closeSearch();
      closeMenu();
    }
  });

  const guideKey = 'iron_ai_docs_progress_v1';
  const guideSteps = [...document.querySelectorAll('[data-guide-step]')];
  const progressLabel = document.getElementById('guide-progress-label');
  const progressBar = document.getElementById('guide-progress-bar');

  const readProgress = () => {
    try {
      const value = JSON.parse(localStorage.getItem(guideKey) || '[]');
      return Array.isArray(value) ? value : [];
    } catch (_) {
      return [];
    }
  };

  const updateProgress = () => {
    const completed = guideSteps.filter((input) => input.checked).map((input) => input.dataset.guideStep);
    const percentage = guideSteps.length ? Math.round((completed.length / guideSteps.length) * 100) : 0;
    if (progressLabel) progressLabel.textContent = `${percentage}%`;
    if (progressBar) progressBar.style.width = `${percentage}%`;
    try { localStorage.setItem(guideKey, JSON.stringify(completed)); } catch (_) { /* private browsing */ }
  };

  const savedProgress = readProgress();
  guideSteps.forEach((input) => {
    input.checked = savedProgress.includes(input.dataset.guideStep);
    input.addEventListener('change', updateProgress);
  });
  document.getElementById('reset-guide')?.addEventListener('click', () => {
    guideSteps.forEach((input) => { input.checked = false; });
    updateProgress();
    showToast('Progresso do guia reiniciado');
  });
  updateProgress();

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (!visible) return;
      navLinks.forEach((link) => link.classList.toggle('active', link.getAttribute('href') === `#${visible.target.id}`));
    }, { rootMargin: '-15% 0px -68% 0px', threshold: [0, 0.1, 0.4] });
    sections.forEach((section) => observer.observe(section));
  }
})();
