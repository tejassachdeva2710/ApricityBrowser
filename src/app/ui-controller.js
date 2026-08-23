/**
 * ui-controller.js
 * Apricity Browser — Front-End Controller
 * 
 * Key fix: webviews are created with NO src initially.
 * URL is only loaded after 'dom-ready' fires, avoiding
 * the proxy-not-ready black screen race condition.
 */
document.addEventListener('DOMContentLoaded', () => {

  // ── DOM refs ──
  const tabBar          = document.getElementById('tab-bar');
  const btnAddTab       = document.getElementById('btn-add-tab');
  const btnNewTabSb     = document.getElementById('btn-new-tab-sb');
  const urlInput        = document.getElementById('url-input');
  const torPill         = document.getElementById('tor-pill');
  const torLabel        = document.getElementById('tor-label');
  const torDotSb        = document.getElementById('tor-dot-sb');
  const torStatusNameSb = document.getElementById('tor-status-name-sb');
  const torStatusSubSb  = document.getElementById('tor-status-sub-sb');
  const btnBack         = document.getElementById('btn-back');
  const btnFwd          = document.getElementById('btn-fwd');
  const btnReload       = document.getElementById('btn-reload');
  const timerDisplay    = document.getElementById('timer-display');
  const btnAddTime      = document.getElementById('btn-add-time');
  const btnEndNow       = document.getElementById('btn-end-now');
  const destroyedList   = document.getElementById('destroyed-list');
  const newTabPage      = document.getElementById('new-tab-page');
  const webviewArea     = document.getElementById('webview-area');
  const activeTabsList  = document.getElementById('active-tabs-list');
  const ntpSearchInput  = document.getElementById('ntp-search-input');
  const ntpSearchBtn    = document.getElementById('ntp-search-btn');
  const wcClose         = document.getElementById('wc-close');
  const wcMin           = document.getElementById('wc-min');
  const wcMax           = document.getElementById('wc-max');

  const DEFAULT_TIMER   = 30 * 60; // 30 minutes in seconds
  const DDG_ONION       = 'http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion';
  const DDG_CLEARNET    = 'https://duckduckgo.com';

  // ── State ──
  const tabs             = new Map(); // tabId → record
  let   activeTabId      = null;
  const recentlyDestroyed = [];
  let   torConnected      = false;
  let   globalTimer       = null;

  // ── Window controls ──
  wcClose?.addEventListener('click', () => window.apricityAPI?.windowControls?.close());
  wcMin?.addEventListener('click',   () => window.apricityAPI?.windowControls?.minimize());
  wcMax?.addEventListener('click',   () => window.apricityAPI?.windowControls?.maximize());

  // ── Tor status — pull polling + push listener ──
  function updateTorUI(data) {
    if (!data || !data.connected) return;
    torConnected = true;
    if (torPill) torPill.className = 'tor-connected';
    if (torLabel) torLabel.textContent = 'Tor Connected';
    if (torDotSb) torDotSb.classList.add('connected');
    if (torStatusNameSb) torStatusNameSb.textContent = 'Tor Connected';
    if (torStatusSubSb) torStatusSubSb.textContent  = `Port ${data.port || 9150} · IP hidden`;
  }

  // Check immediately, then poll every 1s until connected
  const checkTor = async () => {
    try {
      if (window.apricityAPI?.getTorStatus) {
        const status = await window.apricityAPI.getTorStatus();
        if (status && status.connected) {
          updateTorUI(status);
          clearInterval(torPollInterval);
        }
      }
    } catch (e) {
      console.warn('[UI] Tor status check error:', e);
    }
  };
  checkTor();
  const torPollInterval = setInterval(checkTor, 1000);

  // Push listener
  try {
    window.apricityAPI?.onTorStatus?.((data) => {
      updateTorUI(data);
      if (data && data.connected) clearInterval(torPollInterval);
    });
  } catch (e) {
    console.warn('[UI] onTorStatus listener error:', e);
  }


  // ═══════════════════════════════
  // TIMER
  // ═══════════════════════════════
  function fmt(s) {
    const m = Math.floor(Math.max(0, s) / 60).toString().padStart(2, '0');
    const sec = (Math.max(0, s) % 60).toString().padStart(2, '0');
    return `${m}:${sec}`;
  }

  function startGlobalTimer() {
    if (globalTimer) return;
    globalTimer = setInterval(() => {
      let anyAlive = false;
      for (const [tabId, rec] of tabs) {
        if (rec.remaining > 0) {
          rec.remaining--;
          anyAlive = true;
          if (rec.remaining === 0) destroyTab(tabId);
        }
      }
      if (!anyAlive) { clearInterval(globalTimer); globalTimer = null; }
      syncTimerDisplay();
      renderActiveTabsList();
    }, 1000);
  }

  function syncTimerDisplay() {
    if (activeTabId && tabs.has(activeTabId)) {
      timerDisplay.textContent = fmt(tabs.get(activeTabId).remaining);
    } else {
      timerDisplay.textContent = '--:--';
    }
  }

  // ── Timer Presets ──
  const timerPresetSelect = document.getElementById('timer-preset-select');
  let defaultTimerSeconds = 300; // Default: 5 minutes

  if (timerPresetSelect) {
    defaultTimerSeconds = parseInt(timerPresetSelect.value, 10) || 300;
    timerPresetSelect.addEventListener('change', () => {
      defaultTimerSeconds = parseInt(timerPresetSelect.value, 10) || 300;
      if (activeTabId && tabs.has(activeTabId)) {
        tabs.get(activeTabId).remaining = defaultTimerSeconds;
        syncTimerDisplay();
        renderActiveTabsList();
      }
    });
  }

  // ═══════════════════════════════
  // RECENTLY DESTROYED
  // ═══════════════════════════════
  function timeAgo(ts) {
    const d = Math.floor((Date.now() - ts) / 1000);
    if (d < 60)   return `${d}s ago`;
    if (d < 3600) return `${Math.floor(d/60)}m ago`;
    return `${Math.floor(d/3600)}h ago`;
  }

  function addDestroyed(rec) {
    if (!rec || !rec.url || rec.url === 'newtab' || rec.url.startsWith('data:')) return;
    if (recentlyDestroyed.length > 0 && recentlyDestroyed[0].url === rec.url) return;
    recentlyDestroyed.unshift({ title: rec.title || rec.url, url: rec.url, at: Date.now() });
    if (recentlyDestroyed.length > 5) recentlyDestroyed.pop();
    renderDestroyedList();
  }

  function renderDestroyedList() {
    destroyedList.innerHTML = '';
    if (recentlyDestroyed.length === 0) {
      destroyedList.innerHTML = '<li class="destroyed-empty">No tabs destroyed yet.</li>';
      return;
    }
    recentlyDestroyed.forEach(item => {
      let domain = item.url;
      try { domain = new URL(item.url).hostname.replace('www.', ''); } catch (_) {}
      const li = document.createElement('li');
      li.className = 'destroyed-item';
      li.innerHTML = `
        <div class="dest-icon">${domain.charAt(0).toUpperCase()}</div>
        <div class="dest-info">
          <div class="dest-url">${domain}</div>
          <div class="dest-time">Destroyed ${timeAgo(item.at)}</div>
        </div>
      `;
      destroyedList.appendChild(li);
    });
  }

  // ═══════════════════════════════
  // ACTIVE TABS LIST (new tab page)
  // ═══════════════════════════════
  function renderActiveTabsList() {
    activeTabsList.innerHTML = '';
    tabs.forEach((rec, tabId) => {
      let label = rec.title || 'New Tab';
      if (rec.url && rec.url !== 'newtab') {
        try { label = new URL(rec.url).hostname.replace('www.', ''); } catch (_) {}
      }
      const card = document.createElement('div');
      card.className = 'atl-card';
      card.innerHTML = `
        <div class="atl-fav">${label.charAt(0).toUpperCase()}</div>
        <div class="atl-title">${label}</div>
        <div class="atl-timer">${fmt(rec.remaining)}</div>
        <button class="atl-x" data-tab="${tabId}">×</button>
      `;
      card.querySelector('.atl-x').addEventListener('click', (e) => {
        e.stopPropagation();
        destroyTab(tabId);
      });
      activeTabsList.appendChild(card);
    });
  }

  // ═══════════════════════════════
  // TAB CREATION
  // ═══════════════════════════════
  async function createNewTab(targetUrl) {
    try {
      let tabData;
      if (window.apricityAPI?.openTab) {
        tabData = await window.apricityAPI.openTab(targetUrl || 'newtab');
      }
      if (!tabData) {
        const id = Date.now();
        tabData = { tabId: `tab-${id}`, sessionUUID: `uuid-${id}`, partition: `ephemeral-${id}` };
      }

      const rec = {
        tabId:       tabData.tabId,
        sessionUUID: tabData.sessionUUID,
        partition:   tabData.partition,
        url:         targetUrl || 'newtab',
        title:       'New Tab',
        webview:     null,
        tabEl:       null,
        remaining:   defaultTimerSeconds,
        isNewTab:    !targetUrl
      };

      // Build tab UI element
      const tabEl = document.createElement('div');
      tabEl.className = 'tab-item';
      tabEl.dataset.tabId = tabData.tabId;
      tabEl.innerHTML = `
        <div class="tab-favicon">✦</div>
        <span class="tab-title-text">New Tab</span>
        <button class="tab-close">×</button>
      `;
      tabBar.appendChild(tabEl);
      rec.tabEl = tabEl;

      tabs.set(tabData.tabId, rec);

      tabEl.addEventListener('click', (e) => {
        if (!e.target.classList.contains('tab-close')) switchActiveTab(tabData.tabId);
      });
      tabEl.querySelector('.tab-close').addEventListener('click', (e) => {
        e.stopPropagation();
        destroyTab(tabData.tabId);
      });

      switchActiveTab(tabData.tabId);
      startGlobalTimer();
      renderActiveTabsList();
    } catch (err) {
      console.error('[UI] createNewTab error:', err);
    }
  }

  // ═══════════════════════════════
  // TAB SWITCHING
  // ═══════════════════════════════
  function switchActiveTab(tabId) {
    if (!tabs.has(tabId)) return;

    // Deactivate current
    if (activeTabId && tabs.has(activeTabId)) {
      const cur = tabs.get(activeTabId);
      cur.tabEl?.classList.remove('active');
      if (cur.webview) {
        cur.webview.classList.remove('active');
        cur.webview.classList.add('inactive');
      }
    }

    activeTabId = tabId;
    const next = tabs.get(tabId);
    next.tabEl?.classList.add('active');

    if (next.isNewTab || next.url === 'newtab') {
      newTabPage.classList.remove('hidden');
      webviewArea.classList.remove('visible');
      urlInput.value = '';
    } else {
      newTabPage.classList.add('hidden');
      webviewArea.classList.add('visible');
      if (next.webview) {
        next.webview.classList.remove('inactive');
        next.webview.classList.add('active');
      }
      urlInput.value = next.url;
    }

    syncTimerDisplay();
    renderActiveTabsList();
  }

  // ═══════════════════════════════
  // NAVIGATION (KEY FIX: dom-ready before loadURL)
  // ═══════════════════════════════
  async function navigateTo(url) {
    if (!url) return;

    // No active tab → open a new one
    if (!activeTabId || !tabs.has(activeTabId)) {
      await createNewTab(url);
      // After tab created, navigate immediately
      const rec = tabs.get(activeTabId);
      if (rec) {
        rec.url     = url;
        rec.isNewTab = false;
        launchWebview(rec, url);
      }
      return;
    }

    const rec = tabs.get(activeTabId);
    rec.url     = url;
    rec.isNewTab = false;
    newTabPage.classList.add('hidden');
    webviewArea.classList.add('visible');

    if (!rec.webview) {
      launchWebview(rec, url);
    } else {
      rec.webview.loadURL(url);
      urlInput.value = url;
    }
  }

  function launchWebview(rec, url) {
    const wv = document.createElement('webview');
    wv.setAttribute('partition', rec.partition);
    wv.setAttribute('allowpopups', '');
    wv.classList.add('inactive');
    wv.src = url;
    webviewArea.appendChild(wv);
    rec.webview = wv;

    // Sync address bar
    wv.addEventListener('did-navigate', (e) => {
      if (e.url.startsWith('data:')) return;
      rec.url = e.url;
      if (activeTabId === rec.tabId) urlInput.value = e.url;
    });
    wv.addEventListener('did-navigate-in-page', (e) => {
      if (e.url.startsWith('data:')) return;
      rec.url = e.url;
      if (activeTabId === rec.tabId) urlInput.value = e.url;
    });

    // Sync tab title
    wv.addEventListener('page-title-updated', (e) => {
      rec.title = e.title;
      const el = rec.tabEl?.querySelector('.tab-title-text');
      if (el) el.textContent = e.title.substring(0, 28);
      const fav = rec.tabEl?.querySelector('.tab-favicon');
      if (fav) fav.textContent = e.title.charAt(0).toUpperCase();
    });

    // Handle load failures gracefully — inject error page instead of black screen
    wv.addEventListener('did-fail-load', (e) => {
      if (e.errorCode === -3) return; // -3 = aborted (user navigated away), not real error
      console.warn(`[Webview] Load failed: ${e.errorDescription} (${e.errorCode})`);
      const isTorError = e.errorCode === -105 || e.errorCode === -130;
      const html = encodeURIComponent(`<!DOCTYPE html><html>
        <head><style>
          body{font-family:Inter,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;
            height:100vh;margin:0;background:#faf9ff;color:#111827}
          .box{text-align:center;max-width:400px}
          h2{color:#6d28d9;margin-bottom:10px;font-size:20px}
          p{color:#6b7280;font-size:14px;line-height:1.6;margin-bottom:8px}
          .code{display:inline-block;font-family:monospace;background:#ede9fe;padding:3px 8px;border-radius:6px;font-size:12px}
        </style></head><body><div class="box">
          <h2>🧅 Connection Failed</h2>
          <p>${e.errorDescription}</p>
          <p><span class="code">Error ${e.errorCode}</span></p>
          ${isTorError ? '<p>Make sure Tor Browser is running, or wait for Tor to fully bootstrap.</p>' : ''}
        </div></body></html>`);
      wv.loadURL(`data:text/html,${html}`);
    });

    // Activate this webview, deactivate others
    webviewArea.querySelectorAll('webview').forEach(w => {
      w.classList.remove('active');
      w.classList.add('inactive');
    });
    wv.classList.remove('inactive');
    wv.classList.add('active');
    urlInput.value = url;
  }

  // ═══════════════════════════════
  // TAB DESTRUCTION (3-Phase ZTR Wipe)
  // ═══════════════════════════════
  function destroyTab(tabId) {
    const rec = tabs.get(tabId);
    if (!rec) return;

    // 1. Immediately remove DOM elements & local state for INSTANT visual response
    rec.webview?.remove();
    rec.tabEl?.remove();
    tabs.delete(tabId);

    // 2. Add to Recently Destroyed (deduplicated)
    addDestroyed(rec);

    // 3. Switch active tab if needed
    if (activeTabId === tabId) {
      activeTabId = null;
      const remaining = Array.from(tabs.keys());
      if (remaining.length > 0) {
        switchActiveTab(remaining[remaining.length - 1]);
      } else {
        newTabPage.classList.remove('hidden');
        webviewArea.classList.remove('visible');
        urlInput.value = '';
        timerDisplay.textContent = '--:--';
        if (globalTimer) { clearInterval(globalTimer); globalTimer = null; }
      }
    }

    renderActiveTabsList();

    // 4. Background IPC call (non-blocking)
    try {
      window.apricityAPI?.closeTab?.(tabId);
    } catch (_) {}
  }

  // ═══════════════════════════════
  // URL RESOLUTION — ALWAYS USE .ONION FOR SEARCHES
  // ═══════════════════════════════
  function resolveUrl(raw) {
    const t = raw.trim();
    if (!t) return null;
    if (t.startsWith('http://') || t.startsWith('https://')) return t;
    if (t.endsWith('.onion') || t.includes('.onion/')) return `http://${t}`;
    if (t.includes('.') && !t.includes(' ') && !t.startsWith('www ')) return `https://${t}`;
    // Always route search queries through DuckDuckGo's official .onion Hidden Service
    return `${DDG_ONION}/?q=${encodeURIComponent(t)}`;
  }

  // ═══════════════════════════════
  // EVENT BINDINGS
  // ═══════════════════════════════

  // Address bar
  urlInput.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter') return;
    const url = resolveUrl(urlInput.value);
    if (url) await navigateTo(url);
  });

  // Nav buttons
  btnBack.addEventListener('click',   () => { const r = tabs.get(activeTabId); if (r?.webview?.canGoBack())    r.webview.goBack(); });
  btnFwd.addEventListener('click',    () => { const r = tabs.get(activeTabId); if (r?.webview?.canGoForward()) r.webview.goForward(); });
  btnReload.addEventListener('click', () => { tabs.get(activeTabId)?.webview?.reload(); });

  // Timer controls
  btnAddTime.addEventListener('click', () => {
    if (activeTabId && tabs.has(activeTabId)) {
      tabs.get(activeTabId).remaining += 5 * 60; // Add 5 minutes
      syncTimerDisplay();
      renderActiveTabsList();
    }
  });
  btnEndNow.addEventListener('click', () => {
    if (activeTabId) destroyTab(activeTabId);
  });

  // New tab buttons
  btnAddTab.addEventListener('click',   () => createNewTab());
  btnNewTabSb.addEventListener('click', () => createNewTab());

  // NTP search
  const doNtpSearch = async () => {
    const url = resolveUrl(ntpSearchInput.value);
    if (url) await navigateTo(url);
  };
  ntpSearchBtn.addEventListener('click', doNtpSearch);
  ntpSearchInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') doNtpSearch(); });

  // ── INIT ──
  createNewTab(); // Open first tab on launch
});
