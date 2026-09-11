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
    destroyedList.replaceChildren();
    if (recentlyDestroyed.length === 0) {
      const emptyLi = document.createElement('li');
      emptyLi.className = 'destroyed-empty';
      emptyLi.textContent = 'No tabs destroyed yet.';
      destroyedList.appendChild(emptyLi);
      return;
    }
    recentlyDestroyed.forEach(item => {
      let domain = item.url;
      try { domain = new URL(item.url).hostname.replace('www.', ''); } catch (_) {}
      const li = document.createElement('li');
      li.className = 'destroyed-item';

      const iconDiv = document.createElement('div');
      iconDiv.className = 'dest-icon';
      iconDiv.textContent = (domain.charAt(0) || '?').toUpperCase();

      const infoDiv = document.createElement('div');
      infoDiv.className = 'dest-info';

      const urlDiv = document.createElement('div');
      urlDiv.className = 'dest-url';
      urlDiv.textContent = domain;

      const timeDiv = document.createElement('div');
      timeDiv.className = 'dest-time';
      timeDiv.textContent = `Destroyed ${timeAgo(item.at)}`;

      infoDiv.appendChild(urlDiv);
      infoDiv.appendChild(timeDiv);

      li.appendChild(iconDiv);
      li.appendChild(infoDiv);

      destroyedList.appendChild(li);
    });
  }

  // ═══════════════════════════════
  // ACTIVE TABS LIST (new tab page)
  // ═══════════════════════════════
  function renderActiveTabsList() {
    activeTabsList.replaceChildren();
    tabs.forEach((rec, tabId) => {
      let label = rec.title || 'New Tab';
      if (rec.url && rec.url !== 'newtab') {
        try { label = new URL(rec.url).hostname.replace('www.', ''); } catch (_) {}
      }
      const card = document.createElement('div');
      card.className = 'atl-card';

      const favDiv = document.createElement('div');
      favDiv.className = 'atl-fav';
      favDiv.textContent = (label.charAt(0) || '?').toUpperCase();

      const titleDiv = document.createElement('div');
      titleDiv.className = 'atl-title';
      titleDiv.textContent = label;

      const timerDiv = document.createElement('div');
      timerDiv.className = 'atl-timer';
      timerDiv.textContent = fmt(rec.remaining);

      const closeBtn = document.createElement('button');
      closeBtn.className = 'atl-x';
      closeBtn.dataset.tab = tabId;
      closeBtn.textContent = '×';
      closeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        destroyTab(tabId);
      });

      card.appendChild(favDiv);
      card.appendChild(titleDiv);
      card.appendChild(timerDiv);
      card.appendChild(closeBtn);

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

      // Build tab UI element (Safe DOM Construction)
      const tabEl = document.createElement('div');
      tabEl.className = 'tab-item';
      tabEl.dataset.tabId = tabData.tabId;

      const favDiv = document.createElement('div');
      favDiv.className = 'tab-favicon';
      favDiv.textContent = '✦';

      const titleSpan = document.createElement('span');
      titleSpan.className = 'tab-title-text';
      titleSpan.textContent = 'New Tab';

      const closeBtn = document.createElement('button');
      closeBtn.className = 'tab-close';
      closeBtn.textContent = '×';

      tabEl.appendChild(favDiv);
      tabEl.appendChild(titleSpan);
      tabEl.appendChild(closeBtn);

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
    if (activeTabId === tabId) return;

    // Deactivate current
    if (activeTabId && tabs.has(activeTabId)) {
      const cur = tabs.get(activeTabId);
      cur.tabEl?.classList.remove('active');
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
      urlInput.value = next.url;
    }

    window.apricityAPI?.switchTab?.(tabId);
    syncTimerDisplay();
    renderActiveTabsList();
  }

  // ═══════════════════════════════
  // NAVIGATION (KEY FIX: dom-ready before loadURL)
  // ═══════════════════════════════
    async function navigateTo(url) {
    if (!url) return;

    // No active tab -> open a new one
    if (!activeTabId || !tabs.has(activeTabId)) {
      await createNewTab(url);
      return;
    }

    const rec = tabs.get(activeTabId);
    rec.url     = url;
    rec.isNewTab = false;
    newTabPage.classList.add('hidden');
    webviewArea.classList.add('visible');

    window.apricityAPI?.navigate?.(activeTabId, url);
    urlInput.value = url;
  }

  

  // ═══════════════════════════════
  // TAB DESTRUCTION (3-Phase ZTR Wipe)
  // ═══════════════════════════════
    function destroyTab(tabId) {
    const rec = tabs.get(tabId);
    if (!rec) return;

    // 1. Immediately remove DOM elements & local state for INSTANT visual response
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
  btnBack.addEventListener('click',   () => { if (activeTabId) window.apricityAPI?.goBack?.(activeTabId); });
  btnFwd.addEventListener('click',    () => { if (activeTabId) window.apricityAPI?.goForward?.(activeTabId); });
  btnReload.addEventListener('click', () => { if (activeTabId) window.apricityAPI?.reload?.(activeTabId); });

  // Handle IPC Navigation events from WebContentsView
  window.apricityAPI?.onTabDidNavigate?.((data) => {
    const rec = tabs.get(data.tabId);
    if (rec) {
      rec.url = data.url;
      if (activeTabId === data.tabId) urlInput.value = data.url;
    }
  });

  // Observe webviewArea resizing to update WebContentsView bounds
  const updateBounds = () => {
    if (webviewArea.classList.contains('visible')) {
      const rect = webviewArea.getBoundingClientRect();
      window.apricityAPI?.updateBounds?.({
        x: Math.round(rect.x),
        y: Math.round(rect.y),
        width: Math.round(rect.width),
        height: Math.round(rect.height)
      });
    }
  };
  window.addEventListener('resize', updateBounds);
  const observer = new MutationObserver(updateBounds);
  observer.observe(webviewArea, { attributes: true, attributeFilter: ['class', 'style'] });

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
