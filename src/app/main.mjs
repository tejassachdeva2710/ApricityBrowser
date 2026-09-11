
import { app, BrowserWindow, ipcMain, session, WebContentsView } from 'electron';
import { randomUUID } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import net from 'net';
import fs from 'fs';
import os from 'os';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.commandLine.appendSwitch('disable-http-cache');
app.commandLine.appendSwitch('disk-cache-size', '1');
// Force SOCKS5 remote DNS for .onion hostname resolution
app.commandLine.appendSwitch('proxy-server', 'socks5://127.0.0.1:9150');
// Force Chromium to delegate DNS resolution (.onion domains) to the Tor SOCKS proxy
app.commandLine.appendSwitch('host-resolver-rules', 'MAP * ~NOTFOUND , EXCLUDE 127.0.0.1');

// Dynamic search for Tor executable across common installation paths on Windows, macOS, and Linux
function findTorExecutable() {
  if (process.env.TOR_EXEC_PATH && fs.existsSync(process.env.TOR_EXEC_PATH)) {
    return process.env.TOR_EXEC_PATH;
  }

  const homeDir = os.homedir();
  const candidatePaths = [];

  if (process.platform === 'win32') {
    if (process.env.LOCALAPPDATA) {
      candidatePaths.push(path.join(process.env.LOCALAPPDATA, 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'));
    }
    if (process.env.PROGRAMFILES) {
      candidatePaths.push(path.join(process.env.PROGRAMFILES, 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'));
    }
    if (process.env['PROGRAMFILES(X86)']) {
      candidatePaths.push(path.join(process.env['PROGRAMFILES(X86)'], 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'));
    }
    if (homeDir) {
      candidatePaths.push(path.join(homeDir, 'Desktop', 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'));
    }
    candidatePaths.push('C:\\Tor\\tor.exe');
  } else if (process.platform === 'darwin') {
    candidatePaths.push(
      '/Applications/Tor Browser.app/Contents/MacOS/Tor/tor.real',
      '/Applications/Tor Browser.app/Contents/MacOS/Tor/tor',
      path.join(homeDir, 'Applications', 'Tor Browser.app', 'Contents', 'MacOS', 'Tor', 'tor.real'),
      path.join(homeDir, 'Applications', 'Tor Browser.app', 'Contents', 'MacOS', 'Tor', 'tor'),
      '/opt/homebrew/bin/tor',
      '/usr/local/bin/tor',
      '/usr/bin/tor'
    );
  } else {
    // Linux / BSD / POSIX
    candidatePaths.push(
      '/usr/bin/tor',
      '/usr/local/bin/tor',
      '/usr/sbin/tor',
      path.join(homeDir, '.local', 'share', 'torbrowser', 'tbb', 'x86_64', 'tor-browser', 'Browser', 'TorBrowser', 'Tor', 'tor'),
      path.join(homeDir, '.local', 'share', 'torbrowser', 'tbb', 'i686', 'tor-browser', 'Browser', 'TorBrowser', 'Tor', 'tor'),
      path.join(homeDir, '.local', 'share', 'tor-browser', 'Browser', 'TorBrowser', 'Tor', 'tor')
    );
  }

  for (const p of candidatePaths) {
    if (p && fs.existsSync(p)) return p;
  }
  return process.platform === 'win32' ? 'tor.exe' : 'tor';
}

const TOR_EXE = findTorExecutable();
// Tor Browser uses 9150; standalone tor uses 9050. We try both.
const TOR_PORTS = [9150, 9050];

let mainWindow = null;
let torProcess = null;
let torConnected = false;   // global source-of-truth for Tor status
let activeTorPort = 9150;    // whichever port actually responds
// Map<tabId, { sessionUUID, partitionId, view: WebContentsView, url: string }>
const activeTabs = new Map();
let webviewBounds = { x: 0, y: 0, width: 0, height: 0 };
let activeTabId = null;
let nextTabId = 1;

async function applyTorProxy(sess) {
  if (!sess) return;
  try {
    await sess.setProxy({
      proxyRules: `socks5://127.0.0.1:${activeTorPort}`,
      proxyBypassRules: '<-loopback>'
    });
  } catch (err) {
    console.warn('[Apricity] Failed to set proxy configuration on session:', err.message);
  }
}

// Test if a TCP port is accepting connections (Tor already up)
function isPortOpen(port) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host: '127.0.0.1', port }, () => {
      sock.destroy();
      resolve(true);
    });
    sock.on('error', () => resolve(false));
    sock.setTimeout(1500, () => { sock.destroy(); resolve(false); });
  });
}

// Notify renderer of Tor status — guarantees listener gets update
function notifyTorStatus(connected) {
  torConnected = connected;
  if (!mainWindow) return;
  mainWindow.webContents.send('tor:status', { connected, port: activeTorPort });
  mainWindow.webContents.once('did-finish-load', () => {
    mainWindow?.webContents.send('tor:status', { connected, port: activeTorPort });
  });
}

async function startTorDaemon() {
  console.log('[Apricity] Checking for existing Tor SOCKS proxy...');

  // 1. Check if Tor Browser (9150) or standalone Tor (9050) is already running
  for (const port of TOR_PORTS) {
    if (await isPortOpen(port)) {
      activeTorPort = port;
      console.log(`[Apricity] ✓ Tor SOCKS proxy already running on port ${port}. Reusing.`);
      await applyTorProxy(session.defaultSession);
      notifyTorStatus(true);
      return;
    }
  }

  // 2. Not running — start our own tor process
  console.log(`[Apricity] Tor proxy not detected. Attempting to spawn: ${TOR_EXE}...`);
  try {
    const torDataDir = path.join(app.getPath('userData'), 'tor-data');
    if (!fs.existsSync(torDataDir)) fs.mkdirSync(torDataDir, { recursive: true });

    torProcess = spawn(TOR_EXE, ['--SocksPort', '9150', '--DataDirectory', torDataDir], {
      detached: false, stdio: ['ignore', 'pipe', 'pipe']
    });

    let bootstrapped = false;
    torProcess.stdout.on('data', async (data) => {
      const msg = data.toString();
      console.log('[Tor]', msg.trim());
      if (msg.includes('Bootstrapped 100%') && !bootstrapped) {
        bootstrapped = true;
        activeTorPort = 9150;
        console.log('[Apricity] ✓ Tor bootstrapped 100%');
        await applyTorProxy(session.defaultSession);
        notifyTorStatus(true);
      }
    });
    torProcess.stderr.on('data', (d) => console.error('[Tor ERR]', d.toString().trim()));
    torProcess.on('error', (err) => console.warn('[Apricity] Tor process error:', err.message));
  } catch (err) {
    console.warn('[Apricity] Could not spawn Tor process:', err.message);
  }
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1380,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#faf9ff',
    frame: false,            // Custom chrome — we draw our own title bar
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      // webviewTag removed for WebContentsView
      sandbox: true,         // Restored OS-level sandbox
    }
  });

  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  mainWindow.on('closed', () => {
    mainWindow = null;
    if (torProcess) {
      try { torProcess.kill(); } catch (_) {}
      torProcess = null;
    }
  });
}

// ── Window control IPC ──
ipcMain.on('window:minimize', () => mainWindow?.minimize());
ipcMain.on('window:maximize', () => {
  mainWindow?.isMaximized() ? mainWindow.unmaximize() : mainWindow?.maximize();
});
ipcMain.on('window:close', () => mainWindow?.close());

// ── Pull-based Tor status (renderer queries at startup) ──
ipcMain.handle('tor:get-status', () => ({ connected: torConnected, port: activeTorPort }));

// Allowed schemes for renderer-initiated navigation (L3-1)
const ALLOWED_NAV_PROTOCOLS = new Set(['http:', 'https:', 'data:', 'about:']);

function isAllowedNavigationUrl(navUrl) {
  if (navUrl === 'about:blank') return true;
  try {
    const parsed = new URL(navUrl);
    return ALLOWED_NAV_PROTOCOLS.has(parsed.protocol);
  } catch (_) {
    return false;
  }
}

// Allowed schemes for privileged IPC navigation requests (strictly http/https) (L3-3)
function isAllowedIpcUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return false;
  try {
    const parsed = new URL(rawUrl);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

// ── ZTR Tab Open ──
ipcMain.handle('ztr:open-tab', async (_event, targetUrl) => {
  const tabId = `tab-${nextTabId++}`;
  const sessionUUID = randomUUID();
  const partitionId = `ephemeral-${sessionUUID}`;
  const ephemSession = session.fromPartition(partitionId, { cache: false });
  
  await applyTorProxy(ephemSession);
  // L3-4: Deny asynchronous permission prompts and synchronous permission checks
  ephemSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  ephemSession.setPermissionCheckHandler((_wc, _perm, _origin) => false);
  // L3-5: Prevent all downloads to local filesystem
  ephemSession.on('will-download', (event) => {
    event.preventDefault();
  });

  const view = new WebContentsView({
    webPreferences: {
      session: ephemSession,
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true
    }
  });

  // L3-1: will-navigate navigation bounds
  view.webContents.on('will-navigate', (event, navUrl) => {
    if (!isAllowedNavigationUrl(navUrl)) {
      event.preventDefault();
    }
  });

  // L3-2: setWindowOpenHandler window creation bounds
  view.webContents.setWindowOpenHandler(() => {
    return { action: 'deny' };
  });
  
  view.webContents.on('did-navigate', (e, url) => {
    if (url.startsWith('data:')) return;
    activeTabs.get(tabId).url = url;
    mainWindow.webContents.send('tab:did-navigate', { tabId, url });
  });
  view.webContents.on('did-navigate-in-page', (e, url) => {
    if (url.startsWith('data:')) return;
    activeTabs.get(tabId).url = url;
    mainWindow.webContents.send('tab:did-navigate', { tabId, url });
  });
  view.webContents.on('did-fail-load', (e, errorCode, errorDescription) => {
    if (errorCode === -3) return;
    const isTorError = errorCode === -105 || errorCode === -130;
    const html = encodeURIComponent(`<!DOCTYPE html><html>
      <head><style>
        body{font-family:Inter,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;
          height:100vh;margin:0;background:#faf9ff;color:#111827}
        .box{text-align:center;max-width:400px}
        h2{color:#6d28d9;margin-bottom:10px;font-size:20px}
        p{color:#6b7280;font-size:14px;line-height:1.6;margin-bottom:8px}
      </style></head><body><div class="box">
        ${isTorError ? '<p>Make sure Tor Browser is running, or wait for Tor to fully bootstrap.</p>' : '<p>Load failed.</p>'}
      </div></body></html>`);
    view.webContents.loadURL(`data:text/html,${html}`);
  });

  const initialUrl = (targetUrl && targetUrl !== 'newtab' && isAllowedIpcUrl(targetUrl)) ? targetUrl : 'newtab';
  activeTabs.set(tabId, { sessionUUID, partitionId, view, url: initialUrl });
  
  if (initialUrl !== 'newtab') {
    view.webContents.loadURL(initialUrl);
  }
  
  return {
    tabId,
    sessionUUID,
    partition: partitionId,
    url: initialUrl,
    status: 'sealed'
  };
});

// ── ZTR Tab Close ──
ipcMain.handle('ztr:close-tab', async (_event, tabId) => {
  try {
    const tabData = activeTabs.get(tabId);
    if (!tabData) return { success: false };
    
    if (activeTabId === tabId) {
      mainWindow.contentView.removeChildView(tabData.view);
      activeTabId = null;
    }
    
    const partitionId = tabData.partitionId;
    activeTabs.delete(tabId);
    
    tabData.view.webContents.close();
    
    try {
      const s = session.fromPartition(partitionId);
      await s.clearStorageData();
      await s.clearCache();
    } catch (_) { }
    return { success: true, tabId };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.on('ztr:update-bounds', (e, bounds) => {
  webviewBounds = bounds;
  if (activeTabId && activeTabs.has(activeTabId)) {
    activeTabs.get(activeTabId).view.setBounds(bounds);
  }
});

ipcMain.on('ztr:switch-tab', (e, tabId) => {
  if (activeTabId && activeTabs.has(activeTabId)) {
    mainWindow.contentView.removeChildView(activeTabs.get(activeTabId).view);
  }
  activeTabId = tabId;
  const tabData = activeTabs.get(tabId);
  if (tabData && tabData.url !== 'newtab') {
    mainWindow.contentView.addChildView(tabData.view);
    tabData.view.setBounds(webviewBounds);
  }
});

ipcMain.on('ztr:navigate', (e, tabId, url) => {
  // L3-3: Reject non-http/https schemes at the IPC boundary
  if (!isAllowedIpcUrl(url)) return;

  const tabData = activeTabs.get(tabId);
  if (tabData) {
    tabData.url = url;
    if (activeTabId === tabId && !mainWindow.contentView.children.includes(tabData.view)) {
      mainWindow.contentView.addChildView(tabData.view);
      tabData.view.setBounds(webviewBounds);
    }
    tabData.view.webContents.loadURL(url);
  }
});

ipcMain.on('ztr:go-back', (e, tabId) => {
  const tabData = activeTabs.get(tabId);
  if (tabData && tabData.view.webContents.canGoBack()) tabData.view.webContents.goBack();
});

ipcMain.on('ztr:go-forward', (e, tabId) => {
  const tabData = activeTabs.get(tabId);
  if (tabData && tabData.view.webContents.canGoForward()) tabData.view.webContents.goForward();
});

ipcMain.on('ztr:reload', (e, tabId) => {
  const tabData = activeTabs.get(tabId);
  if (tabData) tabData.view.webContents.reload();
});

// ── App Lifecycle ──
app.whenReady().then(async () => {
  // Deny permission requests & synchronous checks by default on default session
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler((_wc, _perm, _origin) => false);
  session.defaultSession.on('will-download', (event) => {
    event.preventDefault();
  });
  await applyTorProxy(session.defaultSession);

  await createWindow();
  startTorDaemon(); // Non-blocking — notifyTorStatus() handles timing
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('certificate-error', (event, _webContents, _url, _error, _certificate, callback) => {
  event.preventDefault();
  callback(false);
});

app.on('window-all-closed', () => {
  if (torProcess) {
    try { torProcess.kill(); } catch (_) {}
    torProcess = null;
  }
  if (process.platform !== 'darwin') app.quit();
});

export { isAllowedNavigationUrl, isAllowedIpcUrl };
