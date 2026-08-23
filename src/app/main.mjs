
import { app, BrowserWindow, ipcMain, session } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import net from 'net';
import { ZeroTrustRenderer } from '../ztr/ZeroTrustRenderer.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.commandLine.appendSwitch('disable-http-cache');
app.commandLine.appendSwitch('disk-cache-size', '1');
// Force SOCKS5 remote DNS for .onion hostname resolution
app.commandLine.appendSwitch('proxy-server', 'socks5://127.0.0.1:9150');
// Force Chromium to delegate DNS resolution (.onion domains) to the Tor SOCKS proxy
app.commandLine.appendSwitch('host-resolver-rules', 'MAP * ~NOTFOUND , EXCLUDE 127.0.0.1');
app.commandLine.appendSwitch('ignore-certificate-errors');

// Dynamic search for Tor executable across common installation paths
function findTorExecutable() {
  if (process.env.TOR_EXEC_PATH && fs.existsSync(process.env.TOR_EXEC_PATH)) {
    return process.env.TOR_EXEC_PATH;
  }
  const candidatePaths = [
    'C:\\Users\\Tejas Sachdeva\\Desktop\\Academics & JEE\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe',
    path.join(process.env.LOCALAPPDATA || '', 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'),
    path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'),
    path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Tor Browser', 'Browser', 'TorBrowser', 'Tor', 'tor.exe'),
    'C:\\Tor\\tor.exe',
    '/usr/bin/tor',
    '/usr/local/bin/tor'
  ];
  for (const p of candidatePaths) {
    if (p && fs.existsSync(p)) return p;
  }
  return 'tor';
}

const TOR_EXE = findTorExecutable();
// Tor Browser uses 9150; standalone tor uses 9050. We try both.
const TOR_PORTS = [9150, 9050];

let mainWindow = null;
let torProcess = null;
let torConnected = false;   // global source-of-truth for Tor status
let activeTorPort = 9150;    // whichever port actually responds
const ztr = new ZeroTrustRenderer();
let nextTabId = 1;

async function applyTorProxy(sess) {
  await sess.setProxy({
    proxyRules: `socks5://127.0.0.1:${activeTorPort}`,
    proxyBypassRules: '<-loopback>'
  });
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
      notifyTorStatus(true);
      return;
    }
  }

  // 2. Not running — start our own tor.exe
  console.log(`[Apricity] Tor not found. Spawning binary: ${TOR_EXE}...`);
  try {
    const torDataDir = path.join(app.getPath('userData'), 'tor-data');
    if (!fs.existsSync(torDataDir)) fs.mkdirSync(torDataDir, { recursive: true });

    torProcess = spawn(TOR_EXE, ['--SocksPort', '9150', '--DataDirectory', torDataDir], {
      detached: false, stdio: ['ignore', 'pipe', 'pipe']
    });

    let bootstrapped = false;
    torProcess.stdout.on('data', (data) => {
      const msg = data.toString();
      console.log('[Tor]', msg.trim());
      if (msg.includes('Bootstrapped 100%') && !bootstrapped) {
        bootstrapped = true;
        activeTorPort = 9150;
        console.log('[Apricity] ✓ Tor bootstrapped 100%');
        notifyTorStatus(true);
      }
    });
    torProcess.stderr.on('data', (d) => console.error('[Tor ERR]', d.toString().trim()));
    torProcess.on('error', (err) => console.warn('[Apricity] tor.exe error:', err.message));
  } catch (err) {
    console.warn('[Apricity] Could not spawn tor.exe:', err.message);
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
      webviewTag: true,      // Required for <webview> content rendering
      sandbox: false,        // MUST be false — sandbox breaks webviewTag
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  mainWindow.on('closed', () => { mainWindow = null; torProcess?.kill(); });
}

// ── Window control IPC ──
ipcMain.on('window:minimize', () => mainWindow?.minimize());
ipcMain.on('window:maximize', () => {
  mainWindow?.isMaximized() ? mainWindow.unmaximize() : mainWindow?.maximize();
});
ipcMain.on('window:close', () => mainWindow?.close());

// ── Pull-based Tor status (renderer queries at startup) ──
ipcMain.handle('tor:get-status', () => ({ connected: torConnected, port: activeTorPort }));

// ── ZTR Tab Open ──
ipcMain.handle('ztr:open-tab', async (_event, targetUrl) => {
  const tabId = `tab-${nextTabId++}`;
  const tabState = await ztr.openTab(tabId, targetUrl || 'newtab');

  // Create isolated ephemeral session partition (no disk cache)
  const partitionId = `ephemeral-${tabState.sessionUUID}`;
  const ephemSession = session.fromPartition(partitionId, { cache: false });
  await applyTorProxy(ephemSession);
  ephemSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));

  return {
    tabId: tabState.tabId,
    sessionUUID: tabState.sessionUUID,
    partition: partitionId,
    url: tabState.url,
    status: tabState.status
  };
});

// ── ZTR Tab Close ──
ipcMain.handle('ztr:close-tab', async (_event, tabId) => {
  try {
    const activeTab = ztr.activeTabs.get(tabId);
    if (!activeTab) return { success: false };
    const partitionId = `ephemeral-${activeTab.sessionUUID}`;
    const destroySummary = await ztr.closeTab(tabId);
    try {
      const s = session.fromPartition(partitionId);
      await s.clearStorageData();
      await s.clearCache();
    } catch (_) { }
    return { success: true, tabId, destroySummary };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ── App Lifecycle ──
app.whenReady().then(async () => {
  await createWindow();
  startTorDaemon(); // Non-blocking — notifyTorStatus() handles timing
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  torProcess?.kill();
  if (process.platform !== 'darwin') app.quit();
});
