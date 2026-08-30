import { app, BrowserWindow, session, WebContentsView } from 'electron';
import path from 'path';
import http from 'http';
import fs from 'fs';

// Force development environment
process.env.NODE_ENV = 'development';

let passedCount = 0;
let failedCount = 0;
let skippedCount = 0;

function logPass(property, message, verification = '') {
  passedCount++;
  console.log(`[PASS] [${property}] ${message}`);
  if (verification) console.log(`       -> ${verification}`);
}

function logFail(property, message, error) {
  failedCount++;
  console.error(`[FAIL] [${property}] ${message}`);
  if (error) console.error(`       -> ${error.message || error}`);
}

function logSkip(property, message) {
  skippedCount++;
  console.log(`[SKIP] [${property}] ${message}`);
}

async function runLiveTests() {
  console.log('\n================================================================');
  console.log('  APRICITY BROWSER: LIVE ELECTRON ARCHITECTURE TESTS');
  console.log('  Testing WebContentsView Architecture (sandbox: true)');
  console.log('================================================================\n');

  // Create a sandboxed main window to host the WebContentsViews
  const mainWindow = new BrowserWindow({
    show: false,
    webPreferences: { sandbox: true }
  });

  // ----------------------------------------------------------------
  // 1. RAM-Only Profile Verification
  // ----------------------------------------------------------------
  try {
    console.log('--- 1. Partition Path Storage Verification ---');
    const testPartitionId = `ephemeral-test-${Date.now()}`;
    const sess = session.fromPartition(testPartitionId, { cache: false });
    const storagePath = sess.getStoragePath();
    
    if (storagePath === null) {
      logPass('RAM_ONLY_PROFILE', 'session.fromPartition created in-memory session profile', 'getStoragePath() returns null');
    } else {
      logFail('RAM_ONLY_PROFILE', 'Session profile is writing to disk', new Error(`Path: ${storagePath}`));
    }
  } catch (err) {
    logFail('RAM_ONLY_PROFILE', 'Test error', err);
  }

  // Set up local server for DOM tests
  let server;
  let localUrl;
  try {
    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body>Apricity Canary Server</body></html>');
    });
    
    await new Promise((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => resolve());
      server.on('error', reject);
    });
    
    const port = server.address().port;
    localUrl = `http://127.0.0.1:${port}/`;
    console.log(`\n[INFO] Local canary server listening on ${localUrl}`);

    // Create two isolated WebContentsViews using EXACT same settings as main.mjs
    const partA = `ephemeral-A-${Date.now()}`;
    const sessA = session.fromPartition(partA, { cache: false });
    
    const partB = `ephemeral-B-${Date.now()}`;
    const sessB = session.fromPartition(partB, { cache: false });

    const viewA = new WebContentsView({
      webPreferences: {
        session: sessA,
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true
      }
    });

    const viewB = new WebContentsView({
      webPreferences: {
        session: sessB,
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true
      }
    });

    mainWindow.contentView.addChildView(viewA);
    mainWindow.contentView.addChildView(viewB);

    await Promise.all([
      viewA.webContents.loadURL(localUrl),
      viewB.webContents.loadURL(localUrl)
    ]);

    // ----------------------------------------------------------------
    // 2. Cookie Partition Isolation
    // ----------------------------------------------------------------
    console.log('\n--- 2. Network Cookie Partition Isolation ---');
    await sessA.cookies.set({ url: localUrl, name: 'canary_cookie_a', value: 'secret-a' });
    
    const aCookies = await sessA.cookies.get({ url: localUrl });
    const bCookies = await sessB.cookies.get({ url: localUrl });
    
    if (aCookies.some(c => c.name === 'canary_cookie_a')) {
      logPass('COOKIE_ISOLATION', 'Session A successfully stored cookie');
      
      if (!bCookies.some(c => c.name === 'canary_cookie_a')) {
        logPass('COOKIE_ISOLATION', 'Session B cannot read Session A cookies', '0 cross-partition cookie leaks');
      } else {
        logFail('COOKIE_ISOLATION', 'Session B read Session A cookie!', new Error('Partition leakage detected'));
      }
    } else {
      logFail('COOKIE_ISOLATION', 'Session A failed to store cookie', new Error('Cookie missing'));
    }

    // ----------------------------------------------------------------
    // 3. DOM localStorage Partition Isolation
    // ----------------------------------------------------------------
    console.log('\n--- 3. DOM localStorage Partition Isolation ---');
    await viewA.webContents.executeJavaScript('localStorage.setItem("canary_lstore_a", "secret-lstore-a"); true;');
    const valA = await viewA.webContents.executeJavaScript('localStorage.getItem("canary_lstore_a");');
    const valB = await viewB.webContents.executeJavaScript('localStorage.getItem("canary_lstore_a");');

    if (valA === 'secret-lstore-a' && valB === null) {
      logPass('DOM_STORAGE_ISOLATION', 'localStorage strictly isolated to Session A partition', 'Session B returned null');
    } else {
      logFail('DOM_STORAGE_ISOLATION', 'localStorage leakage detected', new Error(`Got: ${valB}`));
    }

    // ----------------------------------------------------------------
    // 4. Teardown Lifecycle Verification
    // ----------------------------------------------------------------
    console.log('\n--- 4. Session Teardown Lifecycle (clearStorageData & clearCache) ---');
    await sessA.clearStorageData();
    await sessA.clearCache();
    
    const postClearCookies = await sessA.cookies.get({ url: localUrl });
    if (postClearCookies.length === 0) {
      logPass('SESSION_DESTRUCTION', 'clearStorageData() successfully purged all cookies from partition');
    } else {
      logFail('SESSION_DESTRUCTION', 'Cookies persisted after clearStorageData()', new Error(`Count: ${postClearCookies.length}`));
    }
    
    // Destroy views
    mainWindow.contentView.removeChildView(viewA);
    mainWindow.contentView.removeChildView(viewB);
    viewA.webContents.close();
    viewB.webContents.close();
    mainWindow.close();
    
  } catch (err) {
    console.error('Test suite error:', err);
  } finally {
    if (server) server.close();
  }

  console.log('\n================================================================');
  console.log('  LIVE ELECTRON INTEGRATION TEST SUITE SUMMARY');
  console.log('================================================================');
  console.log(`  [PASS]    PASSED  : ${passedCount}`);
  console.log(`  [FAIL]    FAILED  : ${failedCount}`);
  console.log(`  [SKIPPED] SKIPPED : ${skippedCount}`);
  console.log(`  TOTAL TESTED      : ${passedCount + failedCount + skippedCount}`);
  console.log('================================================================\n');

  setTimeout(() => app.exit(failedCount > 0 ? 1 : 0), 100);
}

app.whenReady().then(runLiveTests).catch((err) => {
  console.error('[Fatal Electron Harness Error]:', err);
  app.exit(1);
});
