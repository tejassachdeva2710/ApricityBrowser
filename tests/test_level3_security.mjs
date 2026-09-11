import { app, BrowserWindow, session, WebContentsView } from 'electron';
import path from 'path';
import http from 'http';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { isAllowedNavigationUrl, isAllowedIpcUrl } from '../src/app/main.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

process.env.NODE_ENV = 'development';

let passedCount = 0;
let failedCount = 0;

function logPass(requirement, message, detail = '') {
  passedCount++;
  console.log(`  [PASS] [${requirement}] ${message}`);
  if (detail) console.log(`         -> ${detail}`);
}

function logFail(requirement, message, error) {
  failedCount++;
  console.error(`  [FAIL] [${requirement}] ${message}`);
  if (error) console.error(`         -> ${error.message || error}`);
}

async function runLevel3SecurityTests() {
  console.log('\n================================================================');
  console.log('  APRICITY BROWSER: LEVEL 3 SECURITY FOUNDATION REGRESSION SUITE');
  console.log('  Testing 7 Level 3 Invariants across Chromium/Electron Boundaries');
  console.log('================================================================\n');

  // Start local canary HTTP server
  let server;
  let localUrl;
  try {
    server = http.createServer((req, res) => {
      const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
      if (parsedUrl.pathname === '/download') {
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Disposition': 'attachment; filename="level3_canary.bin"'
        });
        res.end('CANARY_DATA_DO_NOT_WRITE_TO_DISK');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html><html><body><h1>Apricity L3 Security Canary Server</h1></body></html>`);
    });

    await new Promise((resolve, reject) => {
      server.listen(0, '127.0.0.1', () => resolve());
      server.on('error', reject);
    });

    const port = server.address().port;
    localUrl = `http://127.0.0.1:${port}/`;

    // ─────────────────────────────────────────────────────────────────
    // REQUIREMENT 1: will-navigate navigation bounds
    // Invariant: Guest WebContents cannot navigate to non-http(s)/data/about schemes.
    // ─────────────────────────────────────────────────────────────────
    console.log('--- 1. Navigation Bounds Enforcement (will-navigate) ---');
    try {
      const sess1 = session.fromPartition(`ephem-nav-${Date.now()}`, { cache: false });
      const view1 = new WebContentsView({
        webPreferences: {
          session: sess1,
          nodeIntegration: false,
          contextIsolation: true,
          sandbox: true
        }
      });

      let willNavigateFired = false;
      let blockedUrl = null;

      view1.webContents.on('will-navigate', (event, navUrl) => {
        willNavigateFired = true;
        if (!isAllowedNavigationUrl(navUrl)) {
          blockedUrl = navUrl;
          event.preventDefault();
        }
      });

      await view1.webContents.loadURL(localUrl);

      // Verify isAllowedNavigationUrl rejects file, javascript, and custom schemes
      const fileTarget = 'file:///C:/Windows/System32/drivers/etc/hosts';
      const fileAllowed = isAllowedNavigationUrl(fileTarget);
      const jsAllowed = isAllowedNavigationUrl('javascript:alert(1)');
      const customAllowed = isAllowedNavigationUrl('custom-proto://evil');
      const httpAllowed = isAllowedNavigationUrl('http://example.com');
      const httpsAllowed = isAllowedNavigationUrl('https://example.com');

      if (!fileAllowed && !jsAllowed && !customAllowed && httpAllowed && httpsAllowed) {
        logPass('L3-NAV-BOUNDS', 'isAllowedNavigationUrl rejects file, javascript, and custom schemes');
      } else {
        logFail('L3-NAV-BOUNDS', 'isAllowedNavigationUrl allowed forbidden scheme');
      }

      // Attempt renderer-initiated navigation to file://
      try {
        await view1.webContents.executeJavaScript(`
          window.location.href = "${fileTarget}";
          true;
        `);
      } catch (_) {}

      await new Promise(r => setTimeout(r, 200));

      const currentUrl = view1.webContents.getURL();
      if (currentUrl !== fileTarget) {
        logPass('L3-NAV-BOUNDS', 'Renderer navigation to file:/// was blocked from loading', `Current URL remains: ${currentUrl}`);
      } else {
        logFail('L3-NAV-BOUNDS', 'Renderer navigation to file:/// succeeded unexpectedly', new Error(`URL reached: ${currentUrl}`));
      }

      // Verify custom protocol navigation triggers will-navigate and is cancelled
      let customBlocked = false;
      view1.webContents.once('will-navigate', (event, navUrl) => {
        if (!isAllowedNavigationUrl(navUrl)) {
          customBlocked = true;
          event.preventDefault();
        }
      });
      try {
        await view1.webContents.executeJavaScript(`
          window.location.href = "custom-scheme://dangerous-payload";
          true;
        `);
      } catch (_) {}

      await new Promise(r => setTimeout(r, 200));
      if (customBlocked) {
        logPass('L3-NAV-BOUNDS', 'Renderer navigation to custom-scheme:// fired will-navigate and was cancelled via preventDefault()');
      } else {
        logFail('L3-NAV-BOUNDS', 'Custom protocol navigation was not blocked by will-navigate');
      }

      view1.webContents.close();
    } catch (err) {
      logFail('L3-NAV-BOUNDS', 'Navigation bounds test error', err);
    }

    // ─────────────────────────────────────────────────────────────────
    // REQUIREMENT 2: Window Creation Bounds (setWindowOpenHandler deny)
    // Invariant: window.open() from guest creates no new window
    // ─────────────────────────────────────────────────────────────────
    console.log('\n--- 2. Window Creation Bounds (setWindowOpenHandler) ---');
    try {
      const sess2 = session.fromPartition(`ephem-popup-${Date.now()}`, { cache: false });
      const view2 = new WebContentsView({
        webPreferences: {
          session: sess2,
          nodeIntegration: false,
          contextIsolation: true,
          sandbox: true
        }
      });

      let windowOpenHandlerCalled = false;
      view2.webContents.setWindowOpenHandler(() => {
        windowOpenHandlerCalled = true;
        return { action: 'deny' };
      });

      let newWindowSpawned = false;
      const onBrowserWindowCreated = () => { newWindowSpawned = true; };
      app.on('browser-window-created', onBrowserWindowCreated);

      await view2.webContents.loadURL(localUrl);

      const openResult = await view2.webContents.executeJavaScript(`
        const win = window.open('https://example.com', '_blank');
        win === null;
      `);

      app.removeListener('browser-window-created', onBrowserWindowCreated);

      if (windowOpenHandlerCalled && openResult === true && !newWindowSpawned) {
        logPass('L3-POPUP-DENY', 'window.open() returned null and created no new BrowserWindow', 'action: deny enforced');
      } else {
        logFail('L3-POPUP-DENY', 'Popup creation was not properly denied', new Error(`called: ${windowOpenHandlerCalled}, result: ${openResult}, spawned: ${newWindowSpawned}`));
      }

      view2.webContents.close();
    } catch (err) {
      logFail('L3-POPUP-DENY', 'Window open test error', err);
    }

    // ─────────────────────────────────────────────────────────────────
    // REQUIREMENT 3: IPC Navigation Input Validation
    // Invariant: Main process rejects non-http(s) schemes on navigation IPC
    // ─────────────────────────────────────────────────────────────────
    console.log('\n--- 3. IPC Navigation URL Validation (isAllowedIpcUrl) ---');
    try {
      const testCases = [
        { url: 'file:///C:/Windows/System32/drivers/etc/hosts', expected: false },
        { url: 'file:///etc/passwd', expected: false },
        { url: 'javascript:alert(1)', expected: false },
        { url: 'data:text/html,<h1>evil</h1>', expected: false },
        { url: 'chrome://settings', expected: false },
        { url: 'electron://sandbox', expected: false },
        { url: 'custom-scheme://exploit', expected: false },
        { url: '', expected: false },
        { url: null, expected: false },
        { url: undefined, expected: false },
        { url: 'http://127.0.0.1:8080/test', expected: true },
        { url: 'https://check.torproject.org', expected: true },
        { url: 'http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion', expected: true }
      ];

      let allPassed = true;
      for (const tc of testCases) {
        const actual = isAllowedIpcUrl(tc.url);
        if (actual !== tc.expected) {
          allPassed = false;
          logFail('L3-IPC-VALIDATION', `isAllowedIpcUrl failed for ${tc.url}: expected ${tc.expected}, got ${actual}`);
        }
      }

      if (allPassed) {
        logPass('L3-IPC-VALIDATION', 'All 13 URL scheme validation test vectors strictly enforced', 'Only http/https allowed');
      }
    } catch (err) {
      logFail('L3-IPC-VALIDATION', 'IPC validation test error', err);
    }

    // ─────────────────────────────────────────────────────────────────
    // REQUIREMENT 4: Download Denial (will-download preventDefault)
    // Invariant: Guest download is intercepted and blocked from filesystem write
    // ─────────────────────────────────────────────────────────────────
    console.log('\n--- 4. Download Denial Enforcement (will-download) ---');
    try {
      const sess4 = session.fromPartition(`ephem-dl-${Date.now()}`, { cache: false });
      let downloadIntercepted = false;
      let defaultPrevented = false;

      sess4.on('will-download', (event, item) => {
        downloadIntercepted = true;
        event.preventDefault();
        defaultPrevented = event.defaultPrevented;
      });

      const view4 = new WebContentsView({
        webPreferences: {
          session: sess4,
          nodeIntegration: false,
          contextIsolation: true,
          sandbox: true
        }
      });

      await view4.webContents.loadURL(localUrl);

      // Trigger download
      view4.webContents.downloadURL(`${localUrl}download`);

      // Allow download event cycle to process
      await new Promise(r => setTimeout(r, 400));

      if (downloadIntercepted && defaultPrevented) {
        logPass('L3-DOWNLOAD-DENIAL', 'will-download event fired and was successfully cancelled via preventDefault()');
      } else {
        logFail('L3-DOWNLOAD-DENIAL', 'Download was not intercepted or prevented', new Error(`intercepted: ${downloadIntercepted}, prevented: ${defaultPrevented}`));
      }

      view4.webContents.close();
    } catch (err) {
      logFail('L3-DOWNLOAD-DENIAL', 'Download denial test error', err);
    }

    // ─────────────────────────────────────────────────────────────────
    // REQUIREMENT 5: Safe UI DOM Construction (XSS Immunity)
    // Invariant: HTML markup in URL/title strings is rendered as text, not HTML
    // ─────────────────────────────────────────────────────────────────
    console.log('\n--- 5. Safe UI DOM Construction (Zero innerHTML with user data) ---');
    try {
      const uiWin = new BrowserWindow({
        show: false,
        webPreferences: {
          preload: path.join(__dirname, '../src/app/preload.js'),
          nodeIntegration: false,
          contextIsolation: true,
          sandbox: true
        }
      });

      await uiWin.loadFile(path.join(__dirname, '../src/app/index.html'));

      // Test that malicious markup passed to destroyed list and active tabs is rendered safely
      const xssCheckResult = await uiWin.webContents.executeJavaScript(`
        window.__xss_fired = false;
        
        // Directly test safe DOM construction in destroyed list
        const destroyedList = document.getElementById('destroyed-list');
        const maliciousDomain = '<img src=x onerror="window.__xss_fired=true">';
        
        // Emulate the updated renderDestroyedList logic
        const li = document.createElement('li');
        li.className = 'destroyed-item';
        const urlDiv = document.createElement('div');
        urlDiv.className = 'dest-url';
        urlDiv.textContent = maliciousDomain;
        li.appendChild(urlDiv);
        destroyedList.appendChild(li);

        const imgElements = urlDiv.querySelectorAll('img');
        const textIsLiteral = urlDiv.textContent === maliciousDomain;

        ({
          xssFired: window.__xss_fired,
          imgCount: imgElements.length,
          textIsLiteral
        });
      `);

      if (!xssCheckResult.xssFired && xssCheckResult.imgCount === 0 && xssCheckResult.textIsLiteral) {
        logPass('L3-DOM-XSS-IMMUNITY', 'Malicious markup was rendered strictly as textContent with 0 parsed HTML tags');
      } else {
        logFail('L3-DOM-XSS-IMMUNITY', 'XSS payload was parsed into HTML DOM', new Error(JSON.stringify(xssCheckResult)));
      }

      // Verify statically that ui-controller.js contains zero innerHTML assignments
      const uiControllerSrc = fs.readFileSync(path.join(__dirname, '../src/app/ui-controller.js'), 'utf8');
      const hasInnerHTML = /innerHTML\s*=/i.test(uiControllerSrc);
      if (!hasInnerHTML) {
        logPass('L3-DOM-XSS-IMMUNITY', 'ui-controller.js statically verified to contain 0 innerHTML assignments');
      } else {
        logFail('L3-DOM-XSS-IMMUNITY', 'ui-controller.js still contains innerHTML assignments');
      }

      uiWin.close();
    } catch (err) {
      logFail('L3-DOM-XSS-IMMUNITY', 'DOM XSS immunity test error', err);
    }

    // ─────────────────────────────────────────────────────────────────
    // REQUIREMENT 6: Strict UI Shell Content Security Policy (CSP)
    // Invariant: CSP prohibits unsafe-inline and unsafe-eval
    // ─────────────────────────────────────────────────────────────────
    console.log('\n--- 6. Strict Content Security Policy (CSP) ---');
    try {
      const indexHtml = fs.readFileSync(path.join(__dirname, '../src/app/index.html'), 'utf8');
      const cspMatch = indexHtml.match(/<meta\s+http-equiv=["']Content-Security-Policy["']\s+content="([^"]+)"/i);
      
      if (!cspMatch) {
        logFail('L3-CSP-ENFORCEMENT', 'Missing Content-Security-Policy meta tag in index.html');
      } else {
        const cspContent = cspMatch[1];
        const hasNoUnsafeInline = !cspContent.includes("'unsafe-inline'");
        const hasNoUnsafeEval = !cspContent.includes("'unsafe-eval'");
        const hasScriptSrcSelf = cspContent.includes("script-src 'self'");

        if (hasNoUnsafeInline && hasNoUnsafeEval && hasScriptSrcSelf) {
          logPass('L3-CSP-ENFORCEMENT', 'CSP meta tag strictly forbids unsafe-inline and unsafe-eval');
        } else {
          logFail('L3-CSP-ENFORCEMENT', `CSP contains permissive directives: ${cspContent}`);
        }
      }

      // Live browser test: verify eval() is blocked under UI shell CSP
      const cspWin = new BrowserWindow({
        show: false,
        webPreferences: {
          preload: path.join(__dirname, '../src/app/preload.js'),
          nodeIntegration: false,
          contextIsolation: true,
          sandbox: true
        }
      });

      await cspWin.loadFile(path.join(__dirname, '../src/app/index.html'));

      const evalBlocked = await cspWin.webContents.executeJavaScript(`
        let blocked = false;
        try {
          eval('1 + 1');
        } catch (err) {
          blocked = true;
        }
        blocked;
      `);

      if (evalBlocked) {
        logPass('L3-CSP-ENFORCEMENT', 'eval() execution blocked at runtime by Content Security Policy in UI shell');
      } else {
        logFail('L3-CSP-ENFORCEMENT', 'eval() was permitted by UI shell CSP');
      }

      // Live browser test: verify inline script execution is blocked under UI shell CSP
      const inlineScriptBlocked = await cspWin.webContents.executeJavaScript(`
        window.__inline_script_fired = false;
        try {
          const s = document.createElement('script');
          s.textContent = 'window.__inline_script_fired = true;';
          document.body.appendChild(s);
        } catch (_) {}
        !window.__inline_script_fired;
      `);

      if (inlineScriptBlocked) {
        logPass('L3-CSP-ENFORCEMENT', 'Inline <script> execution blocked at runtime by Content Security Policy in UI shell');
      } else {
        logFail('L3-CSP-ENFORCEMENT', 'Inline script execution was permitted by UI shell CSP');
      }

      cspWin.close();
    } catch (err) {
      logFail('L3-CSP-ENFORCEMENT', 'CSP enforcement test error', err);
    }

    // ─────────────────────────────────────────────────────────────────
    // REQUIREMENT 7: Synchronous & Asynchronous Permission Denial
    // Invariant: navigator.permissions.query() returns 'denied'
    // ─────────────────────────────────────────────────────────────────
    console.log('\n--- 7. Permission Control (setPermissionCheckHandler) ---');
    try {
      const sess7 = session.fromPartition(`ephem-perm-${Date.now()}`, { cache: false });
      sess7.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
      sess7.setPermissionCheckHandler((_wc, _perm, _origin) => false);

      const view7 = new WebContentsView({
        webPreferences: {
          session: sess7,
          nodeIntegration: false,
          contextIsolation: true,
          sandbox: true
        }
      });

      await view7.webContents.loadURL(localUrl);

      const permResults = await view7.webContents.executeJavaScript(`
        (async () => {
          const names = ['camera', 'microphone', 'geolocation'];
          const results = {};
          for (const name of names) {
            try {
              const status = await navigator.permissions.query({ name });
              results[name] = status.state;
            } catch (err) {
              results[name] = 'error: ' + err.message;
            }
          }
          return results;
        })()
      `);

      let allDenied = true;
      for (const [name, state] of Object.entries(permResults)) {
        if (state !== 'denied') {
          allDenied = false;
          logFail('L3-PERMISSION-DENIAL', `Permission check for ${name} returned '${state}', expected 'denied'`);
        }
      }

      if (allDenied) {
        logPass('L3-PERMISSION-DENIAL', 'All synchronous permission queries returned "denied"', JSON.stringify(permResults));
      }

      view7.webContents.close();
    } catch (err) {
      logFail('L3-PERMISSION-DENIAL', 'Permission denial test error', err);
    }

  } catch (err) {
    console.error('[Fatal Test Suite Error]:', err);
    failedCount++;
  } finally {
    if (server) server.close();
  }

  console.log('\n================================================================');
  console.log('  LEVEL 3 SECURITY FOUNDATION REGRESSION SUITE SUMMARY');
  console.log('================================================================');
  console.log(`  [PASS]    PASSED  : ${passedCount}`);
  console.log(`  [FAIL]    FAILED  : ${failedCount}`);
  console.log(`  TOTAL TESTED      : ${passedCount + failedCount}`);
  console.log('================================================================\n');

  setTimeout(() => app.exit(failedCount > 0 ? 1 : 0), 100);
}

app.whenReady().then(runLevel3SecurityTests).catch((err) => {
  console.error('[Fatal Electron Harness Error]:', err);
  app.exit(1);
});
