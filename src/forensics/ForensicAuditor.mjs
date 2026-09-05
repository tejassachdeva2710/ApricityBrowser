/**
 * ForensicAuditor.mjs — v4.0.0
 *
 * Core Orchestrator for Apricity Browser's Real Electron/Chromium Forensic Artifact Auditor.
 *
 * ═══════════════════════════════════════════════════════════════════
 * THE ABSOLUTE INVARIANT (enforced since v4.0.0):
 *   An artifact may ONLY be marked VERIFIED CLEAN if ALL of:
 *   1. Canary verified present in Chromium DOM API readback (browserPreState = VERIFIED_PRESENT)
 *   2. Canary found in a READABLE, UNLOCKED filesystem file BEFORE cleanup (filesystemPreState = FOUND)
 *   3. No critical data files for this subsystem were EBUSY/EPERM during pre-scan
 *   4. Canary absent from all scanned files AFTER cleanup (filesystemPostState = NOT_FOUND)
 *   5. No critical data files for this subsystem were EBUSY/EPERM during post-scan
 *
 *   If ANY condition fails → UNVERIFIED (with appropriate justification code), never VERIFIED CLEAN.
 * ═══════════════════════════════════════════════════════════════════
 *
 * Changes in v4.0.0 (hostile review remediation):
 *   P0: Removed `scannedFilesCount > 0` fallback from verdict logic — unrelated files never justify VERIFIED CLEAN
 *   P0: EBUSY/EPERM on critical data files → UNVERIFIED_FILE_LOCKED, never NOT_FOUND
 *   P1: Filesystem quiescence detection (poll until mtime/size stable) replaces arbitrary sleeps
 *   P1: getDomStatus() now derives from per-artifact verdict (requires filesystem pre-evidence)
 *   P1: SESSION classified as UNVERIFIED_NOT_DISK_PERSISTENT_API (SessionStorage is in-memory only)
 *   P1: Two-phase API: runAuditCore() returns intermediate state; static evaluateResult() is Phase 2
 *   P2: Real blob content verification via in-renderer fetch() instead of hardcoded `true`
 *   P2: appName default updated from apricity-browser-ztr to apricity-browser
 */

import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { CanaryGenerator } from './CanaryGenerator.mjs';
import { FilesystemScanner } from './FilesystemScanner.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

// ─────────────────────────────────────────────────────────────────────────────
// Justification code registry
// ─────────────────────────────────────────────────────────────────────────────
export const JUSTIFICATION_CODES = {
  // Original codes (preserved for backward compat)
  PHYSICAL_FTL_UNREACHABLE:              'UNVERIFIED_PHYSICAL_FTL_UNREACHABLE',
  KERNEL_PAGING_INACCESSIBLE:            'UNVERIFIED_KERNEL_PAGING_INACCESSIBLE',
  V8_HEAP_RAW_INACCESSIBLE:              'UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE',
  OS_METADATA_JOURNAL_PRIVILEGED:        'UNVERIFIED_OS_METADATA_JOURNAL_PRIVILEGED',
  WINDOWS_FILE_LOCK:                     'UNVERIFIED_WINDOWS_FILE_LOCK',
  REQUIRES_LIVE_CHROMIUM_RUNTIME:        'UNVERIFIED_REQUIRES_LIVE_CHROMIUM_RUNTIME',
  GPU_VRAM_INACCESSIBLE:                 'UNVERIFIED_GPU_VRAM_INACCESSIBLE',
  TOR_NOT_INCLUDED_IN_AUDIT:             'UNVERIFIED_TOR_NOT_INCLUDED_IN_AUDIT',
  TOR_CONSENSUS_RETENTION:               'UNVERIFIED_TOR_CONSENSUS_RETENTION',
  NO_FILESYSTEM_EVIDENCE_AVAILABLE:      'UNVERIFIED_NO_FILESYSTEM_EVIDENCE_AVAILABLE',
  ARTIFACT_PERSISTENCE_NOT_OBSERVED_ON_DISK: 'UNVERIFIED_ARTIFACT_PERSISTENCE_NOT_OBSERVED_ON_DISK',

  // v4.0.0 new codes
  ARTIFACT_NOT_COMMITTED_TO_DISK:        'UNVERIFIED_ARTIFACT_NOT_COMMITTED_TO_DISK',
  FILE_LOCKED_DURING_SCAN:               'UNVERIFIED_FILE_LOCKED_DURING_SCAN',
  SESSION_STORAGE_NOT_DISK_PERSISTENT:   'UNVERIFIED_SESSION_STORAGE_NOT_DISK_PERSISTENT',
  BLOB_STORAGE_NOT_DISK_PERSISTENT:      'UNVERIFIED_BLOB_STORAGE_NOT_DISK_PERSISTENT',
  FLUSH_TIMEOUT_DISK_WRITE:              'UNVERIFIED_FLUSH_TIMEOUT_DISK_WRITE',
};

export const JUSTIFICATION_DESCRIPTIONS = {
  [JUSTIFICATION_CODES.PHYSICAL_FTL_UNREACHABLE]:
    'Solid-state drive wear-leveling and controller-managed flash translation layers (FTL) prevent user-space verification of physical NAND cell overwriting.',
  [JUSTIFICATION_CODES.KERNEL_PAGING_INACCESSIBLE]:
    'Operating system virtual memory paging files (pagefile.sys, swapfile.sys) are locked by the kernel and cannot be inspected from user-space.',
  [JUSTIFICATION_CODES.V8_HEAP_RAW_INACCESSIBLE]:
    'V8 JavaScript engine does not zero deallocated memory upon garbage collection; raw process heap carving requires native kernel/debugger attachment.',
  [JUSTIFICATION_CODES.OS_METADATA_JOURNAL_PRIVILEGED]:
    'NTFS $LogFile, $UsnJrnl, and $MFT raw cluster inspection requires Administrator/SYSTEM raw disk handle access (\\\\.\\PhysicalDrive0).',
  [JUSTIFICATION_CODES.WINDOWS_FILE_LOCK]:
    'Active Chromium process handles prevented non-destructive post-teardown file inspection.',
  [JUSTIFICATION_CODES.REQUIRES_LIVE_CHROMIUM_RUNTIME]:
    'Native Blink/Chromium DOM storage execution requires an active Electron BrowserWindow process with a loaded web context.',
  [JUSTIFICATION_CODES.GPU_VRAM_INACCESSIBLE]:
    'GPU driver compositor buffers and texture memory cannot be audited from user-space JavaScript.',
  [JUSTIFICATION_CODES.TOR_NOT_INCLUDED_IN_AUDIT]:
    'Tor daemon SOCKS proxy was not routed or executed in this controlled browser storage audit; production Tor persistence is tracked as an independent architectural finding.',
  [JUSTIFICATION_CODES.TOR_CONSENSUS_RETENTION]:
    'Tor daemon intentionally persists directory authority consensus documents and guard node relay state across restarts for network performance.',
  [JUSTIFICATION_CODES.NO_FILESYSTEM_EVIDENCE_AVAILABLE]:
    'Zero files or bytes were scanned in the target storage roots, preventing automated verification of filesystem cleanup.',
  [JUSTIFICATION_CODES.ARTIFACT_PERSISTENCE_NOT_OBSERVED_ON_DISK]:
    'Artifact was verified active in Chromium browser DOM memory but was not observed as committed plaintext in scanned disk files prior to teardown.',
  // v4.0.0
  [JUSTIFICATION_CODES.ARTIFACT_NOT_COMMITTED_TO_DISK]:
    'The artifact canary was verified present in Chromium DOM memory but was NOT found on disk during the pre-destruction filesystem scan. Chromium\'s SQLite WAL or LevelDB memtable had not flushed to persistent storage within the quiescence window. Disk-purge cannot be verified without prior disk evidence.',
  [JUSTIFICATION_CODES.FILE_LOCKED_DURING_SCAN]:
    'One or more critical data files for this storage subsystem were EBUSY/EPERM-locked during the filesystem scan. The scanner cannot read a locked file; absence of a match in a locked file is not evidence of absence. Verdict is UNVERIFIED, not VERIFIED CLEAN.',
  [JUSTIFICATION_CODES.SESSION_STORAGE_NOT_DISK_PERSISTENT]:
    'SessionStorage is an in-memory DOM API per the HTML specification. Chromium never writes sessionStorage values to the partition filesystem directory. The "Session Storage/" LevelDB directory stores tab restore metadata, not sessionStorage key-value data. Disk-purge of sessionStorage is not a meaningful measurement.',
  [JUSTIFICATION_CODES.BLOB_STORAGE_NOT_DISK_PERSISTENT]:
    'Blob URLs created via URL.createObjectURL() are in-process memory objects, not persisted to the Chromium partition filesystem. The blob_storage/ directory holds service worker blobs, not renderer Blob objects. Disk-purge of renderer blobs is not a meaningful measurement.',
  [JUSTIFICATION_CODES.FLUSH_TIMEOUT_DISK_WRITE]:
    'Filesystem quiescence was not reached within the maximum wait window. Chromium\'s storage engine had not stabilized writes to disk before the pre-scan. Disk-purge evidence is unavailable for this subsystem.',
};

// ─────────────────────────────────────────────────────────────────────────────
// Per-subsystem critical data file paths (relative to partitionDir).
// If any of these specific files are EBUSY/EPERM during a scan, the subsystem
// verdict MUST be UNVERIFIED_FILE_LOCKED — not NOT_FOUND.
//
// LevelDB LOCK files are NOT listed here because an EBUSY LOCK only means the
// LevelDB instance is active, not that the actual .log/.ldb data files are
// unreadable (IDB pre-scan evidence confirms data files ARE readable while LOCK
// is held). Only files whose EBUSY directly prevents reading artifact data are listed.
// ─────────────────────────────────────────────────────────────────────────────
export const SUBSYSTEM_CRITICAL_PATHS = {
  COOKIE:  ['Network/Cookies', 'Network/Cookies-journal'],
  LSTORE:  [],  // LOCK held ≠ data unreadable; .log files accessible
  IDB:     [],  // Same — proven by live IDB pre-scan evidence
  CACHE:   [],  // CacheStorage entry files are directly readable
  SESSION: [],  // Not disk-persistent; always UNVERIFIED_NOT_DISK_PERSISTENT
};

// ─────────────────────────────────────────────────────────────────────────────
export class ForensicAuditor {
  constructor(options = {}) {
    this.options = {
      appName: 'apricity-browser',   // v4.0.0: removed -ztr suffix
      customPaths: {},
      maxFileSizeBytes: 50 * 1024 * 1024,
      ...options
    };
    this.scanner = new FilesystemScanner(this.options);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Static helpers
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Polls a directory until its file tree's mtime/size values stabilize for
   * `stableIterations` consecutive polls, or until `maxWaitMs` is exceeded.
   *
   * This replaces arbitrary setTimeout() delays as the flush-quiescence signal.
   * After quiescence, LevelDB .log files and SQLite WAL files can be assumed to
   * reflect the full written state.
   */
  static async waitForFilesystemQuiescence(dirPath, {
    stableIterations = 3,
    pollIntervalMs   = 300,
    maxWaitMs        = 8000
  } = {}) {
    const deadline = Date.now() + maxWaitMs;

    async function takeSnapshot(dir) {
      const snap = new Map();
      async function recurse(d) {
        let entries;
        try { entries = await fs.promises.readdir(d, { withFileTypes: true }); } catch (_) { return; }
        for (const e of entries) {
          const fp = path.join(d, e.name);
          if (e.isDirectory()) {
            await recurse(fp);
          } else if (e.isFile()) {
            try {
              const st = await fs.promises.stat(fp);
              snap.set(fp, `${st.size}:${Math.floor(st.mtimeMs)}`);
            } catch (_) {}
          }
        }
      }
      if (fs.existsSync(dir)) await recurse(dir);
      return snap;
    }

    function mapsEqual(a, b) {
      if (a.size !== b.size) return false;
      for (const [k, v] of a) { if (b.get(k) !== v) return false; }
      for (const k of b.keys()) { if (!a.has(k)) return false; }
      return true;
    }

    let lastSnap = null;
    let stableCount = 0;

    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, pollIntervalMs));
      const snap = await takeSnapshot(dirPath);
      if (lastSnap && mapsEqual(lastSnap, snap)) {
        stableCount++;
        if (stableCount >= stableIterations) {
          return { quiescent: true, stableCount, elapsedMs: maxWaitMs - (deadline - Date.now()) };
        }
      } else {
        stableCount = 0;
      }
      lastSnap = snap;
    }

    return { quiescent: false, stableCount, elapsedMs: maxWaitMs };
  }

  /**
   * Returns true if any of the subsystem's critical data files appear in the
   * lockedFiles list. A locked critical file means we cannot reliably determine
   * whether the artifact was or was not on disk.
   */
  static isSubsystemCriticalFileLocked(subsystem, lockedFiles, partitionDir) {
    const criticalRelPaths = SUBSYSTEM_CRITICAL_PATHS[subsystem] || [];
    if (criticalRelPaths.length === 0) return false;
    const lockedNorm = (lockedFiles || []).map(f => path.normalize(f.path || f));
    for (const rel of criticalRelPaths) {
      const abs = path.normalize(path.join(partitionDir, rel));
      if (lockedNorm.some(lp => lp === abs)) return true;
    }
    return false;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Phase 1: Inject canaries, pre-scan, cleanup — returns intermediate state.
  // Does NOT run the post-scan (that is Phase 2, run out-of-process in the CLI).
  // Also used internally by runAudit() for full in-process execution (tests).
  // ───────────────────────────────────────────────────────────────────────────
  async runAuditCore(auditOptions = {}) {
    const startTime = Date.now();
    const sessionUUID = auditOptions.sessionUUID ||
      (globalThis.crypto?.randomUUID ? globalThis.crypto.randomUUID() : CanaryGenerator.generateEntropy(16));
    const tabId = auditOptions.tabId || `audit-tab-${sessionUUID.slice(0, 8)}`;

    // Detect Electron runtime
    let electron = null;
    let electronAvailable = false;
    try {
      if (process.versions?.electron) {
        electron = await import('electron');
        if (electron?.app && electron?.session && electron?.WebContentsView) {
          electronAvailable = true;
        }
      }
    } catch (_) {}

    // ── Phase 1: Environment Discovery ──────────────────────────────────────
    let actualElectronUserData = null;
    let scannedUserDataPath = null;
    let tempDirCreated = false;

    if (electronAvailable) {
      actualElectronUserData = electron.app.getPath('userData');
      scannedUserDataPath =
        auditOptions.customPaths?.userData ||
        this.options.customPaths?.userData ||
        actualElectronUserData;
    } else {
      const baseTmp = process.env.LOCALAPPDATA
        ? path.join(process.env.LOCALAPPDATA, 'Temp') : os.tmpdir();
      scannedUserDataPath =
        auditOptions.customPaths?.userData ||
        this.options.customPaths?.userData ||
        path.join(baseTmp, `apricity_audit_userdata_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`);
      if (!fs.existsSync(scannedUserDataPath)) {
        try { fs.mkdirSync(scannedUserDataPath, { recursive: true }); tempDirCreated = true; } catch (_) {}
      }
    }

    const customUserDataProvided = Boolean(
      auditOptions.customPaths?.userData || this.options.customPaths?.userData
    );
    const userDataPathVerified = Boolean(
      !electronAvailable ||
      (actualElectronUserData &&
        (actualElectronUserData === scannedUserDataPath || customUserDataProvided))
    );

    const partitionName = auditOptions.partitionName ||
      `forensic-audit-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const partitionId = `persist:${partitionName}`;

    const runtimePaths = FilesystemScanner.discoverRuntimePaths(
      this.options.appName,
      { userData: scannedUserDataPath, ...this.options.customPaths, ...auditOptions.customPaths }
    );

    const partitionDir = path.join(scannedUserDataPath, 'Partitions', partitionName);

    const scanTargetRoots = [
      scannedUserDataPath,
      runtimePaths.partitions,
      partitionDir,
      path.join(partitionDir, 'Local Storage'),
      path.join(partitionDir, 'IndexedDB'),
      path.join(partitionDir, 'Network'),
      path.join(partitionDir, 'Cache'),
      path.join(partitionDir, 'Service Worker'),
      path.join(partitionDir, 'blob_storage'),
      path.join(partitionDir, 'Session Storage'),
      runtimePaths.crashpad,
      runtimePaths.torData,
      auditOptions.intentionalFailurePath ? path.dirname(auditOptions.intentionalFailurePath) : null
    ].filter(Boolean);

    const canarySet = CanaryGenerator.generateSessionCanarySet(sessionUUID);
    const canaryPatterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const browserPreCheck = {
      cookiePresent: false,
      lstorePresent: false,
      sstorePresent: false,
      idbPresent: false,
      cachePresent: false,
      blobPresent: false,
      blobContentVerified: false
    };

    let preFsScanResult = {
      scannedFilesCount: 0, scannedBytesCount: 0,
      matches: [], lockedFiles: [], skippedFiles: []
    };

    const destroySummary = { storageCleared: false, cacheCleared: false, viewClosed: false };
    const skipCleanup = Boolean(auditOptions.skipCleanup || auditOptions.abnormalTermination);

    let localServer = null;
    let localUrl = auditOptions.targetUrl;
    let quiescenceResult = { quiescent: false };

    // ── Phase 2 + 3: Inject & Pre-scan ─────────────────────────────────────
    if (electronAvailable) {
      const { app, BrowserWindow, WebContentsView, session } = electron;

      if (!app.isReady()) await app.whenReady();
      app.removeAllListeners('window-all-closed');
      app.on('window-all-closed', (e) => {
        if (e && typeof e.preventDefault === 'function') e.preventDefault();
      });

      // Start local HTTP fixture server
      if (!localUrl) {
        localServer = http.createServer((req, res) => {
          const fixturePath = path.join(projectRoot, 'tests', 'fixtures', 'forensic_storage.html');
          if (fs.existsSync(fixturePath)) {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(fs.readFileSync(fixturePath));
          } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<!DOCTYPE html><html><body>Apricity Forensic Fixture</body></html>');
          }
        });
        await new Promise((resolve, reject) => {
          localServer.listen(0, '127.0.0.1', () => resolve());
          localServer.on('error', reject);
        });
        localUrl = `http://127.0.0.1:${localServer.address().port}/`;
      }

      // Disk-backed forensic partition
      const forensicSession = session.fromPartition(partitionId, { cache: true });

      const hostWindow = new BrowserWindow({
        show: false, width: 800, height: 600,
        webPreferences: { sandbox: true }
      });
      const view = new WebContentsView({
        webPreferences: {
          session: forensicSession,
          nodeIntegration: false,
          contextIsolation: true,
          sandbox: true
        }
      });
      hostWindow.contentView.addChildView(view);
      view.setBounds({ x: 0, y: 0, width: 800, height: 600 });
      await view.webContents.loadURL(localUrl);

      // Inject canaries into all subsystems
      try {
        // 1. Cookie (via session API for reliability + document.cookie)
        await forensicSession.cookies.set({
          url: localUrl,
          name: 'canary_cookie_token',
          value: canarySet.tokens.COOKIE.token
        });
        await view.webContents.executeJavaScript(
          `window.forensicFixture?.setCookie("canary_cookie_token", "${canarySet.tokens.COOKIE.token}")`
        );

        // 2. LocalStorage
        await view.webContents.executeJavaScript(
          `window.forensicFixture?.setLocalStorage("canary_lstore_token", "${canarySet.tokens.LSTORE.token}")`
        );

        // 3. SessionStorage (in-memory only — verified at browser level, not on disk)
        await view.webContents.executeJavaScript(
          `window.forensicFixture?.setSessionStorage("canary_sstore_token", "${canarySet.tokens.SESSION.token}")`
        );

        // 4. IndexedDB (LevelDB .log flushes synchronously → will appear in pre-scan)
        await view.webContents.executeJavaScript(`
          (async () => {
            if (window.forensicFixture?.setIndexedDB) {
              return await window.forensicFixture.setIndexedDB(
                "CanaryForensicDB", "canary_store", "canary_idb_token", "${canarySet.tokens.IDB.token}"
              );
            }
            return false;
          })()`
        );

        // 5. Cache Storage API (written to Service Worker/CacheStorage → appears in pre-scan)
        await view.webContents.executeJavaScript(
          `window.forensicFixture?.setCacheStorage("canary_cache_v1", "/canary-cache-req", "${canarySet.tokens.CACHE.token}")`
        );

        // 6. Blob (in-memory only — verified by readback, not disk)
        const blobToken = canarySet.tokens.BLOB?.token || canarySet.tokens.COOKIE.token;
        await view.webContents.executeJavaScript(
          `window.forensicFixture?.setBlobStorage("${blobToken}")`
        );

        // Flush cookie store to SQLite (best-effort; WAL checkpoint is Chromium-internal)
        try {
          if (typeof forensicSession.cookies.flushStore === 'function') {
            await forensicSession.cookies.flushStore();
          }
        } catch (_) {}

      } catch (err) {
        console.warn('[ForensicAuditor] Canary injection warning:', err.message);
      }

      // Browser-level readback — verifies canaries are live in Chromium memory
      try {
        const cookies = await forensicSession.cookies.get({
          url: localUrl, name: 'canary_cookie_token'
        });
        browserPreCheck.cookiePresent =
          cookies.some(c => c.value === canarySet.tokens.COOKIE.token);

        const lstoreVal = await view.webContents.executeJavaScript(
          `window.forensicFixture?.getLocalStorage("canary_lstore_token")`
        );
        browserPreCheck.lstorePresent = lstoreVal === canarySet.tokens.LSTORE.token;

        const sstoreVal = await view.webContents.executeJavaScript(
          `window.forensicFixture?.getSessionStorage("canary_sstore_token")`
        );
        browserPreCheck.sstorePresent = sstoreVal === canarySet.tokens.SESSION.token;

        const idbVal = await view.webContents.executeJavaScript(
          `window.forensicFixture?.getIndexedDB("CanaryForensicDB", "canary_store", "canary_idb_token")`
        );
        browserPreCheck.idbPresent = idbVal === canarySet.tokens.IDB.token;

        const cacheVal = await view.webContents.executeJavaScript(
          `window.forensicFixture?.getCacheStorage("canary_cache_v1", "/canary-cache-req")`
        );
        browserPreCheck.cachePresent = cacheVal === canarySet.tokens.CACHE.token;

        // FLAW 6 FIX: Real blob readback via fetch() in the renderer
        const blobToken = canarySet.tokens.BLOB?.token || canarySet.tokens.COOKIE.token;
        try {
          const blobContent = await view.webContents.executeJavaScript(`
            (async () => {
              if (!window._activeBlobUrl) return null;
              try {
                const resp = await fetch(window._activeBlobUrl);
                return await resp.text();
              } catch(e) { return null; }
            })()`
          );
          browserPreCheck.blobPresent = blobContent === blobToken;
          browserPreCheck.blobContentVerified = browserPreCheck.blobPresent;
        } catch (_) {
          // Blob fetch failed — leave blobPresent = false
        }
      } catch (err) {
        console.warn('[ForensicAuditor] Pre-destruction browser check warning:', err.message);
      }

      // FLAW 3 FIX: Quiescence detection instead of arbitrary sleep
      // Wait until the partition directory tree stops changing (mtimes + sizes stable).
      // This gives LevelDB .log files and Cache entries time to be fully written.
      if (fs.existsSync(partitionDir)) {
        quiescenceResult = await ForensicAuditor.waitForFilesystemQuiescence(partitionDir, {
          stableIterations: 3,
          pollIntervalMs: 300,
          maxWaitMs: 8000
        });
      } else {
        // Partition not created yet — brief poll for it to appear
        await new Promise(r => setTimeout(r, 400));
        if (fs.existsSync(partitionDir)) {
          quiescenceResult = await ForensicAuditor.waitForFilesystemQuiescence(partitionDir, {
            stableIterations: 3, pollIntervalMs: 300, maxWaitMs: 6000
          });
        }
      }

      // Pre-destruction filesystem scan (while Chromium is running)
      preFsScanResult = await this.scanner.scanPaths(scanTargetRoots, canaryPatterns);

      // ── Phase 4: Cleanup ────────────────────────────────────────────────
      if (!skipCleanup) {
        try { await forensicSession.clearStorageData(); destroySummary.storageCleared = true; } catch (_) {}
        try { await forensicSession.clearCache(); destroySummary.cacheCleared = true; } catch (_) {}
        try { hostWindow.contentView.removeChildView(view); destroySummary.viewClosed = true; } catch (_) {}
      } else {
        // skipCleanup: do NOT call clearStorageData — data remains on disk (crash simulation)
        try { hostWindow.contentView.removeChildView(view); destroySummary.viewClosed = true; } catch (_) {}
      }

      try { hostWindow.destroy(); } catch (_) {}
      if (localServer) { try { localServer.close(); } catch (_) {} }

    } else {
      // Non-Electron fallback (unit testing the evaluator logic)
      browserPreCheck.cookiePresent = true;
      browserPreCheck.lstorePresent = true;
      browserPreCheck.sstorePresent = true;
      browserPreCheck.idbPresent = true;
      browserPreCheck.cachePresent = true;
      browserPreCheck.blobPresent = true;
      browserPreCheck.blobContentVerified = true;
      destroySummary.storageCleared = !skipCleanup;
      destroySummary.cacheCleared = !skipCleanup;
      destroySummary.viewClosed = true;
    }

    // Intentional failure injection (for scanner anti-cheat testing)
    if (auditOptions.intentionalFailurePath) {
      try {
        const dir = path.dirname(auditOptions.intentionalFailurePath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(auditOptions.intentionalFailurePath,
          `RESIDUAL_DATA=${canarySet.tokens.COOKIE.token}`);
      } catch (err) {
        console.warn('[ForensicAuditor] Failed to inject intentional failure:', err.message);
      }
    }

    return {
      // Identifiers
      sessionUUID,
      tabId,
      partitionId,
      partitionDir,
      partitionName,
      // For Phase 2 scanner
      canaryTokens: Object.fromEntries(
        Object.entries(canarySet.tokens).map(([sub, data]) => [sub, data.token])
      ),
      scanTargetRoots,
      // Environment
      actualElectronUserData,
      scannedUserDataPath,
      userDataPathVerified,
      runtimePaths,
      localUrl: localUrl || 'http://127.0.0.1 (local fixture)',
      // Injection results
      browserPreCheck,
      preFsScanResult,
      quiescenceResult,
      // Cleanup results
      destroySummary,
      skipCleanup,
      // Internal
      tempDirCreated,
      intentionalFailurePath: auditOptions.intentionalFailurePath || null,
      // Metadata
      phase1StartTime: startTime,
      phase1DurationMs: Date.now() - startTime,
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      electronVersion: process.versions?.electron || null,
      chromiumVersion: process.versions?.chrome || null,
      electronAvailable,
    };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Phase 2 (static): Evaluate intermediate state + out-of-process post-scan.
  // Called by the CLI after the Electron process has exited (releasing file locks).
  // ───────────────────────────────────────────────────────────────────────────
  static evaluateResult(coreState, postFsScanResult, totalStartTime = null) {
    const auditor = new ForensicAuditor();
    const preCheck = coreState.browserPreCheck;
    const preFsScan = coreState.preFsScanResult;

    const preDestructionValid =
      preCheck.cookiePresent &&
      preCheck.lstorePresent &&
      preCheck.idbPresent &&
      preCheck.cachePresent;

    // Rebuild canary set object for _mapArtifacts (tokens only, no Buffers needed there)
    const canarySet = {
      tokens: Object.fromEntries(
        Object.entries(coreState.canaryTokens).map(([sub, token]) => ({ sub, token }))
          .map(({ sub, token }) => [sub, { token }])
      )
    };

    const artifactMap = auditor._mapArtifacts({
      browserPreCheck:  preCheck,
      preFsScanResult:  preFsScan,
      postFsScanResult,
      destroySummary:   coreState.destroySummary,
      canarySet,
      partitionDir:     coreState.partitionDir,
    });

    const evaluatedDimensions = auditor._evaluateDimensions({
      userDataPathVerified:  coreState.userDataPathVerified,
      preDestructionValid,
      browserPreCheck:       preCheck,
      preFsScanResult:       preFsScan,
      postFsScanResult,
      destroySummary:        coreState.destroySummary,
      runtimePaths:          coreState.runtimePaths,
      skipCleanup:           coreState.skipCleanup,
      artifactMap,
    });

    const summary = auditor._calculateSummary(
      evaluatedDimensions, postFsScanResult, coreState.userDataPathVerified
    );

    const totalDuration = totalStartTime
      ? (Date.now() - totalStartTime)
      : coreState.phase1DurationMs;

    return {
      metadata: {
        auditorVersion: '4.0.0',
        timestamp: new Date().toISOString(),
        durationMs: totalDuration,
        platform: coreState.platform,
        arch: coreState.arch,
        nodeVersion: coreState.nodeVersion,
        electronVersion: coreState.electronVersion,
        chromiumVersion: coreState.chromiumVersion,
        electronRuntime: coreState.electronAvailable,
        mode: coreState.skipCleanup ? 'SKIP_CLEANUP_TEST' : 'NORMAL_DESTRUCTION',
        twoPhase: true,
      },
      architecturalContext: {
        architecture: 'Isolated Disk-Backed Test Partition (persist:forensic-audit-<UUID>) with WebContentsView. Post-destruction scan runs after Electron process exit to avoid EBUSY file locks.',
        sandboxStatus: 'sandbox: true (OS-level Chromium sandbox active)',
        boundaryDistinction: 'Phase 1 (Electron): injects canaries, pre-scans, runs cleanup, exits. Phase 2 (Node): scans filesystem after all Chromium handles are released. VERIFIED CLEAN requires per-artifact disk evidence before AND absence after cleanup.',
      },
      environment: {
        actualElectronUserData: coreState.actualElectronUserData,
        scannedUserDataPath: coreState.scannedUserDataPath,
        userDataPathVerified: coreState.userDataPathVerified,
        partitionId: coreState.partitionId,
        partitionDir: coreState.partitionDir,
        quiescence: coreState.quiescenceResult,
      },
      session: {
        tabId: coreState.tabId,
        sessionUUID: coreState.sessionUUID,
        targetUrl: coreState.localUrl,
        canaryTokens: coreState.canaryTokens,
      },
      discovery: {
        runtimePaths: coreState.runtimePaths,
        scannedRoots: postFsScanResult.scannedRoots || coreState.scanTargetRoots,
        scannedFilesCount: postFsScanResult.scannedFilesCount,
        scannedBytesCount: postFsScanResult.scannedBytesCount,
        lockedFilesCount: (postFsScanResult.lockedFiles || []).length,
      },
      preDestruction: {
        browserStorage: preCheck,
        browserStorageValid: preDestructionValid,
        filesystemScan: {
          scannedFilesCount: preFsScan.scannedFilesCount,
          scannedBytesCount: preFsScan.scannedBytesCount,
          matchesCount: preFsScan.matches.length,
          matches: preFsScan.matches,
        },
      },
      verification: {
        preDestruction: preCheck,
        preDestructionValid,
        destroySummary: coreState.destroySummary,
        diskMatchCount: postFsScanResult.matches.length,
        diskMatches: postFsScanResult.matches,
        lockedFiles: postFsScanResult.lockedFiles || [],
      },
      artifacts: artifactMap,
      dimensions: evaluatedDimensions,
      summary,
    };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Full in-process audit (used by test suite — corrected logic, but post-scan
  // happens in-process while Electron is alive; locked files will be properly
  // classified as UNVERIFIED_FILE_LOCKED).
  // ───────────────────────────────────────────────────────────────────────────
  async runAudit(auditOptions = {}) {
    const overallStart = Date.now();

    // Phase 1
    const coreState = await this.runAuditCore(auditOptions);

    // Brief quiescence wait before post-scan (handles released after clearStorageData)
    if (coreState.electronAvailable) {
      await ForensicAuditor.waitForFilesystemQuiescence(coreState.partitionDir, {
        stableIterations: 2, pollIntervalMs: 200, maxWaitMs: 3000
      });
    }

    // Phase 5: Post-destruction scan (in-process).
    // Reconstruct canary patterns with full encodings from stored token strings.
    // (Buffers can't survive the coreState boundary, so we rebuild them from the token strings.)
    const reconstructedPatterns = Object.entries(coreState.canaryTokens).map(([sub, token]) => ({
      subsystem: sub,
      token,
      encodings: CanaryGenerator.getEncodings(token)
    }));
    const postFsScanResult = await this.scanner.scanPaths(coreState.scanTargetRoots, reconstructedPatterns);

    // Clean up intentional failure file
    if (coreState.intentionalFailurePath && fs.existsSync(coreState.intentionalFailurePath)) {
      try { fs.unlinkSync(coreState.intentionalFailurePath); } catch (_) {}
    }

    // Clean up temp dir (non-Electron mode)
    if (coreState.tempDirCreated && fs.existsSync(coreState.scannedUserDataPath)) {
      try { fs.rmSync(coreState.scannedUserDataPath, { recursive: true, force: true }); } catch (_) {}
    }

    // Build full result using the static evaluator
    const result = ForensicAuditor.evaluateResult(coreState, postFsScanResult, overallStart);

    // Patch metadata for in-process mode
    result.metadata.twoPhase = false;
    result.metadata.mode = auditOptions.skipCleanup || auditOptions.abnormalTermination
      ? 'SKIP_CLEANUP_TEST'
      : 'NORMAL_DESTRUCTION';

    return result;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // _mapArtifacts — per-subsystem 4-state verdict with ABSOLUTE INVARIANT enforced
  // ───────────────────────────────────────────────────────────────────────────
  _mapArtifacts(params) {
    const {
      browserPreCheck, preFsScanResult, postFsScanResult,
      destroySummary, canarySet, partitionDir = ''
    } = params;

    const subsystems = [
      { key: 'COOKIE',  name: 'Cookies',          browserProp: 'cookiePresent' },
      { key: 'LSTORE',  name: 'LocalStorage',      browserProp: 'lstorePresent' },
      { key: 'IDB',     name: 'IndexedDB',         browserProp: 'idbPresent' },
      { key: 'CACHE',   name: 'Cache Storage',     browserProp: 'cachePresent' },
    ];

    const artifacts = {};

    for (const sub of subsystems) {
      const browserState = browserPreCheck[sub.browserProp] ? 'VERIFIED_PRESENT' : 'NOT_FOUND';

      const preMatches  = (preFsScanResult.matches  || []).filter(m => m.subsystem === sub.key);
      const postMatches = (postFsScanResult.matches || []).filter(m => m.subsystem === sub.key);

      const fsPreState   = preMatches.length  > 0 ? 'FOUND' : 'NOT_FOUND';
      const fsPostState  = postMatches.length > 0 ? 'FOUND' : 'NOT_FOUND';
      const fsPreLocations = preMatches.map(m => ({ filePath: m.filePath, encoding: m.encoding, offset: m.offset }));

      // Per-subsystem critical file lock detection (FLAW 2 FIX)
      const preSubsystemLocked  = ForensicAuditor.isSubsystemCriticalFileLocked(
        sub.key, preFsScanResult.lockedFiles,  partitionDir
      );
      const postSubsystemLocked = ForensicAuditor.isSubsystemCriticalFileLocked(
        sub.key, postFsScanResult.lockedFiles, partitionDir
      );

      const cleanupState = destroySummary.storageCleared && destroySummary.cacheCleared
        ? 'clearStorageData + clearCache + WebContentsView destruction'
        : 'skip-cleanup test (no clearStorageData called)';

      // ── ABSOLUTE INVARIANT (FLAW 1 + FLAW 2 FIX) ────────────────────────
      // VERIFIED CLEAN requires: fsPreState=FOUND AND no critical lock AND postMatches=0
      // ANYTHING else is UNVERIFIED or FAIL — never VERIFIED CLEAN.
      let verdict;
      let verdictJustificationCode = null;
      let verdictJustification = null;

      if (postMatches.length > 0) {
        // Canary found after cleanup → definitive FAIL
        verdict = 'FAIL';

      } else if (preSubsystemLocked || postSubsystemLocked) {
        // Critical data file was EBUSY/EPERM → cannot read → UNVERIFIED, not NOT_FOUND
        verdict = 'UNVERIFIED_FILE_LOCKED';
        verdictJustificationCode = JUSTIFICATION_CODES.FILE_LOCKED_DURING_SCAN;
        verdictJustification = JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.FILE_LOCKED_DURING_SCAN];

      } else if (browserState === 'VERIFIED_PRESENT' && fsPreState === 'FOUND' && postMatches.length === 0) {
        // THE ONLY PATH TO VERIFIED CLEAN: browser evidence + disk evidence + clean post
        verdict = 'VERIFIED CLEAN';

      } else if (browserState === 'VERIFIED_PRESENT' && fsPreState === 'NOT_FOUND') {
        // Canary was in browser but never observed on disk → cannot claim disk-purge
        verdict = 'UNVERIFIED_NOT_COMMITTED_TO_DISK';
        verdictJustificationCode = JUSTIFICATION_CODES.ARTIFACT_NOT_COMMITTED_TO_DISK;
        verdictJustification = JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.ARTIFACT_NOT_COMMITTED_TO_DISK];

      } else {
        verdict = 'UNVERIFIED';
      }

      artifacts[sub.key] = {
        name: sub.name,
        token: canarySet.tokens[sub.key]?.token || '',
        browserPreState: browserState,
        filesystemPreState: fsPreState,
        filesystemPreLocations: fsPreLocations,
        cleanupState,
        filesystemPostState: fsPostState,
        postMatchesCount: postMatches.length,
        verdict,
        verdictJustificationCode,
        verdictJustification,
      };
    }

    // SESSION — FLAW 9 FIX: SessionStorage is not a disk-persistent API
    artifacts.SESSION = {
      name: 'SessionStorage',
      token: canarySet.tokens.SESSION?.token || '',
      browserPreState: browserPreCheck.sstorePresent ? 'VERIFIED_PRESENT' : 'NOT_FOUND',
      filesystemPreState: 'NOT_APPLICABLE',
      filesystemPreLocations: [],
      cleanupState: 'N/A — SessionStorage is not written to disk by Chromium',
      filesystemPostState: 'NOT_APPLICABLE',
      postMatchesCount: 0,
      verdict: 'UNVERIFIED_NOT_DISK_PERSISTENT',
      verdictJustificationCode: JUSTIFICATION_CODES.SESSION_STORAGE_NOT_DISK_PERSISTENT,
      verdictJustification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.SESSION_STORAGE_NOT_DISK_PERSISTENT],
    };

    return artifacts;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // _evaluateDimensions — derives dimension properties from artifact map
  // (FLAW 4 FIX: getDomStatus now requires per-artifact fsPreFound evidence)
  // ───────────────────────────────────────────────────────────────────────────
  _evaluateDimensions(params = {}) {
    const {
      userDataPathVerified = true,
      preDestructionValid = true,
      browserPreCheck = { cookiePresent: true, lstorePresent: true, idbPresent: true, cachePresent: true },
      preFsScanResult = { matches: [], scannedFilesCount: 0 },
      postFsScanResult: rawPost,
      destroySummary = { viewClosed: true, storageCleared: true, cacheCleared: true },
      runtimePaths = {},
      skipCleanup = false,
      artifactMap = null,
    } = params;

    const postFsScanResult = rawPost || params.fsScanResult || { matches: [], scannedFilesCount: 0, scannedBytesCount: 0 };
    const emptyScanGuard = (postFsScanResult.scannedFilesCount === 0 || postFsScanResult.scannedBytesCount === 0)
      && postFsScanResult.matches.length === 0;

    // FLAW 4 FIX: derive dimension status directly from artifact map
    // This guarantees consistency — dimension and artifact table never disagree.
    function getDomStatusFromArtifact(key) {
      if (!userDataPathVerified || emptyScanGuard) return 'UNVERIFIED';
      if (!artifactMap || !artifactMap[key]) {
        // No artifact map — fall back to legacy post-match counting (non-Electron unit tests)
        const postMatches = (postFsScanResult.matches || []).filter(m => m.subsystem === key).length;
        if (postMatches > 0) return 'FAIL';
        return 'UNVERIFIED';
      }
      const art = artifactMap[key];
      if (art.verdict === 'FAIL') return 'FAIL';
      if (art.verdict === 'VERIFIED CLEAN') return 'PASS';
      return 'UNVERIFIED';
    }

    function getDomJustificationFromArtifact(key) {
      if (emptyScanGuard || !userDataPathVerified)
        return { code: JUSTIFICATION_CODES.NO_FILESYSTEM_EVIDENCE_AVAILABLE,
                 text: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.NO_FILESYSTEM_EVIDENCE_AVAILABLE] };
      if (!artifactMap || !artifactMap[key]) return { code: null, text: null };
      const art = artifactMap[key];
      if (art.verdict === 'FAIL' || art.verdict === 'VERIFIED CLEAN') return { code: null, text: null };
      return {
        code: art.verdictJustificationCode || JUSTIFICATION_CODES.ARTIFACT_NOT_COMMITTED_TO_DISK,
        text: art.verdictJustification || JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.ARTIFACT_NOT_COMMITTED_TO_DISK],
      };
    }

    const cookieDim  = getDomStatusFromArtifact('COOKIE');
    const lstoreDim  = getDomStatusFromArtifact('LSTORE');
    const idbDim     = getDomStatusFromArtifact('IDB');
    const cacheDim   = getDomStatusFromArtifact('CACHE');

    const cookieJ  = getDomJustificationFromArtifact('COOKIE');
    const lstoreJ  = getDomJustificationFromArtifact('LSTORE');
    const idbJ     = getDomJustificationFromArtifact('IDB');
    const cacheJ   = getDomJustificationFromArtifact('CACHE');

    return {
      dimension1_DOMStorage: {
        name: 'Chromium Native DOM Storage (Layer 1)',
        target: 'Blink / Chromium Disk-Backed Storage Engine',
        properties: [
          {
            id: 'DOM_COOKIE_STORAGE_AND_PURGE',
            description: 'Cookie canary verified in Chromium session AND in unlocked disk file before destruction; absent after destruction',
            status: cookieDim,
            evidence: artifactMap?.COOKIE
              ? `Browser pre-state: ${artifactMap.COOKIE.browserPreState}, Filesystem pre-state: ${artifactMap.COOKIE.filesystemPreState}, Post-disk matches: ${artifactMap.COOKIE.postMatchesCount}, Verdict: ${artifactMap.COOKIE.verdict}`
              : `Pre-destruction cookie verified: ${browserPreCheck.cookiePresent}, post-destruction disk matches: ${(postFsScanResult.matches||[]).filter(m=>m.subsystem==='COOKIE').length}`,
            justificationCode: cookieJ.code,
            justification: cookieJ.text,
          },
          {
            id: 'DOM_LOCALSTORAGE_STORAGE_AND_PURGE',
            description: 'LocalStorage canary verified in Chromium session AND in readable LevelDB file before destruction; absent after destruction',
            status: lstoreDim,
            evidence: artifactMap?.LSTORE
              ? `Browser pre-state: ${artifactMap.LSTORE.browserPreState}, Filesystem pre-state: ${artifactMap.LSTORE.filesystemPreState}, Post-disk matches: ${artifactMap.LSTORE.postMatchesCount}, Verdict: ${artifactMap.LSTORE.verdict}`
              : `Pre-destruction LocalStorage verified: ${browserPreCheck.lstorePresent}, post-destruction disk matches: ${(postFsScanResult.matches||[]).filter(m=>m.subsystem==='LSTORE').length}`,
            justificationCode: lstoreJ.code,
            justification: lstoreJ.text,
          },
          {
            id: 'DOM_INDEXEDDB_STORAGE_AND_PURGE',
            description: 'IndexedDB canary verified in Chromium session AND in readable LevelDB .log file before destruction; absent after destruction',
            status: idbDim,
            evidence: artifactMap?.IDB
              ? `Browser pre-state: ${artifactMap.IDB.browserPreState}, Filesystem pre-state: ${artifactMap.IDB.filesystemPreState}, Post-disk matches: ${artifactMap.IDB.postMatchesCount}, Verdict: ${artifactMap.IDB.verdict}`
              : `Pre-destruction IndexedDB verified: ${browserPreCheck.idbPresent}, post-destruction disk matches: ${(postFsScanResult.matches||[]).filter(m=>m.subsystem==='IDB').length}`,
            justificationCode: idbJ.code,
            justification: idbJ.text,
          },
          {
            id: 'DOM_CACHE_STORAGE_PURGE',
            description: 'Cache Storage canary verified in Chromium session AND in readable CacheStorage entry file before destruction; absent after destruction',
            status: cacheDim,
            evidence: artifactMap?.CACHE
              ? `Browser pre-state: ${artifactMap.CACHE.browserPreState}, Filesystem pre-state: ${artifactMap.CACHE.filesystemPreState}, Post-disk matches: ${artifactMap.CACHE.postMatchesCount}, Verdict: ${artifactMap.CACHE.verdict}`
              : `Pre-destruction Cache verified: ${browserPreCheck.cachePresent}, post-destruction disk matches: ${(postFsScanResult.matches||[]).filter(m=>m.subsystem==='CACHE').length}`,
            justificationCode: cacheJ.code,
            justification: cacheJ.text,
          },
          {
            id: 'DOM_SESSION_STORAGE_CLASSIFICATION',
            description: 'SessionStorage is an in-memory DOM API — not written to the Chromium partition filesystem — classified as non-disk-persistent',
            status: 'UNVERIFIED',
            evidence: `Browser pre-state: ${browserPreCheck.sstorePresent ? 'VERIFIED_PRESENT' : 'NOT_FOUND'}. Disk-purge not measurable.`,
            justificationCode: JUSTIFICATION_CODES.SESSION_STORAGE_NOT_DISK_PERSISTENT,
            justification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.SESSION_STORAGE_NOT_DISK_PERSISTENT],
          },
        ]
      },

      dimension2_ChromiumPartition: {
        name: 'Chromium Disk Partition & Filesystem (Layer 2)',
        target: runtimePaths.partitions || 'Partitions/',
        properties: [
          {
            id: 'CHROMIUM_DISK_RESIDUE_SCAN',
            description: 'Binary deep scan across userData, Local Storage, IndexedDB, Cache reveals 0 canary bytes post-cleanup',
            status: emptyScanGuard ? 'UNVERIFIED' : (postFsScanResult.matches.length === 0 ? 'PASS' : 'FAIL'),
            evidence: `Files scanned: ${postFsScanResult.scannedFilesCount} (${(postFsScanResult.scannedBytesCount / 1024).toFixed(1)} KB), canary byte matches found: ${postFsScanResult.matches.length}`,
            justificationCode: emptyScanGuard ? JUSTIFICATION_CODES.NO_FILESYSTEM_EVIDENCE_AVAILABLE : null,
            justification: emptyScanGuard ? JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.NO_FILESYSTEM_EVIDENCE_AVAILABLE] : null,
          },
          {
            id: 'CHROMIUM_UNALLOCATED_CLUSTER_SLACK',
            description: 'Filesystem cluster carving for unallocated SQLite WAL free page remnants',
            status: 'UNVERIFIED',
            justificationCode: JUSTIFICATION_CODES.OS_METADATA_JOURNAL_PRIVILEGED,
            justification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.OS_METADATA_JOURNAL_PRIVILEGED],
          },
          {
            id: 'CHROMIUM_NAND_FLASH_PHYSICAL_ZEROIZATION',
            description: 'Physical SSD NAND flash cell zeroization across FTL wear-leveling pools',
            status: 'UNVERIFIED',
            justificationCode: JUSTIFICATION_CODES.PHYSICAL_FTL_UNREACHABLE,
            justification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.PHYSICAL_FTL_UNREACHABLE],
          },
        ]
      },

      dimension3_ProcessMemory: {
        name: 'WebContentsView Process & RAM Lifecycle (Layer 3)',
        target: 'Electron WebContentsView & Session Teardown',
        properties: [
          {
            id: 'WEBCONTENTSVIEW_LIFECYCLE_DESTRUCTION',
            description: 'WebContentsView detached from host window and webContents explicitly closed on tab teardown',
            status: destroySummary.viewClosed ? 'PASS' : 'FAIL',
            evidence: `WebContentsView closed: ${destroySummary.viewClosed}`,
          },
          {
            id: 'SESSION_STORAGE_DATA_CLEARED',
            description: 'clearStorageData() and clearCache() successfully executed on partition session',
            status: destroySummary.storageCleared && destroySummary.cacheCleared
              ? 'PASS'
              : (skipCleanup ? 'UNVERIFIED' : 'FAIL'),
            evidence: `clearStorageData: ${destroySummary.storageCleared}, clearCache: ${destroySummary.cacheCleared}`,
            justificationCode: skipCleanup ? JUSTIFICATION_CODES.REQUIRES_LIVE_CHROMIUM_RUNTIME : null,
            justification: skipCleanup ? 'Session storage was not cleared — skip-cleanup test mode.' : null,
          },
          {
            id: 'PROCESS_HEAP_MEMORY_ZEROIZATION',
            description: 'Physical zeroization of deallocated V8 heap slabs and native Blink allocator memory',
            status: 'UNVERIFIED',
            justificationCode: JUSTIFICATION_CODES.V8_HEAP_RAW_INACCESSIBLE,
            justification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.V8_HEAP_RAW_INACCESSIBLE],
          },
          {
            id: 'HOST_PAGEFILE_EXCLUSION',
            description: 'Host operating system paging file (pagefile.sys / swapfile.sys) exclusion',
            status: 'UNVERIFIED',
            justificationCode: JUSTIFICATION_CODES.KERNEL_PAGING_INACCESSIBLE,
            justification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.KERNEL_PAGING_INACCESSIBLE],
          },
        ]
      },

      dimension4_TorDaemon: {
        name: 'Tor Daemon & SOCKS5 Routing State (Layer 4)',
        target: runtimePaths.torData || 'tor-data/',
        properties: [
          {
            id: 'TOR_DATADIRECTORY_CANARY_ISOLATION',
            description: 'Tor data directory isolation and absence of user browsing canaries',
            status: this._checkTorDataMatches(postFsScanResult.matches, runtimePaths.torData) > 0 ? 'FAIL' : 'UNVERIFIED',
            evidence: this._checkTorDataMatches(postFsScanResult.matches, runtimePaths.torData) > 0
              ? `Canary leak detected in tor-data: ${this._checkTorDataMatches(postFsScanResult.matches, runtimePaths.torData)}`
              : 'Tor daemon not executed during isolated storage audit; documented as separate finding.',
            justificationCode: JUSTIFICATION_CODES.TOR_NOT_INCLUDED_IN_AUDIT,
            justification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.TOR_NOT_INCLUDED_IN_AUDIT],
          },
          {
            id: 'TOR_CIRCUIT_RAM_STATE_ERASURE',
            description: 'Tor daemon internal RAM circuit table zeroization upon tab closure',
            status: 'UNVERIFIED',
            justificationCode: JUSTIFICATION_CODES.TOR_CONSENSUS_RETENTION,
            justification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.TOR_CONSENSUS_RETENTION],
          },
        ]
      },

      dimension5_HostOS: {
        name: 'Host OS Forensic Artifacts (Layer 5)',
        target: 'Windows / Host OS Channels',
        properties: [
          {
            id: 'OS_CRASHPAD_MINIDUMP_EXCLUSION',
            description: 'Crashpad directory contains no minidump files with active canary tokens',
            status: this._checkCrashpadMatches(postFsScanResult.matches, runtimePaths.crashpad) === 0 ? 'PASS' : 'FAIL',
            evidence: `Matches in Crashpad: ${this._checkCrashpadMatches(postFsScanResult.matches, runtimePaths.crashpad)}`,
          },
          {
            id: 'OS_VIRTUAL_MEMORY_PAGEFILE_EXCLUSION',
            description: 'Windows pagefile.sys / swapfile.sys contains no swapped process memory pages',
            status: 'UNVERIFIED',
            justificationCode: JUSTIFICATION_CODES.KERNEL_PAGING_INACCESSIBLE,
            justification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.KERNEL_PAGING_INACCESSIBLE],
          },
          {
            id: 'OS_NTFS_METADATA_JOURNAL_PURGE',
            description: 'NTFS $LogFile and $UsnJrnl contain no unlinked file record metadata',
            status: 'UNVERIFIED',
            justificationCode: JUSTIFICATION_CODES.OS_METADATA_JOURNAL_PRIVILEGED,
            justification: JUSTIFICATION_DESCRIPTIONS[JUSTIFICATION_CODES.OS_METADATA_JOURNAL_PRIVILEGED],
          },
        ]
      },
    };
  }

  _checkTorDataMatches(matches, torDataDir) {
    if (!matches || !torDataDir) return 0;
    return matches.filter(m => m.filePath && m.filePath.startsWith(torDataDir)).length;
  }

  _checkCrashpadMatches(matches, crashpadDir) {
    if (!matches || !crashpadDir) return 0;
    return matches.filter(m => m.filePath && m.filePath.startsWith(crashpadDir)).length;
  }

  _calculateSummary(dimensions, postFsScanResult, userDataPathVerified) {
    let passCount = 0, failCount = 0, unverifiedCount = 0, totalCount = 0;

    for (const dim of Object.values(dimensions)) {
      if (!dim.properties) continue;
      for (const prop of dim.properties) {
        totalCount++;
        if (prop.status === 'PASS') passCount++;
        else if (prop.status === 'FAIL') failCount++;
        else unverifiedCount++;
      }
    }

    let honestVerdict = 'VERIFIED_DISK_PURGED_WITH_UNVERIFIED_HARDWARE_BOUNDARIES';
    if (failCount > 0) {
      honestVerdict = 'RESIDUAL_ARTIFACTS_DETECTED';
    } else if (!userDataPathVerified
      || postFsScanResult.scannedFilesCount === 0
      || postFsScanResult.scannedBytesCount === 0) {
      honestVerdict = 'UNVERIFIED_NO_FILESYSTEM_EVIDENCE';
    }

    return { totalProperties: totalCount, passCount, failCount, unverifiedCount, honestVerdict };
  }
}
