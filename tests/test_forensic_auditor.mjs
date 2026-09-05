/**
 * test_forensic_auditor.mjs
 * 
 * Comprehensive automated test suite for Apricity Browser's Real Electron Forensic Artifact Auditor.
 * 
 * Verifies the 12 Causal Integrity Requirements:
 * 1. Electron actually uses the isolated temporary userData directory.
 * 2. Disk-backed forensic partition (persist:forensic-audit-<UUID>) is actually created.
 * 3. Real Chromium storage is populated across multiple subsystems.
 * 4. Pre-destruction browser readback succeeds.
 * 5. Filesystem scan operates on the exact same userData tree.
 * 6. Empty filesystem scans cannot produce VERIFIED CLEAN (Empty-Scan Guard).
 * 7. Known file residue produces FAIL and flags RESIDUAL_ARTIFACTS_DETECTED.
 * 8. Clean disk-backed teardown produces VERIFIED CLEAN when causal evidence exists.
 * 9. Failed canary creation produces UNVERIFIED.
 * 10. Abnormal termination is isolated and accurately reports retained state.
 * 11. The user's real AppData is never scanned.
 * 12. No ZTR simulator is involved in the active architecture or auditor.
 */

import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

// If executed via node, respawn inside Electron for full Chromium runtime execution
if (!process.versions.electron) {
  const electronCli = path.join(projectRoot, 'node_modules', 'electron', 'cli.js');
  const args = process.argv.slice(2);
  const result = spawnSync(process.execPath, [electronCli, __filename, ...args], {
    stdio: 'inherit',
    cwd: projectRoot
  });
  process.exit(result.status ?? 0);
}

// In Electron runtime: configure isolated temporary userData BEFORE app is ready
const electron = await import('electron');
const { app } = electron;
const baseTmp = process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'Temp') : 'C:\\Temp';
const testTempUserData = path.join(baseTmp, `apricity_test_userdata_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`);
if (!fs.existsSync(testTempUserData)) {
  try { fs.mkdirSync(testTempUserData, { recursive: true }); } catch (_) {}
}
app.setPath('userData', testTempUserData);

const { CanaryGenerator, CANARY_SUBSYSTEMS } = await import('../src/forensics/CanaryGenerator.mjs');
const { FilesystemScanner, DEFAULT_EXCLUSIONS } = await import('../src/forensics/FilesystemScanner.mjs');
const { ForensicAuditor, JUSTIFICATION_CODES } = await import('../src/forensics/ForensicAuditor.mjs');
const { ForensicReporter } = await import('../src/forensics/ForensicReporter.mjs');

async function runForensicTestSuite() {
  console.log('================================================================');
  console.log('  🔬  Apricity Browser — Real Forensic Auditor Test Suite');
  console.log('  Causal Verification & Isolated Disk-Backed Test Harness');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✓ PASSED: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ FAILED: ${name}`);
      console.error(`    Error: ${err.message}`);
      if (err.stack) console.error(`    Stack: ${err.stack.split('\n').slice(1, 4).join('\n')}`);
      failed++;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. CANARY GENERATOR TESTS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('--- 1. Canary Token Generation & Encoding ---');

  await test('Generates high-entropy unique tokens per subsystem', async () => {
    const t1 = CanaryGenerator.generateToken('COOKIE');
    const t2 = CanaryGenerator.generateToken('COOKIE');
    assert.notStrictEqual(t1, t2, 'Tokens must be unique');
    assert(t1.startsWith('CANARY_COOKIE_'), 'Token must follow subsystem prefix format');

    const validation = CanaryGenerator.validateToken(t1);
    assert.strictEqual(validation.valid, true);
    assert.strictEqual(validation.subsystem, 'COOKIE');
    assert(validation.entropy.length >= 24, 'Entropy must be at least 24 hex characters');
  });

  await test('Generates full session canary set covering all storage subsystems', async () => {
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    assert(canarySet.sessionUUID);
    assert.strictEqual(typeof canarySet.tokens, 'object');

    for (const sub of CANARY_SUBSYSTEMS) {
      assert(canarySet.tokens[sub], `Missing subsystem token for ${sub}`);
      assert.strictEqual(canarySet.tokens[sub].subsystem, sub);
      assert(canarySet.tokens[sub].token.includes(sub));
    }
  });

  await test('Produces multi-encoding buffers (UTF-8, UTF-16LE, ASCII, hex)', async () => {
    const token = 'CANARY_TEST_12345678_1700000000_abcdef0123456789abcdef01';
    const encodings = CanaryGenerator.getEncodings(token);

    assert(Buffer.isBuffer(encodings.utf8));
    assert(Buffer.isBuffer(encodings.utf16le));
    assert(Buffer.isBuffer(encodings.ascii));
    assert.strictEqual(typeof encodings.hex, 'string');

    assert.strictEqual(encodings.utf16le.length, token.length * 2);
    assert.strictEqual(encodings.utf8.toString('utf8'), token);
    assert.strictEqual(encodings.utf16le.toString('utf16le'), token);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. FILESYSTEM & BINARY SCANNER PRECISION TESTS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 2. Filesystem & Binary Scanner Precision ---');

  const testTempDir = path.join(os.tmpdir(), `apricity_test_scan_${Date.now()}`);
  if (!fs.existsSync(testTempDir)) fs.mkdirSync(testTempDir, { recursive: true });

  await test('Scans and detects UTF-8 canary in disk files', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const testFile = path.join(testTempDir, 'test_utf8.log');
    fs.writeFileSync(testFile, `Header\nData=${canarySet.tokens.COOKIE.token}\nFooter`);

    const result = await scanner.scanPaths([testTempDir], patterns);
    assert.strictEqual(result.matches.length, 1);
    assert.strictEqual(result.matches[0].subsystem, 'COOKIE');
    assert.strictEqual(result.matches[0].encoding, 'utf8');

    fs.unlinkSync(testFile);
  });

  await test('Scans and detects UTF-16LE canary in binary/DOMStorage simulation files', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const testFile = path.join(testTempDir, 'test_utf16le.ldb');
    const utf16leBuf = canarySet.tokens.LSTORE.encodings.utf16le;
    const dummyPrefix = Buffer.from([0x00, 0x01, 0x02, 0x03]);
    const fileContent = Buffer.concat([dummyPrefix, utf16leBuf, dummyPrefix]);
    fs.writeFileSync(testFile, fileContent);

    const result = await scanner.scanPaths([testTempDir], patterns);
    assert(result.matches.length >= 1);
    const match = result.matches.find(m => m.encoding === 'utf16le');
    assert(match, 'Must find UTF-16LE match');
    assert.strictEqual(match.subsystem, 'LSTORE');
    assert.strictEqual(match.offset, 4);

    fs.unlinkSync(testFile);
  });

  await test('Filters excluded directories (node_modules, .git, src, etc.)', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const excludedSubdir = path.join(testTempDir, 'node_modules', 'subpkg');
    fs.mkdirSync(excludedSubdir, { recursive: true });
    const excludedFile = path.join(excludedSubdir, 'index.js');
    fs.writeFileSync(excludedFile, `const c = "${canarySet.tokens.COOKIE.token}";`);

    const result = await scanner.scanPaths([testTempDir], patterns);
    assert.strictEqual(result.matches.length, 0, 'Excluded directory file must not be scanned');

    fs.rmSync(path.join(testTempDir, 'node_modules'), { recursive: true, force: true });
  });

  try {
    fs.rmSync(testTempDir, { recursive: true, force: true });
  } catch (_) { }

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. CAUSAL VERIFICATION: REAL CHROMIUM FORENSIC AUDITOR LIFECYCLE
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 3. Real Chromium Forensic Auditor Causal Execution ---');

  let liveAuditResult = null;

  await test('1. Electron actually uses the isolated temporary userData directory', async () => {
    const auditor = new ForensicAuditor();
    liveAuditResult = await auditor.runAudit({ tabId: 'test-causal-tab' });

    assert(liveAuditResult.environment, 'Audit result must include environment metadata');
    assert.strictEqual(
      liveAuditResult.environment.userDataPathVerified,
      true,
      'ACTUAL_ELECTRON_USERDATA_PATH === SCANNED_USERDATA_PATH assertion must pass'
    );
    assert(
      liveAuditResult.environment.scannedUserDataPath.includes('apricity_') ||
      liveAuditResult.environment.scannedUserDataPath.includes('tmp') ||
      liveAuditResult.environment.scannedUserDataPath.includes('Temp'),
      'UserData path must be an isolated temporary test directory'
    );
  });

  await test('2. Disk-backed forensic partition (persist:forensic-audit-<UUID>) is created', async () => {
    assert(liveAuditResult.environment.partitionId.startsWith('persist:forensic-audit-'));
    assert(liveAuditResult.environment.partitionDir.includes('Partitions'));
  });

  await test('3 & 4. Real Chromium storage populated and pre-destruction browser readback succeeds', async () => {
    const pre = liveAuditResult.preDestruction.browserStorage;
    assert.strictEqual(pre.cookiePresent, true, 'Cookies must be verified present in Chromium before destruction');
    assert.strictEqual(pre.lstorePresent, true, 'LocalStorage must be verified present before destruction');
    assert.strictEqual(pre.sstorePresent, true, 'SessionStorage must be verified present before destruction');
    assert.strictEqual(pre.idbPresent, true, 'IndexedDB must be verified present before destruction');
    assert.strictEqual(pre.cachePresent, true, 'Cache Storage must be verified present before destruction');
    assert.strictEqual(liveAuditResult.preDestruction.browserStorageValid, true);
  });

  await test('5. Filesystem scan operates on the exact same userData tree and finds real files', async () => {
    assert(liveAuditResult.discovery.scannedFilesCount > 0, 'Real disk scan must find files in userData');
    assert(liveAuditResult.discovery.scannedBytesCount > 0, 'Real disk scan must scan >0 bytes');
  });

  await test('6. Empty-Scan Guard: Scanned Files = 0 or Bytes = 0 prevents VERIFIED CLEAN', async () => {
    const auditor = new ForensicAuditor();
    const mockDims = auditor._evaluateDimensions({
      userDataPathVerified: true,
      preDestructionValid: true,
      browserPreCheck: { cookiePresent: true, lstorePresent: true, idbPresent: true, cachePresent: true },
      postFsScanResult: { matches: [], scannedFilesCount: 0, scannedBytesCount: 0 },
      destroySummary: { viewClosed: true, storageCleared: true, cacheCleared: true },
      runtimePaths: {}
    });

    const cookieProp = mockDims.dimension1_DOMStorage.properties.find(p => p.id === 'DOM_COOKIE_STORAGE_AND_PURGE');
    assert.strictEqual(cookieProp.status, 'UNVERIFIED', '0-file scan must produce UNVERIFIED for DOM storage');
    assert.strictEqual(cookieProp.justificationCode, JUSTIFICATION_CODES.NO_FILESYSTEM_EVIDENCE_AVAILABLE);

    const summary = auditor._calculateSummary(mockDims, { scannedFilesCount: 0, scannedBytesCount: 0 }, true);
    assert.strictEqual(summary.honestVerdict, 'UNVERIFIED_NO_FILESYSTEM_EVIDENCE');
  });

  await test('7. Known file residue produces FAIL and flags RESIDUAL_ARTIFACTS_DETECTED', async () => {
    const scratchDir = path.join(os.tmpdir(), `apricity_failure_inject_${Date.now()}`);
    if (!fs.existsSync(scratchDir)) fs.mkdirSync(scratchDir, { recursive: true });
    const residualFile = path.join(scratchDir, 'leaked_cookie_state.dat');

    const auditor = new ForensicAuditor({
      customPaths: { userData: scratchDir }
    });

    const result = await auditor.runAudit({
      tabId: 'test-fail-tab',
      intentionalFailurePath: residualFile
    });

    assert(result.summary.failCount > 0, 'Fail count must be > 0 when residue exists');
    assert.strictEqual(result.summary.honestVerdict, 'RESIDUAL_ARTIFACTS_DETECTED');

    try { fs.rmSync(scratchDir, { recursive: true, force: true }); } catch (_) { }
  });

  await test('8. Absolute Invariant: VERIFIED CLEAN requires disk pre-evidence; unverifiable subsystems get honest UNVERIFIED', async () => {
    assert.strictEqual(liveAuditResult.summary.failCount, 0, 'Clean live run must have 0 failures');
    assert.strictEqual(liveAuditResult.verification.diskMatchCount, 0, 'Must have 0 residual canary matches');
    assert.strictEqual(
      liveAuditResult.summary.honestVerdict,
      'VERIFIED_DISK_PURGED_WITH_UNVERIFIED_HARDWARE_BOUNDARIES'
    );

    // IDB: the only path to VERIFIED CLEAN is filesystem pre-evidence AND absence after cleanup
    const idbArt = liveAuditResult.artifacts.IDB;
    assert.strictEqual(idbArt.browserPreState, 'VERIFIED_PRESENT',
      'IDB canary must be verified in Chromium before destruction');
    assert.strictEqual(idbArt.filesystemPreState, 'FOUND',
      'IDB canary MUST be found in LevelDB .log file before cleanup (causal pre-evidence)');
    assert.strictEqual(idbArt.filesystemPostState, 'NOT_FOUND',
      'IDB canary must be absent from disk after cleanup');
    assert.strictEqual(idbArt.verdict, 'VERIFIED CLEAN',
      'IDB with filesystem pre-evidence must be VERIFIED CLEAN');

    // CACHE: same requirement
    const cacheArt = liveAuditResult.artifacts.CACHE;
    assert.strictEqual(cacheArt.browserPreState, 'VERIFIED_PRESENT',
      'Cache canary must be verified in Chromium before destruction');
    assert.strictEqual(cacheArt.filesystemPreState, 'FOUND',
      'Cache canary MUST be found in CacheStorage entry file before cleanup (causal pre-evidence)');
    assert.strictEqual(cacheArt.filesystemPostState, 'NOT_FOUND',
      'Cache canary must be absent from disk after cleanup');
    assert.strictEqual(cacheArt.verdict, 'VERIFIED CLEAN',
      'Cache with filesystem pre-evidence must be VERIFIED CLEAN');

    // COOKIE: must NOT be VERIFIED CLEAN — the Cookies SQLite file is EBUSY-locked while Chromium
    // is running, so we cannot confirm the canary was on disk before cleanup. v4.0.0 fix: P0.
    const cookieArt = liveAuditResult.artifacts.COOKIE;
    assert.strictEqual(cookieArt.browserPreState, 'VERIFIED_PRESENT',
      'Cookie canary must be verified in Chromium before destruction');
    assert.notStrictEqual(cookieArt.verdict, 'VERIFIED CLEAN',
      'COOKIE must NOT be VERIFIED CLEAN — disk pre-evidence cannot be established while Chromium holds the SQLite lock');
    assert(
      ['UNVERIFIED_FILE_LOCKED', 'UNVERIFIED_NOT_COMMITTED_TO_DISK', 'UNVERIFIED'].includes(cookieArt.verdict),
      `COOKIE verdict must be an honest UNVERIFIED variant, got: ${cookieArt.verdict}`
    );

    // LSTORE: may be VERIFIED CLEAN if quiescence detection found the canary in the .log file,
    // or UNVERIFIED_NOT_COMMITTED_TO_DISK if the canary hadn't flushed to disk within the window.
    // Either is honest. Must NOT be VERIFIED CLEAN if filesystemPreState is NOT_FOUND.
    const lstoreArt = liveAuditResult.artifacts.LSTORE;
    assert.strictEqual(lstoreArt.browserPreState, 'VERIFIED_PRESENT',
      'LocalStorage canary must be verified in Chromium before destruction');
    if (lstoreArt.verdict === 'VERIFIED CLEAN') {
      assert.strictEqual(lstoreArt.filesystemPreState, 'FOUND',
        'LSTORE verdict VERIFIED CLEAN requires filesystemPreState=FOUND (invariant enforcement)');
    } else {
      assert(
        ['UNVERIFIED_NOT_COMMITTED_TO_DISK', 'UNVERIFIED_FILE_LOCKED', 'UNVERIFIED'].includes(lstoreArt.verdict),
        `LSTORE non-VERIFIED-CLEAN verdict must be an honest UNVERIFIED variant, got: ${lstoreArt.verdict}`
      );
    }

    // SESSION: must always be UNVERIFIED_NOT_DISK_PERSISTENT (SessionStorage is in-memory only)
    const sessionArt = liveAuditResult.artifacts.SESSION;
    assert.strictEqual(sessionArt.filesystemPreState, 'NOT_APPLICABLE',
      'SESSION filesystemPreState must be NOT_APPLICABLE (not a disk-persistent API)');
    assert.strictEqual(sessionArt.verdict, 'UNVERIFIED_NOT_DISK_PERSISTENT',
      'SESSION must always be UNVERIFIED_NOT_DISK_PERSISTENT — never VERIFIED CLEAN');
    assert(sessionArt.verdictJustificationCode,
      'SESSION must have a justification code explaining the non-disk-persistent classification');
  });

  await test('9. Failed canary creation or unverified browser state produces UNVERIFIED', async () => {
    const auditor = new ForensicAuditor();
    const mockDims = auditor._evaluateDimensions({
      userDataPathVerified: true,
      preDestructionValid: false,
      browserPreCheck: { cookiePresent: false, lstorePresent: false, idbPresent: false, cachePresent: false },
      postFsScanResult: { matches: [], scannedFilesCount: 50, scannedBytesCount: 100000 },
      destroySummary: { viewClosed: true, storageCleared: true, cacheCleared: true },
      runtimePaths: {}
    });

    for (const prop of mockDims.dimension1_DOMStorage.properties) {
      assert.strictEqual(prop.status, 'UNVERIFIED', 'Unverified browser state MUST produce UNVERIFIED');
    }
  });

  await test('10. Skip-cleanup mode: IDB/Cache canaries persist on disk when clearStorageData is not called', async () => {
    // NOTE: This tests the in-process "skip-cleanup" mode (no clearStorageData called).
    // The GENUINE crash test (SIGKILL via --abnormal CLI flag) requires an out-of-process
    // scan and is exercised via: npm run forensic -- --abnormal
    // This test verifies:
    //   a) skipCleanup flag is respected (storageCleared=false)
    //   b) IDB and CACHE canaries ARE found on disk post-scan (they persisted because we skipped cleanup)
    //   c) The mode label is correct (SKIP_CLEANUP_TEST, not ABNORMAL_TERMINATION)

    const auditor = new ForensicAuditor();
    const result = await auditor.runAudit({ skipCleanup: true });

    // Mode label
    assert.strictEqual(result.metadata.mode, 'SKIP_CLEANUP_TEST',
      'Skip-cleanup mode must be labelled SKIP_CLEANUP_TEST');

    // clearStorageData was NOT called
    assert.strictEqual(result.verification.destroySummary.storageCleared, false,
      'storageCleared must be false in skip-cleanup mode');
    assert.strictEqual(result.verification.destroySummary.cacheCleared, false,
      'cacheCleared must be false in skip-cleanup mode');

    // IDB and CACHE should be found on disk post-scan (data persists without cleanup)
    // This is the EXPECTED behavior — proves the data would survive a real crash
    const idbPostMatches = result.verification.diskMatches.filter(m => m.subsystem === 'IDB').length;
    const cachePostMatches = result.verification.diskMatches.filter(m => m.subsystem === 'CACHE').length;

    assert(idbPostMatches > 0,
      `IDB canary must persist on disk when clearStorageData is not called (got ${idbPostMatches} matches)`);
    assert(cachePostMatches > 0,
      `Cache canary must persist on disk when clearStorageData is not called (got ${cachePostMatches} matches)`);

    // Overall verdict must reflect the residual artifacts
    assert.strictEqual(result.summary.honestVerdict, 'RESIDUAL_ARTIFACTS_DETECTED',
      'Skip-cleanup run must produce RESIDUAL_ARTIFACTS_DETECTED');
    assert(result.summary.failCount > 0,
      'Skip-cleanup run must have at least one FAIL property');
  });

  await test('11. The user\'s real AppData is never scanned', async () => {
    const realAppData = process.env.APPDATA;
    for (const root of liveAuditResult.discovery.scannedRoots) {
      if (realAppData && root === realAppData) {
        assert.fail('Real AppData root was scanned directly!');
      }
    }
  });

  await test('12. No ZTR simulator is involved in the active architecture or auditor', async () => {
    assert.strictEqual(typeof globalThis.ZeroTrustRenderer, 'undefined');
    assert.strictEqual(typeof globalThis.ZTRCryptoVault, 'undefined');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. UNVERIFIED CLASSIFICATION & JUSTIFICATION INTEGRITY
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 4. UNVERIFIED Classification & Justifications ---');

  await test('All UNVERIFIED properties have official justification codes and explanations', async () => {
    const auditor = new ForensicAuditor();
    const result = await auditor.runAudit();

    const expectedCodes = new Set(Object.values(JUSTIFICATION_CODES));
    let unverifiedFound = 0;

    for (const dim of Object.values(result.dimensions)) {
      for (const prop of dim.properties) {
        if (prop.status === 'UNVERIFIED') {
          unverifiedFound++;
          assert(prop.justificationCode, `UNVERIFIED property ${prop.id} must have justificationCode`);
          assert(
            expectedCodes.has(prop.justificationCode),
            `justificationCode ${prop.justificationCode} must be from standard JUSTIFICATION_CODES`
          );
          assert(
            prop.justification && prop.justification.length > 20,
            `UNVERIFIED property ${prop.id} must have detailed technical justification text`
          );
        }
      }
    }

    assert(unverifiedFound >= 7, 'Must have UNVERIFIED properties covering OS, Tor, and hardware limits');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. FORENSIC REPORTER SCHEMA & HONESTY VERIFICATION
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 5. Forensic Reporter Schema & Honesty Verification ---');

  await test('Generates structured JSON without naive CLEAN boolean', async () => {
    const jsonStr = ForensicReporter.formatJson(liveAuditResult);
    const parsed = JSON.parse(jsonStr);

    assert(parsed.metadata);
    assert(parsed.dimensions);
    assert(parsed.summary);
    assert.strictEqual(parsed.summary.CLEAN, undefined, 'Must NOT contain naive CLEAN boolean');
    assert.strictEqual(parsed.summary.zeroResidue, undefined, 'Must NOT contain zeroResidue boolean');
  });

  await test('Generates formatted Console and Markdown outputs with explicit causal state tables', async () => {
    const consoleOutput = ForensicReporter.formatConsole(liveAuditResult, { verbose: true });
    assert(consoleOutput.includes('APRICITY BROWSER — REAL CHROMIUM FORENSIC ARTIFACT AUDIT REPORT'));
    assert(consoleOutput.includes('REAL CHROMIUM STORAGE SUBSYSTEM CAUSAL VERIFICATION'));
    assert(consoleOutput.includes('Browser Pre-State'));
    assert(consoleOutput.includes('Filesystem Pre-State'));
    assert(consoleOutput.includes('Filesystem Post-State'));
    assert(consoleOutput.includes('[PASS]'));
    assert(consoleOutput.includes('[UNVERIFIED]'));

    const markdownOutput = ForensicReporter.formatMarkdown(liveAuditResult);
    assert(markdownOutput.includes('# Apricity Browser — Forensic Artifact Audit Report'));
    assert(markdownOutput.includes('## 1. Architectural Context & Security Boundaries'));
    assert(markdownOutput.includes('## 3. Storage Subsystem Causal Verification'));
    assert(markdownOutput.includes('## 5. Multi-Dimensional Verification Matrix'));
    assert(markdownOutput.includes('Honesty Mandate'));
  });

  console.log('\n================================================================');
  console.log(`  RESULTS: ${passed} Passed, ${failed} Failed`);
  console.log('================================================================\n');

  // Clean up test userData directory
  try {
    if (fs.existsSync(testTempUserData)) {
      fs.rmSync(testTempUserData, { recursive: true, force: true });
    }
  } catch (_) {}

  setTimeout(() => app.exit(failed > 0 ? 1 : 0), 100);
}

app.whenReady().then(runForensicTestSuite).catch(err => {
  console.error(err);
  setTimeout(() => app.exit(1), 100);
});
