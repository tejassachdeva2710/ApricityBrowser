/**
 * test_forensic_auditor.mjs
 * 
 * Comprehensive automated test suite for Apricity Browser's Forensic Artifact Auditor.
 * 
 * Verifies:
 * 1. CanaryGenerator (entropy, formatting, multi-encoding generation).
 * 2. FilesystemScanner (binary regex matching, UTF-8/UTF-16LE detection, exclusion filters, lock handling).
 * 3. ForensicAuditor (full 6-phase lifecycle orchestration).
 * 4. Intentional Failure Injection (asserts auditor detects injected canary residue and marks FAIL).
 * 5. UNVERIFIED Classification & Justification integrity.
 * 6. ForensicReporter & Security Honesty (rejection of naive CLEAN booleans, structured schema).
 */

import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { CanaryGenerator, CANARY_SUBSYSTEMS } from '../src/forensics/CanaryGenerator.mjs';
import { FilesystemScanner, DEFAULT_EXCLUSIONS } from '../src/forensics/FilesystemScanner.mjs';
import { ForensicAuditor, JUSTIFICATION_CODES } from '../src/forensics/ForensicAuditor.mjs';
import { ForensicReporter } from '../src/forensics/ForensicReporter.mjs';

async function runForensicTestSuite() {
  console.log('================================================================');
  console.log('  🔬  Apricity Browser — Forensic Auditor Automated Test Suite');
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

  await test('Generates full session canary set covering all 7 subsystems', async () => {
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

    // UTF-16LE should be twice the byte length of ASCII for standard ASCII characters
    assert.strictEqual(encodings.utf16le.length, token.length * 2);
    assert.strictEqual(encodings.utf8.toString('utf8'), token);
    assert.strictEqual(encodings.utf16le.toString('utf16le'), token);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. FILESYSTEM & BINARY SCANNER TESTS
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

  await test('Scans in-memory JavaScript structures (Maps, nested objects)', async () => {
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const mockState = {
      activeSession: {
        id: 'test-session',
        store: new Map([
          ['k1', 'safe-data'],
          ['k2', canarySet.tokens.VAULT.token]
        ])
      }
    };

    const matches = FilesystemScanner.scanMemoryStructure(mockState, patterns);
    assert.strictEqual(matches.length, 1);
    assert.strictEqual(matches[0].subsystem, 'VAULT');
  });

  // Clean up temporary test directory
  try {
    fs.rmSync(testTempDir, { recursive: true, force: true });
  } catch (_) { }

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. FORENSIC AUDITOR LIFECYCLE EXECUTION
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 3. Forensic Auditor Full Lifecycle Execution ---');

  await test('Executes 6-phase audit and evaluates 5 security dimensions', async () => {
    const auditor = new ForensicAuditor();
    const auditResult = await auditor.runAudit({ tabId: 'test-audit-tab' });

    assert(auditResult.metadata);
    assert(auditResult.architecturalContext);
    assert(auditResult.session);
    assert(auditResult.discovery);
    assert(auditResult.verification);
    assert(auditResult.dimensions);
    assert(auditResult.summary);

    // Verify pre-destruction succeeded
    assert.strictEqual(auditResult.verification.preDestructionValid, true);

    // Verify post-destruction memory cleanup succeeded
    assert.strictEqual(auditResult.verification.postDestructionMemory.userStoreDeleted, true);
    assert.strictEqual(auditResult.verification.postDestructionMemory.vaultKeyDeleted, true);
    assert.strictEqual(auditResult.verification.postCloseReadBlocked, true);
    assert.strictEqual(auditResult.verification.inMemoryLeakCount, 0);

    // Verify dimensions are populated
    const dims = auditResult.dimensions;
    assert(dims.dimension1_CryptoVault);
    assert(dims.dimension2_StorageSimulator);
    assert(dims.dimension3_ChromiumPartition);
    assert(dims.dimension4_TorDaemon);
    assert(dims.dimension5_HostOS);

    // Verify summary counts
    assert(auditResult.summary.passCount >= 7);
    assert.strictEqual(auditResult.summary.failCount, 0);
    assert(auditResult.summary.unverifiedCount >= 5);
    assert.strictEqual(
      auditResult.summary.honestVerdict,
      'VERIFIED_EPHEMERAL_COMPLIANT_WITH_UNVERIFIED_HARDWARE_BOUNDARIES'
    );
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. INTENTIONAL FAILURE INJECTION TEST (Anti-Cheat & Non-Facade Verification)
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 4. Intentional Failure Injection (Scanner Precision Test) ---');

  await test('Detects intentional residual canary file and produces FAIL verdict', async () => {
    const scratchDir = path.join(os.tmpdir(), `apricity_failure_inject_${Date.now()}`);
    if (!fs.existsSync(scratchDir)) fs.mkdirSync(scratchDir, { recursive: true });
    const residualFile = path.join(scratchDir, 'leaked_cookie_state.dat');

    const auditor = new ForensicAuditor({
      customPaths: {
        userData: scratchDir
      }
    });

    const result = await auditor.runAudit({
      tabId: 'test-fail-tab',
      intentionalFailurePath: residualFile
    });

    // The auditor MUST detect the failure and mark CHROMIUM_DISK_RESIDUE_SCAN as FAIL
    const partitionDim = result.dimensions.dimension3_ChromiumPartition;
    const diskScanProp = partitionDim.properties.find(p => p.id === 'CHROMIUM_DISK_RESIDUE_SCAN');

    assert(diskScanProp, 'CHROMIUM_DISK_RESIDUE_SCAN property must exist');
    assert.strictEqual(diskScanProp.status, 'FAIL', 'Intentional leak MUST cause property to FAIL');
    assert(result.summary.failCount > 0, 'Fail count must be > 0 when residue exists');
    assert.strictEqual(result.summary.honestVerdict, 'RESIDUAL_ARTIFACTS_DETECTED');

    // Clean up scratch dir
    try {
      fs.rmSync(scratchDir, { recursive: true, force: true });
    } catch (_) { }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. UNVERIFIED CLASSIFICATION & JUSTIFICATION INTEGRITY
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 5. UNVERIFIED Classification & Justifications ---');

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

    assert(unverifiedFound >= 5, 'Must have at least 5 UNVERIFIED properties covering OS/hardware limits');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. FORENSIC REPORTER & SECURITY HONESTY
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 6. Forensic Reporter Schema & Honesty Verification ---');

  await test('Generates structured JSON without naive CLEAN boolean', async () => {
    const auditor = new ForensicAuditor();
    const result = await auditor.runAudit();
    const jsonStr = ForensicReporter.formatJson(result);
    const parsed = JSON.parse(jsonStr);

    assert(parsed.metadata);
    assert(parsed.dimensions);
    assert(parsed.summary);
    assert.strictEqual(parsed.summary.CLEAN, undefined, 'Must NOT contain naive CLEAN boolean');
    assert.strictEqual(parsed.summary.zeroResidue, undefined, 'Must NOT contain zeroResidue boolean');
  });

  await test('Generates formatted Console and Markdown outputs with architectural boundaries', async () => {
    const auditor = new ForensicAuditor();
    const result = await auditor.runAudit();

    const consoleOutput = ForensicReporter.formatConsole(result, { verbose: true });
    assert(consoleOutput.includes('APRICITY BROWSER — EPHEMERAL FORENSIC ARTIFACT AUDIT REPORT'));
    assert(consoleOutput.includes('ARCHITECTURAL LAYER CONTEXT'));
    assert(consoleOutput.includes('Layer A (ZTR Simulator)'));
    assert(consoleOutput.includes('Layer B (Native Webview)'));
    assert(consoleOutput.includes('[PASS]'));
    assert(consoleOutput.includes('[UNVERIFIED]'));

    const markdownOutput = ForensicReporter.formatMarkdown(result);
    assert(markdownOutput.includes('# Apricity Browser — Forensic Artifact Audit Report'));
    assert(markdownOutput.includes('## 1. Architectural Context & Security Boundaries'));
    assert(markdownOutput.includes('## 4. Multi-Dimensional Verification Matrix'));
    assert(markdownOutput.includes('Honesty Mandate'));
  });

  console.log('\n================================================================');
  console.log(`  RESULTS: ${passed} Passed, ${failed} Failed`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runForensicTestSuite();
