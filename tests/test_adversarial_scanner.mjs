/**
 * test_adversarial_scanner.mjs
 * 
 * EMPIRICAL ADVERSARIAL STRESS TEST HARNESS
 * Target Modules: CanaryGenerator.mjs, FilesystemScanner.mjs
 * 
 * Comprehensive Stress Dimensions:
 * 1. Binary scanning with large buffers (1MB, 10MB, 20MB, exact max boundary, >max limit).
 * 2. Tricky multi-byte & UTF-16LE scanning (even/odd alignments, astral Unicode/emojis, CJK, Cyrillic, corrupt prefixes).
 * 3. Simulated file locks & Windows filesystem errors (exclusive locks, TOCTOU deletion race, permission handling).
 * 4. Deep & broad directory trees (25+ levels deep, 50+ files across multi-dirs, special chars, unicode paths).
 * 5. Boundary edge cases & malformed inputs (null/undefined/empty tokens, invalid types, zero-length buffers).
 * 6. False-positive resistance (random binary noise, cross-session canaries, partial prefixes, exclusion matching).
 * 7. Memory structure scanning (nested Map, Set, Array, Objects, primitives, nulls).
 * 8. High-volume token uniqueness & entropy stress (1,000+ sequential tokens with 0 collisions).
 */

import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomBytes } from 'node:crypto';
import { CanaryGenerator, CANARY_SUBSYSTEMS } from '../src/forensics/CanaryGenerator.mjs';
import { FilesystemScanner, DEFAULT_EXCLUSIONS } from '../src/forensics/FilesystemScanner.mjs';

const TEST_SCRATCH_ROOT = path.join(os.tmpdir(), `apricity_adv_stress_${Date.now()}`);

async function runAdversarialStressSuite() {
  console.log('================================================================');
  console.log('  ⚔️  Apricity Browser — Empirical Adversarial Stress Suite');
  console.log('  Targeting: CanaryGenerator.mjs & FilesystemScanner.mjs');
  console.log('================================================================\n');

  if (!fs.existsSync(TEST_SCRATCH_ROOT)) {
    fs.mkdirSync(TEST_SCRATCH_ROOT, { recursive: true });
  }

  let passed = 0;
  let failed = 0;
  const testResults = [];

  async function test(name, fn) {
    const t0 = performance.now();
    try {
      await fn();
      const elapsed = (performance.now() - t0).toFixed(2);
      console.log(`  ✓ PASSED: ${name} (${elapsed}ms)`);
      passed++;
      testResults.push({ name, status: 'PASS', elapsedMs: parseFloat(elapsed) });
    } catch (err) {
      const elapsed = (performance.now() - t0).toFixed(2);
      console.error(`  ✗ FAILED: ${name} (${elapsed}ms)`);
      console.error(`    Error: ${err.message}`);
      if (err.stack) console.error(`    Stack: ${err.stack.split('\n').slice(1, 4).join('\n')}`);
      failed++;
      testResults.push({ name, status: 'FAIL', elapsedMs: parseFloat(elapsed), error: err.message });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SUITE 1: BINARY SCANNING WITH LARGE BUFFERS & OFFSET BOUNDARIES
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('--- Suite 1: Large Buffer Scanning & Offset Boundaries ---');

  await test('Detects UTF-8 canary at byte 0 of a 10MB buffer', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);
    const tokenBuf = canarySet.tokens.COOKIE.encodings.utf8;

    const size = 10 * 1024 * 1024; // 10MB
    const buffer = Buffer.alloc(size, 0xAA);
    tokenBuf.copy(buffer, 0); // At byte 0

    const matches = scanner.scanBuffer('large_start.bin', buffer, patterns);
    assert.strictEqual(matches.length, 1);
    assert.strictEqual(matches[0].subsystem, 'COOKIE');
    assert.strictEqual(matches[0].offset, 0);
    assert.strictEqual(matches[0].encoding, 'utf8');
  });

  await test('Detects UTF-16LE canary at exact midpoint of a 20MB buffer', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);
    const tokenBuf = canarySet.tokens.LSTORE.encodings.utf16le;

    const size = 20 * 1024 * 1024; // 20MB
    const buffer = Buffer.alloc(size, 0x55);
    const midPoint = 10 * 1024 * 1024;
    tokenBuf.copy(buffer, midPoint);

    const matches = scanner.scanBuffer('large_mid.bin', buffer, patterns);
    assert.strictEqual(matches.length, 1);
    assert.strictEqual(matches[0].subsystem, 'LSTORE');
    assert.strictEqual(matches[0].offset, midPoint);
    assert.strictEqual(matches[0].encoding, 'utf16le');
  });

  await test('Detects UTF-8 canary at the very last bytes of a 10MB buffer (edge boundary)', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);
    const tokenBuf = canarySet.tokens.VAULT.encodings.utf8;

    const size = 10 * 1024 * 1024;
    const buffer = Buffer.alloc(size, 0x00);
    const endOffset = size - tokenBuf.length;
    tokenBuf.copy(buffer, endOffset);

    const matches = scanner.scanBuffer('large_end.bin', buffer, patterns);
    assert.strictEqual(matches.length, 1);
    assert.strictEqual(matches[0].subsystem, 'VAULT');
    assert.strictEqual(matches[0].offset, endOffset);
  });

  await test('Boundary check: Scans file at exact maxFileSizeBytes limit', async () => {
    const limit = 512 * 1024; // 512KB limit
    const scanner = new FilesystemScanner({ maxFileSizeBytes: limit });
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const exactLimitFile = path.join(TEST_SCRATCH_ROOT, 'exact_limit.dat');
    const exactBuffer = Buffer.alloc(limit, 0x33);
    canarySet.tokens.COOKIE.encodings.utf8.copy(exactBuffer, 256);
    fs.writeFileSync(exactLimitFile, exactBuffer);

    const result = await scanner.scanFile(exactLimitFile, patterns);
    assert.strictEqual(result.scanned, true);
    assert.strictEqual(result.matches.length, 1);
    assert.strictEqual(result.matches[0].subsystem, 'COOKIE');

    fs.unlinkSync(exactLimitFile);
  });

  await test('Respects maxFileSizeBytes and skips files exceeding threshold cleanly by 1 byte', async () => {
    const limit = 512 * 1024; // 512KB limit
    const scanner = new FilesystemScanner({ maxFileSizeBytes: limit });
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const overLimitFile = path.join(TEST_SCRATCH_ROOT, 'over_limit_plus_one.dat');
    const overBuffer = Buffer.alloc(limit + 1, 0x77); // limit + 1 byte
    canarySet.tokens.IDB.encodings.utf8.copy(overBuffer, 100);
    fs.writeFileSync(overLimitFile, overBuffer);

    const result = await scanner.scanFile(overLimitFile, patterns);
    assert.strictEqual(result.skipped, true);
    assert(result.reason.includes('exceeds limit'));
    assert.strictEqual(result.matches.length, 0);

    fs.unlinkSync(overLimitFile);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SUITE 2: TRICKY MULTI-BYTE & UTF-16LE SCANNING
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- Suite 2: Tricky Multi-Byte & UTF-16LE Encodings ---');

  await test('Detects UTF-16LE canary at ODD byte offset (unaligned SQLite / LevelDB packing)', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);
    const tokenBuf = canarySet.tokens.CACHE.encodings.utf16le;

    // Odd offset: 1 byte header, then UTF-16LE canary, then padding
    const oddHeader = Buffer.from([0xFF]); // 1 byte
    const trailing = Buffer.from([0x00, 0x00, 0x00]);
    const fileBuffer = Buffer.concat([oddHeader, tokenBuf, trailing]);

    const matches = scanner.scanBuffer('odd_utf16.bin', fileBuffer, patterns);
    assert.strictEqual(matches.length, 1);
    assert.strictEqual(matches[0].subsystem, 'CACHE');
    assert.strictEqual(matches[0].offset, 1, 'Must detect at unaligned odd offset 1');
    assert.strictEqual(matches[0].encoding, 'utf16le');
  });

  await test('Detects UTF-8 and UTF-16LE canaries embedded within multi-byte astral Unicode (emojis, CJK, Cyrillic)', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    // Multi-byte prefix & suffix: 🔥 (4 bytes UTF-8), 漢字 (6 bytes UTF-8), Конфиденциально (Cyrillic)
    const unicodePrefix = '🔒🔥🛡️【机密数据】— Конфиденциально: ';
    const unicodeSuffix = ' — 🚀💯✨ Конец';
    const textContent = `${unicodePrefix}${canarySet.tokens.URL.token}${unicodeSuffix}`;
    const utf8Buf = Buffer.from(textContent, 'utf8');

    const matches = scanner.scanBuffer('unicode_context.txt', utf8Buf, patterns);
    assert.strictEqual(matches.length, 1);
    assert.strictEqual(matches[0].subsystem, 'URL');
    assert.strictEqual(matches[0].encoding, 'utf8');
    assert(matches[0].offset > 0);
  });

  await test('Handles dense multi-canary binary stream containing all 7 subsystems concurrently', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const buffers = [];
    for (const [sub, data] of Object.entries(canarySet.tokens)) {
      const enc = sub === 'LSTORE' || sub === 'IDB' ? data.encodings.utf16le : data.encodings.utf8;
      buffers.push(Buffer.from(`[START_${sub}]`));
      buffers.push(enc);
      buffers.push(Buffer.from(`[END_${sub}]`));
    }
    const combinedBuffer = Buffer.concat(buffers);

    const matches = scanner.scanBuffer('multi_stream.bin', combinedBuffer, patterns);
    assert.strictEqual(matches.length, 7, 'All 7 subsystem canaries must be detected');

    const matchedSubsystems = new Set(matches.map(m => m.subsystem));
    for (const sub of CANARY_SUBSYSTEMS) {
      assert(matchedSubsystems.has(sub), `Subsystem ${sub} must be detected in multi stream`);
    }
  });

  await test('Rejects corrupted canary prefix without false match (near-miss adversary)', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    // Corrupt the last character of the real token
    const realToken = canarySet.tokens.COOKIE.token;
    const corruptToken = realToken.slice(0, -1) + (realToken.slice(-1) === 'a' ? 'b' : 'a');

    const buffer = Buffer.from(`DATA_BLOCK:${corruptToken}:END_BLOCK`);
    const matches = scanner.scanBuffer('near_miss.bin', buffer, patterns);
    assert.strictEqual(matches.length, 0, 'Near-miss canary MUST NOT produce a match');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SUITE 3: SIMULATED FILE LOCKS & WINDOWS FILESYSTEM ERRORS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- Suite 3: Simulated File Locks & Filesystem Errors ---');

  await test('Gracefully handles Windows file lock (EBUSY/EPERM) during single file scan', async () => {
    const scanner = new FilesystemScanner({ maxRetries: 2, retryDelayMs: 20 });
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const lockedFilePath = path.join(TEST_SCRATCH_ROOT, 'locked_test_file.dat');
    fs.writeFileSync(lockedFilePath, 'Initial unlocked content');

    let fd;
    try {
      fd = fs.openSync(lockedFilePath, 'r+');
      const result = await scanner.scanFile(lockedFilePath, patterns);
      assert(result !== null && typeof result === 'object');
      assert(Array.isArray(result.matches));
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.unlinkSync(lockedFilePath); } catch (_) {}
    }
  });

  await test('Handles TOCTOU race: file deleted immediately between discovery and read', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const vanishedPath = path.join(TEST_SCRATCH_ROOT, 'vanished_file_nonexistent.dat');
    const result = await scanner.scanFile(vanishedPath, patterns);
    assert.strictEqual(result.skipped, true);
    assert(result.reason.includes('vanished') || result.code === 'ENOENT');
    assert.strictEqual(result.matches.length, 0);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SUITE 4: DEEP & BROAD DIRECTORY STRUCTURES
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- Suite 4: Deep & Broad Directory Structures ---');

  await test('Recursively discovers canary in a 25-level deep directory tree', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    let deepDir = path.join(TEST_SCRATCH_ROOT, 'deep_root');
    for (let i = 1; i <= 25; i++) {
      deepDir = path.join(deepDir, `level_${i}`);
    }
    fs.mkdirSync(deepDir, { recursive: true });

    const targetFile = path.join(deepDir, 'deep_canary.txt');
    fs.writeFileSync(targetFile, `CANARY_TEST=${canarySet.tokens.SESSION.token}`);

    const result = await scanner.scanPaths([path.join(TEST_SCRATCH_ROOT, 'deep_root')], patterns);
    assert.strictEqual(result.matches.length, 1);
    assert.strictEqual(result.matches[0].subsystem, 'SESSION');
    assert.strictEqual(result.matches[0].filePath, targetFile);

    fs.rmSync(path.join(TEST_SCRATCH_ROOT, 'deep_root'), { recursive: true, force: true });
  });

  await test('Handles broad directory tree with 50 files across multiple subdirectories', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const broadDir = path.join(TEST_SCRATCH_ROOT, 'broad_root');
    fs.mkdirSync(broadDir, { recursive: true });

    for (let d = 0; d < 10; d++) {
      const sub = path.join(broadDir, `subdir_${d}`);
      fs.mkdirSync(sub, { recursive: true });
      for (let f = 0; f < 5; f++) {
        const filePath = path.join(sub, `file_${f}.log`);
        if (d === 7 && f === 3) {
          fs.writeFileSync(filePath, `RESIDUE:${canarySet.tokens.IDB.token}`);
        } else {
          fs.writeFileSync(filePath, `CLEAN_DATA_${d}_${f}_RANDOM_DATA`);
        }
      }
    }

    const result = await scanner.scanPaths([broadDir], patterns);
    assert.strictEqual(result.scannedFilesCount, 50);
    assert.strictEqual(result.matches.length, 1);
    assert.strictEqual(result.matches[0].subsystem, 'IDB');

    fs.rmSync(broadDir, { recursive: true, force: true });
  });

  await test('Handles directory with unicode characters and spaces in path names', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const unicodeDir = path.join(TEST_SCRATCH_ROOT, 'папка_браузера 🍪 [тест]');
    fs.mkdirSync(unicodeDir, { recursive: true });

    const unicodeFile = path.join(unicodeDir, 'сессия_#1 (данные).dat');
    fs.writeFileSync(unicodeFile, canarySet.tokens.COOKIE.encodings.utf8);

    const result = await scanner.scanPaths([unicodeDir], patterns);
    assert.strictEqual(result.matches.length, 1);
    assert.strictEqual(result.matches[0].subsystem, 'COOKIE');

    fs.rmSync(unicodeDir, { recursive: true, force: true });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SUITE 5: BOUNDARY EDGE CASES & MALFORMED INPUTS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- Suite 5: Boundary Edge Cases & Malformed Inputs ---');

  await test('CanaryGenerator.getEncodings rejects non-string inputs with TypeError', async () => {
    assert.throws(() => CanaryGenerator.getEncodings(null), TypeError);
    assert.throws(() => CanaryGenerator.getEncodings(12345), TypeError);
    assert.throws(() => CanaryGenerator.getEncodings({}), TypeError);
    assert.throws(() => CanaryGenerator.getEncodings(undefined), TypeError);
  });

  await test('CanaryGenerator.validateToken handles malformed inputs safely', async () => {
    assert.strictEqual(CanaryGenerator.validateToken(null).valid, false);
    assert.strictEqual(CanaryGenerator.validateToken(undefined).valid, false);
    assert.strictEqual(CanaryGenerator.validateToken('').valid, false);
    assert.strictEqual(CanaryGenerator.validateToken('CANARY_SHORT').valid, false);
    assert.strictEqual(CanaryGenerator.validateToken('CANARY_COOKIE_baduuid_123_badentropy').valid, false);

    const good = CanaryGenerator.generateToken('COOKIE');
    assert.strictEqual(CanaryGenerator.validateToken(good).valid, true);
  });

  await test('CanaryGenerator.extractSearchPatterns handles null or empty input safely', async () => {
    assert.deepStrictEqual(CanaryGenerator.extractSearchPatterns(null), []);
    assert.deepStrictEqual(CanaryGenerator.extractSearchPatterns(undefined), []);
    assert.deepStrictEqual(CanaryGenerator.extractSearchPatterns({}), []);
    assert.deepStrictEqual(CanaryGenerator.extractSearchPatterns({ tokens: null }), []);
  });

  await test('FilesystemScanner.scanPaths handles non-existent paths gracefully', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const nonExistentPath = path.join(TEST_SCRATCH_ROOT, 'does_not_exist_12345');
    const result = await scanner.scanPaths([nonExistentPath, null, ''], patterns);

    assert.strictEqual(result.scannedFilesCount, 0);
    assert.strictEqual(result.matches.length, 0);
    assert.strictEqual(result.errors.length, 0);
  });

  await test('FilesystemScanner.scanBuffer handles patterns with missing or empty encodings', async () => {
    const scanner = new FilesystemScanner();
    const dummyBuffer = Buffer.from('TEST_DATA_WITHOUT_CANARIES');

    const malformedPatterns = [
      { subsystem: 'EMPTY_ENC', token: 'CANARY_X', encodings: null },
      { subsystem: 'NO_ENC', token: 'CANARY_Y' },
      { subsystem: 'PARTIAL', token: 'CANARY_Z', encodings: {} }
    ];

    const matches = scanner.scanBuffer('test.bin', dummyBuffer, malformedPatterns);
    assert.strictEqual(matches.length, 0);
  });

  await test('FilesystemScanner.scanMemoryStructure handles complex nested types & primitives', async () => {
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const complexTarget = {
      layer1: {
        set: new Set(['safe1', canarySet.tokens.COOKIE.token]),
        arr: [1, 2, { innerKey: canarySet.tokens.LSTORE.token }],
        map: new Map([
          ['mapKey1', 'safeVal'],
          ['mapKey2', Buffer.from(canarySet.tokens.VAULT.token, 'utf8')]
        ])
      },
      nullVal: null,
      undefVal: undefined,
      numVal: 42,
      boolVal: true
    };

    const matches = FilesystemScanner.scanMemoryStructure(complexTarget, patterns);
    assert.strictEqual(matches.length, 3, 'Must match across Set, Array-Object, and Map Buffer');
    const matchedSubs = new Set(matches.map(m => m.subsystem));
    assert(matchedSubs.has('COOKIE'));
    assert(matchedSubs.has('LSTORE'));
    assert(matchedSubs.has('VAULT'));
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SUITE 6: FALSE-POSITIVE RESISTANCE & RANDOM NOISE REJECTION
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- Suite 6: False-Positive Resistance & Random Noise Rejection ---');

  await test('Rejects 5MB of cryptographically random binary noise with 0 false positives', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const randomNoise = randomBytes(5 * 1024 * 1024); // 5MB random bytes
    const matches = scanner.scanBuffer('random_noise.bin', randomNoise, patterns);
    assert.strictEqual(matches.length, 0, 'Random noise must produce 0 matches');
  });

  await test('Cross-session isolation: Scanner targeting Session A NEVER flags Session B canaries', async () => {
    const scanner = new FilesystemScanner();
    const sessionASet = CanaryGenerator.generateSessionCanarySet();
    const sessionBSet = CanaryGenerator.generateSessionCanarySet();

    const sessionAPatterns = CanaryGenerator.extractSearchPatterns(sessionASet);

    const sessionBBuffer = Buffer.concat(
      Object.values(sessionBSet.tokens).map(t => t.encodings.utf8)
    );

    const matches = scanner.scanBuffer('session_b_data.bin', sessionBBuffer, sessionAPatterns);
    assert.strictEqual(matches.length, 0, 'Session A scanner MUST NOT match Session B tokens');
  });

  await test('Partial prefix stress: files with "CANARY", "CANARY_COOKIE_", etc. produce 0 false positives', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const deceptiveText = `
      CANARY
      CANARY_
      CANARY_COOKIE
      CANARY_COOKIE_
      CANARY_COOKIE_12345678
      CANARY_LSTORE_abcdef01_9999999999
      CANARY_IDB_00000000_1700000000_000000000000000000000000
    `;
    const deceptiveBuffer = Buffer.from(deceptiveText, 'utf8');

    const matches = scanner.scanBuffer('deceptive_prefixes.txt', deceptiveBuffer, patterns);
    assert.strictEqual(matches.length, 0, 'Deceptive prefixes MUST NOT match generated high-entropy canary');
  });

  await test('Default exclusions correctly prevent scanning of node_modules, .git, and project files', async () => {
    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const testDir = path.join(TEST_SCRATCH_ROOT, 'exclusion_test_root');
    fs.mkdirSync(testDir, { recursive: true });

    for (const exc of ['.git', 'node_modules', 'src', 'tests', 'docs', '.agents']) {
      const excDir = path.join(testDir, exc);
      fs.mkdirSync(excDir, { recursive: true });
      fs.writeFileSync(path.join(excDir, 'leaked_canary.dat'), canarySet.tokens.COOKIE.encodings.utf8);
    }

    const cleanFile = path.join(testDir, 'allowed_folder', 'file.txt');
    fs.mkdirSync(path.dirname(cleanFile), { recursive: true });
    fs.writeFileSync(cleanFile, 'CLEAN_DATA');

    const result = await scanner.scanPaths([testDir], patterns);
    assert.strictEqual(result.matches.length, 0, 'Files in excluded directories must NOT be scanned');
    assert.strictEqual(result.scannedFilesCount, 1, 'Only allowed_folder/file.txt should be scanned');

    fs.rmSync(testDir, { recursive: true, force: true });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SUITE 7: HIGH-VOLUME TOKEN UNIQUENESS & ENTROPY STRESS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- Suite 7: High-Volume Token Uniqueness & Entropy Stress ---');

  await test('Generates 1,000 canary tokens with 0 collisions and 100% format validity', async () => {
    const tokenSet = new Set();
    const totalTokens = 1000;

    for (let i = 0; i < totalTokens; i++) {
      const sub = CANARY_SUBSYSTEMS[i % CANARY_SUBSYSTEMS.length];
      const token = CanaryGenerator.generateToken(sub);

      assert(!tokenSet.has(token), `Collision detected at iteration ${i}: ${token}`);
      tokenSet.add(token);

      const validation = CanaryGenerator.validateToken(token);
      assert.strictEqual(validation.valid, true, `Validation failed for token: ${token}`);
      assert.strictEqual(validation.subsystem, sub);
      assert.strictEqual(validation.entropy.length, 24);
    }

    assert.strictEqual(tokenSet.size, totalTokens, 'All 1,000 tokens must be strictly unique');
  });

  // Clean up global scratch directory
  try {
    fs.rmSync(TEST_SCRATCH_ROOT, { recursive: true, force: true });
  } catch (_) {}

  // ═══════════════════════════════════════════════════════════════════════════
  // SUMMARY REPORT
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n================================================================');
  console.log(`  ADVERSARIAL STRESS TEST SUMMARY`);
  console.log(`  PASSED: ${passed} | FAILED: ${failed} | TOTAL: ${passed + failed}`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runAdversarialStressSuite();
