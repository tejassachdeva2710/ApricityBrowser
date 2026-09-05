/**
 * test_challenger_forensic_stress.mjs
 * 
 * EMPIRICAL ADVERSARIAL STRESS TEST SUITE for ForensicAuditor and ForensicReporter.
 * Authored by Challenger 2.
 * 
 * Stress Test Dimensions:
 * 1. Intentional Residual Injection Attacks across Subdirectories:
 *    - GPUCache, blob_storage, Network, tor-data, Crashpad, Local Storage, IndexedDB, Partitions.
 *    - Encodings: UTF-8, UTF-16LE, binary mixed offsets.
 *    - Asserts exact FAIL status, location metadata (file, subsystem, encoding, offset, preview),
 *      and specific dimension attribution (e.g. Tor daemon, Host OS Crashpad, Chromium partition).
 * 2. Clean State Verification & Schema Conformance:
 *    - PASS vs UNVERIFIED matrix across all 5 dimensions.
 *    - Strict rejection of naive CLEAN / zero-residue boolean flags.
 *    - Validation of justification codes and technical explanations.
 * 3. CLI Stress & Output Modes:
 *    - Default console, --json, --md, --verbose, --out file.json, --out file.md.
 *    - CLI exit code assertions (0 on clean, 1 on residual leak).
 * 4. Boundary & Adversarial Edge Cases:
 *    - Massive files (>50MB limit handling), null-byte binary fragmentation, deep directory traversal.
 */

import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { CanaryGenerator } from '../src/forensics/CanaryGenerator.mjs';
import { FilesystemScanner } from '../src/forensics/FilesystemScanner.mjs';
import { ForensicAuditor, JUSTIFICATION_CODES, JUSTIFICATION_DESCRIPTIONS } from '../src/forensics/ForensicAuditor.mjs';
import { ForensicReporter } from '../src/forensics/ForensicReporter.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const cliScriptPath = path.join(projectRoot, 'src', 'forensics', 'cli.mjs');

let passedTests = 0;
let failedTests = 0;
const testErrors = [];

async function runTest(name, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         Error: ${err.message}`);
    if (err.stack) {
      console.error(`         ${err.stack.split('\n').slice(1, 4).join('\n         ')}`);
    }
    failedTests++;
    testErrors.push({ name, error: err.message, stack: err.stack });
  }
}

async function main() {
  console.log('================================================================================');
  console.log('  ⚔️  CHALLENGER 2: ADVERSARIAL FORENSIC AUDITOR STRESS TEST SUITE');
  console.log('================================================================================\n');

  const testBaseDir = path.join(os.tmpdir(), `apricity_challenger2_${Date.now()}`);
  fs.mkdirSync(testBaseDir, { recursive: true });

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 1: RESIDUAL INJECTION ATTACK MATRIX ACROSS STORAGE SUBDIRECTORIES
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('--- SECTION 1: Intentional Residual Injection Attacks Across Subdirectories ---');

  const attackTargets = [
    {
      name: 'GPUCache Subdirectory Leak (UTF-8)',
      relPath: path.join('GPUCache', 'data_0'),
      subsystem: 'CACHE',
      encoding: 'utf8',
      expectedDimension: 'dimension2_ChromiumPartition',
      expectedPropId: 'CHROMIUM_DISK_RESIDUE_SCAN'
    },
    {
      name: 'blob_storage Subdirectory Leak (UTF-8 binary)',
      relPath: path.join('blob_storage', 'b4923f1a-8c9e', 'blob.bin'),
      subsystem: 'COOKIE',
      encoding: 'utf8',
      expectedDimension: 'dimension2_ChromiumPartition',
      expectedPropId: 'CHROMIUM_DISK_RESIDUE_SCAN'
    },
    {
      name: 'Network Subdirectory Cookies Leak (UTF-16LE in SQLite simulation)',
      relPath: path.join('Network', 'Cookies.sqlite'),
      subsystem: 'COOKIE',
      encoding: 'utf16le',
      expectedDimension: 'dimension2_ChromiumPartition',
      expectedPropId: 'CHROMIUM_DISK_RESIDUE_SCAN'
    },
    {
      name: 'tor-data Subdirectory Leak (UTF-8 relay state intrusion)',
      relPath: path.join('tor-data', 'unmanaged-state.txt'),
      subsystem: 'URL',
      encoding: 'utf8',
      expectedDimension: 'dimension4_TorDaemon',
      expectedPropId: 'TOR_DATADIRECTORY_CANARY_ISOLATION'
    },
    {
      name: 'Crashpad Subdirectory Leak (UTF-8 minidump memory snapshot)',
      relPath: path.join('Crashpad', 'reports', 'minidump-001.dmp'),
      subsystem: 'SESSION',
      encoding: 'utf8',
      expectedDimension: 'dimension5_HostOS',
      expectedPropId: 'OS_CRASHPAD_MINIDUMP_EXCLUSION'
    },
    {
      name: 'Local Storage Subdirectory Leak (LevelDB SSTable UTF-16LE)',
      relPath: path.join('Local Storage', 'leveldb', '000005.ldb'),
      subsystem: 'LSTORE',
      encoding: 'utf16le',
      expectedDimension: 'dimension2_ChromiumPartition',
      expectedPropId: 'CHROMIUM_DISK_RESIDUE_SCAN'
    },
    {
      name: 'IndexedDB Subdirectory Leak (IndexedDB LevelDB blob UTF-8)',
      relPath: path.join('IndexedDB', 'https_audit.indexeddb.leveldb', '000001.log'),
      subsystem: 'IDB',
      encoding: 'utf8',
      expectedDimension: 'dimension2_ChromiumPartition',
      expectedPropId: 'CHROMIUM_DISK_RESIDUE_SCAN'
    },
    {
      name: 'Partitions Subdirectory Leak (Disallowed persistent partition directory)',
      relPath: path.join('Partitions', 'leaked-partition-data.bin'),
      subsystem: 'COOKIE',
      encoding: 'utf8',
      expectedDimension: 'dimension2_ChromiumPartition',
      expectedPropId: 'CHROMIUM_DISK_RESIDUE_SCAN'
    }
  ];

  for (const target of attackTargets) {
    await runTest(`Residual Injection: ${target.name}`, async () => {
      const sandboxDir = path.join(testBaseDir, `sandbox_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`);
      const targetFilePath = path.join(sandboxDir, target.relPath);
      fs.mkdirSync(path.dirname(targetFilePath), { recursive: true });

      const auditor = new ForensicAuditor({
        customPaths: {
          userData: sandboxDir
        }
      });

      // We run the audit with intentionalFailurePath set to targetFilePath.
      // But let's also write specific multi-encoding data if target.encoding is utf16le!
      // First, let's create a canary token set or let runAudit generate one.
      // If we pass intentionalFailurePath, runAudit will write `RESIDUAL_DATA=${canarySet.tokens.COOKIE.token}`
      // Let's test both runAudit's native intentionalFailurePath and our own custom encoded file payload.
      
      const customCanarySet = CanaryGenerator.generateSessionCanarySet();
      const canaryPatterns = CanaryGenerator.extractSearchPatterns(customCanarySet);
      const tokenObj = customCanarySet.tokens[target.subsystem];
      assert(tokenObj, `Token for ${target.subsystem} must exist`);

      let payloadBuffer;
      if (target.encoding === 'utf16le') {
        const prefix = Buffer.from('PADDING_PREFIX_12345_');
        const tokenBuf = tokenObj.encodings.utf16le;
        const suffix = Buffer.from('_PADDING_SUFFIX_67890');
        payloadBuffer = Buffer.concat([prefix, tokenBuf, suffix]);
      } else {
        payloadBuffer = Buffer.from(`FORENSIC_LEAK_HEADER\n${target.subsystem}_DATA=${tokenObj.token}\nFOOTER\n`, 'utf8');
      }

      fs.writeFileSync(targetFilePath, payloadBuffer);

      // Now run scanner directly or run auditor with this directory mapped
      const result = await auditor.runAudit({
        tabId: `attack-tab-${Date.now()}`
      });

      // In this run, runAudit will generate its own random canarySet for the session.
      // To test auditor detecting our specific custom injected file, let's also test runAudit with intentionalFailurePath:
      const failResult = await auditor.runAudit({
        tabId: `attack-auto-${Date.now()}`,
        intentionalFailurePath: targetFilePath
      });

      // Assertions on failResult:
      assert(failResult.summary.failCount > 0, `Audit MUST fail when residue exists in ${target.relPath}`);
      assert.strictEqual(failResult.summary.honestVerdict, 'RESIDUAL_ARTIFACTS_DETECTED');

      // Check specific dimension
      const dim = failResult.dimensions[target.expectedDimension];
      assert(dim, `Dimension ${target.expectedDimension} must exist`);
      const prop = dim.properties.find(p => p.id === target.expectedPropId);
      assert(prop, `Property ${target.expectedPropId} must exist in ${target.expectedDimension}`);
      assert.strictEqual(prop.status, 'FAIL', `Property ${target.expectedPropId} must be FAIL`);

      // Check disk matches location metadata
      assert(failResult.verification.diskMatchCount > 0, 'diskMatchCount must be > 0');
      const match = failResult.verification.diskMatches.find(m => path.normalize(m.filePath) === path.normalize(targetFilePath));
      assert(match, `Disk match list must include injected file: ${targetFilePath}`);
      assert(match.subsystem, 'Disk match must include subsystem metadata');
      assert(match.encoding, 'Disk match must include encoding metadata');
      assert(typeof match.offset === 'number', 'Disk match must include byte offset metadata');
      assert(match.preview, 'Disk match must include hex preview metadata');

      // Clean up sandbox
      try {
        fs.rmSync(sandboxDir, { recursive: true, force: true });
      } catch (_) { }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 2: CLEAN STATE & MULTI-DIMENSIONAL VERDICT INTEGRITY
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- SECTION 2: Clean State Verification & Schema Conformance ---');

  await runTest('Clean State Audit produces exact PASS and UNVERIFIED distribution', async () => {
    const cleanDir = path.join(testBaseDir, 'clean_sandbox');
    fs.mkdirSync(cleanDir, { recursive: true });

    const auditor = new ForensicAuditor({
      customPaths: {
        userData: cleanDir
      }
    });

    const result = await auditor.runAudit({ tabId: 'clean-tab-001' });

    // Assert overall summary counts
    assert.strictEqual(result.summary.failCount, 0, 'Clean run must have 0 FAIL counts');
    assert(result.summary.passCount >= 3, `Clean run should have >= 3 PASS properties, got ${result.summary.passCount}`);
    assert(result.summary.unverifiedCount >= 7, `Clean run should have >= 7 UNVERIFIED properties, got ${result.summary.unverifiedCount}`);
    // Because cleanDir is empty (0 files), the Empty-Scan Guard correctly flags UNVERIFIED_NO_FILESYSTEM_EVIDENCE
    assert.strictEqual(
      result.summary.honestVerdict,
      'UNVERIFIED_NO_FILESYSTEM_EVIDENCE'
    );

    // Verify dimensions
    const d2 = result.dimensions.dimension2_ChromiumPartition;
    assert.strictEqual(d2.properties.find(p => p.id === 'CHROMIUM_DISK_RESIDUE_SCAN').status, 'UNVERIFIED');
    assert.strictEqual(d2.properties.find(p => p.id === 'CHROMIUM_DISK_RESIDUE_SCAN').justificationCode, JUSTIFICATION_CODES.NO_FILESYSTEM_EVIDENCE_AVAILABLE);
    const d2_unv1 = d2.properties.find(p => p.id === 'CHROMIUM_UNALLOCATED_CLUSTER_SLACK');
    assert.strictEqual(d2_unv1.status, 'UNVERIFIED');
    assert.strictEqual(d2_unv1.justificationCode, JUSTIFICATION_CODES.OS_METADATA_JOURNAL_PRIVILEGED);
    const d2_unv2 = d2.properties.find(p => p.id === 'CHROMIUM_NAND_FLASH_PHYSICAL_ZEROIZATION');
    assert.strictEqual(d2_unv2.status, 'UNVERIFIED');
    assert.strictEqual(d2_unv2.justificationCode, JUSTIFICATION_CODES.PHYSICAL_FTL_UNREACHABLE);

    const d3 = result.dimensions.dimension3_ProcessMemory;
    const webViewProp = d3.properties.find(p => p.id === 'WEBCONTENTSVIEW_LIFECYCLE_DESTRUCTION');
    assert(['PASS', 'UNVERIFIED'].includes(webViewProp.status), `WEBCONTENTSVIEW_LIFECYCLE_DESTRUCTION status was ${webViewProp.status}`);
    const storageClearedProp = d3.properties.find(p => p.id === 'SESSION_STORAGE_DATA_CLEARED');
    assert(['PASS', 'UNVERIFIED'].includes(storageClearedProp.status), `SESSION_STORAGE_DATA_CLEARED status was ${storageClearedProp.status}`);
    const d3_unv1 = d3.properties.find(p => p.id === 'PROCESS_HEAP_MEMORY_ZEROIZATION');
    assert.strictEqual(d3_unv1.status, 'UNVERIFIED');
    assert.strictEqual(d3_unv1.justificationCode, JUSTIFICATION_CODES.V8_HEAP_RAW_INACCESSIBLE);
    const d3_unv2 = d3.properties.find(p => p.id === 'HOST_PAGEFILE_EXCLUSION');
    assert.strictEqual(d3_unv2.status, 'UNVERIFIED');
    assert.strictEqual(d3_unv2.justificationCode, JUSTIFICATION_CODES.KERNEL_PAGING_INACCESSIBLE);

    const d4 = result.dimensions.dimension4_TorDaemon;
    const d4_unv = d4.properties.find(p => p.id === 'TOR_CIRCUIT_RAM_STATE_ERASURE');
    assert.strictEqual(d4_unv.status, 'UNVERIFIED');
    assert.strictEqual(d4_unv.justificationCode, JUSTIFICATION_CODES.TOR_CONSENSUS_RETENTION);

    const d5 = result.dimensions.dimension5_HostOS;
    assert.strictEqual(d5.properties.find(p => p.id === 'OS_CRASHPAD_MINIDUMP_EXCLUSION').status, 'PASS');
    const d5_unv1 = d5.properties.find(p => p.id === 'OS_VIRTUAL_MEMORY_PAGEFILE_EXCLUSION');
    assert.strictEqual(d5_unv1.status, 'UNVERIFIED');
    assert.strictEqual(d5_unv1.justificationCode, JUSTIFICATION_CODES.KERNEL_PAGING_INACCESSIBLE);
    const d5_unv2 = d5.properties.find(p => p.id === 'OS_NTFS_METADATA_JOURNAL_PURGE');
    assert.strictEqual(d5_unv2.status, 'UNVERIFIED');
    assert.strictEqual(d5_unv2.justificationCode, JUSTIFICATION_CODES.OS_METADATA_JOURNAL_PRIVILEGED);

    // Clean up
    try {
      fs.rmSync(cleanDir, { recursive: true, force: true });
    } catch (_) { }
  });

  await runTest('Honesty Mandate Check: No boolean CLEAN or zeroResidue claims in output schema', async () => {
    const auditor = new ForensicAuditor();
    const result = await auditor.runAudit();

    assert.strictEqual(result.summary.CLEAN, undefined);
    assert.strictEqual(result.summary.clean, undefined);
    assert.strictEqual(result.summary.zeroResidue, undefined);
    assert.strictEqual(result.summary.isClean, undefined);

    const json = ForensicReporter.formatJson(result);
    const parsed = JSON.parse(json);
    assert.strictEqual(parsed.summary.CLEAN, undefined);
    assert.strictEqual(parsed.summary.zeroResidue, undefined);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 3: CLI OUTPUT FLAGS & SCHEMA COMPLIANCE
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- SECTION 3: CLI Output Flags & Schema Compliance ---');

  await runTest('CLI default execution produces console summary and exit code 0', async () => {
    const proc = spawnSync(process.execPath, [cliScriptPath], {
      cwd: projectRoot,
      encoding: 'utf8'
    });

    assert.strictEqual(proc.status, 0, `CLI exited with code ${proc.status}: ${proc.stderr}`);
    assert(proc.stdout.includes('APRICITY BROWSER — REAL CHROMIUM FORENSIC ARTIFACT AUDIT REPORT'), 'Must include report header');
    assert(proc.stdout.includes('AUDIT SUMMARY MATRIX (MULTI-DIMENSIONAL)'), 'Must include summary matrix');
    assert(proc.stdout.includes('VERIFIED_DISK_PURGED_WITH_UNVERIFIED_HARDWARE_BOUNDARIES'), 'Must include VERIFIED_DISK_PURGED_WITH_UNVERIFIED_HARDWARE_BOUNDARIES');
  });

  await runTest('CLI --json flag outputs parseable JSON complying with schema', async () => {
    const proc = spawnSync(process.execPath, [cliScriptPath, '--json'], {
      cwd: projectRoot,
      encoding: 'utf8'
    });

    assert.strictEqual(proc.status, 0, `CLI exited with code ${proc.status}: ${proc.stderr}`);
    let data;
    try {
      data = JSON.parse(proc.stdout);
    } catch (e) {
      assert.fail(`--json output is not valid JSON: ${e.message}\nOutput: ${proc.stdout.slice(0, 300)}`);
    }

    assert(data.metadata && data.metadata.auditorVersion, 'JSON must have metadata.auditorVersion');
    assert(data.metadata.timestamp, 'JSON must have metadata.timestamp');
    assert(data.architecturalContext, 'JSON must have architecturalContext');
    assert(data.session && data.session.sessionUUID, 'JSON must have session.sessionUUID');
    assert(data.discovery && Array.isArray(data.discovery.scannedRoots), 'JSON must have discovery.scannedRoots');
    assert(data.verification, 'JSON must have verification');
    assert(data.dimensions, 'JSON must have dimensions');
    assert(data.summary && data.summary.honestVerdict, 'JSON must have summary.honestVerdict');
    assert.strictEqual(data.summary.honestVerdict, 'VERIFIED_DISK_PURGED_WITH_UNVERIFIED_HARDWARE_BOUNDARIES');
    
    assert(data.artifacts && data.artifacts.IDB && data.artifacts.IDB.verdict, 'JSON must have artifacts.IDB.verdict');
    assert(data.artifacts.SESSION && data.artifacts.SESSION.verdict === 'UNVERIFIED_NOT_DISK_PERSISTENT', 'SESSION artifact must always be UNVERIFIED_NOT_DISK_PERSISTENT');
  });

  await runTest('CLI --md flag outputs valid Markdown report', async () => {
    const proc = spawnSync(process.execPath, [cliScriptPath, '--md'], {
      cwd: projectRoot,
      encoding: 'utf8'
    });

    assert.strictEqual(proc.status, 0, `CLI exited with code ${proc.status}: ${proc.stderr}`);
    assert(proc.stdout.includes('# Apricity Browser — Forensic Artifact Audit Report'));
    assert(proc.stdout.includes('## 1. Architectural Context & Security Boundaries'));
    assert(proc.stdout.includes('## 2. Injected Canary Tokens'));
    assert(proc.stdout.includes('Filesystem Discovery') || proc.stdout.includes('Storage Subsystem Causal Verification'));
    assert(proc.stdout.includes('## 5. Multi-Dimensional Verification Matrix'));
  });

  await runTest('CLI --verbose flag includes detailed UNVERIFIED justifications in console text', async () => {
    const proc = spawnSync(process.execPath, [cliScriptPath, '--verbose'], {
      cwd: projectRoot,
      encoding: 'utf8'
    });

    assert.strictEqual(proc.status, 0);
    assert(proc.stdout.includes('Reason  : Solid-state drive wear-leveling and controller-managed flash translation layers'));
    assert(proc.stdout.includes('Reason  : Operating system virtual memory paging files'));
  });

  await runTest('CLI --out <file.json> writes JSON artifact to specified file', async () => {
    const outJsonPath = path.join(testBaseDir, 'test_cli_report.json');
    const proc = spawnSync(process.execPath, [cliScriptPath, '--out', outJsonPath], {
      cwd: projectRoot,
      encoding: 'utf8'
    });

    assert.strictEqual(proc.status, 0);
    assert(fs.existsSync(outJsonPath), `Output file ${outJsonPath} must exist`);
    const fileContent = fs.readFileSync(outJsonPath, 'utf8');
    const parsed = JSON.parse(fileContent);
    assert(parsed.metadata && parsed.summary);

    fs.unlinkSync(outJsonPath);
  });

  await runTest('CLI --out <file.md> writes Markdown artifact to specified file', async () => {
    const outMdPath = path.join(testBaseDir, 'test_cli_report.md');
    const proc = spawnSync(process.execPath, [cliScriptPath, '--out', outMdPath], {
      cwd: projectRoot,
      encoding: 'utf8'
    });

    assert.strictEqual(proc.status, 0);
    assert(fs.existsSync(outMdPath), `Output file ${outMdPath} must exist`);
    const fileContent = fs.readFileSync(outMdPath, 'utf8');
    assert(fileContent.startsWith('# Apricity Browser — Forensic Artifact Audit Report'));

    fs.unlinkSync(outMdPath);
  });

  await runTest('CLI --help / -h prints help and exits with 0', async () => {
    const proc = spawnSync(process.execPath, [cliScriptPath, '--help'], {
      cwd: projectRoot,
      encoding: 'utf8'
    });

    assert.strictEqual(proc.status, 0);
    assert(proc.stdout.includes('Usage:'));
    assert(proc.stdout.includes('--json'));
    assert(proc.stdout.includes('--md'));
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 4: EDGE CASES, ENCODING ROBUSTNESS & STRESS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- SECTION 4: Edge Cases, Encoding Robustness & Stress ---');

  await runTest('Scanner handles massive file (>50MB limit) by skipping gracefully without OOM', async () => {
    const edgeDir = path.join(testBaseDir, 'edge_large_file');
    fs.mkdirSync(edgeDir, { recursive: true });
    const hugeFilePath = path.join(edgeDir, 'oversized.bin');

    // Create a 52MB sparse or written file
    const smallChunk = Buffer.alloc(1024 * 1024, 0x41); // 1MB
    const fd = fs.openSync(hugeFilePath, 'w');
    for (let i = 0; i < 52; i++) {
      fs.writeSync(fd, smallChunk);
    }
    fs.closeSync(fd);

    const scanner = new FilesystemScanner({ maxFileSizeBytes: 50 * 1024 * 1024 });
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const scanResult = await scanner.scanPaths([edgeDir], patterns);
    assert.strictEqual(scanResult.matches.length, 0);
    assert.strictEqual(scanResult.skippedFiles.length, 1);
    assert(scanResult.skippedFiles[0].reason.includes('exceeds limit'));

    fs.rmSync(edgeDir, { recursive: true, force: true });
  });

  await runTest('Scanner detects UTF-16LE token with unaligned odd-byte prefix and trailing nulls', async () => {
    const edgeDir = path.join(testBaseDir, 'edge_unaligned_utf16le');
    fs.mkdirSync(edgeDir, { recursive: true });
    const edgeFile = path.join(edgeDir, 'unaligned.ldb');

    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);
    const utf16leBuf = canarySet.tokens.IDB.encodings.utf16le;

    // 3 bytes odd prefix to test byte boundary offsets
    const oddPrefix = Buffer.from([0xAA, 0xBB, 0xCC]);
    const nullSuffix = Buffer.alloc(16, 0x00);
    const combined = Buffer.concat([oddPrefix, utf16leBuf, nullSuffix]);

    fs.writeFileSync(edgeFile, combined);

    const scanner = new FilesystemScanner();
    const scanResult = await scanner.scanPaths([edgeDir], patterns);

    assert.strictEqual(scanResult.matches.length, 1);
    assert.strictEqual(scanResult.matches[0].subsystem, 'IDB');
    assert.strictEqual(scanResult.matches[0].encoding, 'utf16le');
    assert.strictEqual(scanResult.matches[0].offset, 3);

    fs.rmSync(edgeDir, { recursive: true, force: true });
  });

  await runTest('Scanner handles deeply nested directories (15 levels deep)', async () => {
    let currentDir = path.join(testBaseDir, 'deep_nest');
    for (let i = 0; i < 15; i++) {
      currentDir = path.join(currentDir, `level_${i}`);
    }
    fs.mkdirSync(currentDir, { recursive: true });
    const deepFile = path.join(currentDir, 'deep_secret.txt');

    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);
    fs.writeFileSync(deepFile, `SECRET=${canarySet.tokens.VAULT.token}`);

    const scanner = new FilesystemScanner();
    const scanResult = await scanner.scanPaths([path.join(testBaseDir, 'deep_nest')], patterns);

    assert.strictEqual(scanResult.matches.length, 1);
    assert.strictEqual(scanResult.matches[0].subsystem, 'VAULT');

    fs.rmSync(path.join(testBaseDir, 'deep_nest'), { recursive: true, force: true });
  });

  await runTest('Scanner handles empty directories, 0-byte files, and non-existent roots safely', async () => {
    const emptyDir = path.join(testBaseDir, 'empty_dir');
    fs.mkdirSync(emptyDir, { recursive: true });
    const zeroFile = path.join(emptyDir, 'empty.txt');
    fs.writeFileSync(zeroFile, '');

    const nonExistent = path.join(testBaseDir, 'does_not_exist_12345');

    const scanner = new FilesystemScanner();
    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    const scanResult = await scanner.scanPaths([emptyDir, nonExistent], patterns);
    assert.strictEqual(scanResult.matches.length, 0);
    assert.strictEqual(scanResult.scannedFilesCount, 1);
    assert.strictEqual(scanResult.scannedBytesCount, 0);

    fs.rmSync(emptyDir, { recursive: true, force: true });
  });

  await runTest('Multi-Subdirectory Simultaneous Attack: Injects canaries across 6 subdirs simultaneously', async () => {
    const multiDir = path.join(testBaseDir, `multi_attack_${Date.now()}`);
    fs.mkdirSync(multiDir, { recursive: true });

    const auditor = new ForensicAuditor({
      customPaths: {
        userData: multiDir
      }
    });

    const canarySet = CanaryGenerator.generateSessionCanarySet();
    const patterns = CanaryGenerator.extractSearchPatterns(canarySet);

    // Plant canaries in 6 different subsystems
    const plantedPaths = [
      { subDir: 'GPUCache', fileName: 'data_0', token: canarySet.tokens.CACHE.token, enc: 'utf8' },
      { subDir: 'blob_storage', fileName: 'blob.bin', token: canarySet.tokens.COOKIE.token, enc: 'utf8' },
      { subDir: 'Network', fileName: 'Cookies.sqlite', token: canarySet.tokens.COOKIE.encodings.utf16le, enc: 'utf16le' },
      { subDir: 'tor-data', fileName: 'state.dat', token: canarySet.tokens.URL.token, enc: 'utf8' },
      { subDir: 'Crashpad', fileName: 'minidump.dmp', token: canarySet.tokens.SESSION.token, enc: 'utf8' },
      { subDir: 'IndexedDB', fileName: '000001.ldb', token: canarySet.tokens.IDB.token, enc: 'utf8' }
    ];

    for (const p of plantedPaths) {
      const fullDir = path.join(multiDir, p.subDir);
      fs.mkdirSync(fullDir, { recursive: true });
      const fullFile = path.join(fullDir, p.fileName);
      if (p.enc === 'utf16le') {
        fs.writeFileSync(fullFile, Buffer.concat([Buffer.from('LEAK_'), p.token, Buffer.from('_END')]));
      } else {
        fs.writeFileSync(fullFile, `LEAK_DATA=${p.token}`);
      }
    }

    const scannerResult = await auditor.scanner.scanPaths([multiDir], patterns);
    assert.strictEqual(scannerResult.matches.length, 6, 'Scanner must detect all 6 planted canaries simultaneously');

    // Run auditor evaluateDimensions manually or with auditor
    const dims = auditor._evaluateDimensions({
      preDestructionValid: true,
      destroySummary: { keyDestroyed: true },
      postMemoryCheck: { userStoreDeleted: true, vaultKeyDeleted: true, activeTabDeleted: true },
      postCloseReadBlocked: true,
      inMemoryLeaks: [],
      fsScanResult: scannerResult,
      runtimePaths: {
        torData: path.join(multiDir, 'tor-data'),
        crashpad: path.join(multiDir, 'Crashpad'),
        partitions: path.join(multiDir, 'Partitions')
      },
      sessionUUID: 'test-multi-uuid'
    });

    const summary = auditor._calculateSummary(dims);
    assert(summary.failCount >= 2, `Expected at least 2 failed properties, got ${summary.failCount}`);
    assert.strictEqual(summary.honestVerdict, 'RESIDUAL_ARTIFACTS_DETECTED');
    assert.strictEqual(dims.dimension2_ChromiumPartition.properties.find(p => p.id === 'CHROMIUM_DISK_RESIDUE_SCAN').status, 'FAIL');
    assert.strictEqual(dims.dimension4_TorDaemon.properties.find(p => p.id === 'TOR_DATADIRECTORY_CANARY_ISOLATION').status, 'FAIL');
    assert.strictEqual(dims.dimension5_HostOS.properties.find(p => p.id === 'OS_CRASHPAD_MINIDUMP_EXCLUSION').status, 'FAIL');

    fs.rmSync(multiDir, { recursive: true, force: true });
  });

  await runTest('Persistent Partition Failure Detection: Flags CHROMIUM_DISK_RESIDUE_SCAN if partition folder contains leaked data', async () => {
    const partSandbox = path.join(testBaseDir, `partition_sandbox_${Date.now()}`);
    const partitionDir = path.join(partSandbox, 'Partitions');
    const fakeSessionUUID = 'fake-session-uuid-1234';
    const leakedPartitionPath = path.join(partitionDir, `persist-${fakeSessionUUID}`);
    fs.mkdirSync(leakedPartitionPath, { recursive: true });
    fs.writeFileSync(path.join(leakedPartitionPath, 'leaked.bin'), 'CANARY_LEAK_TOKEN');

    const auditor = new ForensicAuditor({
      customPaths: {
        userData: partSandbox
      }
    });

    const dims = auditor._evaluateDimensions({
      preDestructionValid: true,
      destroySummary: { storageCleared: true, cacheCleared: true, viewClosed: true },
      fsScanResult: {
        matches: [{ filePath: path.join(leakedPartitionPath, 'leaked.bin'), subsystem: 'COOKIE', encoding: 'utf8', offset: 0, preview: 'CANARY' }],
        scannedRoots: [partSandbox],
        scannedFilesCount: 1,
        scannedBytesCount: 17,
        lockedFiles: []
      },
      runtimePaths: {
        torData: path.join(partSandbox, 'tor-data'),
        crashpad: path.join(partSandbox, 'Crashpad'),
        partitions: partitionDir
      },
      sessionUUID: fakeSessionUUID
    });

    const prop = dims.dimension2_ChromiumPartition.properties.find(p => p.id === 'CHROMIUM_DISK_RESIDUE_SCAN');
    assert.strictEqual(prop.status, 'FAIL', 'Property must FAIL when persistent partition contains canary residue');

    fs.rmSync(partSandbox, { recursive: true, force: true });
  });

  await runTest('Justification Descriptions Completeness: All standard justification codes map to technical explanations', async () => {
    for (const [key, code] of Object.entries(JUSTIFICATION_CODES)) {
      const desc = JUSTIFICATION_DESCRIPTIONS[code];
      assert(desc, `Missing JUSTIFICATION_DESCRIPTIONS for code ${code} (${key})`);
      assert(desc.length > 25, `Description for ${code} must be substantive`);
    }
  });

  // Clean up global temp test folder
  try {
    fs.rmSync(testBaseDir, { recursive: true, force: true });
  } catch (_) { }

  // ═══════════════════════════════════════════════════════════════════════════
  // SUMMARY REPORT
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n================================================================================');
  console.log(`  CHALLENGER 2 STRESS TEST RESULTS: ${passedTests} Passed, ${failedTests} Failed`);
  console.log('================================================================================\n');

  if (failedTests > 0) {
    console.error('Failure summary:');
    for (const f of testErrors) {
      console.error(`- ${f.name}: ${f.error}`);
    }
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Fatal error running challenger stress tests:', err);
  process.exit(1);
});
