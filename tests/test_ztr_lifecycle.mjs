/**
 * test_ztr_lifecycle.mjs
 * 
 * Comprehensive automated test suite for Zero Trust Rendering (ZTR).
 * Tests all 4 layers of isolation, WebCrypto key wipe, and preference compliance.
 */

import assert from 'assert';
import path from 'path';
import { fileURLToPath } from 'url';
import { ZeroTrustRenderer } from '../src/ztr/ZeroTrustRenderer.mjs';
import { ZTRCryptoVault } from '../src/ztr/ZTRCryptoVault.mjs';
import { ZTRPrefs } from '../src/ztr/ZTRPrefs.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runTests() {
  console.log('🧪 Running Zero Trust Rendering (ZTR) Automated Test Suite...\n');

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
      failed++;
    }
  }

  // --------------------------------------------------------------------------
  // TEST GROUP 1: Layer 4 WebCrypto Ephemeral Key Vault
  // --------------------------------------------------------------------------
  console.log('--- Group 1: WebCrypto Key Vault (Layer 4) ---');

  await test('Generates non-extractable AES-256-GCM key per session UUID', async () => {
    const vault = new ZTRCryptoVault();
    const key = await vault.generateKey('session-1');
    assert.strictEqual(key.type, 'secret');
    assert.strictEqual(key.algorithm.name, 'AES-GCM');
    assert.strictEqual(key.extractable, false, 'Key MUST be non-extractable');
    assert.strictEqual(vault.hasKey('session-1'), true);
  });

  await test('Encrypts and decrypts data correctly with active key', async () => {
    const vault = new ZTRCryptoVault();
    await vault.generateKey('session-2');

    const message = 'sensitive-token-12345';
    const { iv, ciphertext } = await vault.encrypt('session-2', message);
    assert(ciphertext instanceof ArrayBuffer);
    assert(iv instanceof Uint8Array);

    const decryptedBuf = await vault.decrypt('session-2', iv, ciphertext);
    const decryptedText = new TextDecoder().decode(decryptedBuf);
    assert.strictEqual(decryptedText, message);
  });

  await test('Destroys key and prevents decryption post-destruction', async () => {
    const vault = new ZTRCryptoVault();
    await vault.generateKey('session-3');

    const { iv, ciphertext } = await vault.encrypt('session-3', 'secret-data');
    const destroyed = vault.destroyKey('session-3');
    assert.strictEqual(destroyed, true);
    assert.strictEqual(vault.hasKey('session-3'), false);

    await assert.rejects(
      async () => await vault.decrypt('session-3', iv, ciphertext),
      /Active key not found/
    );
  });

  // --------------------------------------------------------------------------
  // TEST GROUP 2: Layer 1 & 2 Ephemeral Containers & Storage Isolation
  // --------------------------------------------------------------------------
  console.log('\n--- Group 2: Ephemeral Containers & Storage Isolation (Layer 1 & 2) ---');

  await test('Assigns unique userContextId and sessionUUID to every new tab', async () => {
    const ztr = new ZeroTrustRenderer();
    const tabA = await ztr.openTab(101, 'https://alpha.org');
    const tabB = await ztr.openTab(102, 'https://alpha.org');

    assert.notStrictEqual(tabA.sessionUUID, tabB.sessionUUID);
    assert.notStrictEqual(tabA.userContextId, tabB.userContextId);
    assert.strictEqual(ztr.isStorageIsolated(101, 102), true);
  });

  await test('Isolates encrypted storage between tabs', async () => {
    const ztr = new ZeroTrustRenderer();
    await ztr.openTab(201);
    await ztr.openTab(202);

    await ztr.setEncryptedStorageItem(201, 'localStorage', 'theme', 'dark-mode');
    await ztr.setEncryptedStorageItem(202, 'localStorage', 'theme', 'light-mode');

    const valA = await ztr.getDecryptedStorageItem(201, 'localStorage', 'theme');
    const valB = await ztr.getDecryptedStorageItem(202, 'localStorage', 'theme');

    assert.strictEqual(valA, 'dark-mode');
    assert.strictEqual(valB, 'light-mode');
  });

  await test('Executes Cryptographic Wipe Protocol on TabClose', async () => {
    const ztr = new ZeroTrustRenderer();
    await ztr.openTab(301);
    await ztr.setEncryptedStorageItem(301, 'cookies', 'auth_session', 'jwt-token-999');

    const closeSummary = await ztr.closeTab(301);
    assert.strictEqual(closeSummary.keyDestroyed, true);
    assert.strictEqual(closeSummary.storagePurged, true);
    assert.strictEqual(closeSummary.status, 'wiped');

    await assert.rejects(
      async () => await ztr.getDecryptedStorageItem(301, 'cookies', 'auth_session'),
      /Cannot read from unsealed\/destroyed tab/
    );
  });

  // --------------------------------------------------------------------------
  // TEST GROUP 3: Layer 3 Preference Auditing
  // --------------------------------------------------------------------------
  console.log('\n--- Group 3: Hardened Preferences Validation (Layer 3) ---');

  await test('Validates Level 9 Sandbox & Fission preferences in ztr-user.js', async () => {
    const userJsPath = path.join(__dirname, '..', 'src', 'ztr', 'ztr-user.js');
    const prefsMap = ZTRPrefs.loadUserJs(userJsPath);
    const result = ZTRPrefs.validatePrefs(prefsMap);

    assert.strictEqual(result.valid, true, `Errors: ${result.errors.join(', ')}`);
    assert.strictEqual(prefsMap.get('security.sandbox.content.level'), 9);
    assert.strictEqual(prefsMap.get('fission.autostart'), true);
    assert.strictEqual(prefsMap.get('browser.cache.disk.enable'), false);
    assert.strictEqual(prefsMap.get('network.cookie.cookieBehavior'), 5);
  });

  // --------------------------------------------------------------------------
  // SUMMARY
  // --------------------------------------------------------------------------
  console.log('\n====================================================');
  console.log(`  RESULTS: ${passed} Passed, ${failed} Failed`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
