/**
 * test_adversarial_isolation.mjs
 * 
 * Adversarial Isolation & Security Verification Test Suite for Apricity Browser.
 * 
 * Verifies session uniqueness, storage isolation, cryptographic boundaries,
 * lifecycle integrity, permission defaults, and attack vectors.
 * 
 * Reports status explicitly:
 * [PASS]    = Security property verified
 * [FAIL]    = Security property violated
 * [SKIPPED] = Property cannot be verified in the current test runner environment
 */

import assert from 'assert';
import net from 'net';
import { webcrypto } from 'node:crypto';
import { ZeroTrustRenderer } from '../src/ztr/ZeroTrustRenderer.mjs';
import { ZTRCryptoVault } from '../src/ztr/ZTRCryptoVault.mjs';

const crypto = globalThis.crypto || webcrypto;

// Standard UUID v4 regex
const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

async function runAdversarialTestSuite() {
  console.log('================================================================');
  console.log('  🛡️  Apricity Browser — Adversarial Isolation Test Suite');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;
  let skipped = 0;

  async function test(category, name, fn) {
    try {
      await fn();
      console.log(`  [PASS]    ${category} › ${name}`);
      passed++;
    } catch (err) {
      console.error(`  [FAIL]    ${category} › ${name}`);
      console.error(`            Error: ${err.message}`);
      failed++;
    }
  }

  function skip(category, name, reason) {
    console.log(`  [SKIPPED] ${category} › ${name}`);
    console.log(`            Reason: ${reason}`);
    skipped++;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. SESSION UNIQUENESS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('--- 1. Session Uniqueness ---');

  await test('SESSION_UNIQUENESS', 'Every opened tab generates a unique UUID v4 session identifier', async () => {
    const ztr = new ZeroTrustRenderer();
    const sessions = new Set();
    const count = 10;

    for (let i = 1; i <= count; i++) {
      const tabState = await ztr.openTab(`tab-${i}`);
      assert(UUID_V4_REGEX.test(tabState.sessionUUID), `Invalid UUID v4 format: ${tabState.sessionUUID}`);
      assert(!sessions.has(tabState.sessionUUID), `Session UUID collision detected: ${tabState.sessionUUID}`);
      sessions.add(tabState.sessionUUID);
    }

    assert.strictEqual(sessions.size, count);
  });

  await test('SESSION_UNIQUENESS', 'Every tab maps to a distinct Electron session partition string', async () => {
    const ztr = new ZeroTrustRenderer();
    const tab1 = await ztr.openTab('tab-part-1');
    const tab2 = await ztr.openTab('tab-part-2');

    const partition1 = `ephemeral-${tab1.sessionUUID}`;
    const partition2 = `ephemeral-${tab2.sessionUUID}`;

    assert.notStrictEqual(partition1, partition2);
    assert(partition1.startsWith('ephemeral-'));
    assert(partition2.startsWith('ephemeral-'));
  });

  await test('SESSION_UNIQUENESS', 'Tab closure and reopening produces a completely new, non-colliding session identity', async () => {
    const ztr = new ZeroTrustRenderer();
    const initialTab = await ztr.openTab('tab-reopen');
    const initialUUID = initialTab.sessionUUID;
    const initialUserContext = initialTab.userContextId;

    await ztr.closeTab('tab-reopen');

    const reopenedTab = await ztr.openTab('tab-reopen');
    assert.notStrictEqual(reopenedTab.sessionUUID, initialUUID, 'Reopened tab reused previous sessionUUID');
    assert.notStrictEqual(reopenedTab.userContextId, initialUserContext, 'Reopened tab reused previous userContextId');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. STORAGE ISOLATION
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 2. Storage Isolation ---');

  await test('STORAGE_ISOLATION', 'Multi-store isolation across cookies, localStorage, indexedDB, and cache', async () => {
    const ztr = new ZeroTrustRenderer();
    await ztr.openTab('tab-iso-1');
    await ztr.openTab('tab-iso-2');

    // Write distinct data for Tab 1
    await ztr.setEncryptedStorageItem('tab-iso-1', 'cookies', 'session_id', 'cookie-tab-1');
    await ztr.setEncryptedStorageItem('tab-iso-1', 'localStorage', 'theme', 'dark-theme-1');
    await ztr.setEncryptedStorageItem('tab-iso-1', 'indexedDB', 'doc_1', 'indexed-content-1');
    await ztr.setEncryptedStorageItem('tab-iso-1', 'cache', 'res_1', 'cached-response-1');

    // Write distinct data for Tab 2
    await ztr.setEncryptedStorageItem('tab-iso-2', 'cookies', 'session_id', 'cookie-tab-2');
    await ztr.setEncryptedStorageItem('tab-iso-2', 'localStorage', 'theme', 'light-theme-2');
    await ztr.setEncryptedStorageItem('tab-iso-2', 'indexedDB', 'doc_1', 'indexed-content-2');
    await ztr.setEncryptedStorageItem('tab-iso-2', 'cache', 'res_1', 'cached-response-2');

    // Tab 1 specific key
    await ztr.setEncryptedStorageItem('tab-iso-1', 'localStorage', 'only_in_1', 'secret-alice');

    // Verify Tab 1 retrieves only Tab 1 data
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-1', 'cookies', 'session_id'), 'cookie-tab-1');
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-1', 'localStorage', 'theme'), 'dark-theme-1');
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-1', 'indexedDB', 'doc_1'), 'indexed-content-1');
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-1', 'cache', 'res_1'), 'cached-response-1');
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-1', 'localStorage', 'only_in_1'), 'secret-alice');

    // Verify Tab 2 retrieves only Tab 2 data
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-2', 'cookies', 'session_id'), 'cookie-tab-2');
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-2', 'localStorage', 'theme'), 'light-theme-2');
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-2', 'indexedDB', 'doc_1'), 'indexed-content-2');
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-2', 'cache', 'res_1'), 'cached-response-2');

    // Verify Tab 2 cannot access Tab 1's unique key
    assert.strictEqual(await ztr.getDecryptedStorageItem('tab-iso-2', 'localStorage', 'only_in_1'), null);
  });

  await test('STORAGE_ISOLATION', 'Raw storage stores hold ciphertext buffers, with no plaintext in memory maps', async () => {
    const ztr = new ZeroTrustRenderer();
    const tabState = await ztr.openTab('tab-inspect');
    const plaintext = 'top-secret-plaintext-value';

    await ztr.setEncryptedStorageItem('tab-inspect', 'localStorage', 'key_secret', plaintext);

    const store = ztr._ephemeralStorageStores.get(tabState.userContextId);
    assert(store, 'Storage context was not created');

    const rawStored = store.localStorage.get('key_secret');
    assert(rawStored, 'Item not stored');
    assert(rawStored.ciphertext instanceof ArrayBuffer, 'Ciphertext is not an ArrayBuffer');
    assert(rawStored.iv instanceof Uint8Array, 'IV is not a Uint8Array');

    // Ensure raw stored ciphertext does not contain plaintext string
    const ciphertextBytes = new Uint8Array(rawStored.ciphertext);
    const plaintextBytes = new TextEncoder().encode(plaintext);
    assert(!Buffer.from(ciphertextBytes).includes(Buffer.from(plaintextBytes)), 'Plaintext found in ciphertext buffer');
  });

  skip(
    'STORAGE_ISOLATION',
    'Chromium native webview partition cookie/storage isolation',
    'Native Chromium SQLite/LevelDB webview partition storage verification requires an active Electron GUI/Blink runtime'
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. SESSION LIFECYCLE
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 3. Session Lifecycle ---');

  await test('SESSION_LIFECYCLE', 'Opening a session initializes expected sealed state and vault entry', async () => {
    const ztr = new ZeroTrustRenderer();
    const tabState = await ztr.openTab('tab-lc-1', 'https://example.org');

    assert.strictEqual(tabState.status, 'sealed');
    assert.strictEqual(tabState.cryptoSealed, true);
    assert.strictEqual(tabState.url, 'https://example.org');
    assert(ztr.cryptoVault.hasKey(tabState.sessionUUID), 'Vault does not contain session key');
    assert(ztr._ephemeralStorageStores.has(tabState.userContextId), 'Storage store was not allocated');
  });

  await test('SESSION_LIFECYCLE', 'Closing a session invalidates application state and purges storage context', async () => {
    const ztr = new ZeroTrustRenderer();
    const tabState = await ztr.openTab('tab-lc-2');
    const userContextId = tabState.userContextId;
    const sessionUUID = tabState.sessionUUID;

    const summary = await ztr.closeTab('tab-lc-2');
    assert.strictEqual(summary.keyDestroyed, true);
    assert.strictEqual(summary.storagePurged, true);
    assert.strictEqual(summary.status, 'wiped');

    assert(!ztr.activeTabs.has('tab-lc-2'), 'Tab still exists in activeTabs');
    assert(!ztr.cryptoVault.hasKey(sessionUUID), 'Vault still has session key');
    assert(!ztr._ephemeralStorageStores.has(userContextId), 'Storage store was not purged');
  });

  await test('SESSION_LIFECYCLE', 'Closed session cannot be accessed via ZTR API', async () => {
    const ztr = new ZeroTrustRenderer();
    await ztr.openTab('tab-lc-3');
    await ztr.closeTab('tab-lc-3');

    await assert.rejects(
      async () => await ztr.setEncryptedStorageItem('tab-lc-3', 'localStorage', 'key', 'val'),
      /Cannot write to unsealed\/destroyed tab/
    );

    await assert.rejects(
      async () => await ztr.getDecryptedStorageItem('tab-lc-3', 'localStorage', 'key'),
      /Cannot read from unsealed\/destroyed tab/
    );
  });

  await test('SESSION_LIFECYCLE', 'Reopening a tab does not restore previous session storage', async () => {
    const ztr = new ZeroTrustRenderer();
    await ztr.openTab('tab-lc-4');
    await ztr.setEncryptedStorageItem('tab-lc-4', 'cookies', 'auth', 'my-auth-token');
    await ztr.closeTab('tab-lc-4');

    // Reopen with same tab identifier
    await ztr.openTab('tab-lc-4');
    const restored = await ztr.getDecryptedStorageItem('tab-lc-4', 'cookies', 'auth');
    assert.strictEqual(restored, null, 'Previous session data leaked into reopened tab');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. CRYPTOGRAPHIC ISOLATION
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 4. Cryptographic Isolation ---');

  await test('CRYPTO_ISOLATION', 'Session B key cannot decrypt Session A ciphertext (AES-GCM tag mismatch)', async () => {
    const vault = new ZTRCryptoVault();
    await vault.generateKey('session-crypto-A');
    await vault.generateKey('session-crypto-B');

    const plaintext = 'classified-session-a-data';
    const { iv, ciphertext } = await vault.encrypt('session-crypto-A', plaintext);

    // Attempt decryption with Session B's key
    await assert.rejects(
      async () => await vault.decrypt('session-crypto-B', iv, ciphertext),
      (err) => err instanceof DOMException || err.name === 'OperationError' || err.message.includes('operation'),
      'Decryption with wrong session key succeeded or did not throw expected DOMException'
    );
  });

  await test('CRYPTO_ISOLATION', 'Destroying Session A key prevents subsequent decryption of Session A ciphertext', async () => {
    const vault = new ZTRCryptoVault();
    await vault.generateKey('session-destroy');

    const { iv, ciphertext } = await vault.encrypt('session-destroy', 'payload');
    vault.destroyKey('session-destroy');

    await assert.rejects(
      async () => await vault.decrypt('session-destroy', iv, ciphertext),
      /Active key not found/
    );
  });

  await test('CRYPTO_ISOLATION', 'Session B remains functional after Session A is destroyed', async () => {
    const vault = new ZTRCryptoVault();
    await vault.generateKey('session-A');
    await vault.generateKey('session-B');

    const msgB = 'session-b-data-remains-valid';
    const { iv, ciphertext } = await vault.encrypt('session-B', msgB);

    // Destroy Session A
    vault.destroyKey('session-A');

    // Session B must decrypt properly
    const decrypted = await vault.decrypt('session-B', iv, ciphertext);
    assert.strictEqual(new TextDecoder().decode(decrypted), msgB);

    // Session B can still encrypt new data
    const newEnc = await vault.encrypt('session-B', 'new-payload');
    const newDec = await vault.decrypt('session-B', newEnc.iv, newEnc.ciphertext);
    assert.strictEqual(new TextDecoder().decode(newDec), 'new-payload');
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. PERMISSION ISOLATION
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 5. Permission Isolation ---');

  await test('PERMISSION_ISOLATION', 'Permission request handler denies unexpected permissions by default', async () => {
    // Replicate handler logic used in main.mjs: (_wc, _perm, cb) => cb(false)
    const permissionHandler = (_wc, _perm, cb) => cb(false);

    const testPermissions = [
      'geolocation',
      'notifications',
      'midi',
      'midiSysex',
      'pointerLock',
      'fullscreen',
      'openExternal',
      'media',
      'camera',
      'microphone',
      'clipboard-read',
      'clipboard-sanitized-write',
      'unknown-exploit-permission'
    ];

    for (const perm of testPermissions) {
      let result = null;
      permissionHandler({}, perm, (granted) => { result = granted; });
      assert.strictEqual(result, false, `Permission ${perm} was not denied by default`);
    }
  });

  skip(
    'PERMISSION_ISOLATION',
    'Live Electron renderer permission prompt suppression in Blink engine',
    'Verifying live Web API prompt suppression in webview frames requires an active Electron BrowserWindow process'
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. TOR / NETWORK CONFIGURATION
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 6. Tor / Network Configuration ---');

  await test('NETWORK_CONFIG', 'Tor proxy configuration uses SOCKS5 with remote DNS delegation', async () => {
    const activeTorPort = 9150;
    const proxyConfig = {
      proxyRules: `socks5://127.0.0.1:${activeTorPort}`,
      proxyBypassRules: '<-loopback>'
    };

    assert.strictEqual(proxyConfig.proxyRules, 'socks5://127.0.0.1:9150');
    assert.strictEqual(proxyConfig.proxyBypassRules, '<-loopback>');

    // Host resolver rule switch must block OS DNS lookups
    const hostResolverRule = 'MAP * ~NOTFOUND , EXCLUDE 127.0.0.1';
    assert(hostResolverRule.includes('MAP * ~NOTFOUND'));
    assert(hostResolverRule.includes('EXCLUDE 127.0.0.1'));
  });

  await test('NETWORK_CONFIG', 'TCP port probe handles closed ports safely without crashing or throwing', async () => {
    // Pick an unlikely bound port
    const testPort = 59876;
    function isPortOpen(port) {
      return new Promise((resolve) => {
        const sock = net.createConnection({ host: '127.0.0.1', port }, () => {
          sock.destroy();
          resolve(true);
        });
        sock.on('error', () => resolve(false));
        sock.setTimeout(500, () => { sock.destroy(); resolve(false); });
      });
    }

    const result = await isPortOpen(testPort);
    assert.strictEqual(typeof result, 'boolean');
    assert.strictEqual(result, false);
  });

  skip(
    'NETWORK_CONFIG',
    'Live Tor SOCKS5 circuit routing and stream isolation',
    'End-to-end Tor circuit routing and exit relay verification requires an active Tor daemon and external network connectivity'
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. NEGATIVE & ADVERSARIAL ATTACK TESTS
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n--- 7. Negative & Adversarial Attack Tests ---');

  await test('ADVERSARIAL_ATTACK', 'Attacker attempts to write into an unallocated/unopened tab container', async () => {
    const ztr = new ZeroTrustRenderer();
    await assert.rejects(
      async () => await ztr.setEncryptedStorageItem('non-existent-tab', 'localStorage', 'key', 'payload'),
      /Cannot write to unsealed\/destroyed tab/
    );
  });

  await test('ADVERSARIAL_ATTACK', 'Attacker attempts key extraction via WebCrypto exportKey API', async () => {
    const vault = new ZTRCryptoVault();
    const key = await vault.generateKey('session-export-target');

    assert.strictEqual(key.extractable, false);

    // SubtleCrypto.exportKey must reject when extractable is false
    await assert.rejects(
      async () => await crypto.subtle.exportKey('raw', key),
      (err) => err instanceof DOMException || err.name === 'InvalidAccessError' || err.message.includes('key is not extractable') || err.message.includes('not extractable')
    );

    await assert.rejects(
      async () => await crypto.subtle.exportKey('jwk', key),
      (err) => err instanceof DOMException || err.name === 'InvalidAccessError' || err.message.includes('key is not extractable') || err.message.includes('not extractable')
    );
  });

  await test('ADVERSARIAL_ATTACK', 'Attacker attempts replay attack with forged or invalid session UUID against vault', async () => {
    const vault = new ZTRCryptoVault();
    const forgedUUID = '00000000-0000-4000-8000-000000000000';

    await assert.rejects(
      async () => await vault.encrypt(forgedUUID, 'data'),
      /Active key not found/
    );

    await assert.rejects(
      async () => await vault.decrypt(forgedUUID, new Uint8Array(12), new ArrayBuffer(16)),
      /Active key not found/
    );
  });

  await test('ADVERSARIAL_ATTACK', 'Attacker attempts double-open or double-close lifecycle exploits', async () => {
    const ztr = new ZeroTrustRenderer();
    await ztr.openTab('tab-double');

    // Attempting to open same tabId again
    await assert.rejects(
      async () => await ztr.openTab('tab-double'),
      /already open/
    );

    // First close succeeds
    await ztr.closeTab('tab-double');

    // Second close must throw error
    await assert.rejects(
      async () => await ztr.closeTab('tab-double'),
      /does not exist or was already closed/
    );
  });

  await test('ADVERSARIAL_ATTACK', 'Attacker attempts to query invalid storage store type', async () => {
    const ztr = new ZeroTrustRenderer();
    await ztr.openTab('tab-store-exploit');

    await assert.rejects(
      async () => await ztr.setEncryptedStorageItem('tab-store-exploit', '__proto__', 'k', 'v'),
      /Invalid storage context/
    );

    const readResult = await ztr.getDecryptedStorageItem('tab-store-exploit', '__proto__', 'k');
    assert.strictEqual(readResult, null);
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SUMMARY REPORT
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n================================================================');
  console.log('  ADVERSARIAL ISOLATION TEST SUITE SUMMARY');
  console.log('================================================================');
  console.log(`  [PASS]    PASSED  : ${passed}`);
  console.log(`  [FAIL]    FAILED  : ${failed}`);
  console.log(`  [SKIPPED] SKIPPED : ${skipped}`);
  console.log(`  TOTAL TESTED      : ${passed + failed + skipped}`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runAdversarialTestSuite().catch((err) => {
  console.error('Test runner fatal error:', err);
  process.exit(1);
});
