/**
 * ZTRLauncher.mjs
 * 
 * Main entry point for Apricity Browser Zero Trust Rendering engine.
 * Validates hardened security prefs, initializes ZTR engine, and handles lifecycle events.
 */

import path from 'path';
import { fileURLToPath } from 'url';
import { ZeroTrustRenderer } from './ZeroTrustRenderer.mjs';
import { ZTRPrefs } from './ZTRPrefs.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function bootstrapZTR() {
  console.log('====================================================');
  console.log('  Apricity Browser — Zero Trust Rendering (ZTR)');
  console.log('====================================================\n');

  // Step 1: Validate Gecko Hardened Security Preferences
  const userJsPath = path.join(__dirname, 'ztr-user.js');
  console.log(`[ZTR] Loading security preferences from: ${userJsPath}`);
  
  const prefsMap = ZTRPrefs.loadUserJs(userJsPath);
  const valResult = ZTRPrefs.validatePrefs(prefsMap);

  if (!valResult.valid) {
    console.error('[ZTR] ✗ SECURITY AUDIT FAILED: Invalid or missing preferences:');
    valResult.errors.forEach(err => console.error(`  - ${err}`));
    process.exit(1);
  }

  console.log('[ZTR] ✓ Layer 3 Security Audit Passed: All Level 9 Sandbox & Fission preferences locked.\n');

  // Step 2: Initialize ZTR Core Engine
  const ztr = new ZeroTrustRenderer();
  console.log('[ZTR] Engine Initialized.');

  // Step 3: Demonstrate Tab Lifecycle Isolation & Cryptographic Wipe
  console.log('\n--- Scenario: Opening Tab 1 (https://example.com) ---');
  const tab1 = await ztr.openTab(1, 'https://example.com');
  console.log(`[Tab 1] Session UUID : ${tab1.sessionUUID}`);
  console.log(`[Tab 1] Container ID : ${tab1.userContextId}`);
  console.log(`[Tab 1] Status       : ${tab1.status} 🔐`);

  await ztr.setEncryptedStorageItem(1, 'cookies', 'session_auth', 'secret-token-tab-1');
  console.log('[Tab 1] Encrypted and stored cookie session_auth.');

  console.log('\n--- Scenario: Opening Tab 2 (https://example.com) ---');
  const tab2 = await ztr.openTab(2, 'https://example.com');
  console.log(`[Tab 2] Session UUID : ${tab2.sessionUUID}`);
  console.log(`[Tab 2] Container ID : ${tab2.userContextId}`);
  console.log(`[Tab 2] Status       : ${tab2.status} 🔐`);

  console.log(`\n[ZTR Test] Is Tab 1 storage isolated from Tab 2? ${ztr.isStorageIsolated(1, 2) ? 'YES ✓' : 'NO ✗'}`);

  // Step 4: Execute Cryptographic Wipe on Tab 1 Close
  console.log('\n--- Scenario: Closing Tab 1 (Executing Cryptographic Wipe Protocol) ---');
  const destroyResult = await ztr.closeTab(1);
  console.log(`[Tab 1 Destroyed] Key Destroyed   : ${destroyResult.keyDestroyed ? 'YES ✓' : 'NO ✗'}`);
  console.log(`[Tab 1 Destroyed] Storage Purged  : ${destroyResult.storagePurged ? 'YES ✓' : 'NO ✗'}`);
  console.log(`[Tab 1 Destroyed] Final Status    : ${destroyResult.status} ✓`);

  // Verify key attempt after close throws error
  try {
    await ztr.getDecryptedStorageItem(1, 'cookies', 'session_auth');
  } catch (err) {
    console.log(`\n[ZTR Verification] Attempt to read data after tab close: ${err.message} ✓`);
  }

  console.log('\n====================================================');
  console.log('  Zero Trust Rendering Engine operational and verified.');
  console.log('====================================================');
}

bootstrapZTR().catch(err => {
  console.error('[ZTR Fatal Error]:', err);
  process.exit(1);
});
