/**
 * ZTRCryptoVault.mjs
 * 
 * Layer 4 of Zero Trust Rendering Architecture:
 * In-Memory Ephemeral Cryptographic Key Vault.
 * 
 * Key Properties:
 * 1. Generates non-extractable AES-256-GCM keys per tab session UUID using WebCrypto API.
 * 2. Setting extractable to false prevents key extraction via WebCrypto export APIs.
 * 3. Destroying a key clears the in-memory reference and removes the entry from the vault Map,
 *    preventing further cryptographic operations for that session.
 */

import { webcrypto } from 'node:crypto';

const crypto = globalThis.crypto || webcrypto;

export class ZTRCryptoVault {
  constructor() {
    // Map<sessionUUID, { key: CryptoKey, createdAt: number, metadata: object }>
    this._vault = new Map();
  }

  /**
   * Generates a non-extractable AES-256-GCM key bound to a tab's session UUID.
   * @param {string} sessionUUID 
   * @returns {Promise<CryptoKey>}
   */
  async generateKey(sessionUUID) {
    if (!sessionUUID || typeof sessionUUID !== 'string') {
      throw new Error('[ZTRCryptoVault] Invalid sessionUUID provided for key generation.');
    }

    if (this._vault.has(sessionUUID)) {
      throw new Error(`[ZTRCryptoVault] Key for session ${sessionUUID} already exists.`);
    }

    const key = await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256
      },
      false, // NOT extractable via WebCrypto export APIs
      ['encrypt', 'decrypt']
    );

    this._vault.set(sessionUUID, {
      key,
      createdAt: Date.now(),
      destroyed: false
    });

    return key;
  }

  /**
   * Encrypts plaintext data using the tab's non-extractable session key.
   * @param {string} sessionUUID 
   * @param {Uint8Array|ArrayBuffer|string} data 
   * @returns {Promise<{ iv: Uint8Array, ciphertext: ArrayBuffer }>}
   */
  async encrypt(sessionUUID, data) {
    const entry = this._vault.get(sessionUUID);
    if (!entry || entry.destroyed) {
      throw new Error(`[ZTRCryptoVault] Active key not found for session ${sessionUUID}`);
    }

    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM
    const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      entry.key,
      buffer
    );

    return { iv, ciphertext };
  }

  /**
   * Decrypts ciphertext data using the tab's non-extractable session key.
   * @param {string} sessionUUID 
   * @param {Uint8Array} iv 
   * @param {ArrayBuffer} ciphertext 
   * @returns {Promise<ArrayBuffer>}
   */
  async decrypt(sessionUUID, iv, ciphertext) {
    const entry = this._vault.get(sessionUUID);
    if (!entry || entry.destroyed) {
      throw new Error(`[ZTRCryptoVault] Active key not found for session ${sessionUUID}`);
    }

    return await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv
      },
      entry.key,
      ciphertext
    );
  }

  /**
   * Clears the ephemeral AES key for a session UUID and removes it from the vault.
   * Step 1: Clears internal key reference.
   * Step 2: Removes entry from vault Map.
   * @param {string} sessionUUID 
   * @returns {boolean} True if key was successfully found and removed
   */
  destroyKey(sessionUUID) {
    const entry = this._vault.get(sessionUUID);
    if (!entry) {
      return false;
    }

    // Clear references from vault
    entry.key = null;
    entry.destroyed = true;
    this._vault.delete(sessionUUID);

    // Request GC if exposed in runtime environment
    if (typeof globalThis.gc === 'function') {
      globalThis.gc();
    }

    return true;
  }

  /**
   * Checks if an active key exists for the session.
   * @param {string} sessionUUID 
   * @returns {boolean}
   */
  hasKey(sessionUUID) {
    const entry = this._vault.get(sessionUUID);
    return Boolean(entry && !entry.destroyed && entry.key);
  }

  /**
   * Returns count of active non-destroyed keys in vault.
   * @returns {number}
   */
  activeKeyCount() {
    return this._vault.size;
  }
}
