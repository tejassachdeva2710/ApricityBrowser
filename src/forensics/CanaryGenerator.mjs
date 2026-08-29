/**
 * CanaryGenerator.mjs
 * 
 * High-entropy canary token generation and multi-encoding binary representation
 * for Apricity Browser's ephemeral forensic artifact auditor.
 * 
 * Generates unique, non-guessable canary tokens per session across all storage
 * subsystems (cookies, localStorage, indexedDB, cache, cryptoVault key IDs, URLs, session UUIDs).
 * Converts tokens into multiple binary encodings (UTF-8, ASCII, UTF-16LE, hex, URL-encoded)
 * to detect residue in SQLite databases, LevelDB SSTables/logs, V8 byte caches, and memory dumps.
 */

import { webcrypto, randomBytes } from 'node:crypto';

const crypto = globalThis.crypto || webcrypto;

// Canonical subsystems mapped for forensic tracking
export const CANARY_SUBSYSTEMS = [
  'COOKIE',
  'LSTORE',
  'IDB',
  'CACHE',
  'VAULT',
  'URL',
  'SESSION'
];

export class CanaryGenerator {
  /**
   * Generates a cryptographically strong high-entropy hex string.
   * @param {number} byteLength Number of random bytes (default 16 -> 32 hex chars)
   * @returns {string} Hex string
   */
  static generateEntropy(byteLength = 16) {
    if (crypto.getRandomValues) {
      const bytes = new Uint8Array(byteLength);
      crypto.getRandomValues(bytes);
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    return randomBytes(byteLength).toString('hex');
  }

  /**
   * Generates a single canary token for a specific storage subsystem.
   * Format: CANARY_<SUBSYSTEM>_<SESSION_UUID_SHORT>_<TIMESTAMP>_<HIGH_ENTROPY_HEX>
   * 
   * @param {string} subsystem One of CANARY_SUBSYSTEMS or custom subsystem name
   * @param {string} [sessionUUID] Optional session UUID; if omitted, a fresh random UUID is generated
   * @returns {string} High-entropy canary token
   */
  static generateToken(subsystem = 'GENERIC', sessionUUID = null) {
    const cleanSubsystem = String(subsystem).toUpperCase().replace(/[^A-Z0-9_]/g, '');
    const uuid = sessionUUID || (crypto.randomUUID ? crypto.randomUUID() : this.generateEntropy(16));
    const sessionShort = uuid.replace(/-/g, '').slice(0, 8);
    const timestamp = Date.now();
    const entropy = this.generateEntropy(12);

    return `CANARY_${cleanSubsystem}_${sessionShort}_${timestamp}_${entropy}`;
  }

  /**
   * Generates a comprehensive canary token set for an entire browsing session.
   * 
   * @param {string} [sessionUUID] Optional session UUID
   * @returns {object} Map of subsystem to canary token object with multi-encoding buffers
   */
  static generateSessionCanarySet(sessionUUID = null) {
    const uuid = sessionUUID || (crypto.randomUUID ? crypto.randomUUID() : this.generateEntropy(16));
    const canarySet = {
      sessionUUID: uuid,
      createdAt: Date.now(),
      tokens: {}
    };

    for (const sub of CANARY_SUBSYSTEMS) {
      const token = this.generateToken(sub, uuid);
      canarySet.tokens[sub] = {
        subsystem: sub,
        token,
        encodings: this.getEncodings(token)
      };
    }

    return canarySet;
  }

  /**
   * Converts a canary token string into multiple binary encodings
   * matching how different storage engines (SQLite, LevelDB, V8, NTFS) store strings.
   * 
   * @param {string} token 
   * @returns {object} Encodings dictionary
   */
  static getEncodings(token) {
    if (typeof token !== 'string') {
      throw new TypeError('[CanaryGenerator] Token must be a string');
    }

    const utf8Buffer = Buffer.from(token, 'utf8');
    const asciiBuffer = Buffer.from(token, 'ascii');
    const utf16leBuffer = Buffer.from(token, 'utf16le');
    const hexString = utf8Buffer.toString('hex');
    const urlEncoded = encodeURIComponent(token);

    return {
      utf8: utf8Buffer,
      ascii: asciiBuffer,
      utf16le: utf16leBuffer,
      hex: hexString,
      urlEncoded,
      // Raw string for regex / text lookups
      raw: token
    };
  }

  /**
   * Validates if a given string matches the standard Apricity Canary format.
   * 
   * @param {string} token 
   * @returns {object} Validation result { valid: boolean, subsystem?, sessionShort?, timestamp?, entropy? }
   */
  static validateToken(token) {
    if (typeof token !== 'string') {
      return { valid: false, reason: 'Token must be a string' };
    }

    const regex = /^CANARY_([A-Z0-9]+)_([0-9a-f]{8})_(\d+)_([0-9a-f]{24})$/i;
    const match = token.match(regex);

    if (!match) {
      return { valid: false, reason: 'Token format does not match CANARY pattern' };
    }

    const [, subsystem, sessionShort, timestampStr, entropy] = match;
    const timestamp = parseInt(timestampStr, 10);

    return {
      valid: true,
      subsystem,
      sessionShort,
      timestamp,
      entropy,
      ageMs: Date.now() - timestamp
    };
  }

  /**
   * Extracts all raw token strings and their multi-encoding Buffers from a canary set.
   * Useful for bulk search in FilesystemScanner.
   * 
   * @param {object} canarySet Output of generateSessionCanarySet()
   * @returns {Array<{ subsystem: string, token: string, encodings: object }>}
   */
  static extractSearchPatterns(canarySet) {
    if (!canarySet || !canarySet.tokens) {
      return [];
    }

    return Object.values(canarySet.tokens).map(item => ({
      subsystem: item.subsystem,
      token: item.token,
      encodings: item.encodings
    }));
  }
}
