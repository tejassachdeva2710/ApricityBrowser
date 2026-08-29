/**
 * ZTRPrefs.mjs
 * 
 * Preference verification module for the Zero Trust Rendering Reference Specification.
 * Validates baseline security preferences defined in ztr-user.js.
 * 
 * Architectural Context:
 * Serves as the ZTR conceptual policy auditor. The Electron GUI runtime
 * enforces equivalent sandboxing via Chromium command-line switches and
 * webPreferences.
 */

import fs from 'fs';
import path from 'path';

export class ZTRPrefs {
  static REQUIRED_PREFS = {
    "security.sandbox.content.level": 9,
    "fission.autostart": true,
    "browser.cache.disk.enable": false,
    "browser.cache.memory.enable": true,
    "network.cookie.cookieBehavior": 5,
    "dom.ipc.keepProcessesAlive": 0,
    "places.history.enabled": false
  };

  /**
   * Loads and parses ztr-user.js into key-value map.
   * @param {string} filePath 
   * @returns {Map<string, any>}
   */
  static loadUserJs(filePath) {
    if (!fs.existsSync(filePath)) {
      throw new Error(`[ZTRPrefs] Preference file not found: ${filePath}`);
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const prefsMap = new Map();
    const regex = /user_pref\(\s*["']([^"']+)["']\s*,\s*([^)]+)\s*\);/g;

    let match;
    while ((match = regex.exec(content)) !== null) {
      const key = match[1];
      let valRaw = match[2].trim();
      let value;

      if (valRaw === 'true') value = true;
      else if (valRaw === 'false') value = false;
      else if (!isNaN(Number(valRaw))) value = Number(valRaw);
      else value = valRaw.replace(/^["']|["']$/g, '');

      prefsMap.set(key, value);
    }

    return prefsMap;
  }

  /**
   * Validates parsed preferences against required ZTR baseline.
   * @param {Map<string, any>} prefsMap 
   * @returns {{ valid: boolean, errors: string[] }}
   */
  static validatePrefs(prefsMap) {
    const errors = [];

    for (const [key, requiredVal] of Object.entries(ZTRPrefs.REQUIRED_PREFS)) {
      if (!prefsMap.has(key)) {
        errors.push(`Missing required preference: ${key}`);
      } else if (prefsMap.get(key) !== requiredVal) {
        errors.push(`Invalid preference value for ${key}. Expected: ${requiredVal}, Found: ${prefsMap.get(key)}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}
