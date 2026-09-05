/**
 * FilesystemScanner.mjs
 * 
 * Multi-platform deep filesystem and binary scanner for Apricity Browser's
 * forensic artifact auditor.
 * 
 * Capabilities:
 * 1. Resolves runtime storage directories across Windows, macOS, and Linux
 *    (userData, Partitions, Network, Local Storage, IndexedDB, Code Cache, GPUCache,
 *    blob_storage, Crashpad, tor-data, %TEMP%).
 * 2. Scans files as raw binary buffers matching multi-encoding canary patterns
 *    (UTF-8, UTF-16LE, ASCII, hex).
 * 3. Gracefully handles Windows file locking (EBUSY, EPERM) with retry backoff
 *    and classification.
 * 4. Filters out static source code repositories (src, tests, docs, node_modules, .git, .agents)
 *    to eliminate false positive self-referential matches.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Default directory names and files to exclude from forensic scans
// to prevent false positives from static source code or auditor logs
export const DEFAULT_EXCLUSIONS = [
  'node_modules',
  '.git',
  '.agents',
  '.vscode',
  '.idea',
  'src',
  'tests',
  'docs',
  'coverage',
  'dist',
  'build',
  'forensic-report.json',
  'forensic-report.md',
  'package.json',
  'package-lock.json',
  'PROJECT.md',
  'README.md',
  'LICENSE',
  'ApricityBrowser.cmd'
];

export class FilesystemScanner {
  constructor(options = {}) {
    this.options = {
      maxFileSizeBytes: options.maxFileSizeBytes || 50 * 1024 * 1024, // 50MB per file limit
      maxRetries: options.maxRetries || 2,
      retryDelayMs: options.retryDelayMs || 50,
      customExclusions: options.customExclusions || [],
      ...options
    };

    this.exclusions = new Set([
      ...DEFAULT_EXCLUSIONS,
      ...this.options.customExclusions
    ]);
  }

  /**
   * Resolves realistic runtime and artifact storage paths for the current OS.
   * Dynamically resolves Windows %APPDATA%, %LOCALAPPDATA%, %TEMP%, macOS Application Support,
   * and Linux ~/.config directories.
   * 
   * @param {string} [appName='apricity-browser'] Application name or Electron folder
   * @param {object} [customPaths={}] Optional explicit paths (e.g. from Electron app.getPath)
   * @returns {object} Map of subsystem names to candidate directory paths
   */
  static discoverRuntimePaths(appName = 'apricity-browser', customPaths = {}) {
    const platform = process.platform;
    const homedir = os.homedir();
    const tempDir = os.tmpdir();

    let userDataDir = '';
    let localAppDataDir = '';

    if (customPaths.userData && fs.existsSync(customPaths.userData)) {
      userDataDir = customPaths.userData;
    } else if (platform === 'win32') {
      const appData = process.env.APPDATA || path.join(homedir, 'AppData', 'Roaming');
      const localAppData = process.env.LOCALAPPDATA || path.join(homedir, 'AppData', 'Local');
      userDataDir = path.join(appData, appName);
      localAppDataDir = path.join(localAppData, appName);
    } else if (platform === 'darwin') {
      userDataDir = path.join(homedir, 'Library', 'Application Support', appName);
      localAppDataDir = path.join(homedir, 'Library', 'Caches', appName);
    } else {
      // Linux / POSIX
      const configHome = process.env.XDG_CONFIG_HOME || path.join(homedir, '.config');
      const cacheHome = process.env.XDG_CACHE_HOME || path.join(homedir, '.cache');
      userDataDir = path.join(configHome, appName);
      localAppDataDir = path.join(cacheHome, appName);
    }

    return {
      platform,
      userData: userDataDir,
      localAppData: localAppDataDir,
      temp: customPaths.temp || path.join(tempDir, appName),
      crashTemp: path.join(tempDir, `${appName} Crashes`),
      torData: path.join(userDataDir, 'tor-data'),
      partitions: path.join(userDataDir, 'Partitions'),
      network: path.join(userDataDir, 'Network'),
      localStorage: path.join(userDataDir, 'Local Storage'),
      indexedDB: path.join(userDataDir, 'IndexedDB'),
      codeCache: path.join(userDataDir, 'Code Cache'),
      gpuCache: path.join(userDataDir, 'GPUCache'),
      blobStorage: path.join(userDataDir, 'blob_storage'),
      crashpad: path.join(userDataDir, 'Crashpad'),
      logs: path.join(userDataDir, 'logs')
    };
  }

  /**
   * Scans a single file buffer against a list of canary search patterns.
   * Performs binary substring searches for UTF-8, UTF-16LE, and ASCII encodings.
   * 
   * @param {string} filePath Absolute file path
   * @param {Array<object>} canaryPatterns Array of { subsystem, token, encodings }
   * @returns {Array<object>} Matches found
   */
  scanBuffer(filePath, fileBuffer, canaryPatterns) {
    const matches = [];

    for (const pattern of canaryPatterns) {
      const { subsystem, token, encodings } = pattern;
      if (!encodings) continue;

      // Check UTF-8 encoding
      if (encodings.utf8 && fileBuffer.includes(encodings.utf8)) {
        const offset = fileBuffer.indexOf(encodings.utf8);
        matches.push({
          filePath,
          token,
          subsystem,
          encoding: 'utf8',
          offset,
          preview: this._createHexPreview(fileBuffer, offset, encodings.utf8.length)
        });
      }

      // Check UTF-16LE encoding (Crucial for Chromium DOMStorage & Windows internal strings)
      if (encodings.utf16le && fileBuffer.includes(encodings.utf16le)) {
        const offset = fileBuffer.indexOf(encodings.utf16le);
        matches.push({
          filePath,
          token,
          subsystem,
          encoding: 'utf16le',
          offset,
          preview: this._createHexPreview(fileBuffer, offset, encodings.utf16le.length)
        });
      }

      // Check ASCII if distinct from UTF-8 (fallback)
      if (encodings.ascii && !encodings.utf8.equals(encodings.ascii) && fileBuffer.includes(encodings.ascii)) {
        const offset = fileBuffer.indexOf(encodings.ascii);
        matches.push({
          filePath,
          token,
          subsystem,
          encoding: 'ascii',
          offset,
          preview: this._createHexPreview(fileBuffer, offset, encodings.ascii.length)
        });
      }
    }

    return matches;
  }

  /**
   * Creates a sanitized hex/ascii snippet around the matched offset.
   * @private
   */
  _createHexPreview(buffer, offset, length) {
    const start = Math.max(0, offset - 8);
    const end = Math.min(buffer.length, offset + length + 8);
    const slice = buffer.subarray(start, end);
    return slice.toString('hex');
  }

  /**
   * Reads and scans a single file on disk with retry logic for Windows file locks.
   * 
   * @param {string} filePath 
   * @param {Array<object>} canaryPatterns 
   * @returns {Promise<object>} Result object { matches, locked: boolean, error?: string }
   */
  async scanFile(filePath, canaryPatterns) {
    let attempts = 0;
    const maxAttempts = this.options.maxRetries + 1;

    while (attempts < maxAttempts) {
      attempts++;
      try {
        const stat = await fs.promises.stat(filePath);
        if (!stat.isFile()) {
          return { matches: [], skipped: true, reason: 'Not a regular file' };
        }

        if (stat.size > this.options.maxFileSizeBytes) {
          return {
            matches: [],
            skipped: true,
            reason: `File size (${stat.size} bytes) exceeds limit (${this.options.maxFileSizeBytes} bytes)`
          };
        }

        // Read binary file buffer
        const buffer = await fs.promises.readFile(filePath);
        const matches = this.scanBuffer(filePath, buffer, canaryPatterns);

        return {
          matches,
          sizeBytes: stat.size,
          scanned: true
        };
      } catch (err) {
        if ((err.code === 'EBUSY' || err.code === 'EPERM') && attempts < maxAttempts) {
          await new Promise(r => setTimeout(r, this.options.retryDelayMs));
          continue;
        }

        if (err.code === 'EBUSY' || err.code === 'EPERM') {
          return {
            matches: [],
            locked: true,
            code: err.code,
            error: `File is locked by an active process: ${err.message}`
          };
        }

        if (err.code === 'ENOENT') {
          return { matches: [], skipped: true, reason: 'File vanished before read' };
        }

        return {
          matches: [],
          error: err.message,
          code: err.code
        };
      }
    }

    return { matches: [], locked: true, error: 'Max retries exceeded' };
  }

  /**
   * Recursively discovers all files in a directory, honoring exclusion filters.
   * 
   * @param {string} dirPath Target directory
   * @param {Array<string>} fileList Accumulator array
   * @returns {Promise<Array<string>>}
   */
  async enumerateFiles(dirPath, fileList = []) {
    try {
      if (!fs.existsSync(dirPath)) {
        return fileList;
      }

      const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        // Check if directory/file name is in exclusion list
        if (this.exclusions.has(entry.name)) {
          continue;
        }

        if (entry.isDirectory()) {
          await this.enumerateFiles(fullPath, fileList);
        } else if (entry.isFile()) {
          fileList.push(fullPath);
        }
      }
    } catch (err) {
      // Permission errors or deleted dirs in traversal handled gracefully
    }

    return fileList;
  }

  /**
   * Scans multiple directory roots or specific paths against canary patterns.
   * 
   * @param {Array<string>} targetPaths Directories or files to scan
   * @param {Array<object>} canaryPatterns Extracted patterns from CanaryGenerator
   * @returns {Promise<object>} Comprehensive scan report
   */
  async scanPaths(targetPaths, canaryPatterns) {
    const startTime = Date.now();
    const uniquePaths = Array.from(new Set(targetPaths.filter(Boolean)));
    const allFiles = [];

    for (const targetPath of uniquePaths) {
      if (!fs.existsSync(targetPath)) {
        continue;
      }

      const stat = await fs.promises.stat(targetPath);
      if (stat.isDirectory()) {
        await this.enumerateFiles(targetPath, allFiles);
      } else if (stat.isFile()) {
        const basename = path.basename(targetPath);
        if (!this.exclusions.has(basename)) {
          allFiles.push(targetPath);
        }
      }
    }

    // Deduplicate discovered files
    const deduplicatedFiles = Array.from(new Set(allFiles));

    let scannedBytesCount = 0;
    const allMatches = [];
    const lockedFiles = [];
    const skippedFiles = [];
    const errors = [];

    for (const file of deduplicatedFiles) {
      const result = await this.scanFile(file, canaryPatterns);

      if (result.scanned) {
        scannedBytesCount += result.sizeBytes || 0;
        if (result.matches && result.matches.length > 0) {
          allMatches.push(...result.matches);
        }
      } else if (result.locked) {
        lockedFiles.push({ path: file, code: result.code, error: result.error });
      } else if (result.skipped) {
        skippedFiles.push({ path: file, reason: result.reason });
      } else if (result.error) {
        errors.push({ path: file, code: result.code, error: result.error });
      }
    }

    return {
      scannedRoots: uniquePaths,
      scannedFilesCount: deduplicatedFiles.length,
      scannedBytesCount,
      matches: allMatches,
      lockedFiles,
      skippedFiles,
      errors,
      durationMs: Date.now() - startTime
    };
  }

  /**
   * Scans in-memory JavaScript objects/maps/arrays for canary token strings.
   * Useful for testing simulator stores before and after teardown.
   * 
   * @param {any} target In-memory object/Map/Set/Array to inspect
   * @param {Array<object>} canaryPatterns 
   * @returns {Array<object>} In-memory match findings
   */
  static scanMemoryStructure(target, canaryPatterns) {
    const rawTokens = new Map(canaryPatterns.map(p => [p.token, p]));
    const matches = [];

    function traverse(val, currentPath = '') {
      if (val === null || val === undefined) return;

      if (typeof val === 'string') {
        for (const [token, pattern] of rawTokens.entries()) {
          if (val.includes(token)) {
            matches.push({
              path: currentPath,
              token,
              subsystem: pattern.subsystem,
              type: 'memory_string'
            });
          }
        }
      } else if (val instanceof Uint8Array || Buffer.isBuffer(val)) {
        const buf = Buffer.from(val);
        for (const pattern of canaryPatterns) {
          if (pattern.encodings && pattern.encodings.utf8 && buf.includes(pattern.encodings.utf8)) {
            matches.push({
              path: currentPath,
              token: pattern.token,
              subsystem: pattern.subsystem,
              type: 'memory_buffer_utf8'
            });
          }
        }
      } else if (val instanceof Map) {
        for (const [k, v] of val.entries()) {
          traverse(k, `${currentPath}.MapKey(${k})`);
          traverse(v, `${currentPath}.MapValue(${k})`);
        }
      } else if (val instanceof Set || Array.isArray(val)) {
        let idx = 0;
        for (const item of val) {
          traverse(item, `${currentPath}[${idx++}]`);
        }
      } else if (typeof val === 'object') {
        for (const [k, v] of Object.entries(val)) {
          traverse(v, `${currentPath}.${k}`);
        }
      }
    }

    traverse(target, 'root');
    return matches;
  }
}
