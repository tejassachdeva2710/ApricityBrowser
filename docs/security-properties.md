# Apricity Browser — Security & Isolation Properties Specification

**Document Version:** 1.1.0  
**Classification:** Technical Isolation Specification  
**Companion Document:** [Threat Model & Security Architecture](threat-model.md)

This document specifies the actual security and isolation properties provided by the current Apricity Browser implementation, what the automated test suite verifies, what Apricity does **not** guarantee, and known architectural limitations.

---

## 1. What Apricity Currently Enforces (Application-Level & Configuration)

1. **Ephemeral Partition Configuration**:
   * Each tab is opened with a uniquely generated UUID v4 (`sessionUUID`) that maps to an in-memory Electron partition configuration (`ephemeral-${sessionUUID}`).
   * Partitions are configured with in-memory caching (`{ cache: false }`), and `disable-http-cache` / `disk-cache-size: 1` command-line switches instruct Chromium to avoid standard disk caching.
   * *Limitation*: This represents application configuration and runtime unlinking; it does not prove physical absence of RAM artifacts or prevent OS kernel paging.

2. **Default Permission Denial**:
   * Both `session.defaultSession` and tab-specific ephemeral sessions enforce a strict default-deny permission handler (`setPermissionRequestHandler((_wc, _perm, cb) => cb(false))`).
   * Standard Web API permission prompts (geolocation, notifications, media/camera/microphone, clipboard access, external protocols) are denied by default at the session layer.

3. **In-Memory Cryptographic Separation (`ZTRCryptoVault`)**:
   * Ephemeral AES-256-GCM keys (256-bit) are generated per tab session via the WebCrypto API with `extractable: false`.
   * Cryptographic operations are isolated per session UUID. Ciphertext generated under Session A's key cannot be decrypted under Session B's key (guaranteed by AES-GCM authentication tag verification).
   * Key references are removed from the in-memory vault Map upon session close, preventing subsequent encryption/decryption requests for that session ID.

4. **Fail-Closed Tor Proxy Configuration**:
   * Network requests in Electron sessions are configured to route through a local Tor SOCKS5 proxy (`socks5://127.0.0.1:9150` or `9050`).
   * Chromium host resolver rules (`MAP * ~NOTFOUND , EXCLUDE 127.0.0.1`) prevent the browser from using the host OS DNS resolver for external hostnames.
   * If the Tor SOCKS proxy is unreachable or down, requests fail closed with connection errors rather than falling back to unproxied clearnet.

5. **Tab Lifecycle State Invalidation**:
   * Closing a tab purges its state from `activeTabs`, deletes the in-memory storage store, removes its key from the vault, and issues `clearStorageData()` / `clearCache()` to the Electron partition.
   * Subsequent API operations on closed tab IDs are explicitly rejected at the application level.

---

## 2. What the Test Suite Empirically Verifies

The automated test suites (`npm test` and `npm run forensic`) verify:

* **Session Uniqueness**:
  * Every opened tab receives a unique session UUID v4 and non-overlapping partition identifier string.
  * Reopening a previously closed tab ID creates a new, independent session identity with no historical state linkage.
* **Storage Isolation (ZTR In-Memory Store)**:
  * Concurrent sessions writing to `cookies`, `localStorage`, `indexedDB`, and `cache` cannot retrieve or overwrite each other's data.
  * Raw values stored in the in-memory layer are encrypted payloads (`{ iv, ciphertext }`), not plaintext.
* **Cryptographic Isolation**:
  * Cross-session decryption attacks are rejected with cryptographic authentication errors.
  * Replay attacks or decryption requests against destroyed session keys are rejected.
  * Surviving peer sessions remain fully operational and uncorrupted when other sessions close.
* **Permission Denial**:
  * Permission request handler consistently returns `false` across all standard permission types.
* **Tor Configuration & Port Probing**:
  * Verification of proxy configuration strings, loopback handling, DNS resolver rules, and deterministic port probing failure safety.
* **Forensic Canary Absence (Within Scanned Filesystem Surface)**:
  * High-entropy canary tokens injected across session subsystems are not detected in user-space file sweeps across `%APPDATA%\...\userData` after tab closure.
* **Negative & Adversarial Attacks**:
  * Direct attempts to write into unallocated containers, forge session UUIDs, export non-extractable keys via WebCrypto API, and execute double-open/double-close exploits are rejected.

---

## 3. What Apricity Does NOT Guarantee (Non-Guarantees)

1. **Physical RAM & Heap Zeroization**:
   * Dereferencing JavaScript objects and invoking `globalThis.gc()` marks memory as reclaimable for the V8 heap allocator; it does **not** physically zero or overwrite host DRAM bytes.
   * Forensic physical memory inspection of a compromised host or process memory dumping can recover unallocated heap fragments.

2. **Absolute Anonymity or Circuit Stream Isolation**:
   * Routing network requests through Tor SOCKS5 provides network pseudonymity, but does **not** guarantee absolute anonymity against browser fingerprinting, application-layer deanonymization, or global passive traffic correlation.
   * SOCKS5 proxy routing at port 9150/9050 shares the Tor daemon's circuit pool across tabs unless per-session stream isolation is explicitly configured.

3. **Protection Against Host / Process-Level Compromise**:
   * WebCrypto `extractable: false` is an API-level barrier enforced by the JavaScript runtime. It does **not** protect cryptographic keys or memory against a local debugger, memory dumper, root malware, or kernel-level process inspection.

4. **Complete Erasure of OS-Level Artifacts**:
   * A clean filesystem scan proves only that known canary tokens were not found within the scanned directory tree.
   * It does **not** guarantee the absence of OS-level artifacts in NTFS journals (`$LogFile`, `$UsnJrnl`), Windows Prefetch, crash minidumps, or virtual memory paging (`pagefile.sys`).

5. **Solid-State Drive (SSD) Physical Cell Erasure**:
   * Due to Flash Translation Layer (FTL) wear-leveling, overwriting or unlinking files in user-space does not erase physical NAND flash cells.

---

## 4. Known Architectural Limitations

1. **ZTR Storage Simulator vs Chromium Webview Storage**:
   * The encrypted storage store in `ZeroTrustRenderer.mjs` (`this._ephemeralStorageStores`) is an in-memory state simulator and test abstraction.
   * Web browsing inside `<webview>` elements uses Electron's native Chromium storage engine isolated by partition names (`partition="ephemeral-UUID"`). Webview DOM storage (e.g. `document.cookie` or `localStorage` set by live web pages) does **not** route through `ZeroTrustRenderer`'s JavaScript WebCrypto encryption layer.

2. **Electron `<webview>` Sandbox Limitation**:
   * The main `BrowserWindow` runs with `sandbox: false` because Electron requires this setting for `<webview>` tag management. Web content runs in isolated guest processes, but the shell process does not have Chromium sandbox restrictions.

3. **Gecko vs Chromium Preferences Disconnect**:
   * `src/ztr/ztr-user.js` and `ZTRPrefs.mjs` define and validate Firefox/Gecko security preferences (such as `security.sandbox.content.level: 9` and `fission.autostart: true`).
   * Apricity executes on Chromium/Electron, which does not read or apply Gecko `user_pref()` settings.
