# Apricity Browser — Security & Isolation Properties

This document specifies the actual security and isolation properties provided by the current Apricity Browser implementation, what the automated test suite verifies, what Apricity does **not** guarantee, and known architectural limitations.

---

## 1. What Apricity Currently Guarantees

1. **Ephemeral Partitioning**:
   * Each tab is opened with a uniquely generated UUID v4 (`sessionUUID`) that maps to an isolated in-memory Electron partition (`ephemeral-${sessionUUID}`).
   * Partitions are configured with in-memory caching (`{ cache: false }`), and `disable-http-cache` / `disk-cache-size: 1` command-line switches prevent standard disk caching.

2. **Default Permission Lockdown**:
   * Both `session.defaultSession` and tab-specific ephemeral sessions enforce a strict default-deny permission handler (`setPermissionRequestHandler((_wc, _perm, cb) => cb(false))`).
   * High-risk APIs (geolocation, notifications, media/camera/microphone, clipboard access, external protocols) are blocked by default.

3. **In-Memory Cryptographic Isolation (`ZTRCryptoVault`)**:
   * Ephemeral AES-256-GCM keys (256-bit) are generated per tab session via the WebCrypto API with `extractable: false`.
   * Cryptographic operations are isolated per session UUID. Ciphertext generated under Session A's key cannot be decrypted under Session B's key (guaranteed by AES-GCM authentication tag verification).
   * Key references are removed from the in-memory vault Map upon session close, preventing subsequent encryption/decryption requests for that session ID.

4. **Fail-Closed Tor Proxy Routing**:
   * Network requests in Electron sessions are directed to Tor SOCKS5 proxy (`socks5://127.0.0.1:9150` or `9050`).
   * Chromium host resolver rules (`MAP * ~NOTFOUND , EXCLUDE 127.0.0.1`) prevent the browser from using the OS DNS resolver for external hostnames.
   * If the Tor SOCKS proxy is unreachable or down, requests fail closed with connection errors rather than silently falling back to unproxied clearnet.

5. **Tab Lifecycle State Invalidation**:
   * Closing a tab purges its state from `activeTabs`, deletes the in-memory storage store, removes its key from the vault, and issues `clearStorageData()` / `clearCache()` to the Electron partition.
   * Subsequent API operations on closed tab IDs are explicitly rejected.

---

## 2. What the Test Suite Verifies

The test suite (`npm test`) executes unit, lifecycle, and adversarial isolation tests covering:

* **Session Uniqueness**:
  * Every opened tab receives a unique session UUID and non-overlapping partition identifier.
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
* **Negative & Adversarial Attacks**:
  * Direct attempts to write into unallocated containers, forge session UUIDs, export non-extractable keys via WebCrypto API, and execute double-open/double-close exploits are rejected.

---

## 3. What Apricity Does NOT Currently Guarantee

1. **Forensic Physical Memory Erasure**:
   * Removing JavaScript object references and calling `globalThis.gc()` is a best-effort runtime hint. It does **not** guarantee immediate physical overwriting or zeroing of RAM, nor does it guarantee data cannot be recovered by forensic memory analysis of a compromised host.

2. **Absolute Anonymity or Circuit Isolation**:
   * Routing traffic through Tor SOCKS5 does not provide complete anonymity guarantees against advanced traffic analysis, correlation attacks, or application-level fingerprinting.
   * SOCKS5 proxy routing at port 9150/9050 shares the Tor daemon's circuit pool unless stream isolation is explicitly configured.

3. **Protection Against Compromised Host Process**:
   * While `extractable: false` prevents exporting keys via standard WebCrypto JavaScript APIs (`exportKey`), it does not protect cryptographic keys against a debugger, memory dumper, or root-level malware with direct access to process memory.

---

## 4. Known Architectural Limitations

1. **ZTR Storage Simulator vs Chromium Webview Storage**:
   * The encrypted storage store in `ZeroTrustRenderer.mjs` (`this._ephemeralStorageStores`) is currently an in-memory simulation and test abstraction.
   * Real web browsing inside `<webview>` elements uses Electron's native Chromium storage engine isolated by partition names (`partition="ephemeral-UUID"`). Webview web storage (e.g. DOM localStorage set by web pages) is **not** currently passed through `ZeroTrustRenderer`'s WebCrypto AES-GCM encryption layer.

2. **Electron `<webview>` Sandbox Limitation**:
   * The main `BrowserWindow` runs with `sandbox: false` because Electron requires this setting for `<webview>` tag management. Web content runs in isolated guest processes, but the shell process does not have Chromium sandbox restrictions.

3. **Gecko vs Chromium Preferences Disconnect**:
   * `src/ztr/ztr-user.js` and `ZTRPrefs.mjs` define and validate Firefox/Gecko security preferences (such as `security.sandbox.content.level: 9` and `fission.autostart: true`).
   * Apricity executes on Chromium/Electron, which does not read or apply Gecko `user_pref()` settings.
