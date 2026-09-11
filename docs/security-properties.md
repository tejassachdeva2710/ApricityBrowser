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

1. **Default Permission Denial**:
   * Both `session.defaultSession` and tab-specific ephemeral sessions enforce a strict default-deny permission handler (`setPermissionRequestHandler((_wc, _perm, cb) => cb(false))`).
   * Standard Web API permission prompts (geolocation, notifications, media/camera/microphone, clipboard access, external protocols) are denied by default at the session layer.

2. **Native WebContentsView Isolation & Sandboxing**:
   * Guest web content runs inside `WebContentsView` instances with `sandbox: true`, `nodeIntegration: false`, and `contextIsolation: true`.
   * Guest content has no access to Electron or Node.js APIs and is strictly isolated from the trusted UI shell.
   * `will-navigate` blocks navigation to non-whitelisted schemes (`file:`, `javascript:`, custom schemes).
   * `setWindowOpenHandler` denies all window creation from guest content (`action: 'deny'`).
   * Main process validates all incoming navigation URLs over IPC, accepting only `http:` and `https:`.
   * `will-download` cancels downloads to prevent silent disk persistence.

3. **Fail-Closed Tor Proxy Configuration**:
   * Network requests in Electron sessions are configured to route through a local Tor SOCKS5 proxy (`socks5://127.0.0.1:9150` or `9050`).
   * Chromium host resolver rules (`MAP * ~NOTFOUND , EXCLUDE 127.0.0.1`) prevent the browser from using the host OS DNS resolver for external hostnames.
   * If the Tor SOCKS proxy is unreachable or down, requests fail closed with connection errors rather than falling back to unproxied clearnet.

4. **Tab Lifecycle State Invalidation**:
   * Closing a tab purges its state from `activeTabs`, closes the `WebContentsView`, and issues `clearStorageData()` / `clearCache()` to the Electron partition.
   * Subsequent API operations on closed tab IDs are explicitly rejected at the application level.

---

## 2. What the Test Suite Empirically Verifies

The automated test suites (`npm test`, `npm run test:security`, and `npm run forensic`) verify:

* **Session Uniqueness**:
  * Every opened tab receives a unique session UUID v4 and non-overlapping partition identifier string (`ephemeral-${sessionUUID}`).
  * Reopening a previously closed tab ID creates a new, independent session identity with no historical state linkage.
* **Native Chromium Partition Storage Isolation**:
  * Live Electron integration tests (`tests/test_electron_live.mjs`) verify that concurrent sessions writing to `cookies` and `localStorage` cannot retrieve or observe each other's data across distinct partitions.
  * *Note on IndexedDB & sessionStorage*: Cross-partition IndexedDB and sessionStorage isolation rely on Chromium partition separation in RAM, but are **NOT CURRENTLY TESTED** by automated tests in the repository.
* **Level 3 Security Foundation**:
  * `will-navigate` actively cancels non-http/https navigations (`tests/test_level3_security.mjs`).
  * `window.open()` produces null and creates 0 BrowserWindows (`tests/test_level3_security.mjs`).
  * IPC navigation rejects dangerous schemes (`file:`, `javascript:`, custom schemes) (`tests/test_level3_security.mjs`).
  * `will-download` cancels downloads via `preventDefault()` (`tests/test_level3_security.mjs`).
  * Safe DOM construction with zero `innerHTML` in the UI controller (`tests/test_level3_security.mjs`).
  * Strict `<meta>` CSP blocks `eval()` and inline scripts (`tests/test_level3_security.mjs`).
  * Synchronous permission checks return `"denied"` (`tests/test_level3_security.mjs`).
  * Permission request handler configured to deny standard Web API requests (`tests/test_level3_security.mjs`).
* **Forensic Canary Absence (Within Scanned Filesystem Surface)**:
  * High-entropy canary tokens injected across session subsystems are not detected in user-space file sweeps across temporary `userData` after tab closure (`npm run forensic`).

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

## 4. Known Architectural Limitations & Unverified Areas

1. **Tor SOCKS5 Configuration & Stream Isolation (UNVERIFIED / NOT CURRENTLY TESTED)**:
   * Automated verification of Tor proxy rules, host-resolver-rules, and live circuit routing is not currently covered by automated tests. Tor integration and traffic isolation are scheduled for Level 4.
   * Tabs currently share the default Tor daemon's circuit pool unless per-session stream isolation credentials (`IsolateSOCKSAuth`) are explicitly configured.

2. **IndexedDB & sessionStorage Automated Test Coverage (NOT CURRENTLY TESTED)**:
   * While `localStorage` and `cookies` are verified across partitions in `tests/test_electron_live.mjs`, `IndexedDB` and `sessionStorage` cross-partition isolation are not currently covered by automated test cases.

3. **Abnormal Process Termination**:
   * If the process terminates abnormally (e.g. SIGKILL, sudden power loss), asynchronous session teardown hooks (`clearStorageData()` and `clearCache()`) cannot execute, leaving residual artifacts in Chromium's temporary partition directories.

4. **OS Kernel & Hardware Remanence**:
   * Kernel virtual memory paging (`pagefile.sys`), filesystem journals (`$LogFile`, `$UsnJrnl`), and SSD wear-leveling (FTL) operate below the application boundary and cannot be purged by user-space software.
