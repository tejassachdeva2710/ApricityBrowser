# Apricity Browser — Threat Model & Security Architecture

**Document Version:** 1.0.0  
**Classification:** Security Architecture & Threat Specification  
**Scope:** Apricity Zero Trust Rendering (ZTR) Core, Electron `<webview>` Partitioning, and Tor SOCKS5 Network Routing

---

## 1. Overview & Purpose

Apricity Browser is an experimental desktop privacy browser designed to explore **ephemeral per-tab session isolation**, **disposable in-memory browser state**, **controlled network proxy routing**, and **empirically measured session destruction**.

This document defines the formal threat model for Apricity: what assets the browser protects, the threat actors and adversary capabilities considered, the boundaries that enforce isolation, what security properties are experimentally verified versus unverified or out of scope, and an empirical security matrix.

---

## 2. Protected Assets

Apricity manages and attempts to isolate the following assets:

| Asset | Description | Storage Layer |
|---|---|---|
| **Browsing Session State** | Tab URL history, DOM state, active render trees, and navigation history | Chromium Webview Process RAM |
| **HTTP & Session Cookies** | Authentication tokens, session identifiers, and tracking cookies | Chromium `CookieStore` (RAM partition) & ZTR simulator `Map` |
| **DOM Web Storage** | Key-value data stored via `localStorage` and `sessionStorage` | Chromium `DOMStorage` (LevelDB in RAM) & ZTR simulator `Map` |
| **IndexedDB Databases** | Structured client-side databases stored by web applications | Chromium `IndexedDB` (LevelDB in RAM) & ZTR simulator `Map` |
| **HTTP & Code Cache** | Cached images, stylesheets, scripts, and compiled V8 bytecode | Chromium in-memory cache & V8 isolate heap |
| **Service Workers & Blobs** | Background worker registrations and in-memory binary Blob handles | Chromium ServiceWorker database & Blob storage in RAM |
| **Cryptographic Session Keys** | Ephemeral AES-256-GCM symmetric keys generated per session UUID | V8 WebCrypto `CryptoKey` handles (`extractable: false`) |
| **Network Routing Identity** | User origin IP address and DNS queries | Localhost loopback → Tor SOCKS5 daemon (`127.0.0.1:9150/9050`) |
| **Ephemeral Session Context** | Correlation between concurrent tabs and historical browsing sessions | Tab-specific UUID v4 and context partition strings |

---

## 3. Threat Actors & Adversary Models

Apricity considers the following adversary capabilities:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          THREAT ACTOR SPECTRUM                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  [IN SCOPE: In-Session & Cross-Site Adversaries]                            │
│  • Malicious Web Origins & Web Scripts (XSS, CSRF, tracking pixels)        │
│  • Cross-Origin Tab Attackers (Cross-site data access attempts)            │
│  • Compromised / Buggy Guest Renderer Process                               │
│  • Passive Local Network Observers (Local ISP, Wi-Fi eavesdroppers)         │
│  • Non-Destructive Post-Session Local User (Casual filesystem examination)  │
│                                                                             │
│  [PARTIALLY MITIGATED: Advanced Forensic Scenarios]                         │
│  • Unallocated Filesystem Residue Analysis (Standard directory listing)    │
│                                                                             │
│  [OUT OF SCOPE: Privileged & Hardware Adversaries]                          │
│  • Compromised Host OS / Local Process Debugger / Root-level Malware       │
│  • Host Kernel Memory Paging Inspection (pagefile.sys / swapfile.sys)       │
│  • Physical SSD Controller / Flash Translation Layer (FTL) Carving          │
│  • Global Passive Network Adversaries (Traffic correlation / confirmation)  │
│  • Hardware-level Cold Boot / DRAM Remanence Attacks                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 In-Scope Threat Actors

1. **Malicious Web Origins & Web Scripts**:
   - *Goal*: Steal authentication cookies, access local storage across domains, fingerprint browser environments, or retain tracking identifiers across visits.
   - *Threat Level*: High.
2. **Cross-Tab / Cross-Session Attackers**:
   - *Goal*: Correlate user activity between Tab A (e.g. an authenticated account) and Tab B (e.g. an untrusted site), or access Tab A's in-memory storage from Tab B.
   - *Threat Level*: High.
3. **Compromised Guest Renderer Process**:
   - *Goal*: A renderer exploited via a Blink memory corruption vulnerability attempting to access Node.js APIs or cross into other guest webviews.
   - *Threat Level*: High.
4. **Passive Local Network Observers**:
   - *Goal*: Intercept plaintext HTTP traffic, monitor visited domains via cleartext DNS lookups, or log destination IP addresses.
   - *Threat Level*: Moderate to High.
5. **Post-Session Casual File Inspector**:
   - *Goal*: Inspect browser history, persistent cookie databases, or cached images on the filesystem after the user closes tabs or quits the browser.
   - *Threat Level*: Moderate.

### 3.2 Out-of-Scope Threat Actors & Attacks

1. **Local Root / SYSTEM / Debugger Adversaries**:
   - An attacker with root/administrator access, capability to attach debuggers (`WinDbg`, `gdb`, `ptrace`), or running background memory-dumping malware can read raw process memory belonging to Electron or Node.js regardless of JavaScript-level isolation.
2. **Kernel Virtual Memory & Swap Extraction**:
   - When the host operating system experiences RAM exhaustion, virtual memory pages containing decrypted strings or keys can be paged to `pagefile.sys` or `swapfile.sys`. Apricity does not prevent OS kernel paging.
3. **Physical Solid-State Drive (SSD) Hardware Carving**:
   - SSD controllers utilize Flash Translation Layer (FTL) wear-leveling algorithms that write data to new NAND flash blocks without immediately erasing old physical blocks. User-space applications cannot enforce physical NAND block zeroization.
4. **Global Passive Network Adversaries & Advanced Traffic Correlation**:
   - While Tor masks source IP addresses and encrypts traffic through onion relays, global adversaries monitoring both ingress (entry guard) and egress (exit node) traffic flows can perform statistical timing correlation attacks.
5. **Hardware Attacks (Cold Boot, Rowhammer, CPU Cache Side Channels)**:
   - Physical extraction of DRAM remanence or microarchitectural side-channel attacks against host CPUs are outside Apricity's threat model.

---

## 4. Security Boundaries

Apricity enforces isolation across six distinct architectural boundaries:

```
                      ┌─────────────────────────────────┐
                      │    Host OS & Platform Memory    │
                      └────────────────┬────────────────┘
                                       │ [Boundary 6: OS / Filesystem]
                      ┌────────────────▼────────────────┐
                      │    Electron Main Shell Host     │
                      └───────┬─────────────────┬───────┘
                              │                 │
     [Boundary 3: ZTR Engine] │                 │ [Boundary 2: Electron Partition]
     ┌────────────────────────▼──┐           ┌──▼────────────────────────┐
     │ ZeroTrustRenderer Core    │           │ Ephemeral Webview Session │
     │ (In-Memory Simulator Map) │           │ (Chromium Blink Engine)   │
     └────────────┬──────────────┘           └──┬────────────────────────┘
                  │ [Boundary 4: WebCrypto]     │ [Boundary 1: Web Content]
     ┌────────────▼──────────────┐           ┌──▼────────────────────────┐
     │ CryptoVault (AES-256-GCM) │           │ Web Content (DOM / JS)    │
     └───────────────────────────┘           └──┬────────────────────────┘
                                                │ [Boundary 5: Proxy / Tor]
                                             ┌──▼────────────────────────┐
                                             │ Tor SOCKS5 Proxy Daemon   │
                                             └───────────────────────────┘
```

### Boundary 1: Web Content Boundary (Guest Webview Isolation)
* **What is Enforced**: Web content executes inside Chromium `<webview>` guest renderers. `nodeIntegration` is disabled (`false`), `contextIsolation` is enabled (`true`), and permissions default to deny (`cb(false)`). Guest web pages cannot access Node.js runtime primitives or Electron internal APIs.
* **What is NOT Enforced**: The parent `BrowserWindow` runs with `sandbox: false` (required by Electron for `<webview>` hosting). If a severe Chromium zero-day sandbox escape is executed from guest web content, the host process could be compromised.

### Boundary 2: Electron Session / Partition Boundary (Chromium Storage)
* **What is Enforced**: Every tab is assigned a unique `sessionUUID` mapping to an in-memory session partition (`ephemeral-${sessionUUID}`). Partitions are instantiated with `{ cache: false }`. On tab closure, `clearStorageData()` and `clearCache()` are triggered asynchronously to purge Chromium's internal partition state.
* **What is NOT Enforced**: Chromium internally manages SQLite/LevelDB structures in memory. User-space JavaScript cannot directly verify the exact microsecond when Chromium deallocates internal C++ buffers in RAM.

### Boundary 3: ZeroTrustRenderer Application Abstraction (ZTR Engine)
* **What is Enforced**: Application-level state machine in `ZeroTrustRenderer.mjs` stores key-value pairs in memory `Map` instances (`_ephemeralStorageStores`). Context IDs are strictly separated; closing a tab deletes the map reference and marks the session destroyed.
* **What is NOT Enforced**: This is an application-level test and state abstraction. Live web content DOM storage (e.g. `document.cookie` set by websites inside webviews) operates directly within Chromium's C++ storage subsystem (Boundary 2) and does **not** route through the ZTR JavaScript Map abstraction.

### Boundary 4: WebCrypto Key Boundary (`ZTRCryptoVault`)
* **What is Enforced**: Symmetric keys are generated via `crypto.subtle.generateKey` using AES-256-GCM with `extractable: false`. Script execution within the application cannot export raw key bytes via `crypto.subtle.exportKey()`. On tab closure, key references are deleted from the vault Map.
* **What is NOT Enforced**: Non-extractability is an API-level guarantee enforced by the V8/Node.js JavaScript engine. It does not prevent a native process debugger, root user, or kernel memory inspector from reading raw cryptographic key bytes in process memory.

### Boundary 5: Network / Proxy Boundary (Tor SOCKS5 Routing)
* **What is Enforced**: Browser network routing is configured to route through Tor SOCKS5 (`127.0.0.1:9150/9050`). Chromium command-line switches (`host-resolver-rules = 'MAP * ~NOTFOUND , EXCLUDE 127.0.0.1'`) instruct Chromium not to resolve hostnames through the local OS DNS resolver. If the Tor proxy is offline, connections fail closed.
* **What is NOT Enforced**: By default, all tabs sharing the same Tor SOCKS port share the Tor daemon's circuit pool. Without per-tab `IsolateSOCKSAuth` credentials, concurrent tabs may share the same Tor exit relay. Tor routing provides network pseudonymity, not absolute application-layer anonymity against browser fingerprinting.

### Boundary 6: OS / Filesystem Boundary
* **What is Enforced**: The application enables switches `disable-http-cache` and `disk-cache-size: 1`. Automated deep scans verify that no persistent tab partition folders are created on disk under `%APPDATA%\apricity-browser-ztr\Partitions`.
* **What is NOT Enforced**: OS-level artifacts (NTFS transaction metadata in `$LogFile` and `$UsnJrnl`, OS crash logs, Windows Prefetch, and virtual memory paging in `pagefile.sys`) are managed by the operating system kernel and cannot be purged or zeroed by user-space applications.

---

## 5. Security Properties & Verification Taxonomy

Apricity classifies all security properties using four precise categories:

* **VERIFIED**: The property is experimentally demonstrated and continuously validated by automated test suites or forensic binary scans.
* **PARTIALLY VERIFIED**: The property is verified at the application/API layer, but full end-to-end enforcement depends on runtime conditions (such as live Electron GUI execution or active network daemons).
* **UNVERIFIED**: The property cannot be reliably verified from user-space automated tooling due to operating system or hardware limitations. An explicit justification code is documented.
* **NOT PROVIDED**: The property is explicitly outside Apricity's security model and is not provided by the architecture.

---

## 6. Comprehensive Security Matrix

| Property | Status | Empirical Evidence & Architectural Justification |
|---|:---:|---|
| **Session Identity Uniqueness** | **VERIFIED** | Verified by `test_adversarial_isolation.mjs` (UUID v4 generation and non-overlapping partition strings). |
| **ZTR In-Memory Storage Isolation** | **VERIFIED** | Verified by `test_adversarial_isolation.mjs` (cross-tab storage separation across cookies, localStorage, indexedDB, cache). |
| **Raw Storage Ciphertext Protection** | **VERIFIED** | Verified by `test_adversarial_isolation.mjs` (raw ZTR store contains `{ iv, ciphertext }`, no plaintext). |
| **WebCrypto Non-Extractable Key Gen** | **VERIFIED** | Verified by `test_forensic_auditor.mjs` (`extractable: false` rejects `exportKey` API calls). |
| **Cryptographic Cross-Session Decryption Rejection** | **VERIFIED** | Verified by `test_adversarial_isolation.mjs` (AES-GCM authentication tag mismatch rejection). |
| **Post-Destruction Invalidation in ZTR** | **VERIFIED** | Verified by `test_ztr_lifecycle.mjs` and `test_forensic_auditor.mjs` (key deletion prevents subsequent decryption). |
| **Ephemeral Partition Disk Non-Persistence** | **VERIFIED** | Verified by `npm run forensic` (no persistent folders created under `%APPDATA%\...\Partitions`). |
| **UserData Filesystem Canary Absence** | **VERIFIED** | Verified by `npm run forensic` (deep binary scan of 45 runtime files in `userData` detects 0 residual canary bytes). |
| **Default Permission Denial (API Layer)** | **VERIFIED** | Verified by `test_adversarial_isolation.mjs` (`setPermissionRequestHandler` returns `false` for all standard APIs). |
| **Tor Proxy Configuration & Port Probing** | **VERIFIED** | Verified by `test_adversarial_isolation.mjs` (SOCKS5 proxy switches and remote DNS rule validation). |
| **Chromium Native Partition Storage Isolation** | **PARTIALLY VERIFIED** | Verified at configuration level; live Blink SQLite/LevelDB webview DOM storage requires live Electron GUI execution. |
| **Live Webview Permission Suppression** | **PARTIALLY VERIFIED** | Verified at session handler level; live Blink UI prompt suppression requires live BrowserWindow runtime. |
| **Live Tor Circuit Routing & Stream Isolation** | **PARTIALLY VERIFIED** | Verified via configuration strings and port probing; end-to-end exit relay routing requires live Tor daemon and external network connectivity. |
| **Physical RAM & V8 Heap Zeroization** | **NOT PROVIDED** | JS GC frees object references for reuse; it does not physically zero deallocated memory (`UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE`). |
| **Immunity to Process Memory Inspection** | **NOT PROVIDED** | Non-extractable WebCrypto keys can still be extracted by native process debuggers or root malware with host memory access. |
| **Absolute Anonymity via Tor** | **NOT PROVIDED** | SOCKS5 proxy routing masks IP address, but does not provide mathematical anonymity against global traffic correlation or fingerprinting. |
| **SSD Physical NAND Flash Zeroization** | **UNVERIFIED** | Solid-state drive wear-leveling (FTL) writes out-of-place; physical cells are inaccessible (`UNVERIFIED_PHYSICAL_FTL_UNREACHABLE`). |
| **OS Virtual Memory Pagefile Exclusion** | **UNVERIFIED** | OS Virtual Memory Manager may page process memory to `pagefile.sys` under RAM exhaustion (`UNVERIFIED_KERNEL_PAGING_INACCESSIBLE`). |
| **NTFS Metadata & Journal Erasure** | **UNVERIFIED** | File unlinking leaves transaction records in NTFS `$LogFile` and `$UsnJrnl` (`UNVERIFIED_OS_METADATA_JOURNAL_PRIVILEGED`). |

---

## 7. Operational & Development Guidelines

1. **Never Make Absolute Forensic Claims**: Do not claim "zero disk trace", "unrecoverable browsing", or "complete RAM wiping". Use precise terminology such as "application-level ephemeral cleanup" or "within the scanned filesystem surface".
2. **Preserve Architectural Honesty**: Clearly distinguish between `ZeroTrustRenderer` (the in-memory cryptographic test and simulator layer) and native Chromium `<webview>` storage.
3. **Validate Changes Empirically**: Any security assertion added to documentation or codebase must be backed by an automated test in `tests/` or a forensic check in `src/forensics/`.
