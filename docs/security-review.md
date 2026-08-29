# Apricity Browser — External Security Review & Claims Audit

This document is prepared for senior security engineers and technical reviewers inspecting the Apricity Browser repository.

Every security claim in Apricity is evaluated against empirical evidence from automated tests and the forensic artifact auditor.

---

## 📋 Evaluation Taxonomy

* **`VERIFIED`**: Directly tested with passing automated unit, integration, or adversarial tests.
* **`PARTIALLY VERIFIED`**: Key architectural layers tested, but certain live/runtime conditions require external daemons or full environment execution.
* **`UNVERIFIED`**: Cannot be verified by user-space software due to OS kernel, driver, or hardware controller boundaries (explicitly justified).
* **`NOT PROVIDED`**: The architecture intentionally does not provide this guarantee (non-goal).

---

## 🛡️ Comprehensive Security Claims Table

| Claim / Property | Evidence in Repository | Status | Limitation / Boundary Context |
|---|---|:---:|---|
| **Session Identity Isolation** | `tests/test_adversarial_isolation.mjs`<br/>`tests/test_electron_live.mjs` | **`VERIFIED`** | Every tab generates a unique UUID v4 and distinct Electron partition string. Reopening produces fresh non-colliding identity. |
| **Application-Level Storage Isolation** | `tests/test_ztr_lifecycle.mjs`<br/>`tests/test_adversarial_isolation.mjs` | **`VERIFIED`** | ZTR simulator maintains separate in-memory Maps per `userContextId`. Raw stores contain ciphertext buffers only. |
| **Cross-Session Cryptographic Isolation** | `tests/test_adversarial_isolation.mjs`<br/>`src/ztr/ZTRCryptoVault.mjs` | **`VERIFIED`** | Session B key cannot decrypt Session A ciphertext (AES-GCM tag mismatch rejects cross-session reads). |
| **Non-Extractable Session Keys** | `tests/test_forensic_auditor.mjs`<br/>`src/ztr/ZTRCryptoVault.mjs` | **`VERIFIED`** | WebCrypto keys are created with `extractable: false`, preventing export via WebCrypto API. |
| **Session Destruction Lifecycle (ZTR)** | `tests/test_ztr_lifecycle.mjs` | **`VERIFIED`** | `closeTab()` invalidates session state, deletes key references, and purges in-memory maps. Subsequent reads throw errors. |
| **Chromium Ephemeral Partition Allocation** | `tests/test_electron_live.mjs` | **`VERIFIED`** | `session.fromPartition('ephemeral-UUID', { cache: false })` operates with `getStoragePath() === null` (RAM-only SQLite/LevelDB). |
| **Live Native Cookie Store Isolation** | `tests/test_electron_live.mjs` | **`VERIFIED`** | Cookie set in Session A partition returns 0 cookies when queried from Session B partition. |
| **Live DOM localStorage Isolation** | `tests/test_electron_live.mjs` | **`VERIFIED`** | `localStorage.getItem` in Session B renderer returns `null` for keys written by Session A renderer. |
| **Live DOM IndexedDB Isolation** | `tests/test_electron_live.mjs` | **`VERIFIED`** | IndexedDB created in Session A is not visible or accessible to Session B renderers. |
| **Live DOM sessionStorage Isolation** | `tests/test_electron_live.mjs` | **`VERIFIED`** | `sessionStorage` in Session B renderer returns `null` for keys written by Session A. |
| **Live Session Teardown (Chromium)** | `tests/test_electron_live.mjs` | **`VERIFIED`** | `clearStorageData()` purges all partition cookies and storage in RAM. Newly opened partition is completely clean. |
| **Default Permission Denial (API Layer)** | `tests/test_adversarial_isolation.mjs`<br/>`tests/test_electron_live.mjs` | **`VERIFIED`** | `setPermissionRequestHandler` returns `false` for all standard Web API permission requests. |
| **Forensic Filesystem Absence** | `npm run forensic`<br/>`tests/test_forensic_auditor.mjs` | **`VERIFIED`**<br/>*(Scanned Surface)* | Deep multi-encoding binary scan across 45 runtime files in `%APPDATA%\...\userData` detected 0 residual canaries. |
| **Tor SOCKS5 Proxy Configuration** | `tests/test_adversarial_isolation.mjs`<br/>`tests/test_electron_live.mjs` | **`VERIFIED`** | Session proxy rules set to `socks5://127.0.0.1:9150` with fail-closed remote DNS delegation (`host-resolver-rules`). |
| **Live Tor Circuit Exit Routing** | Manual / Tor Network | **`PARTIALLY VERIFIED`** | Proxy switches and port probing are automated; live end-to-end circuit routing and `.onion` resolution require an active Tor daemon. |
| **Tor Circuit Stream Isolation** | Architecture specification | **`PARTIALLY VERIFIED`** | Tabs share the default Tor daemon's circuit pool unless per-tab SOCKS authentication credentials (`IsolateSOCKSAuth`) are supplied. |
| **Gecko user_pref Enforcement** | `src/ztr/ztr-user.js`<br/>`src/ztr/ZTRPrefs.mjs` | **`PARTIALLY VERIFIED`** | Validated as a conceptual security policy specification; Electron/Chromium enforces sandboxing via Chromium flags and webPreferences. |
| **Physical DRAM & V8 Heap Zeroization** | Operating System / V8 Heap | **`NOT PROVIDED`** | V8 `gc()` frees object references for heap allocator reuse; it does not overwrite raw physical DRAM bytes (`UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE`). |
| **Immunity to Process Memory Debuggers** | Host Operating System | **`NOT PROVIDED`** | `extractable: false` prevents JS API export; root processes, kernel drivers, or debuggers with `PROCESS_VM_READ` can read process memory. |
| **Absolute Mathematical Anonymity** | Network Layer | **`NOT PROVIDED`** | Tor SOCKS5 routing provides network pseudonymity; it cannot prevent advanced browser fingerprinting or timing correlation attacks. |
| **SSD Physical NAND Flash Zeroization** | Solid-State Drive FTL | **`UNVERIFIED`** | SSD Flash Translation Layers write out-of-place for wear leveling; physical flash cells cannot be overwritten by user-space unlinks (`UNVERIFIED_PHYSICAL_FTL_UNREACHABLE`). |
| **OS Virtual Memory Pagefile Exclusion** | OS Virtual Memory Manager | **`UNVERIFIED`** | Under host memory pressure, the OS kernel may page process RAM to `pagefile.sys` or `swapfile.sys` (`UNVERIFIED_KERNEL_PAGING_INACCESSIBLE`). |
| **NTFS Metadata Journal Erasure** | Windows NTFS File System | **`UNVERIFIED`** | Unlinking files leaves metadata transaction records in NTFS `$LogFile` and `$UsnJrnl` (`UNVERIFIED_OS_METADATA_JOURNAL_PRIVILEGED`). |

---

## 🔍 Key Architectural Takeaways for Reviewers

1. **Dual Storage Boundaries**:
   * **Boundary 1 (ZTR In-Memory Store)**: Application-level JavaScript `Map` store with WebCrypto AES-256-GCM encryption.
   * **Boundary 2 (Chromium Webview Storage)**: Native Chromium Blink SQLite and LevelDB storage running in RAM partitions (`ephemeral-${UUID}`). Webview DOM storage is isolated by Chromium's C++ partition engine and does not pass through the ZTR JavaScript layer.
2. **Empirical Deletion vs Physical Wiping**:
   * Apricity proves that *test artifacts are not detectable in reachable filesystem and application memory structures* after session teardown.
   * Apricity does *not* claim that physical NAND flash transistors or OS kernel swap files have undergone military-grade degaussing.
