# Apricity Browser — External Security Review & Claims Audit

This document is prepared for senior security engineers and technical reviewers inspecting the Apricity Browser repository.

Every security claim in Apricity is evaluated against empirical evidence from automated tests and the forensic artifact auditor.

---

## 📋 Evaluation Taxonomy

* **`VERIFIED`**: Directly tested with passing automated unit, integration, or adversarial tests in the current repository.
* **`PARTIALLY VERIFIED`**: Key architectural layers tested, but certain live/runtime conditions require external daemons or full environment execution.
* **`UNVERIFIED / NOT CURRENTLY TESTED`**: Not currently covered by an automated test in the repository, or cannot be verified by user-space software due to OS kernel, driver, or hardware controller boundaries (explicitly justified).
* **`NOT PROVIDED`**: The architecture intentionally does not provide this guarantee (non-goal).

---

## 🛡️ Comprehensive Security Claims Table

| Claim / Property | Evidence in Repository | Status | Limitation / Boundary Context |
|---|---|:---:|---|
| **Session Identity Isolation** | `tests/test_electron_live.mjs` | **`VERIFIED`** | Every tab generates a unique UUID v4 and distinct Electron partition string (`ephemeral-${UUID}`). Reopening produces fresh non-colliding identity. |
| **Chromium Ephemeral Partition Allocation** | `tests/test_electron_live.mjs` | **`VERIFIED`** | `session.fromPartition('ephemeral-UUID', { cache: false })` operates with `getStoragePath() === null` (RAM-only SQLite/LevelDB). |
| **Live Native Cookie Store Isolation** | `tests/test_electron_live.mjs` | **`VERIFIED`** | Cookie set in Session A partition returns 0 cookies when queried from Session B partition. |
| **Live DOM localStorage Isolation** | `tests/test_electron_live.mjs` | **`VERIFIED`** | `localStorage.getItem` in Session B renderer returns `null` for keys written by Session A renderer. |
| **Live DOM IndexedDB Isolation** | None (Not currently tested in automated suite) | **`NOT CURRENTLY TESTED`** | Cross-partition IndexedDB isolation relies on Chromium partition separation in RAM, but is not currently exercised by an automated test in the repository. |
| **Live DOM sessionStorage Isolation** | None (Not currently tested in automated suite) | **`NOT CURRENTLY TESTED`** | `sessionStorage` partition separation is not verified by current automated tests. Note that sessionStorage is an in-memory window/tab construct without persistent disk guarantees. |
| **Live Session Teardown (Chromium)** | `tests/test_electron_live.mjs` | **`VERIFIED`** | `clearStorageData()` and `clearCache()` purge partition storage in RAM. WebContentsView is explicitly closed. |
| **Navigation Bounds Enforcement** | `tests/test_level3_security.mjs` | **`VERIFIED`** | `will-navigate` blocks non-http(s)/about/data schemes (such as `file://` and `javascript:`) from loading in guest renderers. |
| **Window Creation Bounds** | `tests/test_level3_security.mjs` | **`VERIFIED`** | `setWindowOpenHandler` enforces `action: 'deny'`, preventing unmanaged `BrowserWindow` creation from guest content. |
| **IPC Navigation URL Validation** | `tests/test_level3_security.mjs` | **`VERIFIED`** | Main process validates incoming navigation URLs at the IPC boundary (`isAllowedIpcUrl`), strictly accepting only `http:` and `https:`. |
| **Download Denial Enforcement** | `tests/test_level3_security.mjs` | **`VERIFIED`** | `will-download` event is intercepted and cancelled via `event.preventDefault()`, suppressing disk writes. |
| **Safe UI DOM Construction** | `tests/test_level3_security.mjs` | **`VERIFIED`** | UI shell controller statically verified to contain 0 `innerHTML` assignments; dynamic test verifies markup renders strictly as text. |
| **Strict UI Shell CSP** | `tests/test_level3_security.mjs` | **`VERIFIED`** | `<meta>` CSP forbids `unsafe-inline` and `unsafe-eval`; dynamically verified to block `eval()` and inline `<script>` in UI shell. |
| **Synchronous Permission Denial** | `tests/test_level3_security.mjs` | **`VERIFIED`** | `setPermissionCheckHandler` returns `false`, ensuring `navigator.permissions.query()` synchronously returns `"denied"`. |
| **Default Permission Denial (API Layer)** | `tests/test_level3_security.mjs` | **`VERIFIED`** | `setPermissionRequestHandler` is configured on ephemeral sessions to deny standard Web API permission requests; exercised in Level 3 test harness. |
| **Forensic Filesystem Absence** | `npm run forensic`<br/>`tests/test_forensic_auditor.mjs` | **`VERIFIED`**<br/>*(Scanned Surface)* | Deep multi-encoding binary scan across runtime files in isolated temporary `userData` detects 0 residual canaries post-cleanup. |
| **Tor SOCKS5 Proxy Configuration** | None (Scheduled for Level 4) | **`UNVERIFIED / NOT CURRENTLY TESTED`** | Automated Tor configuration, `proxyRules`, and `host-resolver-rules` validation are not covered by the current test suite. Tor integration and traffic isolation are Level 4 work. |
| **Live Tor Circuit Exit Routing** | Manual / Tor Network | **`UNVERIFIED / NOT CURRENTLY TESTED`** | Automated proxy routing not tested; live end-to-end circuit routing and `.onion` resolution require an active Tor daemon (Level 4 objective). |
| **Tor Circuit Stream Isolation** | Architecture specification | **`NOT CURRENTLY TESTED`** | Tabs share the default Tor daemon's circuit pool unless per-tab SOCKS authentication credentials (`IsolateSOCKSAuth`) are supplied. |
| **Physical DRAM & V8 Heap Zeroization** | Operating System / V8 Heap | **`NOT PROVIDED`** | V8 `gc()` frees object references for heap allocator reuse; it does not overwrite raw physical DRAM bytes (`UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE`). |
| **Immunity to Process Memory Debuggers** | Host Operating System | **`NOT PROVIDED`** | Root processes, kernel drivers, or debuggers with `PROCESS_VM_READ` can read process memory. |
| **Absolute Mathematical Anonymity** | Network Layer | **`NOT PROVIDED`** | Tor SOCKS5 routing provides network pseudonymity; it cannot prevent advanced browser fingerprinting or timing correlation attacks. |
| **SSD Physical NAND Flash Zeroization** | Solid-State Drive FTL | **`UNVERIFIED`** | SSD Flash Translation Layers write out-of-place for wear leveling; physical flash cells cannot be overwritten by user-space unlinks (`UNVERIFIED_PHYSICAL_FTL_UNREACHABLE`). |
| **OS Virtual Memory Pagefile Exclusion** | OS Virtual Memory Manager | **`UNVERIFIED`** | Under host memory pressure, the OS kernel may page process RAM to `pagefile.sys` or `swapfile.sys` (`UNVERIFIED_KERNEL_PAGING_INACCESSIBLE`). |
| **NTFS Metadata Journal Erasure** | Windows NTFS File System | **`UNVERIFIED`** | Unlinking files leaves metadata transaction records in NTFS `$LogFile` and `$UsnJrnl` (`UNVERIFIED_OS_METADATA_JOURNAL_PRIVILEGED`). |

---

## 🔍 Key Architectural Takeaways for Reviewers

1. **Native Chromium Ephemeral Partition Isolation**:
   * Web content executes directly in sandboxed `WebContentsView` instances (`sandbox: true`, `nodeIntegration: false`, `contextIsolation: true`) backed by in-memory partitions (`session.fromPartition('ephemeral-${UUID}', { cache: false })`).
   * Partition storage operates entirely in memory (`getStoragePath() === null`). On tab teardown, `clearStorageData()` and `clearCache()` purge in-memory storage, and the `WebContentsView` is destroyed.
2. **Empirical Deletion vs Physical Wiping**:
   * Apricity proves that *test artifacts are not detectable in reachable filesystem and application memory structures* after session teardown.
   * Apricity does *not* claim that physical NAND flash transistors or OS kernel swap files have undergone military-grade degaussing.

## Forensic Verification Standard

The auditor verifies the absence of known test canaries from the filesystem surfaces it scans after a real Chromium session is destroyed. It does not prove complete forensic absence from physical hardware. The legacy application-level cryptographic storage simulator (`ZeroTrustRenderer`) has been completely removed from the architecture.
