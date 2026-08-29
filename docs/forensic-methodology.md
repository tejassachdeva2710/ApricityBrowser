# Apricity Browser — Forensic Audit Methodology Specification

**Document Version:** 1.0.0  
**Classification:** Security Architecture & Forensic Verification Standard  
**Target Engine:** Apricity Zero Trust Rendering (ZTR) v1.0.0 / Electron Chromium  

---

## 1. Overview & Threat Model

Apricity Browser is designed to provide ephemeral desktop web browsing through **Zero Trust Rendering (ZTR)**. Its security architecture combines per-tab ephemeral session partitions, in-memory cryptographic isolation, Tor SOCKS5 network routing, and automated self-destruct teardown lifecycles.

However, in computer forensics and adversarial analysis, privacy claims such as "zero disk residue", "unrecoverable browsing", or "complete physical wipe" frequently fail when examined against the physical realities of operating systems, solid-state flash memory controllers, and process memory managers.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               CORE FORENSIC PRINCIPLE                                   │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ Filesystem silence does NOT prove forensic zeroization. An absence of reachable files   │
│ in user-space directory traversals demonstrates only that operating system file pointers│
│ have been unlinked. It does not prove that plaintext data has been purged from physical │
│ NAND flash blocks, virtual memory paging files, kernel journals, or hardware buffers.   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

The Apricity Forensic Artifact Auditor (`npm run forensic`) is an empirical testing subsystem built to systematically search for residual session artifacts, evaluate Apricity's destruction lifecycle, and report findings with absolute security honesty.

---

## 2. Architectural Boundaries & Isolation Layers

Apricity operates across four distinct architectural layers, each with separate storage mechanisms, lifecycle scopes, and forensic observables:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               APRICITY RUNTIME BOUNDARIES                               │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  [BOUNDARY 1: ZTR In-Memory Simulator]                                                  │
│  • Components: src/ztr/ZeroTrustRenderer.mjs, src/ztr/ZTRCryptoVault.mjs                │
│  • Storage: In-memory JavaScript Map objects (_ephemeralStorageStores, _vault)          │
│  • Security: WebCrypto AES-256-GCM non-extractable keys (extractable: false)             │
│  • Lifecycle: 3-Phase cleanup on closeTab(tabId)                                        │
│                                                                                         │
│  [BOUNDARY 2: Native Chromium Webview Storage Subsystem]                                │
│  • Components: src/app/main.mjs, src/app/ui-controller.js, Electron <webview>           │
│  • Storage: Chromium in-memory partitions (session.fromPartition('ephemeral-UUID'))     │
│  • Engine: Blink SQLite CookieStore, LevelDB DOMStorage (RAM-only, getStoragePath=null) │
│  • Destruction: Asynchronous session.clearStorageData() & session.clearCache()           │
│                                                                                         │
│  [BOUNDARY 3: Host Operating System & Electron Main Process]                            │
│  • Components: Node.js / Electron main process runtime                                  │
│  • Filesystem: userData (%APPDATA%\apricity-browser-ztr), %LOCALAPPDATA%\Temp           │
│  • Subdirectories: Code Cache, GPUCache, blob_storage, Crashpad                         │
│  • OS Artifacts: Windows Prefetch, NTFS $LogFile/$MFT, pagefile.sys, crash minidumps    │
│                                                                                         │
│  [BOUNDARY 4: Tor SOCKS5 Network Subprocess]                                            │
│  • Components: tor.exe child daemon, socks5://127.0.0.1:9150                            │
│  • Storage: tor-data directory (%APPDATA%\apricity-browser-ztr\tor-data)                │
│  • Artifacts: cached-microdesc-consensus, state, lock, Tor daemon RAM circuit tables    │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### Critical Architectural Distinction: Simulator vs Native Webview

A fundamental architectural distinction exists within Apricity:
1. **`ZeroTrustRenderer.mjs` (Layer A)** is an in-memory cryptographic state machine simulator. It encrypts key-value items with WebCrypto AES-256-GCM and stores ciphertext in memory `Map` objects. It is evaluated directly in unit test suites (`npm test`).
2. **`<webview>` Web Content (Layer B)** runs directly on Chromium's native C++ Blink engine. Real DOM storage (`document.cookie`, `localStorage`, `indexedDB`) is managed by Chromium's in-memory partition engine (`ephemeral-${sessionUUID}`). Webview storage does **not** pass through the ZTR JavaScript WebCrypto wrapper.
3. The forensic auditor tests **both** boundaries: it validates ZTR key destruction and in-memory map purging, while also performing binary disk sweeps across Chromium's runtime storage paths.

---

## 3. Forensic Audit Lifecycle & Methodology

The auditor executes a controlled 6-phase audit lifecycle to empirically measure residue:

```
+-----------------------------------------------------------------------------------------+
|                              AUDITOR 6-PHASE LIFECYCLE                                  |
+-----------------------------------------------------------------------------------------+
| Phase 1: Baseline Discovery     -> Maps userData, Partitions, tor-data, %TEMP%          |
| Phase 2: Canary Injection       -> Injects high-entropy canary tokens into all stores   |
| Phase 3: Pre-Destruction Check  -> Validates canary presence in active session state     |
| Phase 4: Lifecycle Destruction  -> Executes closeTab, clearStorageData, key zeroing     |
| Phase 5: Deep Binary Scan       -> Scans disk & memory for UTF-8, UTF-16LE, ASCII bytes |
| Phase 6: Multi-Dimensional Eval -> Synthesizes PASS, FAIL, UNVERIFIED matrix            |
+-----------------------------------------------------------------------------------------+
```

### 3.1 Canary Token Specification
Canary tokens are generated with high entropy to avoid collision with standard strings while allowing robust binary regex carving:
```
CANARY_<SUBSYSTEM>_<SESSION_UUID_SHORT>_<TIMESTAMP>_<HIGH_ENTROPY_HEX>

Examples:
CANARY_COOKIE_a1b2c3d4_1772345678000_f89e2c4a91b2c3d4e5f60718
CANARY_LSTORE_a1b2c3d4_1772345678000_d4e5f60123456789abcdef01
CANARY_IDB_a1b2c3d4_1772345678000_9876543210abcdef01234567
CANARY_CACHE_a1b2c3d4_1772345678000_cba09876543210fedcba9876
CANARY_VAULT_a1b2c3d4_1772345678000_13579bdf2468ace013579bdf
```

### 3.2 Multi-Encoding Binary Matching Engine
Chromium and operating systems store strings in varying binary encodings:
- **UTF-8 / ASCII**: Standard web strings and plain text files.
- **UTF-16LE**: Chromium LevelDB values (DOMStorage), V8 bytecode caches, and Windows internal APIs.
- **Hex**: Raw binary stream identifiers.

The `FilesystemScanner` converts every canary token into multiple `Buffer` encodings and performs raw byte search (`buffer.includes(tokenBuffer)`) across all files in scanned runtime roots.

---

## 4. Detection Capabilities vs Inherent Physical & OS Limitations

Software-level automated auditing has definitive boundaries. The auditor explicitly documents what it can verify and what is physically unverifiable from user-space JavaScript:

```
                  ┌──────────────────────────────────────────────┐
                  │             USER-SPACE AUDITOR               │
                  │   (Bounded by OS APIs, Permissions, & FS)    │
                  └──────────────────────┬───────────────────────┘
                                         │  CANNOT PENETRATE
     ════════════════════════════════════╪══════════════════════════════════════
     HARDWARE & OS PERSISTENCE BARRIERS  │
                                         ▼
     ┌─────────────────────────────────────────────────────────────────────────┐
     │ 1. SSD Flash Translation Layer (FTL) & Wear-Leveling Out-of-Place Writes│
     │ 2. Kernel Virtual Memory Subsystem (pagefile.sys, swapfile.sys, RAM)    │
     │ 3. NTFS Master File Table ($MFT) & Transaction Journals ($LogFile)      │
     │ 4. Host OS Forensics (Windows Prefetch, BAM/DAM, Shellbags, WER Dumps)  │
     │ 5. Hardware GPU Compositor Textures & Display Driver VRAM Buffers       │
     └─────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Flash Storage (SSD) & Wear-Leveling Out-of-Place Writes
NAND flash memory cannot overwrite bytes in-place. The SSD controller's **Flash Translation Layer (FTL)** writes new data to unallocated physical blocks and marks old blocks as stale. User-space file overwriting writes to *new physical cells*, leaving the original plaintext intact in over-provisioning pools until asynchronous garbage collection occurs.

### 4.2 Operating System Paging & RAM Remanence
Under memory pressure, the Windows Virtual Memory Manager pages virtual memory pages belonging to Node.js, Electron, or Chromium renderer processes out of physical RAM and writes them to `pagefile.sys` or `swapfile.sys`. Plaintext keys and DOM storage cached in memory can be committed to non-volatile disk without browser awareness.

### 4.3 V8 Engine Garbage Collection vs Zeroization
JavaScript's `globalThis.gc()` marks unreferenced V8 objects as reclaimable; it **does not zero physical memory**. Plaintext string buffers remain in unallocated V8 heap slabs and Node.js `Buffer` pools indefinitely until overwritten by new allocations.

### 4.4 Filesystem Metadata & Transaction Journals
On NTFS (Windows), file creations, renames, and deletions are recorded in transaction journals (`$LogFile` and `$UsnJrnl`). When ephemeral files or directories are deleted, their record—including timestamp, file name, and directory path—remains in the NTFS journal until journal rollover.

---

## 5. Platform-Specific Filesystem Limitations (Windows)

- **Mandatory File Locking (`EBUSY` / `EPERM`)**: On Windows, open handles held by Chromium background helper processes prevent file reading or deletion. The scanner uses retry backoff and handles lock errors gracefully.
- **Hidden & Multi-Rooted AppData Paths**: Files are distributed across `%APPDATA%` (Roaming), `%LOCALAPPDATA%` (Local), and `%TEMP%`. The auditor dynamically resolves these roots from environment variables.
- **Path Length Limits (`MAX_PATH`)**: Nested Chromium LevelDB paths can approach 260 characters.

---

## 6. Multi-Dimensional Verification Taxonomy & Justification Codes

The auditor rejects simplistic single-boolean verdicts (such as `CLEAN: true`). All findings are categorized into a multi-dimensional matrix:

| Status | Definition |
|:---:|---|
| **PASS** | The canary artifact was confirmed created pre-destruction, and was conclusively **not detected** in reachable user-space scanned locations post-destruction. |
| **FAIL** | The canary artifact, residual session state, or active key was still detected in scanned storage, memory maps, or filesystem paths post-destruction. |
| **UNVERIFIED** | The property **cannot be verified** in automated user-space execution due to OS privilege limits, hardware FTL, or architecture. **Must include an official justification code.** |

### Official Technical Justification Codes

| Code | Subsystem | Technical Reason |
|---|---|---|
| `UNVERIFIED_PHYSICAL_FTL_UNREACHABLE` | SSD Storage | Solid-state drive wear-leveling and controller-managed flash translation layers (FTL) prevent user-space verification of physical NAND cell overwriting. |
| `UNVERIFIED_KERNEL_PAGING_INACCESSIBLE` | OS Kernel | Operating system virtual memory paging files (`pagefile.sys`, `swapfile.sys`) are locked by the kernel and cannot be inspected from user-space. |
| `UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE` | Process RAM | V8 JavaScript engine does not zero deallocated memory upon garbage collection; raw process heap carving requires native kernel/debugger attachment. |
| `UNVERIFIED_OS_METADATA_JOURNAL_PRIVILEGED` | NTFS Filesystem | NTFS `$LogFile`, `$UsnJrnl`, and `$MFT` raw cluster inspection requires Administrator/SYSTEM raw disk handle access (`\\.\PhysicalDrive0`). |
| `UNVERIFIED_WINDOWS_FILE_LOCK` | File System | Active Chromium process handles prevented non-destructive post-teardown file inspection. |
| `UNVERIFIED_REQUIRES_LIVE_CHROMIUM_RUNTIME` | Chromium Engine | Native Blink/Chromium DOM storage execution requires an active Electron BrowserWindow process with a loaded web context. |
| `UNVERIFIED_GPU_VRAM_INACCESSIBLE` | GPU Subsystem | GPU driver compositor buffers and texture memory cannot be audited from user-space JavaScript. |
| `UNVERIFIED_TOR_CONSENSUS_RETENTION` | Tor Subprocess | Tor daemon intentionally persists directory authority consensus documents and guard node relay state across restarts for network performance. |

---

## 7. Multi-Dimensional Evaluation Matrix Dimensions

1. **Dimension 1: In-Memory Cryptographic Vault (Layer 4)**
   - `VAULT_NON_EXTRACTABLE_KEY`: Non-extractable WebCrypto AES-256-GCM key generation (`PASS`).
   - `VAULT_DECRYPTION_INVALIDATION`: Invalidation of decryption capability upon key wipe (`PASS`).
   - `VAULT_KEY_DEREFERENCING`: Key reference removal from vault Map (`PASS`).
   - `VAULT_PHYSICAL_RAM_ZEROIZATION`: Physical DRAM zeroization (`UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE`).

2. **Dimension 2: In-Memory Storage Simulator (Layer 1 & 2)**
   - `SIM_MULTI_STORE_ENCRYPTION`: Ephemeral encrypted storage stores (`PASS`).
   - `SIM_EPHEMERAL_STORE_PURGE`: Store deletion from memory Maps on tab close (`PASS`).
   - `SIM_CROSS_TAB_ISOLATION`: Tab context isolation (`PASS`).
   - `SIM_V8_HEAP_SLAB_ZEROIZATION`: V8 ArrayBuffer slab zeroization (`UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE`).

3. **Dimension 3: Chromium Partition Filesystem (Native Webview Storage)**
   - `CHROMIUM_IN_MEMORY_PARTITION_NON_PERSISTENCE`: RAM-only partition isolation (`PASS`).
   - `CHROMIUM_DISK_RESIDUE_SCAN`: Binary deep scan across userData and subfolders (`PASS`).
   - `CHROMIUM_UNALLOCATED_CLUSTER_SLACK`: Unallocated cluster carving (`UNVERIFIED_OS_METADATA_JOURNAL_PRIVILEGED`).
   - `CHROMIUM_NAND_FLASH_PHYSICAL_ZEROIZATION`: Physical flash block state (`UNVERIFIED_PHYSICAL_FTL_UNREACHABLE`).

4. **Dimension 4: Tor Daemon & SOCKS5 Routing State**
   - `TOR_SOCKS5_REMOTE_DNS_CONFIG`: SOCKS5 proxy rules with remote DNS (`PASS`).
   - `TOR_DATADIRECTORY_CANARY_ISOLATION`: tor-data isolation with 0 user canaries (`PASS`).
   - `TOR_CIRCUIT_RAM_STATE_ERASURE`: Tor daemon RAM circuit zeroization (`UNVERIFIED_TOR_CONSENSUS_RETENTION`).

5. **Dimension 5: Host OS Forensic Artifacts**
   - `OS_CRASHPAD_MINIDUMP_EXCLUSION`: Crashpad minidump inspection (`PASS`).
   - `OS_VIRTUAL_MEMORY_PAGEFILE_EXCLUSION`: Virtual memory pagefile inspection (`UNVERIFIED_KERNEL_PAGING_INACCESSIBLE`).
   - `OS_NTFS_METADATA_JOURNAL_PURGE`: NTFS transaction journal purging (`UNVERIFIED_OS_METADATA_JOURNAL_PRIVILEGED`).

---

## 8. CLI Usage Reference

Run the forensic auditor CLI:

```bash
# Run standard audit with terminal console output
npm run forensic

# Output structured JSON
npm run forensic -- --json

# Output GitHub-flavored Markdown
npm run forensic -- --md

# Save report artifact to disk
npm run forensic -- --out forensic-report.json
npm run forensic -- --out forensic-report.md --verbose
```
