# Apricity Browser — Forensic Audit Methodology Specification

**Document Version:** 1.1.0  
**Classification:** Security Architecture & Forensic Verification Standard  
**Companion Document:** [Threat Model & Security Architecture](threat-model.md)  
**Target Engine:** Apricity Zero Trust Rendering (ZTR) Core / Electron Chromium

---

## 1. Overview & Threat Model

Apricity Browser provides ephemeral desktop web browsing through **Zero Trust Rendering (ZTR)**. Its security architecture combines per-tab ephemeral session partitions, in-memory cryptographic isolation, Tor SOCKS5 network routing, and automated self-destruct teardown lifecycles.

However, in computer forensics and adversarial analysis, privacy claims such as "zero disk residue", "unrecoverable browsing", or "complete physical wipe" frequently fail when examined against the physical realities of operating systems, solid-state flash memory controllers, and process memory managers.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               CORE FORENSIC PRINCIPLE                                   │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ A clean canary scan means:                                                              │
│ "The known test artifacts were not detected in the scanned locations."                  │
│                                                                                         │
│ It does NOT mean:                                                                       │
│ "No forensic evidence exists anywhere on the machine or physical media."                │
│                                                                                         │
│ Filesystem silence does NOT prove forensic zeroization. An absence of reachable files   │
│ in user-space directory traversals demonstrates only that operating system file pointers│
│ have been unlinked. It does not prove that plaintext data has been purged from physical │
│ NAND flash blocks, virtual memory paging files, kernel journals, or hardware buffers.   │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

The Apricity Forensic Artifact Auditor (`npm run forensic`) is an empirical testing subsystem built to systematically search for residual session artifacts, evaluate Apricity's destruction lifecycle, and report findings with absolute security honesty.

---

## 2. The Multi-Layer Deletion Continuum

To understand why application-level cleanup does not equal forensic eradication, Apricity formalizes the six layers of the deletion continuum:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       THE 6-LAYER DELETION CONTINUUM                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. LOGICAL DELETION          │ Purging JavaScript Map keys & session state │
│    (Controlled by Apricity)  │ WebCrypto key dereferencing in V8 isolate   │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ 2. FILESYSTEM DELETION       │ Unlinking file handles via OS APIs          │
│    (Controlled by Apricity)  │ Calling clearStorageData() / clearCache()   │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ 3. OS MEMORY HANDLING        │ Kernel memory paging to pagefile.sys        │
│    (Beyond App Control)      │ V8 unallocated heap slab retention          │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ 4. FILESYSTEM JOURNALING     │ NTFS $LogFile and $UsnJrnl change logs      │
│    (Beyond App Control)      │ Master File Table ($MFT) record remnants    │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ 5. SSD WEAR LEVELING (FTL)   │ Controller out-of-place NAND block writes   │
│    (Beyond App Control)      │ Over-provisioned uncollected block pools    │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ 6. PHYSICAL NAND REMANENCE   │ Floating-gate / charge-trap oxide remanence │
│    (Beyond App Control)      │ Hardware-level forensic microscope recovery │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Logical Deletion**: Application-level reference dereferencing (e.g. `vault._vault.delete(sessionUUID)` and `_ephemeralStorageStores.delete(userContextId)`). *Apricity enforces this.*
2. **Filesystem Deletion**: Operating system directory entry unlinking via standard system calls. *Apricity enforces this by verifying no partition directories exist under `%APPDATA%\...\Partitions`.*
3. **OS-Level Memory Handling**: Under memory pressure, the OS Kernel Virtual Memory Manager can page process memory pages out of DRAM and write them into `pagefile.sys` or `swapfile.sys`. *Apricity cannot control OS virtual memory paging.*
4. **Filesystem Journaling**: Modern journaled filesystems (such as NTFS on Windows or ext4 on Linux) record file creation, modification, and deletion transactions in system journals (`$LogFile`, `$UsnJrnl`). Transaction metadata remains until log rollover. *Apricity cannot purge OS filesystem journals from user-space.*
5. **SSD Wear Leveling (Flash Translation Layer)**: NAND flash memory cannot overwrite bytes in place. The SSD controller writes modified blocks to fresh physical NAND cells and marks old blocks as stale. The stale blocks retain original plaintext data until asynchronous TRIM/garbage collection occurs. *Apricity cannot control SSD controller FTL behavior.*
6. **Physical NAND Remanence**: Physical microscopic charge levels in floating-gate or charge-trap flash cells can retain forensic traces readable by specialized hardware equipment. *Apricity cannot alter physical semiconductor behavior.*

---

## 3. Architectural Boundaries & Isolation Layers

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

1. **`ZeroTrustRenderer.mjs` (Layer A)** is an in-memory cryptographic state machine simulator. It encrypts key-value items with WebCrypto AES-256-GCM and stores ciphertext in memory `Map` objects. It is evaluated directly in unit and adversarial test suites (`npm test`).
2. **`<webview>` Web Content (Layer B)** runs directly on Chromium's native C++ Blink engine. Real DOM storage (`document.cookie`, `localStorage`, `indexedDB`) is managed by Chromium's in-memory partition engine (`ephemeral-${sessionUUID}`). Webview storage does **not** pass through the ZTR JavaScript WebCrypto wrapper.
3. The forensic auditor tests **both** boundaries: it validates ZTR key destruction and in-memory map purging, while also performing binary disk sweeps across Chromium's runtime storage paths.

---

## 4. Forensic Audit Lifecycle & Methodology

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

### 4.1 Canary Token Specification
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

### 4.2 Multi-Encoding Binary Matching Engine
Chromium and operating systems store strings in varying binary encodings:
- **UTF-8 / ASCII**: Standard web strings and plain text files.
- **UTF-16LE**: Chromium LevelDB values (DOMStorage), V8 bytecode caches, and Windows internal APIs.
- **Hex**: Raw binary stream identifiers.

The `FilesystemScanner` converts every canary token into multiple `Buffer` encodings and performs raw byte search (`buffer.includes(tokenBuffer)`) across all files in scanned runtime roots.

---

## 5. Multi-Dimensional Verification Taxonomy & Justification Codes

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

## 6. CLI Usage Reference

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
