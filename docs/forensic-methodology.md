# Apricity Browser — Forensic Audit Methodology Specification

**Document Version:** 2.0.0  
**Classification:** Security Architecture & Forensic Verification Standard  
**Companion Document:** [Threat Model & Security Architecture](threat-model.md)  
**Target Engine:** Electron Main Process / Chromium WebContentsView / Ephemeral Partitions

---

## 1. Overview & Core Forensic Principle

Apricity Browser provides ephemeral desktop web browsing through native **Chromium WebContentsView process isolation** paired with ephemeral session partitions (`session.fromPartition('ephemeral-UUID', { cache: false })`), Tor SOCKS5 network routing, and automated self-destruct teardown lifecycles.

The previous prototype utilized an application-level cryptographic storage simulator (`ZeroTrustRenderer`). Following a comprehensive security audit, that simulator was eliminated. The browser and forensic auditor now operate entirely on real Chromium storage subsystems with OS-level sandboxing (`sandbox: true`).

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               CORE FORENSIC PRINCIPLE                                   │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ The auditor verifies the absence of known test canaries from the filesystem surfaces it │
│ scans after a real Chromium session is destroyed. It does not prove complete forensic   │
│ absence from physical hardware.                                                         │
│                                                                                         │
│ Filesystem silence does NOT prove physical zeroization. An absence of reachable files   │
│ in user-space directory traversals demonstrates only that operating system file pointers│
│ and in-memory partition caches have been unlinked. It does not prove that plaintext data│
│ has been purged from physical NAND flash blocks, virtual memory paging files, kernel    │
│ journals, or hardware caches.                                                           │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

The Apricity Forensic Artifact Auditor (`npm run forensic`) is an empirical testing subsystem that starts an actual Electron runtime, navigates an isolated `WebContentsView` to a controlled origin, writes deterministic high-entropy canaries into real Chromium storage (Cookies, LocalStorage, SessionStorage, IndexedDB, Cache Storage, Blob Storage), validates pre-destruction presence, executes the teardown lifecycle (`clearStorageData()`, `clearCache()`, view removal), and deep-scans candidate filesystem locations with binary pattern matchers.

---

## 2. The Multi-Layer Deletion Continuum

To understand why application-level cleanup does not equal forensic eradication, Apricity formalizes the six layers of the deletion continuum:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       THE 6-LAYER DELETION CONTINUUM                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. LOGICAL DELETION          │ Purging Chromium session memory structures  │
│    (Controlled by Apricity)  │ clearStorageData(), clearCache(), View drop │
├──────────────────────────────┼─────────────────────────────────────────────┤
│ 2. FILESYSTEM DELETION       │ Unlinking file handles via OS APIs          │
│    (Controlled by Apricity)  │ Ephemeral partitions allocate 0 disk dirs   │
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

1. **Logical Deletion**: Application and Chromium renderer state dereferencing (`clearStorageData()`, `clearCache()`, detaching and destroying `WebContentsView`). *Apricity enforces this.*
2. **Filesystem Deletion**: Operating system directory entry unlinking via standard system calls. *Apricity enforces this by verifying no partition directories exist on disk.*
3. **OS-Level Memory Handling**: Under memory pressure, the OS Kernel Virtual Memory Manager can page process memory pages out of DRAM and write them into `pagefile.sys` or `swapfile.sys`. *Apricity cannot control OS virtual memory paging.*
4. **Filesystem Journaling**: Modern journaled filesystems (such as NTFS on Windows or ext4 on Linux) record file creation, modification, and deletion transactions in system journals (`$LogFile`, `$UsnJrnl`). Transaction metadata remains until log rollover. *Apricity cannot purge OS filesystem journals from user-space.*
5. **SSD Wear Leveling (Flash Translation Layer)**: NAND flash memory cannot overwrite bytes in place. The SSD controller writes modified blocks to fresh physical NAND cells and marks old blocks as stale. The stale blocks retain original plaintext data until asynchronous TRIM/garbage collection occurs. *Apricity cannot control SSD controller FTL behavior.*
6. **Physical NAND Remanence**: Physical microscopic charge levels in floating-gate or charge-trap flash cells can retain forensic traces readable by specialized hardware equipment. *Apricity cannot alter physical semiconductor behavior.*

---

## 3. Real Chromium Lifecycle & Audit Architecture

Apricity structures its forensic auditor directly against the native Chromium architecture:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               REAL CHROMIUM AUDIT FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  [PHASE 1: Isolated Environment & Causal Harness Setup]                                 │
│  • Allocates temporary userData directory via app.setPath('userData', tempDir)          │
│  • Runtime assertion confirms Electron userData matches target scan roots               │
│  • Uses disk-backed test partition (persist:forensic-audit-<UUID>) in isolated userData │
│    to allow empirical observation of disk persistence and subsequent cleanup            │
│  • Production Apricity continues to use ephemeral in-memory partitions                  │
│                                                                                         │
│  [PHASE 2: Real Chromium Session & Canary Injection]                                    │
│  • Starts Electron runtime & local HTTP canary fixture                                  │
│  • Creates sandboxed WebContentsView bound to the disk-backed forensic partition        │
│  • Injects high-entropy canary tokens into real Blink/Chromium storage subsystems:       │
│    - Cookies (document.cookie and session.cookies)                                      │
│    - DOM localStorage                                                                   │
│    - DOM sessionStorage                                                                 │
│    - IndexedDB database records (IndexedDB LevelDB)                                     │
│    - Cache Storage API cache responses (SimpleCache / Service Worker)                    │
│    - Blob storage / Object URLs                                                         │
│                                                                                         │
│  [PHASE 3: Pre-Destruction Presence Validation & Pre-Scan]                              │
│  • Reads back every canary token from the live Chromium session (Browser Pre-State)     │
│  • Deep-scans userData before teardown to record physical disk presence (Fs Pre-State)  │
│                                                                                         │
│  [PHASE 4: Apricity Session Destruction Lifecycle]                                      │
│  • Executes session.clearStorageData() & session.clearCache()                            │
│  • Detaches WebContentsView from host window and destroys webContents                   │
│  • Supports --abnormal flag to test unexpected termination without clearStorageData     │
│                                                                                         │
│  [PHASE 5: Deep Binary Filesystem Scan & Empty-Scan Guard]                              │
│  • Multi-encoding binary scan (UTF-8, UTF-16LE, ASCII, hex) on exact same directory     │
│  • Inspects SQLite files, LevelDB SSTables, and cache blobs                             │
│  • Empty-Scan Guard: If Scanned Files = 0 or Bytes = 0, flags UNVERIFIED (never CLEAN)  │
│                                                                                         │
│  [PHASE 6: 4-State Causal Breakdown & Multi-Dimensional Matrix]                         │
│  • Reports 4-state causal lifecycle per subsystem:                                      │
│    Browser Pre-State | Filesystem Pre-State | Cleanup Method | Filesystem Post-State     │
│  • Classifies each as VERIFIED CLEAN, FAIL, or UNVERIFIED with justification codes      │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Multi-Dimensional Verification Matrix

The auditor evaluates 16 properties across 5 distinct dimensions:

### Dimension 1: Chromium Native DOM Storage (Layer 1)
- `DOM_COOKIE_STORAGE_AND_PURGE`: Cookies confirmed in Chromium session and not found in post-destruction filesystem scan.
- `DOM_LOCALSTORAGE_STORAGE_AND_PURGE`: LocalStorage confirmed in Chromium session and not found in post-destruction filesystem scan.
- `DOM_INDEXEDDB_STORAGE_AND_PURGE`: IndexedDB records confirmed in Chromium session and not found in post-destruction filesystem scan.
- `DOM_CACHE_STORAGE_PURGE`: Cache Storage API entries confirmed in Chromium session and not found in post-destruction filesystem scan.

### Dimension 2: Chromium Disk Partition & Filesystem (Layer 2)
- `CHROMIUM_DISK_RESIDUE_SCAN`: Binary deep scan across candidate storage roots reveals 0 canary byte matches post-cleanup.
- `CHROMIUM_UNALLOCATED_CLUSTER_SLACK`: SQLite/filesystem cluster slack carving (UNVERIFIED - `UNVERIFIED_OS_METADATA_JOURNAL_PRIVILEGED`).
- `CHROMIUM_NAND_FLASH_PHYSICAL_ZEROIZATION`: SSD NAND flash cell wear-leveling (UNVERIFIED - `UNVERIFIED_PHYSICAL_FTL_UNREACHABLE`).

### Dimension 3: WebContentsView Process & RAM Lifecycle (Layer 3)
- `WEBCONTENTSVIEW_LIFECYCLE_DESTRUCTION`: WebContentsView detached and webContents closed on tab teardown.
- `SESSION_STORAGE_DATA_CLEARED`: `clearStorageData()` & `clearCache()` successfully executed.
- `PROCESS_HEAP_MEMORY_ZEROIZATION`: V8 heap slab zeroization (UNVERIFIED - `UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE`).
- `HOST_PAGEFILE_EXCLUSION`: OS pagefile exclusion (UNVERIFIED - `UNVERIFIED_KERNEL_PAGING_INACCESSIBLE`).

### Dimension 4: Tor Daemon & SOCKS5 Routing State (Layer 4)
- `TOR_DATADIRECTORY_CANARY_ISOLATION`: Tor data directory isolation (UNVERIFIED - `UNVERIFIED_TOR_NOT_INCLUDED_IN_AUDIT`).
- `TOR_CIRCUIT_RAM_STATE_ERASURE`: Tor daemon internal RAM circuit tables (UNVERIFIED - `UNVERIFIED_TOR_CONSENSUS_RETENTION`).

### Dimension 5: Host OS Forensic Artifacts (Layer 5)
- `OS_CRASHPAD_MINIDUMP_EXCLUSION`: Crashpad contains no minidump files with active canary tokens.
- `OS_VIRTUAL_MEMORY_PAGEFILE_EXCLUSION`: Windows pagefile.sys inspection (UNVERIFIED - `UNVERIFIED_KERNEL_PAGING_INACCESSIBLE`).
- `OS_NTFS_METADATA_JOURNAL_PURGE`: NTFS journal records (UNVERIFIED - `UNVERIFIED_OS_METADATA_JOURNAL_PRIVILEGED`).

---

## 5. Security Honesty Mandate

1. **Causal Chain Requirement**: A PASS is awarded only when there is a demonstrated causal chain: real artifact created -> verified in browser before destruction -> verified disk surface scanned -> real cleanup executed -> same disk surface scanned post-destruction -> canary absent.
2. **Empty-Scan Guard**: If scanned files or bytes equals 0, the auditor reports `UNVERIFIED — NO FILESYSTEM EVIDENCE AVAILABLE` rather than `VERIFIED CLEAN`.
3. **No Binary "CLEAN" Booleans**: The auditor produces multi-dimensional status matrices, explicitly distinguishing verified user-space absence from unverified hardware boundaries.
4. **Explicit Justifications**: Every UNVERIFIED property maps to an official code explaining why user-space software cannot verify physical or kernel hardware state.
5. **No Simulation Theater**: Canaries are written to and verified within real Chromium browser storage engines.
