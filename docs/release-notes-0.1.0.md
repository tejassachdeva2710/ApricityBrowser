# Apricity Browser v0.1.0 Release Notes

**Release Date**: August 30, 2026  
**Status**: Experimental / Research Prototype  
**License**: MIT  

---

> ### ⚠️ Security & Threat Model Disclaimer
> **Apricity Browser v0.1.0 is an experimental research/portfolio project and is not intended to provide absolute anonymity or forensic-proof deletion.**
> It is designed to explore ephemeral session isolation architectures, disposable browser state, and empirical forensic auditing methodologies.

---

## 🌟 Overview

Modern web browsers persist large amounts of user data to disk by default. Apricity Browser explores an alternative architecture where tabs are treated as ephemeral, short-lived containers. Each tab runs inside an independent in-memory partition with automated session destruction upon closure or timer expiry.

Apricity pairs its architecture with an automated **Forensic Artifact Auditor** that deep-scans the filesystem and runtime state to empirically measure what data is destroyed and explicitly catalog what remains outside application control.

---

## 🚀 Key Capabilities in v0.1.0

### 1. Ephemeral In-Memory Partitions
* Each tab runs inside a unique in-memory Electron partition (`session.fromPartition('ephemeral-UUID', { cache: false })`).
* Chromium DOM storage (cookies, `localStorage`, `indexedDB`, `sessionStorage`) is managed in RAM with `getStoragePath() === null`.
* Disk caching and history persistence are disabled.

### 2. Sandboxed WebContentsView Architecture
* Native Chromium `WebContentsView` instances run with `sandbox: true`, `contextIsolation: true`, and `nodeIntegration: false`.
* Strict navigation bounds (`will-navigate`), popup suppression (`setWindowOpenHandler`), and IPC URL validation isolate the guest from host capabilities.

### 3. Tor SOCKS5 Network Routing
* Configured to route web traffic through a local Tor SOCKS5 proxy (`127.0.0.1:9150`).
* Enforces remote DNS resolution (`host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"`).

### 4. Forensic Artifact Auditor (`npm run forensic`)
* Injects high-entropy canaries across 7 subsystems with multi-encoding representations (`UTF-8`, `UTF-16LE`, `ASCII`, hex).
* Scans `%APPDATA%\...\userData`, `Partitions`, `tor-data`, and `%TEMP%` for residual tokens post-destruction.
* Multi-dimensional reporting distinguishing `PASS`, `FAIL`, and `UNVERIFIED` properties.

---

## 🔬 Test Suite & Verification Results

All test suites execute cleanly out-of-the-box:

```bash
# Core Lifecycle, Adversarial, and Auditor Tests
npm test
# Result: 39 Passed, 0 Failed

# Live Electron & Chromium Runtime Harness
npm run test:electron
# Result: 5 Passed, 0 Failed (Live DOM localStorage and Cookie partition isolation)

# Forensic Artifact Auditor
npm run forensic
# Result: 11 Verified PASS, 0 FAIL, 7 Documented UNVERIFIED Hardware Boundaries

# Adversarial Binary Scanner & Buffer Stress Suite
npm run test:scanner
# Result: 25 Passed, 0 Failed

# Challenger Subdirectory Residue Injection Suite
npm run test:stress
# Result: 24 Passed, 0 Failed
```

---

## ⚠️ Known Limitations & Empirical Boundaries

1. **Hardware / SSD Wear Leveling**: User-space software cannot force immediate physical erasure of NAND flash cells across SSD Flash Translation Layer (FTL) blocks (`UNVERIFIED_PHYSICAL_FTL_UNREACHABLE`).
2. **OS Virtual Memory Paging**: Under host RAM pressure, the operating system virtual memory manager may commit process memory to disk (`pagefile.sys` / `swapfile.sys`) (`UNVERIFIED_KERNEL_PAGING_INACCESSIBLE`).
3. **Physical DRAM Remanence**: Garbage collection frees memory handles for V8 allocator reuse, but does not zero raw bytes in physical RAM (`UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE`).
4. **Tor Stream Isolation**: Concurrent tabs share the default Tor daemon's circuit pool unless per-tab `IsolateSOCKSAuth` credentials are configured.

---

## 💻 Supported Development Environment

* **Node.js**: v18.0.0 or higher
* **Electron**: v34.x / Chromium 128+
* **Platforms Tested**: Windows 11 (x64), Linux (x64 / headless), macOS (x64 / ARM64)
* **Tor Proxy**: Tor Browser or standalone `tor` daemon on `127.0.0.1:9150` (optional for unit tests, required for live Tor routing)

---

## 📖 Related Documentation

* [Threat Model & Security Architecture](threat-model.md)
* [Security Properties Specification](security-properties.md)
* [Forensic Audit Methodology](forensic-methodology.md)
* [Security Review & Evaluation Table](security-review.md)
* [Contributing Guide & Empirical Honesty Mandate](../CONTRIBUTING.md)
