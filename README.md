# ☀️ Apricity Browser

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node: v18+](https://img.shields.io/badge/Node-v18%2B-green.svg)](https://nodejs.org/)
[![Electron: v34](https://img.shields.io/badge/Electron-v34-blueviolet.svg)](https://www.electronjs.org/)
[![Tests: 39 Passed](https://img.shields.io/badge/Tests-39%20Passed-success.svg)](tests/)
[![ZTR: Ephemeral Isolation](https://img.shields.io/badge/ZTR-Ephemeral%20Isolation-orange.svg)](docs/threat-model.md)

> *An experimental desktop privacy browser exploring ephemeral session isolation, disposable browser state, controlled network proxy routing, and empirically tested session destruction.*

---

## 🌟 Why Apricity?

Standard web browsers treat privacy as an afterthought. Every time you browse the web, modern browsers leave persistent digital trails: cookie databases, DOM local storage, indexed databases, compiled code caches, and session history records committed to non-volatile disk. Even "incognito" or "private" modes frequently share process caches, persist DNS records, and retain state in memory long after tabs are closed.

**Apricity Browser reverses this paradigm by treating browser state as disposable and temporary.**

Every tab in Apricity is allocated an independent ephemeral session identity, isolated in memory, and routed through a controlled Tor SOCKS5 proxy with remote DNS resolution. When a tab reaches its user-configured countdown timer (or is closed manually), an automated teardown lifecycle executes: session keys are dereferenced, in-memory partition stores are cleared, and active renderer state is purged.

Rather than relying on unprovable marketing claims, Apricity pairs its architecture with an automated **Forensic Artifact Auditor** that deep-scans the filesystem to empirically measure what is destroyed and explicitly catalog what remains outside application control.

---

## 🏗️ Architecture

Apricity separates its security responsibilities across four distinct layers, maintaining a strict distinction between the **ZTR in-memory simulator** and **native Chromium session storage**:

```mermaid
graph TD
    User([User / UI Shell]) -->|Opens Tab| Shell[Electron Frameless Shell / Main Process]
    
    subgraph Browser Shell & IPC
        Shell -->|Manages Tab Lifecycle| UI[UI Controller & Timer HUD]
        Shell -->|Generates Session UUID| ZTR[Zero Trust Renderer Core]
    end

    subgraph Boundary 1 & 4: ZTR State & Cryptography
        ZTR -->|extractable: false| Vault[(WebCrypto Vault<br/>AES-256-GCM Keys)]
        ZTR -->|Application State| SimStore[(In-Memory Simulator Store<br/>Ciphertext Maps)]
    end

    subgraph Boundary 2: Chromium Webview Isolation
        Shell -->|Instantiates partition| Part[Electron In-Memory Partition<br/>ephemeral-UUID / cache: false]
        Part -->|Blink Engine RAM| Webview[Chromium Webview Guest Renderer]
        Webview -->|DOM Storage / Cookies| BlinkRAM[(Chromium SQLite & LevelDB<br/>In-Memory RAM Engines)]
    end

    subgraph Boundary 5: Network Routing
        Part -->|Proxy: socks5://127.0.0.1:9150| TorNet[Tor SOCKS5 Daemon]
        Part -->|host-resolver-rules| RemoteDNS[Remote SOCKS5 DNS Delegation]
        TorNet --> OnionRelay[Tor Onion Relays / .onion Services]
    end

    classDef core fill:#ede9fe,stroke:#7c3aed,stroke-width:2px;
    classDef storage fill:#dbeafe,stroke:#2563eb,stroke-width:2px;
    classDef net fill:#dcfce7,stroke:#16a34a,stroke-width:2px;
    class Shell,ZTR,UI core;
    class Vault,SimStore,Part,BlinkRAM storage;
    class TorNet,RemoteDNS,OnionRelay net;
```

> **Architectural Boundary Note**: Webview web content (`document.cookie`, `localStorage`, `indexedDB`) executes on Chromium's native Blink engine in RAM partitions (`ephemeral-${UUID}`). It is isolated by Chromium partition engines and cleared via `clearStorageData()`. The `ZeroTrustRenderer` JavaScript layer is an application-level state machine and test abstraction; webview DOM traffic does not pass through the ZTR JavaScript WebCrypto wrapper.

---

## 🛡️ Security Properties Matrix

Apricity evaluates all security properties against empirical test evidence:

| Property | Status | Empirical Evidence & Architectural Justification |
|---|:---:|---|
| **Session Identity Isolation** | **VERIFIED** | Verified by `test_adversarial_isolation.mjs` (UUID v4 generation and non-overlapping partition strings). |
| **Application Storage Isolation** | **VERIFIED** | Verified by `test_adversarial_isolation.mjs` (cross-tab storage separation across cookies, storage, indexedDB, cache). |
| **Cryptographic Key Separation** | **VERIFIED** | Verified by `test_adversarial_isolation.mjs` (AES-GCM authentication tag mismatch rejects cross-session reads). |
| **Session Destruction Lifecycle** | **VERIFIED** | Verified by `test_ztr_lifecycle.mjs` (vault key dereferencing and state invalidation). |
| **Chromium Native Partition Storage** | **PARTIALLY VERIFIED** | Verified via partition configuration; live Blink DOM storage isolation requires live Electron GUI execution. |
| **Forensic Filesystem Absence** | **VERIFIED** *(Scanned Surface)* | Verified by `npm run forensic` (deep binary scan of 45 runtime files in `userData` detected 0 residual canaries). |
| **Default Permission Denial** | **VERIFIED** *(API Layer)* | Verified by `test_adversarial_isolation.mjs` (`setPermissionRequestHandler` returns `false` by default). |
| **Physical RAM & Heap Zeroization** | **NOT PROVIDED** | JS GC frees heap references for reuse; it does not physically zero deallocated memory (`UNVERIFIED_V8_HEAP_RAW_INACCESSIBLE`). |
| **Protection from Memory Dumpers** | **NOT PROVIDED** | Non-extractable WebCrypto keys can still be extracted by local process debuggers or root malware. |
| **Absolute Anonymity via Tor** | **NOT PROVIDED** | Tor SOCKS5 proxy provides network pseudonymity, not mathematical anonymity against traffic correlation or fingerprinting. |
| **SSD Physical NAND Zeroization** | **UNVERIFIED** | Solid-state drive wear-leveling (FTL) writes out-of-place; physical cells are inaccessible (`UNVERIFIED_PHYSICAL_FTL_UNREACHABLE`). |
| **OS Virtual Memory Pagefile Exclusion** | **UNVERIFIED** | Host OS Kernel may page process RAM to `pagefile.sys` under memory exhaustion (`UNVERIFIED_KERNEL_PAGING_INACCESSIBLE`). |

---

## 🔬 Forensic Artifact Auditor

Apricity includes a built-in automated **Forensic Artifact Auditor** (`npm run forensic`) designed to experimentally measure session residue:

```bash
# Run standard forensic audit
npm run forensic

# Generate structured JSON report artifact
npm run forensic -- --out forensic-report.json

# Generate verbose Markdown report with technical justifications
npm run forensic -- --md --verbose
```

### How the Auditor Works:
1. **Canary Injection**: Generates high-entropy canary tokens across 7 subsystems (`COOKIE`, `LSTORE`, `IDB`, `CACHE`, `VAULT`, `SWORKER`, `TOR`) encoded in `UTF-8`, `UTF-16LE` (LevelDB/SQLite DOMStorage format), `ASCII`, and hex.
2. **Pre-Destruction Validation**: Confirms canary existence during active session state.
3. **Destruction Execution**: Executes Apricity's teardown protocol (`closeTab`, `clearStorageData`, `clearCache`, key zeroing).
4. **Deep Binary Sweep**: Multi-encoding binary file scan across `%APPDATA%\...\userData`, `Partitions`, `tor-data`, and `%TEMP%`.
5. **Multi-Dimensional Classification**:
   * **PASS**: Canary artifact was created pre-destruction and was conclusively **not detected** in reachable scanned locations post-destruction.
   * **FAIL**: Canary artifact or residual session state was detected post-destruction.
   * **UNVERIFIED**: Property cannot be reliably verified due to OS kernel, hardware FTL, or driver barriers (documented with official justification codes).

---

## 🧪 Automated Testing

Run the automated test suites covering lifecycle state management, adversarial isolation, and binary scanner precision:

```bash
# Run all core test suites (Lifecycle + Adversarial + Forensic Auditor)
npm test

# Run specific test suites
npm run test:lifecycle      # ZTR in-memory engine and preferences tests
npm run test:adversarial    # Adversarial session, partition, and crypto tests
npm run test:forensic       # Forensic auditor unit & integration tests
npm run test:scanner        # Binary scanner multi-encoding & buffer stress tests
npm run test:stress         # Challenger adversarial residue injection tests
```

---

## 📚 Security Documentation

For detailed technical specifications, threat models, and methodology papers:

* [**Threat Model & Security Architecture**](docs/threat-model.md): Assets, threat actors, 6 security boundaries, and comprehensive threat specification.
* [**Security Properties Specification**](docs/security-properties.md): Formal breakdown of guaranteed vs non-guaranteed isolation properties.
* [**Forensic Audit Methodology**](docs/forensic-methodology.md): The 6-layer deletion continuum, SSD wear leveling (FTL), OS paging, NTFS journaling, and justification taxonomy.

---

## ⚠️ Known Limitations

1. **Hardware & SSD Wear Leveling**: Flash memory controllers write out-of-place. Unlinking operating system files does not guarantee immediate physical erasure of NAND flash cells.
2. **OS Memory Paging**: Under host RAM pressure, the operating system virtual memory manager may commit process memory to disk (`pagefile.sys` / `swapfile.sys`).
3. **V8 Heap Memory Remanence**: Garbage collection frees memory handles for V8 allocator reuse, but does not wipe raw bytes in physical RAM.
4. **Tor Stream Isolation**: Concurrent tabs share the default Tor daemon's circuit pool unless per-tab `IsolateSOCKSAuth` credentials are configured.

---

## 🗺️ Roadmap

Realistic future milestones based on the current architecture:

* [ ] **Live Electron Chromium Test Harness**: Automated end-to-end Blink DOM storage testing in headless Electron windows.
* [ ] **Per-Tab Tor Stream Isolation**: Dynamically generate unique SOCKS authentication credentials (`IsolateSOCKSAuth`) per tab session to ensure isolated Tor circuit paths.
* [ ] **Native Memory Zeroization Addon**: Implement a lightweight C++ Node.js addon using platform-specific memory wipers (`SecureZeroMemory` / `explicit_bzero`) for cryptographic buffers.
* [ ] **Automated Tor Daemon Lifecycle**: Integrated cross-platform child process supervisor for standalone Tor binary initialization and teardown.

---

## 🚀 Installation & Development

### Prerequisites
* **Node.js** v18.0.0 or higher
* **Tor Browser** or standalone `tor` daemon (optional for unit tests, required for live Tor proxy routing)

### Getting Started

```bash
# 1. Clone the repository
git clone https://github.com/tejassachdeva2710/ApricityBrowser.git
cd ApricityBrowser

# 2. Install dependencies
npm install

# 3. Launch Apricity Browser
npm start

# 4. Run automated test suites
npm test

# 5. Run the forensic auditor
npm run forensic
```

---

## 🤝 Contributing

Contributions are welcome! Please read [**`CONTRIBUTING.md`**](CONTRIBUTING.md) for coding standards, test requirements, and our empirical honesty mandate.

---

## 📄 License

Licensed under the [MIT License](LICENSE).
