# ☀️ Apricity Browser

> **Privacy that shines, then disappears.**  
> *An experimental privacy browser exploring ephemeral session isolation, disposable browser state, controlled network routing, and empirically tested session destruction.*

---

## 🌟 Overview

Modern web browsers persist long-term state across sessions — retaining cookie databases, local storage, cached web assets, and historical session trails on disk long after a tab is closed.

**Apricity Browser** is an experimental project exploring disposable browser state: **isolating web sessions in memory and clearing them upon tab closure**.

Built around the concept of **Zero Trust Rendering (ZTR)**, Apricity treats every tab as an ephemeral, isolated container. Each tab is assigned a non-extractable WebCrypto key, configured to route through the Tor SOCKS5 network proxy by default, and triggers an automated teardown lifecycle after a user-configured countdown timer (or upon closure).

---

## 🛡️ Core Features

- 🔐 **Zero Trust Rendering (ZTR)**: Per-tab in-memory cryptographic state machine. Key-value items are encrypted in memory using WebCrypto AES-256-GCM non-extractable keys (`extractable: false`).
- ⏱ **Self-Destructing Tabs**: User-configurable timers (1 min, 5 min, 15 min, 30 min) per tab with a real-time countdown interface.
- 💣 **3-Phase Tab Teardown Protocol**:
  1. **Phase A**: WebCrypto Session Key Dereferencing & Invalidation.
  2. **Phase B**: Ephemeral RAM Storage & Partition Purge (`clearStorageData()`, `clearCache()`).
  3. **Phase C**: Tab State Dereferencing & Cleanup.
- 🧅 **Tor SOCKS5 Proxy Routing**: Traffic — including clearnet and `.onion` Hidden Services — is configured to route through a local Tor SOCKS5 proxy (`socks5://127.0.0.1:9150` or `9050`) with remote SOCKS5 DNS resolution.
- 🔍 **Strict `.onion` Search Engine**: Default search interface configured for DuckDuckGo's official `.onion` Hidden Service.
- 🎨 **Modern Minimalist UI**: Frameless window, light/purple interface, vertical privacy sidebar, and tab strip.
- 🧹 **Ephemeral Session Partitions**: Memory-only session partitions (`session.fromPartition('ephemeral-UUID', { cache: false })`) with disk caching disabled.

---

## 🚀 Quick Start

### Prerequisites
- [Node.js](https://nodejs.org/) v18+ 
- [Tor Browser](https://www.torproject.org/) or standalone `tor` daemon installed on your system.

### Installation

```bash
# Clone the repository
git clone https://github.com/tejassachdeva2710/ApricityBrowser.git
cd ApricityBrowser

# Install dependencies
npm install

# Launch Apricity Browser
npm start
```

---

## 🏗️ Architecture

```
                                  ┌────────────────────────────────────────┐
                                  │           Apricity Browser             │
                                  └───────────────────┬────────────────────┘
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       │                                                             │
        ┌──────────────▼──────────────┐                               ┌──────────────▼──────────────┐
        │       UI Shell / IPC        │                               │     Zero Trust Renderer     │
        │  (Frameless Light Chrome)   │                               │       (ZTR Core)            │
        └──────────────┬──────────────┘                               └──────────────┬──────────────┘
                       │                                                             │
        ┌──────────────▼──────────────┐                               ┌──────────────▼──────────────┐
        │ Isolated Webview Partition  │                               │   WebCrypto Key Vault       │
        │    (RAM-Only Storage)       │                               │   (AES-256-GCM Ephemeral)   │
        └──────────────┬──────────────┘                               └──────────────┬──────────────┘
                       │                                                             │
                       └──────────────────────────────┬──────────────────────────────┘
                                                      │
                                       ┌──────────────▼──────────────┐
                                       │     Tor SOCKS5 Network      │
                                       │   (Port 9150 / Remote DNS)  │
                                       └─────────────────────────────┘
```

---

## 🧪 Automated Testing

Run the automated test suites covering lifecycle state management, adversarial isolation properties, and forensic scanning:

```bash
npm test
```

---

## 🔬 Forensic Artifact Auditor

Apricity includes an automated **Forensic Artifact Auditor** that injects high-entropy canary tokens into session storage subsystems, executes the tab teardown protocol, and deep-scans the filesystem and runtime memory for residual artifacts:

```bash
# Run forensic auditor scan
npm run forensic

# Generate structured JSON report
npm run forensic -- --out forensic-report.json
```

For complete threat models, physical limitations (SSD FTL, RAM paging, NTFS journals), and multi-dimensional `PASS` / `FAIL` / `UNVERIFIED` taxonomy, read the:
* [Threat Model & Security Architecture](docs/threat-model.md)
* [Security Properties Specification](docs/security-properties.md)
* [Forensic Methodology Specification](docs/forensic-methodology.md)

---

## 📄 License

Licensed under the [MIT License](LICENSE).
