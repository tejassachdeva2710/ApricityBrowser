# ☀️ Apricity Browser

> **Privacy that shines, then disappears.**  
> *A next-generation, open-source privacy desktop browser featuring per-tab Zero Trust Rendering (ZTR), automatic self-destructing tabs, and native Tor SOCKS5 network routing.*

---

## 🌟 Overview

Modern web browsers treat privacy as an afterthought — leaving cookie databases, local storage, cached images, and forensic trail history on disk long after you close a tab.

**Apricity Browser** reverses this paradigm: **it hides the web from your device after use**.

Built around the core concept of **Zero Trust Rendering (ZTR)**, Apricity treats every tab as an ephemeral, isolated container. Each tab is assigned a non-extractable WebCrypto key, routes through the Tor network by default, and self-destructs after a user-configured countdown timer (or upon closure).

---

## 🛡️ Core Features

- 🔐 **Zero Trust Rendering (ZTR)**: Per-tab in-memory cryptographic isolation. Data is encrypted in memory using WebCrypto AES-256-GCM non-extractable keys.
- ⏱ **Self-Destructing Tabs**: User-configurable timers (1 min, 5 min, 15 min, 30 min) per tab with real-time countdown HUD.
- 💣 **3-Phase Tab Cleanup Protocol**:
  1. **Phase A**: WebCrypto Session Key Dereferencing & Invalidation.
  2. **Phase B**: Ephemeral RAM Storage & Partition Purge.
  3. **Phase C**: Tab State Dereferencing & Cleanup.
- 🧅 **Tor Network Native**: Traffic — including clearnet and `.onion` Hidden Services — is configured to route through Tor SOCKS5 proxy (`socks5://127.0.0.1:9150`) with remote SOCKS5 DNS resolution.
- 🔍 **Strict `.onion` Search Engine**: Default search engine uses DuckDuckGo's official `.onion` Hidden Service.
- 🎨 **Modern Minimalist UI**: Frameless window, light/purple custom interface, vertical privacy sidebar, and tab strip.
- 🧹 **Zero Disk Residue**: RAM-only ephemeral partitions with disk caching disabled.

---

## 🚀 Quick Start

### Prerequisites
- [Node.js](https://nodejs.org/) v18+ 
- [Tor Browser](https://www.torproject.org/) or standalone `tor` daemon installed on your system.

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/ApricityBrowser.git
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

Run the Zero Trust Rendering test suite covering key vault lifecycle, container isolation, and preference audits:

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

For complete threat models, physical limitations (SSD FTL, RAM paging, NTFS journals), and multi-dimensional `PASS` / `FAIL` / `UNVERIFIED` taxonomy, read the [Forensic Methodology Specification](docs/forensic-methodology.md).

---

## 📄 License

Licensed under the [MIT License](LICENSE).
