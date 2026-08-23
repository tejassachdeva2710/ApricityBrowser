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
- 💣 **3-Phase Destruction Protocol**:
  1. **Phase A**: WebCrypto Session Key Destruction (data becomes forensically unreadable immediately).
  2. **Phase B**: RAM Storage & Partition Purge.
  3. **Phase C**: Renderer Process Termination & Memory Garbage Collection.
- 🧅 **Tor Network Native**: All network traffic — including clearnet and `.onion` Hidden Services — routes automatically through Tor SOCKS5 proxy (`socks5://127.0.0.1:9150`) with remote SOCKS5 DNS resolution.
- 🔍 **Strict `.onion` Search Engine**: Default search engine uses DuckDuckGo's official `.onion` Hidden Service.
- 🎨 **Modern Minimalist UI**: Frameless window, light/purple custom interface, vertical privacy sidebar, and tab strip.
- 🧹 **Zero Disk Residue**: RAM-only ephemeral partitions with disk caching permanently disabled.

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

Run the Zero Trust Rendering test suite covering key vault zeroing, container isolation, and preference audits:

```bash
npm test
```

---

## 📄 License

Licensed under the [MIT License](LICENSE).
