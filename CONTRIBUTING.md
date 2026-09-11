# Contributing to Apricity Browser

Thank you for your interest in contributing to **Apricity Browser**!

Apricity is an experimental security and privacy project exploring ephemeral per-tab session isolation, disposable in-memory browser state, controlled network proxy routing, and empirically verified session destruction.

---

## 1. Core Engineering Principle: Empirical Honesty

Apricity values **empirically demonstrated security properties** over marketing claims.

When contributing code, tests, or documentation:
1. **Never Make Unsubstantiated Security Claims**: Avoid absolute claims such as "zero forensic trace", "military-grade", "unbreakable", or "100% anonymous".
2. **Back Claims with Automated Tests**: Every guaranteed security property must have a corresponding test assertion in `tests/` or an evaluation metric in `src/forensics/`.
3. **Label Unverifiable Properties Honestly**: If an OS, kernel, or hardware limitation prevents conclusive verification (such as SSD wear leveling or OS kernel memory paging), document it as `UNVERIFIED` with a clear technical justification code.

---

## 2. Development Setup

### Prerequisites
* **Node.js** v18.0.0 or higher
* **Tor Browser** or a standalone `tor` daemon (optional for unit tests, required for live Tor routing)

### Installation

```bash
# 1. Clone repository
git clone https://github.com/tejassachdeva2710/ApricityBrowser.git
cd ApricityBrowser

# 2. Install dependencies
npm install

# 3. Launch application
npm start
```

---

## 3. Running Automated Tests

Apricity maintains a multi-tiered test suite covering lifecycle operations, adversarial isolation, binary scanner precision, and forensic residue evaluation.

```bash
# Run standard test suite (Live Electron + Level 3 Security + Forensic Auditor)
npm test

# Run individual test suites
npm run test:security     # Level 3 Electron security foundation tests
npm run test:electron     # Live WebContentsView runtime partition isolation tests
npm run test:forensic     # Forensic auditor unit & integration tests
npm run test:scanner      # Binary scanner multi-encoding & buffer stress tests
npm run test:stress       # Challenger adversarial residue injection tests
```

---

## 4. Running the Forensic Artifact Auditor

The forensic auditor injects high-entropy canary tokens into active session storage layers, triggers the tab destruction lifecycle, and deep-scans the filesystem and memory for residual artifacts:

```bash
# Standard console audit
npm run forensic

# Generate structured JSON report
npm run forensic -- --json

# Generate Markdown report
npm run forensic -- --md

# Export to a file
npm run forensic -- --out audit-results.json
```

---

## 5. Coding & Architecture Expectations

* **Sandboxed Architecture**: Understand that guest web content executes directly inside sandboxed `WebContentsView` instances with in-memory session partitions (`session.fromPartition('ephemeral-UUID', { cache: false })`). No guest content has access to Node.js or internal Electron APIs.
* **Preserve Security Defaults**: Never enable `nodeIntegration`, never disable `contextIsolation`, and never bypass permission denial or navigation bounds without explicit architectural justification.
* **Clean Code**: Keep changes minimal, focused, and well-documented. Avoid adding large dependencies.

---

## 6. Reporting Security Issues

If you discover a security vulnerability, isolation failure, or residual forensic artifact in Apricity:
* Please open a detailed issue on GitHub describing the reproduction steps, platform, and forensic findings.
* Include full auditor logs or test output where applicable.
