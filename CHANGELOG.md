# Changelog

All notable changes to the **Apricity Browser** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-08-30

### Initial Experimental Release

Apricity Browser v0.1.0 is an experimental desktop privacy browser and research prototype exploring disposable session state, cryptographic key isolation, and empirically measured forensic destruction.

> **Disclaimer**: Apricity Browser v0.1.0 is an experimental research/portfolio project and is not intended to provide absolute anonymity or forensic-proof deletion.

### Added
* **Ephemeral In-Memory Partitions**: Per-tab memory-only session partitioning (`session.fromPartition('ephemeral-UUID', { cache: false })`) preventing persistent disk caching and isolated LevelDB/SQLite storage in RAM.
* **Zero Trust Renderer (ZTR) Core Engine**: In-memory tab lifecycle state manager and application storage isolation simulator (`src/ztr/ZeroTrustRenderer.mjs`).
* **WebCrypto AES-256-GCM Vault**: Non-extractable (`extractable: false`) ephemeral cryptographic key generation per session UUID (`src/ztr/ZTRCryptoVault.mjs`).
* **Tor SOCKS5 Network Routing**: Native proxy integration with remote DNS resolution delegation (`socks5://127.0.0.1:9150`, fail-closed `host-resolver-rules`).
* **Self-Destruct Session Lifecycle**: Automated per-tab countdown timer HUD and teardown protocol calling `clearStorageData()`, `clearCache()`, and vault key invalidation.
* **Forensic Artifact Auditor**: Multi-layer scanner and canary injector deep-scanning 7 subsystems across `%APPDATA%\...\userData`, `Partitions`, and `%TEMP%` (`npm run forensic`).
* **Adversarial & Live Test Suites**:
  * `tests/test_ztr_lifecycle.mjs`: ZTR engine and key vault tests (7 Passed).
  * `tests/test_adversarial_isolation.mjs`: Negative attack, partition, and cross-session crypto tests (20 Passed).
  * `tests/test_forensic_auditor.mjs`: Forensic auditor unit & integration tests (12 Passed).
  * `tests/test_adversarial_scanner.mjs`: Binary scanner multi-encoding & buffer edge cases (25 Passed).
  * `tests/test_challenger_forensic_stress.mjs`: Adversarial residue injection challenger suite (24 Passed).
  * `tests/test_electron_live.mjs`: Live Electron Chromium runtime integration suite (8 Passed).
* **Comprehensive Documentation Suite**:
  * `docs/threat-model.md`: Formal threat model covering protected assets, adversaries, 6 security boundaries, and empirical matrix.
  * `docs/security-properties.md`: Detailed specification of verified vs unverified isolation properties.
  * `docs/forensic-methodology.md`: The 6-layer deletion continuum, SSD FTL wear leveling, OS paging, and canary methodology.
  * `docs/security-review.md`: External reviewer reference table.
  * `docs/release-notes-0.1.0.md`: Release notes and verification guide.
  * `CONTRIBUTING.md`: Developer contribution guide and Empirical Honesty Mandate.
