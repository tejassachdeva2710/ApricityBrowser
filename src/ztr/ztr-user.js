// ============================================================================
// Apricity Browser — Zero Trust Rendering (ZTR) Hardened Preferences
// File: ztr-user.js
// Target: Firefox ESR / Tor Browser Core Engine
// ============================================================================

// ----------------------------------------------------------------------------
// LAYER 3: OS-LEVEL PROCESS SANDBOXING & FISSION ISOLATION
// ----------------------------------------------------------------------------
user_pref("security.sandbox.content.level", 9);                 // Maximum Win32k syscall lockdown
user_pref("security.sandbox.content.read_path_whitelist", "");   // Deny default filesystem read access
user_pref("security.sandbox.gpu.level", 1);                     // GPU process isolation
user_pref("fission.autostart", true);                           // Enable Fission Site Isolation
user_pref("browser.tabs.remote.autostart", true);               // Force multi-process rendering architecture
user_pref("dom.ipc.processCount", 8);                           // Isolated content process pool limit
user_pref("dom.ipc.processCount.webIsolated", 4);               // Dedicated per-site renderer processes
user_pref("dom.ipc.keepProcessesAlive", 0);                     // Do NOT reuse content processes on tab close

// ----------------------------------------------------------------------------
// LAYER 2: EPHEMERAL IN-MEMORY STORAGE & ZERO DISK PERSISTENCE
// ----------------------------------------------------------------------------
user_pref("browser.cache.disk.enable", false);                  // Disable disk cache entirely
user_pref("browser.cache.memory.enable", true);                 // Enable RAM-only cache
user_pref("browser.cache.memory.capacity", 131072);             // 128 MB RAM cache budget limit
user_pref("dom.caches.enabled", false);                         // Disable persistent Cache API
user_pref("dom.storage.enabled", true);                         // Enable DOM storage (isolated per userContextId)
user_pref("network.cookie.cookieBehavior", 5);                  // Total Cookie Protection (dFPI)
user_pref("network.cookie.lifetimePolicy", 2);                  // Session-only cookies (purged on close)

// ----------------------------------------------------------------------------
// DISK & FORENSIC HYGIENE
// ----------------------------------------------------------------------------
user_pref("places.history.enabled", false);                     // Disable browsing history persistence
user_pref("browser.formfill.enable", false);                    // Disable form autofill storage
user_pref("signon.rememberSignons", false);                     // Disable password saving prompt
user_pref("privacy.sanitize.sanitizeOnShutdown", true);        // Automatic shutdown sanitizer
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.firstparty.isolate", true);                  // Tor-style First Party Isolation (FPI)
user_pref("privacy.resistFingerprinting", true);                // Resist Fingerprinting (RFP) baseline
