#!/usr/bin/env node

/**
 * cli.mjs — v4.0.0
 *
 * Two-Phase Forensic Audit CLI for Apricity Browser.
 *
 * Architecture:
 *   NODE MODE (orchestrator, no Electron):
 *     1. Creates isolated tempDir.
 *     2. Spawns Electron child with --forensic-phase=core (or crash-inject for --abnormal).
 *     3. Electron child: injects canaries, quiescence-waits, pre-scans, cleans up, writes
 *        intermediate state to tempDir/forensic-state.json, then exits (releasing ALL file handles).
 *     4. Node parent: reads state file, runs post-scan in pure Node (no EBUSY locks),
 *        evaluates, reports, then deletes tempDir.
 *
 *   --abnormal (genuine crash test):
 *     1. Spawns Electron with --forensic-phase=crash-inject (no cleanup, hangs after writing state).
 *     2. Polls for state file (signals canaries are on disk + pre-scan done).
 *     3. Kills Electron with SIGKILL / TerminateProcess (genuine crash simulation).
 *     4. Runs post-scan: expects canary residue → documents crash-persistence risk.
 *
 *   ELECTRON MODE (--forensic-phase=core|crash-inject):
 *     Internal child process — runs ForensicAuditor.runAuditCore() and writes state.
 */

import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { spawnSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

function printHelp() {
  console.log(`
Apricity Browser — Real Electron Forensic Artifact Auditor CLI (v4.0.0)

Usage:
  npm run forensic [-- [options]]
  node src/forensics/cli.mjs [options]

Options:
  --json           Output structured JSON to stdout instead of formatted text
  --md             Output GitHub-flavored Markdown to stdout
  --out <file>     Write report artifact to disk (.json or .md)
  --verbose        Include detailed justifications for UNVERIFIED items
  --abnormal       Genuine crash test: injects canaries then kills Electron with SIGKILL.
                   Expects residual artifacts on disk (documents crash-persistence risk).
                   RENAMED from the old "skip-cleanup" mode which was not a real crash.
  --help, -h       Display this help message

Two-Phase Architecture:
  Phase 1 (Electron process): inject canaries → quiescence wait → pre-scan → cleanup → write state → EXIT
  Phase 2 (Node process):     read state → post-scan (no file locks) → evaluate → report

  This guarantees the post-destruction scan runs after ALL Chromium file handles are released,
  eliminating EBUSY false-negatives that corrupted previous audit results.
`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: extract --key=value or positional args
// ─────────────────────────────────────────────────────────────────────────────
function getArgValue(args, key) {
  const kv = args.find(a => a.startsWith(`${key}=`));
  if (kv) return kv.slice(key.length + 1);
  const idx = args.indexOf(key);
  if (idx !== -1 && args[idx + 1] && !args[idx + 1].startsWith('--')) return args[idx + 1];
  return null;
}

function hasFlag(args, ...flags) {
  return flags.some(f => args.includes(f));
}

// ─────────────────────────────────────────────────────────────────────────────
// Poll until a file appears on disk (for crash-inject handshake)
// ─────────────────────────────────────────────────────────────────────────────
async function waitForFile(filePath, timeoutMs = 30000, pollMs = 200) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(filePath)) return true;
    await new Promise(r => setTimeout(r, pollMs));
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Wait for a child process to exit
// ─────────────────────────────────────────────────────────────────────────────
function waitForExit(child, timeoutMs = 15000) {
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (!done) { done = true; resolve(null); }
    }, timeoutMs);
    child.on('exit', (code) => {
      if (!done) { done = true; clearTimeout(timer); resolve(code); }
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// NODE ORCHESTRATOR PATH (no process.versions.electron)
// ─────────────────────────────────────────────────────────────────────────────
if (!process.versions.electron) {
  const args = process.argv.slice(2);

  if (hasFlag(args, '--help', '-h')) { printHelp(); process.exit(0); }

  const jsonMode   = hasFlag(args, '--json');
  const mdMode     = hasFlag(args, '--md');
  const verbose    = hasFlag(args, '--verbose');
  const abnormal   = hasFlag(args, '--abnormal', '--crash');

  let outFile = getArgValue(args, '--out');

  const electronCli = path.join(projectRoot, 'node_modules', 'electron', 'cli.js');

  // Create isolated tempDir for Chromium userData + state handshake file
  const baseTmp = process.env.LOCALAPPDATA
    ? path.join(process.env.LOCALAPPDATA, 'Temp')
    : os.tmpdir();
  const tempDir = path.join(
    baseTmp,
    `apricity_audit_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`
  );
  fs.mkdirSync(tempDir, { recursive: true });

  const stateFile = path.join(baseTmp, `apricity_audit_state_${Date.now()}_${Math.random().toString(36).slice(2, 7)}.json`);
  const overallStart = Date.now();
  let exitCode = 0;

  try {
    if (!abnormal) {
      // ── NORMAL MODE: spawnSync Electron (Phase 1) ──────────────────────
      // Electron runs inject→quiescence→pre-scan→cleanup→write state→exit
      const result = spawnSync(
        process.execPath,
        [electronCli, __filename,
          `--forensic-phase=core`,
          `--temp-dir=${tempDir}`,
          `--state-file=${stateFile}`
        ],
        { stdio: 'inherit', cwd: projectRoot }
      );

      if (!fs.existsSync(stateFile)) {
        console.error('[Forensic CLI] ERROR: Electron phase did not produce state file.');
        console.error('[Forensic CLI] Electron exit code:', result.status);
        process.exit(1);
      }

    } else {
      // ── ABNORMAL / CRASH-INJECT MODE ───────────────────────────────────
      // Spawn Electron non-blocking. It injects canaries, pre-scans, writes
      // state, then HANGS (does not clean up, does not exit).
      console.error('[Forensic CLI] Crash test: spawning Electron in crash-inject mode...');

      const child = spawn(
        process.execPath,
        [electronCli, __filename,
          `--forensic-phase=crash-inject`,
          `--temp-dir=${tempDir}`,
          `--state-file=${stateFile}`
        ],
        { stdio: 'inherit', cwd: projectRoot, detached: false }
      );

      // Poll for state file — signals that canaries are injected + pre-scan complete
      const appeared = await waitForFile(stateFile, 60000, 300);
      if (!appeared) {
        console.error('[Forensic CLI] Crash test: state file never appeared — aborting.');
        child.kill('SIGKILL');
        process.exit(1);
      }

      // Add a brief extra wait so the canaries have time to flush to disk
      await new Promise(r => setTimeout(r, 500));

      console.error('[Forensic CLI] Crash test: sending SIGKILL to Electron process...');
      try { child.kill('SIGKILL'); } catch (_) {}

      // Wait for the process to actually die
      await waitForExit(child, 10000);
      console.error('[Forensic CLI] Crash test: Electron process terminated.');

      // Brief wait for OS to release remaining file handles after SIGKILL
      await new Promise(r => setTimeout(r, 800));
    }

    // ── Phase 2: Read state + post-scan in Node (no Chromium running) ───
    const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));

    // Dynamically import scanner and auditor (pure Node, no Electron needed)
    const { FilesystemScanner } = await import('./FilesystemScanner.mjs');
    const { ForensicAuditor, JUSTIFICATION_CODES } = await import('./ForensicAuditor.mjs');
    const { ForensicReporter } = await import('./ForensicReporter.mjs');
    const { CanaryGenerator } = await import('./CanaryGenerator.mjs');

    // Reconstruct canary patterns from stored tokens (Buffers can't survive JSON serialization).
    // Must use CanaryGenerator.getEncodings(token) to rebuild the Buffer objects so that
    // FilesystemScanner.scanBuffer() can actually search file contents.
    const canaryPatterns = Object.entries(state.canaryTokens).map(([sub, token]) => ({
      subsystem: sub,
      token,
      encodings: CanaryGenerator.getEncodings(token)
    }));

    const scanner = new FilesystemScanner({ appName: 'apricity-browser' });

    console.error('[Forensic CLI] Phase 2: running post-destruction scan (Electron exited)...');
    const postFsScanResult = await scanner.scanPaths(state.scanTargetRoots, canaryPatterns);

    // Clean up intentional failure file if present
    if (state.intentionalFailurePath && fs.existsSync(state.intentionalFailurePath)) {
      try { fs.unlinkSync(state.intentionalFailurePath); } catch (_) {}
    }

    // Evaluate (static — no Electron needed)
    const result = ForensicAuditor.evaluateResult(state, postFsScanResult, overallStart);

    // Patch mode label for abnormal run
    if (abnormal) {
      result.metadata.mode = 'GENUINE_CRASH_TEST';
      result.metadata.crashNote =
        'Electron was killed with SIGKILL after canary injection. ' +
        'Any residual artifacts prove crash-persistence risk. ' +
        'This is expected behavior: FAIL here means data survives a real crash.';
    }

    // Output
    if (outFile) {
      const ext = path.extname(outFile).toLowerCase();
      const fmt = ext === '.md' ? 'md' : 'json';
      ForensicReporter.writeReportFile(result, outFile, fmt);
    }

    if (jsonMode) {
      console.log(ForensicReporter.formatJson(result));
    } else if (mdMode) {
      console.log(ForensicReporter.formatMarkdown(result));
    } else {
      console.log(ForensicReporter.formatConsole(result, { verbose }));
      if (outFile) console.log(`  💾 Report saved to: ${outFile}\n`);
    }

    exitCode = (result.summary && result.summary.failCount > 0) ? 1 : 0;

  } catch (err) {
    console.error('[Forensic CLI] Fatal error:', err);
    exitCode = 1;
  } finally {
    // Clean up tempDir (userData) + state file
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (_) {}
    try { fs.unlinkSync(stateFile); } catch (_) {}
  }

  process.exit(exitCode);

// ─────────────────────────────────────────────────────────────────────────────
// ELECTRON CHILD PATH (spawned by Node orchestrator above)
// ─────────────────────────────────────────────────────────────────────────────
} else {
  const electron = await import('electron');
  const { app } = electron;

  const args = process.argv.slice(2);

  // Extract phase + paths from arguments
  const phase     = args.find(a => a.startsWith('--forensic-phase='))?.split('=')[1] || 'legacy';
  const tempDir   = args.find(a => a.startsWith('--temp-dir='))?.split('=')[1] || null;
  const stateFile = args.find(a => a.startsWith('--state-file='))?.split('=')[1] || null;

  // ── CRITICAL: setPath BEFORE app.whenReady() ──────────────────────────
  if (tempDir) {
    try {
      if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
      app.setPath('userData', tempDir);
    } catch (_) {}
  } else if (phase === 'legacy') {
    // Legacy single-process mode (backward compat for direct invocation)
    const baseTmp = process.env.LOCALAPPDATA
      ? path.join(process.env.LOCALAPPDATA, 'Temp') : 'C:\\Temp';
    const legacyTemp = path.join(
      baseTmp,
      `apricity_audit_userdata_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`
    );
    try {
      if (!fs.existsSync(legacyTemp)) fs.mkdirSync(legacyTemp, { recursive: true });
      app.setPath('userData', legacyTemp);
    } catch (_) {}
  }

  const { ForensicAuditor } = await import('./ForensicAuditor.mjs');
  const { ForensicReporter } = await import('./ForensicReporter.mjs');

  app.whenReady().then(async () => {

    if (phase === 'core') {
      // ── PHASE 1 (CORE): inject, quiescence, pre-scan, cleanup, write state, EXIT ──
      try {
        const coreState = await new ForensicAuditor().runAuditCore({ skipCleanup: false });

        // Write intermediate state (JSON-serializable — no Buffers)
        fs.writeFileSync(stateFile, JSON.stringify(coreState, null, 2));
      } catch (err) {
        console.error('[Forensic CLI / Electron core] Error in Phase 1:', err);
        // Write an error marker so Node parent doesn't hang
        try { fs.writeFileSync(stateFile, JSON.stringify({ __error: err.message })); } catch (_) {}
      }

      // Clean exit — releases ALL Chromium file handles
      setTimeout(() => app.exit(0), 50);

    } else if (phase === 'crash-inject') {
      // ── CRASH-INJECT: inject, pre-scan, write state, HANG (wait for SIGKILL) ──
      try {
        const coreState = await new ForensicAuditor().runAuditCore({ skipCleanup: true });

        // Write state file — this signals the Node parent that we're ready to be killed
        fs.writeFileSync(stateFile, JSON.stringify(coreState, null, 2));

        // Hang forever — parent will SIGKILL us
        // (do NOT call clearStorageData or app.exit)
        await new Promise(() => {}); // never resolves

      } catch (err) {
        console.error('[Forensic CLI / Electron crash-inject] Error:', err);
        try { fs.writeFileSync(stateFile, JSON.stringify({ __error: err.message })); } catch (_) {}
        setTimeout(() => app.exit(1), 50);
      }

    } else {
      // ── LEGACY / DIRECT MODE: full in-process audit (e.g. invoked without Node parent) ──
      const legacyTempUserData = app.getPath('userData');
      try {
        const legacyArgs = args.filter(a => !a.startsWith('--forensic-phase')
          && !a.startsWith('--temp-dir') && !a.startsWith('--state-file'));

        if (hasFlag(legacyArgs, '--help', '-h')) { printHelp(); setTimeout(() => app.exit(0), 50); return; }

        const jsonMode = hasFlag(legacyArgs, '--json');
        const mdMode   = hasFlag(legacyArgs, '--md');
        const verbose  = hasFlag(legacyArgs, '--verbose');
        const abnormal = hasFlag(legacyArgs, '--abnormal', '--crash');

        let outFile = getArgValue(legacyArgs, '--out');

        const auditor = new ForensicAuditor();
        const result = await auditor.runAudit({ skipCleanup: abnormal });

        if (outFile) {
          const ext = path.extname(outFile).toLowerCase();
          ForensicReporter.writeReportFile(result, outFile, ext === '.md' ? 'md' : 'json');
        }

        if (jsonMode) {
          console.log(ForensicReporter.formatJson(result));
        } else if (mdMode) {
          console.log(ForensicReporter.formatMarkdown(result));
        } else {
          console.log(ForensicReporter.formatConsole(result, { verbose }));
          if (outFile) console.log(`  💾 Report saved to: ${outFile}\n`);
        }

        try {
          if (fs.existsSync(legacyTempUserData)) {
            fs.rmSync(legacyTempUserData, { recursive: true, force: true });
          }
        } catch (_) {}

        const exitCode = (result.summary && result.summary.failCount > 0) ? 1 : 0;
        setTimeout(() => app.exit(exitCode), 100);

      } catch (err) {
        console.error('[Forensic CLI] Fatal error:', err);
        try {
          if (fs.existsSync(legacyTempUserData)) {
            fs.rmSync(legacyTempUserData, { recursive: true, force: true });
          }
        } catch (_) {}
        setTimeout(() => app.exit(1), 100);
      }
    }

  }).catch((err) => {
    console.error('[Forensic CLI] Fatal error initializing Electron:', err);
    setTimeout(() => app.exit(1), 100);
  });
}
