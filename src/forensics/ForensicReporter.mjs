/**
 * ForensicReporter.mjs
 * 
 * Multi-dimensional report formatter for Apricity Browser's forensic artifact auditor.
 * 
 * Produces structured JSON artifacts, formatted Markdown reports, and clean terminal
 * console summaries with clear distinction between:
 * - Browser Storage State (Pre-destruction readback)
 * - Filesystem Pre-State (Disk scan prior to teardown)
 * - Cleanup Action (Lifecycle execution)
 * - Filesystem Post-State (Post-destruction scan)
 * - Result (VERIFIED CLEAN / FAIL / UNVERIFIED)
 * 
 * Strict Security Honesty:
 * - Rejects naive boolean CLEAN / zeroResidue summaries.
 * - Documents all UNVERIFIED hardware, kernel, and network boundaries with justification codes.
 */

import fs from 'node:fs';

export class ForensicReporter {
  /**
   * Formats the audit result into a clean terminal-friendly text output.
   * 
   * @param {object} auditResult Output from ForensicAuditor.runAudit()
   * @param {object} [options={}] Formatting options { verbose: boolean }
   * @returns {string} Formatted terminal string
   */
  static formatConsole(auditResult, options = {}) {
    const lines = [];
    const { metadata, architecturalContext, environment, session, discovery, verification, artifacts, dimensions, summary } = auditResult;

    lines.push('================================================================================');
    lines.push('  🔬  APRICITY BROWSER — REAL CHROMIUM FORENSIC ARTIFACT AUDIT REPORT');
    lines.push('================================================================================');
    lines.push(`  Platform        : ${metadata.platform} (${metadata.arch}) | Node: ${metadata.nodeVersion}`);
    if (metadata.electronVersion) {
      lines.push(`  Electron / Chrome: v${metadata.electronVersion} / v${metadata.chromiumVersion}`);
    }
    lines.push(`  Runtime Mode    : ${metadata.mode || 'NORMAL_DESTRUCTION'} (Electron: ${metadata.electronRuntime})`);
    lines.push(`  Timestamp       : ${metadata.timestamp}`);
    lines.push(`  Execution Time  : ${metadata.durationMs} ms`);
    lines.push(`  Session UUID    : ${session.sessionUUID}`);
    lines.push(`  Scanned Files   : ${discovery.scannedFilesCount} files (${(discovery.scannedBytesCount / 1024).toFixed(1)} KB)`);
    lines.push(`  Locked Files    : ${discovery.lockedFilesCount}`);
    if (environment) {
      lines.push(`  Test UserData   : ${environment.scannedUserDataPath || 'N/A'}`);
      lines.push(`  Path Match Check: ${environment.userDataPathVerified ? 'VERIFIED (Matches Electron runtime)' : 'MISMATCH'}`);
    }
    lines.push('--------------------------------------------------------------------------------');
    lines.push('  ARCHITECTURAL CONTEXT & TEST ISOLATION:');
    lines.push(`  • Test Session : ${architecturalContext.architecture}`);
    lines.push(`  • Sandboxing   : ${architecturalContext.sandboxStatus}`);
    lines.push(`  • Boundary Note: ${architecturalContext.boundaryDistinction}`);
    lines.push('================================================================================\n');

    // Section 1: Storage Subsystem Causal Breakdown
    if (artifacts && Object.keys(artifacts).length > 0) {
      lines.push('--- REAL CHROMIUM STORAGE SUBSYSTEM CAUSAL VERIFICATION ---');
      for (const [key, art] of Object.entries(artifacts)) {
        lines.push(`  [${art.verdict.padEnd(14)}] Artifact: ${art.name} (${key})`);
        lines.push(`                   Browser Pre-State   : ${art.browserPreState}`);
        lines.push(`                   Filesystem Pre-State: ${art.filesystemPreState}${art.filesystemPreLocations?.length > 0 ? ` (Found in ${art.filesystemPreLocations.length} file[s])` : ''}`);
        lines.push(`                   Cleanup Method      : ${art.cleanupState}`);
        lines.push(`                   Filesystem Post-State: ${art.filesystemPostState} (${art.postMatchesCount} residual matches)`);
        lines.push(`                   Result              : ${art.verdict}`);
        lines.push('');
      }
    }

    // Section 2: Multi-Dimensional Architecture Matrix
    lines.push('--- MULTI-DIMENSIONAL SECURITY & ARCHITECTURAL MATRIX ---');
    for (const [dimKey, dim] of Object.entries(dimensions)) {
      lines.push(`\n  [ ${dim.name} ]`);
      lines.push(`  Target: ${dim.target}`);

      for (const prop of dim.properties) {
        let tag = '[PASS]       ';
        if (prop.status === 'FAIL') tag = '[FAIL]       ';
        if (prop.status === 'UNVERIFIED') tag = '[UNVERIFIED] ';

        lines.push(`    ${tag} ${prop.id}`);
        lines.push(`                   ${prop.description}`);

        if (prop.evidence) {
          lines.push(`                   Evidence: ${prop.evidence}`);
        }
        if (prop.status === 'UNVERIFIED' && prop.justificationCode) {
          lines.push(`                   Code    : ${prop.justificationCode}`);
          if (options.verbose && prop.justification) {
            lines.push(`                   Reason  : ${prop.justification}`);
          }
        }
      }
    }

    if (verification.diskMatches && verification.diskMatches.length > 0) {
      lines.push('\n--------------------------------------------------------------------------------');
      lines.push('  ⚠️  FORENSIC CANARY RESIDUE DETECTED ON DISK:');
      for (const match of verification.diskMatches) {
        lines.push(`  ✗ Match in: ${match.filePath}`);
        lines.push(`    Subsystem: ${match.subsystem} | Encoding: ${match.encoding} | Offset: ${match.offset}`);
      }
      lines.push('--------------------------------------------------------------------------------\n');
    }

    lines.push('\n================================================================================');
    lines.push('  AUDIT SUMMARY MATRIX (MULTI-DIMENSIONAL)');
    lines.push('================================================================================');
    lines.push(`  ✓ Verified PASS Properties     : ${summary.passCount}`);
    lines.push(`  ✗ Detected FAIL Residues       : ${summary.failCount}`);
    lines.push(`  ? UNVERIFIED Physical/OS Limits: ${summary.unverifiedCount}`);
    lines.push(`  Total Evaluated Properties     : ${summary.totalProperties}`);
    lines.push('--------------------------------------------------------------------------------');
    lines.push(`  Honest Forensic Assessment:`);
    lines.push(`  >> ${summary.honestVerdict} <<`);
    lines.push('================================================================================\n');

    return lines.join('\n');
  }

  /**
   * Formats the audit result into a comprehensive GitHub-flavored Markdown report.
   * 
   * @param {object} auditResult Output from ForensicAuditor.runAudit()
   * @returns {string} Markdown document
   */
  static formatMarkdown(auditResult) {
    const { metadata, architecturalContext, environment, session, discovery, verification, artifacts, dimensions, summary } = auditResult;
    const lines = [];

    lines.push('# Apricity Browser — Forensic Artifact Audit Report');
    lines.push('');
    lines.push(`**Generated:** ${metadata.timestamp}  `);
    lines.push(`**Platform:** ${metadata.platform} (${metadata.arch}) | **Node:** ${metadata.nodeVersion}  `);
    if (metadata.electronVersion) {
      lines.push(`**Electron / Chromium:** v${metadata.electronVersion} / v${metadata.chromiumVersion}  `);
    }
    lines.push(`**Session UUID:** \`${session.sessionUUID}\`  `);
    lines.push(`**Duration:** ${metadata.durationMs} ms  `);
    lines.push(`**Mode:** \`${metadata.mode || 'NORMAL_DESTRUCTION'}\`  `);
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 1. Architectural Context & Security Boundaries');
    lines.push('');
    lines.push(`- **Architecture:** ${architecturalContext.architecture}`);
    lines.push(`- **Sandboxing:** ${architecturalContext.sandboxStatus}`);
    lines.push(`- **Boundary Scope:** ${architecturalContext.boundaryDistinction}`);
    if (environment) {
      lines.push(`- **Isolated Test UserData:** \`${environment.scannedUserDataPath || 'N/A'}\``);
      lines.push(`- **UserData Path Assertion:** \`${environment.userDataPathVerified ? 'VERIFIED' : 'MISMATCH'}\``);
    }
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 2. Injected Canary Tokens (Real Chromium Storage)');
    lines.push('');
    lines.push('| Storage Subsystem | Canary Identifier |');
    lines.push('|---|---|');
    for (const [sub, token] of Object.entries(session.canaryTokens)) {
      lines.push(`| \`${sub}\` | \`${token}\` |`);
    }
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 3. Storage Subsystem Causal Verification');
    lines.push('');
    lines.push('| Storage Subsystem | Browser Pre-State | Filesystem Pre-State | Cleanup Action | Filesystem Post-State | Verdict |');
    lines.push('|---|---|---|---|---|---|');
    if (artifacts) {
      for (const [key, art] of Object.entries(artifacts)) {
        lines.push(`| **${art.name}** (\`${key}\`) | \`${art.browserPreState}\` | \`${art.filesystemPreState}\` | ${art.cleanupState} | \`${art.filesystemPostState}\` | **${art.verdict}** |`);
      }
    }
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 4. Filesystem Discovery & Scan Scope');
    lines.push('');
    lines.push(`- **Scanned Files Count:** ${discovery.scannedFilesCount}`);
    lines.push(`- **Scanned Data Size:** ${(discovery.scannedBytesCount / 1024).toFixed(2)} KB`);
    lines.push(`- **Locked Files Encountered:** ${discovery.lockedFilesCount}`);
    lines.push('');
    lines.push('### Scanned Target Roots:');
    for (const root of discovery.scannedRoots) {
      lines.push(`- \`${root}\``);
    }
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 5. Multi-Dimensional Verification Matrix');
    lines.push('');
    for (const [dimKey, dim] of Object.entries(dimensions)) {
      lines.push(`### ${dim.name}`);
      lines.push(`*Target:* \`${dim.target}\``);
      lines.push('');
      lines.push('| Property | Status | Description | Evidence / Code |');
      lines.push('|---|---|---|---|');

      for (const prop of dim.properties) {
        const evidenceOrCode = prop.justificationCode
          ? `\`${prop.justificationCode}\`<br>${prop.justification || ''}`
          : (prop.evidence || 'N/A');
        lines.push(`| \`${prop.id}\` | **${prop.status}** | ${prop.description} | ${evidenceOrCode} |`);
      }
      lines.push('');
    }
    lines.push('---');
    lines.push('');
    lines.push('## 6. Summary & Forensic Assessment');
    lines.push('');
    lines.push(`- **Verified PASS Properties:** ${summary.passCount}`);
    lines.push(`- **Detected FAIL Residues:** ${summary.failCount}`);
    lines.push(`- **UNVERIFIED Physical/OS Limits:** ${summary.unverifiedCount}`);
    lines.push(`- **Total Properties Evaluated:** ${summary.totalProperties}`);
    lines.push(`- **Assessment Verdict:** \`${summary.honestVerdict}\``);
    lines.push('');
    lines.push('### Honesty Mandate:');
    lines.push('> A clean scan within user-space storage proves that known canary identifiers were absent from accessible filesystem surfaces after destruction. It does NOT prove physical zeroization from SSD flash cells, OS swapfiles, NTFS metadata logs, or kernel memory.');
    lines.push('');

    return lines.join('\n');
  }

  /**
   * Formats the audit result as a clean JSON string with indentation.
   * 
   * @param {object} auditResult Output from ForensicAuditor.runAudit()
   * @returns {string} JSON string
   */
  static formatJson(auditResult) {
    return JSON.stringify(auditResult, null, 2);
  }

  /**
   * Writes the audit result to disk.
   * 
   * @param {object} auditResult Output from ForensicAuditor.runAudit()
   * @param {string} filePath Target output path
   * @param {'json'|'md'} [format='json'] Output format
   */
  static writeReportFile(auditResult, filePath, format = 'json') {
    const content = format === 'md'
      ? this.formatMarkdown(auditResult)
      : this.formatJson(auditResult);
    fs.writeFileSync(filePath, content, 'utf8');
  }
}
