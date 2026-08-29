/**
 * ForensicReporter.mjs
 * 
 * Multi-dimensional report formatter for Apricity Browser's forensic artifact auditor.
 * 
 * Produces structured JSON artifacts, formatted Markdown reports, and clean terminal
 * console summaries.
 * 
 * Strict Security Honesty:
 * - Explicitly rejects naive "CLEAN: true" or single-boolean summaries.
 * - Presents 5-dimensional breakdown (In-Memory Vault, In-Memory Simulator,
 *   Chromium Webview Partitions, Tor Daemon State, Host OS Forensics).
 * - Documents all UNVERIFIED hardware and kernel boundaries with justification codes.
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
    const { metadata, architecturalContext, session, discovery, verification, dimensions, summary } = auditResult;

    lines.push('================================================================================');
    lines.push('  🔬  APRICITY BROWSER — EPHEMERAL FORENSIC ARTIFACT AUDIT REPORT');
    lines.push('================================================================================');
    lines.push(`  Platform        : ${metadata.platform} (${metadata.arch}) | Node: ${metadata.nodeVersion}`);
    lines.push(`  Timestamp       : ${metadata.timestamp}`);
    lines.push(`  Execution Time  : ${metadata.durationMs} ms`);
    lines.push(`  Session UUID    : ${session.sessionUUID}`);
    lines.push(`  Scanned Files   : ${discovery.scannedFilesCount} files (${(discovery.scannedBytesCount / 1024).toFixed(1)} KB)`);
    lines.push(`  Locked Files    : ${discovery.lockedFilesCount}`);
    lines.push('--------------------------------------------------------------------------------');
    lines.push('  ARCHITECTURAL LAYER CONTEXT:');
    lines.push(`  • Layer A (ZTR Simulator) : ${architecturalContext.layerA_Simulator}`);
    lines.push(`  • Layer B (Native Webview): ${architecturalContext.layerB_NativeChromium}`);
    lines.push(`  • Boundary Note           : ${architecturalContext.boundaryDistinction}`);
    lines.push('================================================================================\n');

    for (const [dimKey, dim] of Object.entries(dimensions)) {
      lines.push(`--- ${dim.name} ---`);
      lines.push(`    Target: ${dim.target}`);

      for (const prop of dim.properties) {
        let tag = '[PASS]       ';
        if (prop.status === 'FAIL') tag = '[FAIL]       ';
        if (prop.status === 'UNVERIFIED') tag = '[UNVERIFIED] ';

        lines.push(`  ${tag} ${prop.id}`);
        lines.push(`                 ${prop.description}`);

        if (prop.evidence) {
          lines.push(`                 Evidence: ${prop.evidence}`);
        }
        if (prop.status === 'UNVERIFIED' && prop.justificationCode) {
          lines.push(`                 Code    : ${prop.justificationCode}`);
          if (options.verbose && prop.justification) {
            lines.push(`                 Reason  : ${prop.justification}`);
          }
        }
      }
      lines.push('');
    }

    if (verification.diskMatches && verification.diskMatches.length > 0) {
      lines.push('--------------------------------------------------------------------------------');
      lines.push('  ⚠️  FORENSIC CANARY RESIDUE DETECTED ON DISK:');
      for (const match of verification.diskMatches) {
        lines.push(`  ✗ Match in: ${match.filePath}`);
        lines.push(`    Subsystem: ${match.subsystem} | Encoding: ${match.encoding} | Offset: ${match.offset}`);
      }
      lines.push('--------------------------------------------------------------------------------\n');
    }

    lines.push('================================================================================');
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
    const { metadata, architecturalContext, session, discovery, verification, dimensions, summary } = auditResult;
    const lines = [];

    lines.push('# Apricity Browser — Forensic Artifact Audit Report');
    lines.push('');
    lines.push(`**Generated:** ${metadata.timestamp}  `);
    lines.push(`**Platform:** ${metadata.platform} (${metadata.arch}) | **Node:** ${metadata.nodeVersion}  `);
    lines.push(`**Session UUID:** \`${session.sessionUUID}\`  `);
    lines.push(`**Duration:** ${metadata.durationMs} ms  `);
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 1. Architectural Context & Security Boundaries');
    lines.push('');
    lines.push('| Layer | Engine | Implementation & Scope |');
    lines.push('|---|---|---|');
    lines.push(`| **Layer A: ZTR Simulator** | Node.js / WebCrypto | ${architecturalContext.layerA_Simulator} |`);
    lines.push(`| **Layer B: Native Webview** | Chromium / Blink | ${architecturalContext.layerB_NativeChromium} |`);
    lines.push('');
    lines.push(`> **Boundary Distinction Note:** ${architecturalContext.boundaryDistinction}`);
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 2. Injected Canary Tokens');
    lines.push('');
    lines.push('| Subsystem | Canary Identifier |');
    lines.push('|---|---|');
    for (const [sub, token] of Object.entries(session.canaryTokens)) {
      lines.push(`| \`${sub}\` | \`${token}\` |`);
    }
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 3. Filesystem Discovery & Scan Scope');
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
    lines.push('## 4. Multi-Dimensional Verification Matrix');
    lines.push('');

    for (const [, dim] of Object.entries(dimensions)) {
      lines.push(`### ${dim.name}`);
      lines.push(`*Target: \`${dim.target}\`*`);
      lines.push('');
      lines.push('| Status | Property ID | Description | Evidence / Justification |');
      lines.push('|:---:|---|---|---|');

      for (const prop of dim.properties) {
        let statusBadge = '🟢 **PASS**';
        if (prop.status === 'FAIL') statusBadge = '🔴 **FAIL**';
        if (prop.status === 'UNVERIFIED') statusBadge = '⚪ **UNVERIFIED**';

        let notes = prop.evidence || '';
        if (prop.status === 'UNVERIFIED') {
          notes = `\`${prop.justificationCode}\`<br>${prop.justification}`;
        }

        lines.push(`| ${statusBadge} | \`${prop.id}\` | ${prop.description} | ${notes} |`);
      }
      lines.push('');
    }

    lines.push('---');
    lines.push('');
    lines.push('## 5. Summary & Forensic Assessment');
    lines.push('');
    lines.push('| Metric | Count |');
    lines.push('|---|:---:|');
    lines.push(`| Verified **PASS** Properties | **${summary.passCount}** |`);
    lines.push(`| Detected **FAIL** Residues | **${summary.failCount}** |`);
    lines.push(`| **UNVERIFIED** Hardware/Kernel Boundaries | **${summary.unverifiedCount}** |`);
    lines.push(`| **Total Evaluated Properties** | **${summary.totalProperties}** |`);
    lines.push('');
    lines.push(`### Assessment Verdict`);
    lines.push(`\`${summary.honestVerdict}\``);
    lines.push('');
    lines.push('> **Honesty Mandate:** Software-level deletion tests demonstrate that operating system file pointers are removed. Physical flash wear-leveling (FTL), OS kernel virtual memory paging, and low-level filesystem journals cannot be zeroized from user-space JavaScript.');
    lines.push('');

    return lines.join('\n');
  }

  /**
   * Serializes the audit result to a formatted JSON string.
   * 
   * @param {object} auditResult 
   * @returns {string} JSON string
   */
  static formatJson(auditResult) {
    return JSON.stringify(auditResult, null, 2);
  }

  /**
   * Writes the audit result to disk as JSON or Markdown.
   * 
   * @param {object} auditResult 
   * @param {string} filePath Output path
   * @param {'json'|'md'} [format='json']
   */
  static writeReportFile(auditResult, filePath, format = 'json') {
    const content = format === 'md'
      ? this.formatMarkdown(auditResult)
      : this.formatJson(auditResult);

    fs.writeFileSync(filePath, content, 'utf8');
  }
}
