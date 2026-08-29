#!/usr/bin/env node

/**
 * cli.mjs
 * 
 * Command-line interface entry point for Apricity Browser's Forensic Artifact Auditor.
 * Executed via `npm run forensic`.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ForensicAuditor } from './ForensicAuditor.mjs';
import { ForensicReporter } from './ForensicReporter.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function printHelp() {
  console.log(`
Apricity Browser — Forensic Artifact Auditor CLI

Usage:
  node src/forensics/cli.mjs [options]
  npm run forensic [-- [options]]

Options:
  --json          Output structured JSON to stdout instead of formatted text
  --md            Output GitHub-flavored Markdown to stdout
  --out <file>    Write report artifact to disk (.json or .md)
  --verbose       Include detailed justifications for UNVERIFIED items
  --help, -h      Display this help message

Examples:
  npm run forensic
  npm run forensic -- --json
  npm run forensic -- --out forensic-report.json
  npm run forensic -- --out forensic-report.md --verbose
`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  const jsonMode = args.includes('--json');
  const mdMode = args.includes('--md');
  const verbose = args.includes('--verbose');

  let outFile = null;
  const outIndex = args.indexOf('--out');
  if (outIndex !== -1 && args[outIndex + 1]) {
    outFile = args[outIndex + 1];
  }

  try {
    const auditor = new ForensicAuditor();
    const result = await auditor.runAudit();

    if (outFile) {
      const ext = path.extname(outFile).toLowerCase();
      const format = ext === '.md' ? 'md' : 'json';
      ForensicReporter.writeReportFile(result, outFile, format);
    }

    if (jsonMode) {
      console.log(ForensicReporter.formatJson(result));
    } else if (mdMode) {
      console.log(ForensicReporter.formatMarkdown(result));
    } else {
      console.log(ForensicReporter.formatConsole(result, { verbose }));
      if (outFile) {
        console.log(`  💾 Report saved to: ${outFile}\n`);
      }
    }

    // Exit with failure code if any detected residue occurred
    if (result.summary && result.summary.failCount > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (err) {
    console.error('Fatal error during forensic audit execution:', err);
    process.exit(1);
  }
}

main();
