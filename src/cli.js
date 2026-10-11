#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { loadConfig } from './config.js';
import { PAYLOADS } from './payloads.js';
import { planScan, scan } from './scanner.js';
import { writeReports } from './report.js';
import { formatError } from './errors.js';

const HELP = `Scoped XSS Suite — explicit, authorized targets only

Usage:
  node src/cli.js scan --config examples/local-demo.json [options]
  node src/cli.js validate --config examples/local-demo.json
  node src/cli.js payloads

Options:
  --config FILE       JSON scope and test cases (required)
  --out DIRECTORY     Report directory (default: reports/<timestamp>)
  --dry-run           Show planned probes without making network requests
  --allow-writes      Enable form/JSON POST and browser form submissions
  --http-only         Inspect response reflection without browser execution checks
  --headed            Display Chromium during verification
  --fail-on-confirmed Exit 2 if execution is confirmed (useful in CI)
  --help              Show this help

Exit codes: 0 completed; 1 invalid configuration/runtime failure;
            2 confirmed XSS with --fail-on-confirmed; 3 incomplete/skipped coverage.
Run 'npm run setup:browser' once to install Chromium.
`;

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      config: { type: 'string' }, out: { type: 'string' },
      'dry-run': { type: 'boolean' }, 'allow-writes': { type: 'boolean' },
      'http-only': { type: 'boolean' }, headed: { type: 'boolean' },
      'fail-on-confirmed': { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help || positionals.length === 0) { console.log(HELP); return; }
  const command = positionals[0];
  if (positionals.length > 1) throw new Error('Unexpected positional arguments');
  if (command === 'payloads') {
    console.log(JSON.stringify(PAYLOADS, null, 2));
    return;
  }
  if (!['scan', 'validate'].includes(command)) throw new Error(`Unknown command: ${command}`);
  if (!values.config) throw new Error('--config is required');
  const config = await loadConfig(values.config);
  const options = { allowWrites: values['allow-writes'], httpOnly: values['http-only'], headed: values.headed };
  const plan = planScan(config, options);
  if (command === 'validate' || values['dry-run']) {
    console.log(JSON.stringify({ valid: true, scope: config.scope, ...plan }, null, 2));
    return;
  }
  console.log(`Running ${plan.plannedProbes} probes; max ${plan.maxRequests} requests; ${plan.delayMs} ms request spacing.`);
  const report = await scan(config, { ...options, onProgress: (result, number, total) => {
    console.log(`[${number}/${total}] ${result.caseId} / ${result.payloadId}: ${result.status}`);
  } });
  const output = values.out ?? `reports/${new Date().toISOString().replace(/[:.]/g, '-')}`;
  const files = await writeReports(report, output);
  console.log(JSON.stringify({ summary: report.summary, stopReason: report.stopReason, reports: files }, null, 2));
  if (values['fail-on-confirmed'] && report.summary.confirmed) process.exitCode = 2;
  else if (report.stopReason || report.summary.inconclusive || report.summary.skipped ||
    report.results.some(result => result.errors?.length || result.blockedRequestCount)) process.exitCode = 3;
}

main().catch(error => {
  console.error(`Error: ${formatError(error)}`);
  process.exitCode = 1;
});
