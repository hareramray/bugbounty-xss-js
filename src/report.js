import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

export function renderReport(report) {
  const e = escapeHtml;
  const rows = report.results.map(result => `<details><summary><strong>${e(result.status)}</strong> — ${e(result.caseId)} / ${e(result.payloadId ?? '')}</summary>
    <pre>${e(JSON.stringify(result, null, 2))}</pre></details>`).join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>XSS test report</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 24px;color:#17243b;background:#f6f8fc}h1{margin-bottom:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#fff;padding:18px;border:1px solid #dce3ee;border-radius:8px}details{margin:12px 0;background:#fff;border:1px solid #dce3ee;border-radius:8px;padding:14px}summary{cursor:pointer}strong{color:#18499c}li{margin:6px 0}</style></head><body>
<h1>XSS test report</h1><p>${e(report.startedAt)} · ${e(report.mode)} · ${e(report.probeCount)} probes · ${e(report.requestCount)} requests</p>
<pre>${e(JSON.stringify(report.summary, null, 2))}</pre>
${report.stopReason ? `<p><strong>Stopped: ${e(report.stopReason)}</strong></p>` : ''}
<p>Confirmed means the probe's exact marker executed in an allowed browser frame. Reflected means input appeared in a response; it is not execution proof. Counts are payload observations, not unique vulnerabilities.</p>
<ul>${report.limitations.map(item => `<li>${e(item)}</li>`).join('')}</ul>${rows}</body></html>`;
}

export async function writeReports(report, outputDirectory) {
  const directory = resolve(outputDirectory);
  await mkdir(directory, { recursive: true });
  const json = join(directory, 'report.json');
  const html = join(directory, 'report.html');
  await writeFile(json, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  await writeFile(html, renderReport(report), { mode: 0o600 });
  return { json, html };
}
