import { loadConfig } from '../src/config.js';
import { scan } from '../src/scanner.js';
import { writeReports } from '../src/report.js';
import { createDemoServer } from '../demo/server.js';
import { fileURLToPath } from 'node:url';
import { formatError } from '../src/errors.js';

const server = createDemoServer();
try {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const config = await loadConfig(fileURLToPath(new URL('../examples/local-demo.json', import.meta.url)));
  config.scope = [`${origin}/`];
  for (const testCase of config.cases) {
    testCase.url = testCase.url.replace('http://127.0.0.1:8765', origin);
    testCase.verifyUrls = testCase.verifyUrls.map(url => url.replace('http://127.0.0.1:8765', origin));
  }
  console.log(`Local lab: ${origin}`);
  const report = await scan(config, { allowWrites: true, onProgress(result, number, total) {
    console.log(`[${number}/${total}] ${result.caseId} / ${result.payloadId}: ${result.status}`);
  } });
  const files = await writeReports(report, 'reports/local-demo');
  console.log(JSON.stringify({ summary: report.summary, stopReason: report.stopReason, reports: files }, null, 2));
  if (report.stopReason || report.summary.confirmed === 0) process.exitCode = 1;
} catch (error) {
  console.error(formatError(error));
  process.exitCode = 1;
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
