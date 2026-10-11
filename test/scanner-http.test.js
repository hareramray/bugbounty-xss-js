import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateConfig } from '../src/config.js';
import { scan } from '../src/scanner.js';

async function localServer(t, handler) {
  const requests = [];
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const record = {
      method: request.method,
      url: new URL(request.url, `http://${request.headers.host}`),
      headers: request.headers,
      body: Buffer.concat(chunks).toString('utf8'),
    };
    requests.push(record);
    handler(record, response);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    const closed = new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    server.closeAllConnections();
    await closed;
  });
  return { origin: `http://127.0.0.1:${server.address().port}`, requests };
}

function scanConfig(origin, overrides = {}) {
  return validateConfig({
    scope: [`${origin}/`],
    cases: [{ id: 'query', type: 'query', url: `${origin}/test`, param: 'q' }],
    payloadIds: ['html-script', 'html-svg', 'attribute-double'],
    ...overrides,
    defaults: { delayMs: 0, settleMs: 0, timeoutMs: 5000, ...overrides.defaults },
  });
}

test('HTTP request budget stops within a redirect chain before another request starts', async t => {
  const local = await localServer(t, (request, response) => {
    const next = request.url.pathname === '/start' ? '/middle' : '/end';
    response.writeHead(302, { location: next });
    response.end('redirect');
  });
  const report = await scan(scanConfig(local.origin, {
    cases: [{ id: 'redirect', type: 'query', url: `${local.origin}/start`, param: 'q' }],
    defaults: { maxRequests: 2 },
  }), { httpOnly: true });
  assert.deepEqual(local.requests.map(request => request.url.pathname), ['/start', '/middle']);
  assert.equal(report.requestCount, 2);
  assert.equal(report.probeCount, 1);
  assert.equal(report.stopReason, 'Request budget exhausted');
  assert.match(report.results[0].errors.join('\n'), /Request budget exhausted/u);
});

test('HTTP probe budget stops remaining payloads', async t => {
  const local = await localServer(t, (request, response) => {
    response.setHeader('content-type', 'text/plain');
    response.end(request.url.searchParams.get('q'));
  });
  const report = await scan(scanConfig(local.origin, { defaults: { maxProbes: 2 } }), { httpOnly: true });
  assert.equal(local.requests.length, 2);
  assert.equal(report.requestCount, 2);
  assert.equal(report.probeCount, 2);
  assert.equal(report.results.length, 2);
  assert.equal(report.stopReason, 'Probe budget exhausted');
  assert.equal(report.summary.reflected, 2);
  assert.equal(report.summary.confirmed, 0);
});

test('HTTP 429 stops all subsequent probes', async t => {
  const local = await localServer(t, (_request, response) => {
    response.writeHead(429, { 'retry-after': '120' });
    response.end('Slow down');
  });
  const report = await scan(scanConfig(local.origin), { httpOnly: true });
  assert.equal(local.requests.length, 1);
  assert.equal(report.requestCount, 1);
  assert.equal(report.probeCount, 1);
  assert.match(report.stopReason, /HTTP 429/u);
  assert.equal(report.results[0].responses[0].status, 429);
});

test('manual HTTP redirects apply POST-to-GET and body-preserving status semantics', async t => {
  const local = await localServer(t, (request, response) => {
    const [, phase, status] = request.url.pathname.split('/');
    if (phase === 'redirect') {
      response.writeHead(Number(status), { location: `/final/${status}` });
      response.end('redirect');
    } else {
      response.setHeader('content-type', 'text/plain');
      response.end(request.body || 'final GET');
    }
  });
  const statuses = [301, 302, 303, 307, 308];
  const report = await scan(scanConfig(local.origin, {
    cases: statuses.map(status => ({
      id: `redirect-${status}`, type: 'form', url: `${local.origin}/redirect/${status}`,
      param: 'message', data: { token: 'test-token' },
    })),
    payloadIds: ['html-svg'],
  }), { httpOnly: true, allowWrites: true });
  assert.equal(report.requestCount, statuses.length * 2);
  assert.equal(report.results.length, statuses.length);
  for (const status of statuses) {
    const initial = local.requests.find(request => request.url.pathname === `/redirect/${status}`);
    const final = local.requests.find(request => request.url.pathname === `/final/${status}`);
    assert.equal(initial.method, 'POST');
    assert.equal(new URLSearchParams(initial.body).get('token'), 'test-token');
    assert.match(new URLSearchParams(initial.body).get('message'), /alert\('xss/u);
    if ([301, 302, 303].includes(status)) {
      assert.equal(final.method, 'GET', `status ${status}`);
      assert.equal(final.body, '', `status ${status}`);
      assert.equal(final.headers['content-type'], undefined, `status ${status}`);
    } else {
      assert.equal(final.method, 'POST', `status ${status}`);
      assert.equal(final.body, initial.body, `status ${status}`);
      assert.equal(final.headers['content-type'], initial.headers['content-type'], `status ${status}`);
    }
    assert.deepEqual(report.results.find(result => result.caseId === `redirect-${status}`).errors, []);
  }
});

test('explicit authorization and custom headers never follow a redirect to a second allowed origin', async t => {
  const second = await localServer(t, (_request, response) => response.end('second origin'));
  const first = await localServer(t, (_request, response) => {
    response.writeHead(302, { location: `${second.origin}/destination` });
    response.end('redirect');
  });
  const report = await scan(scanConfig(first.origin, {
    scope: [`${first.origin}/`, `${second.origin}/`],
    headers: { Authorization: 'Bearer fixture-secret', 'X-Test': 'fixture-custom-secret' },
    cases: [{ id: 'headers', type: 'query', url: `${first.origin}/start`, param: 'q', headers: { 'X-Case': 'fixture-case-secret' } }],
    payloadIds: ['html-svg'],
  }), { httpOnly: true });
  assert.equal(first.requests.length, 1);
  assert.equal(second.requests.length, 1);
  assert.equal(report.requestCount, 2);
  assert.equal(first.requests[0].headers.authorization, 'Bearer fixture-secret');
  assert.equal(first.requests[0].headers['x-test'], 'fixture-custom-secret');
  assert.equal(first.requests[0].headers['x-case'], 'fixture-case-secret');
  for (const name of ['authorization', 'x-test', 'x-case']) {
    assert.equal(second.requests[0].headers[name], undefined, name);
  }
});

test('HTTP redirect outside configured scope is recorded and never requested', async t => {
  const excluded = await localServer(t, (_request, response) => response.end('excluded'));
  const allowed = await localServer(t, (_request, response) => {
    response.writeHead(302, { location: `${excluded.origin}/excluded` });
    response.end('redirect');
  });
  const report = await scan(scanConfig(allowed.origin, { payloadIds: ['html-svg'] }), { httpOnly: true });
  assert.equal(allowed.requests.length, 1);
  assert.equal(excluded.requests.length, 0);
  assert.equal(report.requestCount, 1);
  assert.equal(report.results[0].status, 'inconclusive');
  assert.equal(report.results[0].blockedRequestCount, 1);
  assert.match(report.results[0].blockedRequests[0].reason, /Out-of-scope HTTP redirect/u);
});

test('oversized declared and chunked bodies cannot produce a reflection claim', async t => {
  const local = await localServer(t, (request, response) => {
    const body = `${request.url.searchParams.get('q')}${'x'.repeat(1024)}`;
    response.setHeader('content-type', 'text/html');
    if (request.url.pathname === '/declared') {
      response.setHeader('content-length', Buffer.byteLength(body));
      response.end(body);
    } else {
      response.write(body.slice(0, 32));
      response.end(body.slice(32));
    }
  });
  const report = await scan(scanConfig(local.origin, {
    cases: ['declared', 'chunked'].map(id => ({ id, type: 'query', url: `${local.origin}/${id}`, param: 'q' })),
    payloadIds: ['html-svg'],
    defaults: { maxResponseBytes: 64 },
  }), { httpOnly: true });
  assert.equal(report.requestCount, 2);
  assert.equal(report.results.length, 2);
  assert.equal(report.summary.reflected, 0);
  assert.equal(report.summary.confirmed, 0);
  for (const result of report.results) {
    assert.equal(result.status, 'inconclusive');
    assert.deepEqual(result.responses, []);
    assert.match(result.errors.join('\n'), /exceeds maxResponseBytes/u);
  }
});

test('missing and corrupted storage-state files produce useful errors before requests', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'xss-http-state-test-'));
  const corrupted = join(directory, 'corrupted-state.json');
  await writeFile(corrupted, '{ invalid json');
  t.after(async () => {
    await unlink(corrupted);
    await rmdir(directory);
  });
  const local = await localServer(t, (_request, response) => response.end('must not be reached'));
  for (const storageState of [join(directory, 'missing-state.json'), corrupted]) {
    const report = await scan(scanConfig(local.origin, {
      storageState,
      payloadIds: ['html-svg'],
    }), { httpOnly: true });
    assert.equal(report.requestCount, 0);
    assert.equal(report.results.length, 1);
    assert.equal(report.results[0].status, 'inconclusive');
    assert.match(report.results[0].errors.join('\n'), /storage state|storageState|ENOENT|JSON|Unexpected/iu);
  }
  assert.equal(local.requests.length, 0);
});
