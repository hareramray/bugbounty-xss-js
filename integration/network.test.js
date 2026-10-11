import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { validateConfig } from '../src/config.js';
import { scan } from '../src/scanner.js';
import { renderReport } from '../src/report.js';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  const closed = new Promise(resolve => server.close(resolve));
  server.closeAllConnections();
  await closed;
}

async function fixtures(t) {
  const outsideHits = [];
  const writes = [];
  const outside = createServer((req, res) => {
    outsideHits.push(`${req.method} ${req.url}`);
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('outside');
  });
  outside.on('upgrade', (req, socket) => {
    outsideHits.push(`UPGRADE ${req.url}`);
    socket.destroy();
  });
  const outsideOrigin = await listen(outside);
  const inside = createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/connection-reset') {
      req.socket.destroy();
      return;
    }
    if (url.pathname === '/redirect') {
      res.writeHead(302, { location: `${outsideOrigin}/redirect-destination` });
      res.end();
      return;
    }
    if (req.method === 'POST') {
      writes.push(url.pathname);
      req.resume();
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    const payload = url.searchParams.get('q') ?? '';
    if (url.pathname === '/network') {
      res.end(`<!doctype html>${payload}
        <img src="${outsideOrigin}/image"><img src="/redirect">
        <script>
          fetch('${outsideOrigin}/fetch').catch(() => {});
          fetch('/redirect').catch(() => {});
          window.open('${outsideOrigin}/popup');
          window.open('/redirect');
          new WebSocket('${outsideOrigin.replace('http:', 'ws:')}/socket');
        </script>`);
    } else if (url.pathname === '/sandbox') {
      res.end(`<!doctype html><iframe sandbox="allow-scripts allow-modals"
        src="/frame?q=${encodeURIComponent(payload)}"></iframe>`);
    } else if (url.pathname === '/incidental-write') {
      res.end(`<!doctype html>${payload}<script>fetch('/write', {
        method: 'POST', body: 'test fixture' }).catch(() => {});</script>`);
    } else if (url.pathname === '/queued-resources') {
      res.end(`<!doctype html>${Array.from({ length: 25 }, (_, index) =>
        `<img src="/resource-${index}">`).join('')}`);
    } else {
      res.end(`<!doctype html>${payload}`);
    }
  });
  const insideOrigin = await listen(inside);
  t.after(async () => {
    await close(inside);
    await close(outside);
  });
  return { insideOrigin, outsideOrigin, outsideHits, writes };
}

function config(origin, cases) {
  return validateConfig({
    scope: [`${origin}/`],
    defaults: { delayMs: 0, settleMs: 120, timeoutMs: 5000 },
    payloadIds: ['html-svg'],
    cases,
  });
}

test('browser requests, redirect hops, popups and WebSockets stay inside scope', async t => {
  const fixture = await fixtures(t);
  const report = await scan(config(fixture.insideOrigin, [{
    id: 'network', type: 'query', url: `${fixture.insideOrigin}/network`, param: 'q',
  }]));
  const result = report.results[0];
  assert.equal(result.status, 'confirmed', JSON.stringify(result.errors));
  assert.deepEqual(fixture.outsideHits, []);
  assert.ok(result.blockedRequests.some(item => item.reason.includes('Out-of-scope')));
  assert.ok(result.blockedRequests.some(item => item.reason.includes('redirects are blocked')));
  assert.ok(result.blockedRequests.some(item => item.reason.includes('WebSockets')));
});

test('HTTP-only redirects never reach an out-of-scope destination', async t => {
  const fixture = await fixtures(t);
  const report = await scan(config(fixture.insideOrigin, [{
    id: 'http-redirect', type: 'query', url: `${fixture.insideOrigin}/redirect`, param: 'q',
  }]), { httpOnly: true });
  assert.deepEqual(fixture.outsideHits, []);
  assert.equal(report.results[0].status, 'inconclusive');
  assert.ok(report.results[0].blockedRequests.some(item => item.reason === 'Out-of-scope HTTP redirect'));
});

test('opaque-origin sandbox execution is not first-party XSS proof', async t => {
  const fixture = await fixtures(t);
  const report = await scan(config(fixture.insideOrigin, [
    { id: 'positive-control', type: 'query', url: `${fixture.insideOrigin}/frame`, param: 'q' },
    { id: 'opaque-sandbox', type: 'query', url: `${fixture.insideOrigin}/sandbox`, param: 'q' },
  ]));
  assert.equal(report.results[0].status, 'confirmed');
  assert.equal(report.results[1].status, 'reflected');
  assert.deepEqual(report.results[1].executions, []);
});

test('write opt-in gates explicit probes and incidental page POSTs', async t => {
  const fixture = await fixtures(t);
  const settings = config(fixture.insideOrigin, [
    { id: 'explicit-write', type: 'form', url: `${fixture.insideOrigin}/submit`, param: 'message' },
    { id: 'incidental-write', type: 'query', url: `${fixture.insideOrigin}/incidental-write`, param: 'q' },
  ]);
  const withoutWrites = await scan(settings);
  assert.equal(withoutWrites.results[0].status, 'skipped');
  assert.deepEqual(fixture.writes, []);
  assert.ok(withoutWrites.results[1].blockedRequests.some(item => item.reason.includes('needs --allow-writes')));
  const withWrites = await scan(settings, { allowWrites: true });
  assert.notEqual(withWrites.results[0].status, 'skipped');
  assert.deepEqual(fixture.writes.toSorted(), ['/submit', '/write']);
});

test('HTML report renders hostile payloads and metadata as escaped text', () => {
  const hostile = '</pre><script>alert(1)</script><img src=x onerror=alert(2)>';
  const html = renderReport({
    results: [{ status: 'reflected', caseId: hostile, payload: hostile }],
    startedAt: hostile, mode: hostile, probeCount: 1, requestCount: 1,
    summary: { reflected: 1 }, stopReason: hostile, limitations: [hostile],
  });
  assert.ok(!html.includes(hostile));
  assert.ok(!html.includes('<script>'));
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(html.includes('default-src \'none\''));
});

test('transport failures do not copy authentication headers into reports', async t => {
  const fixture = await fixtures(t);
  const settings = config(fixture.insideOrigin, [{
    id: 'connection-reset', type: 'query', url: `${fixture.insideOrigin}/connection-reset`, param: 'q',
  }]);
  const secret = 'Bearer test-secret-sentinel-943842';
  settings.headers.authorization = secret;
  for (const httpOnly of [true, false]) {
    const report = await scan(settings, { httpOnly });
    assert.equal(report.results[0].status, 'inconclusive');
    assert.ok(report.results[0].errors.length > 0);
    assert.ok(!JSON.stringify(report).includes(secret),
      `${httpOnly ? 'HTTP' : 'browser'} report must omit request headers from transport call logs`);
  }
});

test('queued requests from a closed probe do not starve the next probe', async t => {
  const fixture = await fixtures(t);
  const settings = config(fixture.insideOrigin, [
    { id: 'queued-resources', type: 'query', url: `${fixture.insideOrigin}/queued-resources`, param: 'q' },
    { id: 'next-control', type: 'query', url: `${fixture.insideOrigin}/frame`, param: 'q' },
  ]);
  settings.defaults = { ...settings.defaults, delayMs: 100, settleMs: 100,
    timeoutMs: 700, maxRequests: 14 };
  const report = await scan(settings);
  assert.ok(report.results[0].errors.some(error => error.includes('pending browser requests')));
  assert.equal(report.results[1]?.status, 'confirmed', JSON.stringify({
    stopReason: report.stopReason,
    errors: report.results[1]?.errors,
    requestCount: report.requestCount,
  }));
  assert.equal(report.stopReason, null);
});
