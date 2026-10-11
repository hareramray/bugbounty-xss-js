import assert from 'node:assert/strict';
import { once } from 'node:events';
import { after, before, test } from 'node:test';
import { createDemoServer } from '../demo/server.js';
import { validateConfig } from '../src/config.js';
import { scan } from '../src/scanner.js';

let server;
let origin;

before(async () => {
  server = createDemoServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  origin = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

function configuration(cases, payloadIds) {
  return validateConfig({
    scope: [`${origin}/`],
    payloadIds,
    defaults: {
      delayMs: 0,
      settleMs: 120,
      timeoutMs: 5000,
      maxProbes: 100,
      maxRequests: 200,
    },
    cases: cases.map((item) => ({
      ...item,
      url: `${origin}${item.url}`,
      ...(item.verifyUrls ? { verifyUrls: item.verifyUrls.map((path) => `${origin}${path}`) } : {}),
    })),
  });
}

function resultFor(report, caseId, payloadId = 'html-script') {
  const result = report.results.find((item) => item.caseId === caseId && item.payloadId === payloadId);
  assert.ok(result, `Missing result for ${caseId}/${payloadId}: ${JSON.stringify(report)}`);
  return result;
}

function assertConfirmed(result) {
  assert.equal(result.status, 'confirmed', JSON.stringify(result));
  assert.ok(result.executions.length > 0, JSON.stringify(result));
  for (const event of result.executions) {
    assert.equal(event.marker, result.marker);
    assert.equal(event.origin, origin);
  }
}

function assertNotExecuted(result, expectedStatus) {
  assert.equal(result.status, expectedStatus, JSON.stringify(result));
  assert.deepEqual(result.executions, [], JSON.stringify(result));
  assert.deepEqual(result.errors, [], JSON.stringify(result));
}

test('browser confirmation distinguishes executable XSS from safe reflection and preserves stored verification', { timeout: 120000 }, async (t) => {
  const config = configuration([
    { id: 'reflected', type: 'query', url: '/reflected', param: 'q' },
    { id: 'escaped', type: 'query', url: '/escaped', param: 'q' },
    { id: 'dom', type: 'fragment', url: '/dom' },
    { id: 'dom-safe', type: 'fragment', url: '/dom-safe' },
    { id: 'csp', type: 'query', url: '/csp', param: 'q' },
    { id: 'json-control', type: 'json', url: '/api/echo', param: 'message', data: {} },
    { id: 'json-html', type: 'json', url: '/json-html', param: 'message', data: {} },
    { id: 'stored-form', type: 'form', url: '/stored', param: 'message', data: {}, verifyUrls: ['/stored'] },
    {
      id: 'stored-browser-form', type: 'browser-form', url: '/form',
      field: 'textarea[name=message]', submit: 'button[type=submit]', verifyUrls: ['/stored'],
    },
  ], ['html-script', 'html-svg']);
  const report = await scan(config, { allowWrites: true });
  assert.equal(report.stopReason, null, JSON.stringify(report));
  assert.equal(report.probeCount, 18);

  await t.test('HTML script execution is confirmed in the target origin', () => {
    assertConfirmed(resultFor(report, 'reflected'));
  });
  await t.test('escaped reflection does not execute', () => {
    for (const payloadId of config.payloadIds) {
      const result = resultFor(report, 'escaped', payloadId);
      assertNotExecuted(result, 'reflected');
      assert.ok(result.responses.some((response) => response.markerReflected));
      assert.ok(result.responses.every((response) => !response.payloadReflectedVerbatim));
    }
  });
  await t.test('fragment XSS executes despite no server-side payload reflection', () => {
    const result = resultFor(report, 'dom', 'html-svg');
    assertConfirmed(result);
    assert.ok(result.responses.every((response) => !response.markerReflected));
  });
  await t.test('textContent DOM control does not execute either payload', () => {
    for (const payloadId of config.payloadIds) {
      assertNotExecuted(resultFor(report, 'dom-safe', payloadId), 'not_observed');
    }
  });
  await t.test('CSP remains effective despite raw script reflection', () => {
    const result = resultFor(report, 'csp');
    assertNotExecuted(result, 'reflected');
    assert.ok(result.responses.some((response) => response.payloadReflectedVerbatim && response.csp.includes("script-src 'none'")));
  });
  await t.test('raw JSON API responses are reflection evidence only, including text/html responses', () => {
    for (const caseId of ['json-control', 'json-html']) {
      assertNotExecuted(resultFor(report, caseId), 'reflected');
    }
    assert.ok(resultFor(report, 'json-control').responses.some((response) => response.contentType.startsWith('application/json')));
    assert.ok(resultFor(report, 'json-html').responses.some((response) => response.contentType.startsWith('text/html')));
  });
  await t.test('raw form submission shares cookies with the verification browser', () => {
    const result = resultFor(report, 'stored-form');
    assertConfirmed(result);
    assert.equal(result.storedExecutionObserved, true);
    assert.ok(result.executions.some((event) => event.step === 'verify'));
  });
  await t.test('browser form storage is verified even when its redirect is blocked', () => {
    const result = resultFor(report, 'stored-browser-form');
    assertConfirmed(result);
    assert.equal(result.storedExecutionObserved, true);
    assert.ok(result.executions.some((event) => event.step === 'verify'));
    assert.ok(result.blockedRequests.some((request) => request.reason.includes('Browser redirects are blocked')));
  });
});

test('HTTP-only scanning records raw reflection without claiming execution', { timeout: 30000 }, async () => {
  const config = configuration([
    { id: 'reflected', type: 'query', url: '/reflected', param: 'q' },
    { id: 'escaped', type: 'query', url: '/escaped', param: 'q' },
    { id: 'json-html', type: 'json', url: '/json-html', param: 'message', data: {} },
  ], ['html-script']);
  const report = await scan(config, { allowWrites: true, httpOnly: true });
  assert.equal(report.mode, 'http-only');
  assert.equal(report.probeCount, 3);
  assert.equal(report.summary.confirmed, 0);
  for (const result of report.results) assertNotExecuted(result, 'reflected');
  assert.ok(resultFor(report, 'reflected').responses.some((response) => response.payloadReflectedVerbatim));
  assert.ok(resultFor(report, 'escaped').responses.every((response) => !response.payloadReflectedVerbatim));
  assert.ok(resultFor(report, 'json-html').responses.some((response) => response.payloadReflectedVerbatim));
});
