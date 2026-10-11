import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DEFAULTS, loadConfig, validateConfig, validateHeaders } from '../src/config.js';
import { Scope, parseHttpUrl } from '../src/scope.js';
import { PAYLOADS, makeMarker, renderPayload } from '../src/payloads.js';
import { buildRequest } from '../src/requests.js';

function config(overrides = {}) {
  return {
    scope: ['https://example.test/app'],
    cases: [{ id: 'search', type: 'query', url: 'https://example.test/app/search?q=old', param: 'q' }],
    ...overrides,
  };
}

test('scope uses an exact origin and path segments, including decoded segments', () => {
  const scope = new Scope(['https://example.test/app']);
  for (const url of ['https://example.test/app', 'https://example.test/app/',
    'https://example.test:443/app/search?q=1#x', 'https://example.test/%61pp/search']) {
    assert.equal(scope.allows(url), true, url);
  }
  for (const url of ['https://example.test/application', 'https://example.test/app2',
    'http://example.test/app', 'https://example.test:444/app', 'https://sub.example.test/app',
    'https://example.test.evil.test/app', 'https://example.test/app/../other',
    'https://example.test/app/%2e%2e/other', 'https://example.test/other?next=/app']) {
    assert.equal(scope.allows(url), false, url);
  }
  assert.throws(() => scope.assert('https://other.test/app'), /outside the configured scope/u);
  assert.equal(new Scope(['https://example.test/app/private']).allows('https://example.test/app//private'), false);
});

test('scope rejects credentials, malformed URLs, and ambiguous encoded paths', () => {
  const scope = new Scope(['https://example.test/']);
  for (const url of ['//example.test/', 'javascript:alert(1)', 'https://a:b@example.test/',
    'https://@example.test/', ' https://example.test/', 'https://example.test/a b',
    'https://example.test/app%2fsecret', 'https://example.test/app/%252e%252e/secret',
    'https://example.test/app/%255csecret', 'https://example.test/app/%00',
    'https://example.test/app/%zz', 'https://example.test/app\\secret',
    'https://example.test/\nadmin']) {
    assert.equal(scope.allows(url), false, url);
    assert.throws(() => parseHttpUrl(url), undefined, url);
  }
  assert.throws(() => new Scope([]), /at least one/u);
  assert.throws(() => new Scope(['https://example.test/?q=x']), /query string or fragment/u);
  assert.throws(() => new Scope(['https://example.test/#x']), /query string or fragment/u);
});

test('config fills defaults and resolves storageState relative to its file', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'xss-config-test-'));
  try {
    const file = join(directory, 'config.json');
    await writeFile(file, `\uFEFF${JSON.stringify(config({ storageState: 'session.json' }))}`);
    const result = await loadConfig(file);
    assert.deepEqual(result.defaults, DEFAULTS);
    assert.equal(result.storageState, resolve(directory, 'session.json'));
    assert.deepEqual(result.cases[0].headers, {});
    assert.deepEqual(result.cases[0].verifyUrls, []);
    assert.deepEqual(result.payloadIds, PAYLOADS.map((payload) => payload.id));
    await writeFile(file, '{broken json');
    await assert.rejects(loadConfig(file), /Cannot read config/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('config validates all supported case types', () => {
  const cases = [
    { id: 'query', type: 'query', url: 'https://example.test/app', param: 'q' },
    { id: 'fragment', type: 'fragment', url: 'https://example.test/app', fragmentTemplate: '/search/{payload}' },
    { id: 'form', type: 'form', url: 'https://example.test/app', param: 'message', data: { token: 'abc' }, verifyUrls: ['https://example.test/app/list'] },
    { id: 'json', type: 'json', url: 'https://example.test/app', param: 'message', data: { nested: { a: [1, true, null] } } },
    { id: 'browser', type: 'browser-form', url: 'https://example.test/app', field: '[name=message]', submit: 'button[type=submit]', fields: { '[name=title]': 'test' } },
  ];
  assert.equal(validateConfig(config({ cases })).cases.length, 5);
});

test('config rejects invalid case definitions and out-of-scope verification URLs', () => {
  const base = config().cases[0];
  const badCases = [
    { ...base, id: '' }, { ...base, type: 'put' }, { ...base, param: '' },
    { ...base, url: 'https://example.test/admin' }, { ...base, data: { q: 'body' } },
    { ...base, body: 'body' }, { ...base, method: 'POST' },
    { ...base, verifyUrls: ['https://example.test/app/list'] },
    { id: 'fragment', type: 'fragment', url: base.url, fragmentTemplate: '{payload}{payload}' },
    { id: 'fragment', type: 'fragment', url: base.url, fragmentTemplate: 'none' },
    { id: 'form', type: 'form', url: base.url, param: 'q', data: { a: ['array'] } },
    { id: 'json', type: 'json', url: base.url, param: 'q', data: { nested: { invalid: undefined } } },
    { id: 'json', type: 'json', url: base.url, param: 'q', data: { nested: { invalid: Infinity } } },
    { id: 'json', type: 'json', url: base.url, param: 'q', data: null },
    { id: 'form', type: 'form', url: base.url, param: 'q', verifyUrls: ['https://other.test/app'] },
    { id: 'browser', type: 'browser-form', url: base.url, field: '#input' },
    { id: 'browser', type: 'browser-form', url: base.url, field: '#input', submit: '#go', fields: { '#input': 'conflict' } },
  ];
  for (const bad of badCases) assert.throws(() => validateConfig(config({ cases: [bad] })), undefined, JSON.stringify(bad));
  assert.throws(() => validateConfig(config({ cases: [base, base] })), /duplicates/u);
  assert.throws(() => validateConfig(config({ cases: [] })), /1–1000/u);
});

test('config rejects invalid budgets, unsupported keys, and payload selections', () => {
  for (const defaults of [{ delayMs: -1 }, { delayMs: 60001 }, { timeoutMs: 0 }, { timeoutMs: 120001 },
    { settleMs: 30001 }, { maxProbes: 0 }, { maxRequests: 0 }, { maxRedirects: 21 },
    { maxResponseBytes: NaN }, { maxProbes: 2.5 }, { timeoutMs: '100' }, { typo: 1 }]) {
    assert.throws(() => validateConfig(config({ defaults })));
  }
  for (const payloadIds of [[], ['unknown'], ['html-svg', 'html-svg'], null, 'html-svg']) {
    assert.throws(() => validateConfig(config({ payloadIds })), /payloadIds/u);
  }
  assert.throws(() => validateConfig(config({ defaults: null })), /defaults must be an object/u);
  assert.throws(() => validateConfig(config({ unexpected: true })), /unsupported option/u);
  assert.equal(validateConfig(config({ defaults: { delayMs: 0, settleMs: 0, maxRedirects: 0 } })).defaults.delayMs, 0);
});

test('headers support authorization/custom values and reject transport overrides and injection', () => {
  assert.deepEqual(validateHeaders({ Authorization: 'Bearer fake-test-token', 'X-Test': 'yes' }),
    { authorization: 'Bearer fake-test-token', 'x-test': 'yes' });
  for (const name of ['Host', 'COOKIE', 'Content-Length', 'Connection', 'Transfer-Encoding',
    'Proxy-Authorization', 'Sec-Fetch-Site', 'Accept-Encoding', 'Bad Header']) {
    assert.throws(() => validateHeaders({ [name]: 'value' }), /unsupported header/u);
  }
  assert.throws(() => validateHeaders({ 'X-Test': 'one\r\nInjected: yes' }), /control characters/u);
  assert.throws(() => validateHeaders({ 'X-Test': 42 }), /must be a string/u);
  assert.throws(() => validateHeaders({ 'X-Test': 'one', 'x-test': 'two' }), /repeats header/u);
});

test('query and fragment transports preserve payload content with exactly one encoding layer', () => {
  const payload = "<svg onload=\"alert('xss123')\"> & %+/#?";
  const query = buildRequest({ type: 'query', url: 'https://example.test/app?q=one&q=two&keep=yes', param: 'q' }, payload);
  const queryUrl = new URL(query.url);
  assert.equal(query.method, 'GET');
  assert.equal(query.body, undefined);
  assert.deepEqual(queryUrl.searchParams.getAll('q'), [payload]);
  assert.equal(queryUrl.searchParams.get('keep'), 'yes');
  const fragment = buildRequest({ type: 'fragment', url: 'https://example.test/app#old', fragmentTemplate: '/search/{payload}' }, payload);
  assert.equal(decodeURIComponent(new URL(fragment.url).hash.slice('#/search/'.length)), payload);
  assert.equal(fragment.body, undefined);
});

test('POST transports replace only the selected field and set the matching content type', () => {
  const payload = "<script>alert('xss123')</script>&a=1+%";
  const form = buildRequest({ type: 'form', url: 'https://example.test/app', param: 'q',
    data: { q: 'old', token: 'csrf', flag: true, empty: null }, headers: { 'X-Test': 'case' } }, payload,
  { 'x-test': 'global', Authorization: 'Bearer fake-token', 'Content-Type': 'text/plain' });
  assert.equal(form.method, 'POST');
  assert.equal(new URLSearchParams(form.body).get('q'), payload);
  assert.equal(new URLSearchParams(form.body).get('token'), 'csrf');
  assert.equal(new URLSearchParams(form.body).get('empty'), '');
  assert.equal(form.headers['x-test'], 'case');
  assert.equal(form.headers.authorization, 'Bearer fake-token');
  assert.equal(form.headers['content-type'], 'application/x-www-form-urlencoded;charset=UTF-8');
  const json = buildRequest({ type: 'json', url: 'https://example.test/app', param: 'q', data: { nested: { keep: 1 } } }, payload);
  assert.deepEqual(JSON.parse(json.body), { nested: { keep: 1 }, q: payload });
  assert.equal(json.headers['content-type'], 'application/json');
  const prototypeKey = buildRequest({ type: 'json', url: 'https://example.test/app', param: '__proto__' }, payload);
  assert.equal(Object.hasOwn(JSON.parse(prototypeKey.body), '__proto__'), true);
  const browser = buildRequest({ type: 'browser-form', url: 'https://example.test/app' }, payload);
  assert.equal(browser.method, 'GET');
  assert.equal(browser.body, undefined);
});

test('all payloads render unique benign marker proofs', () => {
  assert.equal(new Set(PAYLOADS.map((payload) => payload.id)).size, PAYLOADS.length);
  const markers = Array.from({ length: 100 }, makeMarker);
  assert.equal(new Set(markers).size, markers.length);
  for (const payload of PAYLOADS) {
    const rendered = renderPayload(payload, markers[0]);
    assert.ok(rendered.includes(`alert('${markers[0]}')`));
    assert.equal(rendered.includes('{marker}'), false);
    assert.equal(/https?:|document\.cookie|fetch\(/u.test(rendered), false);
  }
  assert.throws(() => renderPayload(PAYLOADS[0], "bad');code()"), /marker/u);
});
