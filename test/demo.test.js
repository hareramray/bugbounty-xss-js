import assert from 'node:assert/strict';
import { once } from 'node:events';
import { after, before, test } from 'node:test';
import { createDemoServer } from '../demo/server.js';

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

test('landing page and form stay local', async () => {
  const landing = await fetch(`${origin}/`);
  assert.equal(landing.status, 200);
  assert.match(await landing.text(), /Local XSS test fixtures/);
  const form = await fetch(`${origin}/form`);
  assert.match(await form.text(), /<form method="post" action="\/stored">/);
});

test('raw HTML is reflected, while the escaped control encodes markup', async () => {
  const payload = '<img src=x onerror="window.testMarker=1">';
  const raw = await fetch(`${origin}/reflected?q=${encodeURIComponent(payload)}`);
  assert.ok((await raw.text()).includes(payload));
  const escaped = await fetch(`${origin}/escaped?q=${encodeURIComponent(payload)}`);
  const text = await escaped.text();
  assert.ok(!text.includes(payload));
  assert.match(text, /&lt;img src=x onerror=&quot;window.testMarker=1&quot;&gt;/);
});

test('attribute and script fixtures preserve their deliberately unsafe contexts', async () => {
  const attribute = '\"><img src=x onerror="window.testMarker=1">';
  const attrResponse = await fetch(`${origin}/attribute?q=${encodeURIComponent(attribute)}`);
  assert.ok((await attrResponse.text()).includes(`value="${attribute}"`));
  const script = "';window.testMarker=1;//";
  const scriptResponse = await fetch(`${origin}/script?q=${encodeURIComponent(script)}`);
  assert.ok((await scriptResponse.text()).includes(`window.demoValue = '${script}';`));
});

test('DOM fixtures use HTML versus text sinks and do not reflect the URL fragment', async () => {
  const raw = await fetch(`${origin}/dom#fragment-marker`);
  const html = await raw.text();
  assert.match(html, /\.innerHTML = value/);
  assert.ok(!html.includes('fragment-marker'));
  const safe = await fetch(`${origin}/dom-safe#fragment-marker`);
  assert.match(await safe.text(), /\.textContent = value/);
});

test('CSP control sends script-src none even though markup is reflected', async () => {
  const payload = '<script>window.testMarker=1</script>';
  const response = await fetch(`${origin}/csp?q=${encodeURIComponent(payload)}`);
  assert.match(response.headers.get('content-security-policy'), /script-src 'none'/);
  assert.ok((await response.text()).includes(payload));
});

test('stored values persist only in the submitting session', async () => {
  const firstSession = await fetch(`${origin}/form`);
  const cookie = firstSession.headers.get('set-cookie').split(';')[0];
  assert.match(firstSession.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
  const payload = '<img src=x onerror="window.testMarker=1">';
  const post = await fetch(`${origin}/stored`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ message: payload }),
    redirect: 'manual',
  });
  assert.equal(post.status, 303);
  assert.equal(post.headers.get('location'), '/stored');
  const stored = await fetch(`${origin}/stored`, { headers: { cookie } });
  assert.ok((await stored.text()).includes(payload));
  const secondSession = await fetch(`${origin}/stored`);
  assert.ok(!(await secondSession.text()).includes(payload));
  assert.notEqual(secondSession.headers.get('set-cookie').split(';')[0], cookie);
  const forged = await fetch(`${origin}/stored`, { headers: { cookie: 'xss_demo_session=invalid' } });
  assert.ok(!(await forged.text()).includes(payload));
  assert.ok(forged.headers.get('set-cookie'));
});

test('JSON echo is non-HTML while the JSON-to-HTML endpoint reflects raw markup', async () => {
  const payload = '<svg onload="window.testMarker=1"></svg>';
  const options = {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ message: payload }),
  };
  const echo = await fetch(`${origin}/api/echo`, options);
  assert.match(echo.headers.get('content-type'), /^application\/json/);
  assert.equal(echo.headers.get('x-content-type-options'), 'nosniff');
  assert.deepEqual(await echo.json(), { message: payload });
  const html = await fetch(`${origin}/json-html`, options);
  assert.match(html.headers.get('content-type'), /^text\/html/);
  assert.ok((await html.text()).includes(payload));
});

test('bad JSON, unexpected content types, oversized bodies, and unknown routes are rejected', async () => {
  const badJson = await fetch(`${origin}/api/echo`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{',
  });
  assert.equal(badJson.status, 400);
  const badType = await fetch(`${origin}/stored`, { method: 'POST', body: 'message=test' });
  assert.equal(badType.status, 415);
  const tooLarge = await fetch(`${origin}/stored`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `message=${'x'.repeat(65 * 1024)}`,
  });
  assert.equal(tooLarge.status, 413);
  assert.equal((await fetch(`${origin}/missing`)).status, 404);
  assert.equal((await fetch(`${origin}/`, { method: 'DELETE' })).status, 405);
});
