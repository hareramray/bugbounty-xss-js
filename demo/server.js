import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_BODY_BYTES = 64 * 1024;
const SESSION_COOKIE = 'xss_demo_session';

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function page(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size <= MAX_BODY_BYTES) chunks.push(chunk);
  }
  if (size > MAX_BODY_BYTES) {
    const error = new Error('Request body exceeds 64 KiB.');
    error.status = 413;
    throw error;
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Deliberately vulnerable, in-memory test fixtures. The CLI binds loopback only. */
export function createDemoServer() {
  const sessions = new Map();

  return http.createServer(async (request, response) => {
    const send = (status, body, contentType = 'text/html; charset=utf-8') => {
      response.writeHead(status, {
        'content-type': contentType,
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
      });
      response.end(body);
    };

    try {
      const url = new URL(request.url, 'http://127.0.0.1');
      const cookie = (request.headers.cookie ?? '').split(';')
        .map((part) => part.trim()).find((part) => part.startsWith(`${SESSION_COOKIE}=`));
      let sessionId = cookie?.slice(SESSION_COOKIE.length + 1);
      if (!sessionId || !/^[a-f0-9]{48}$/.test(sessionId) || !sessions.has(sessionId)) {
        sessionId = randomBytes(24).toString('hex');
        if (sessions.size >= 1000) sessions.delete(sessions.keys().next().value);
        sessions.set(sessionId, { message: '' });
        response.setHeader('set-cookie', `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; SameSite=Strict`);
      }
      const session = sessions.get(sessionId);
      const q = url.searchParams.get('q') ?? '';

      if (request.method === 'GET') {
        switch (url.pathname) {
          case '/':
            return send(200, page('Local XSS test fixtures', `<p>Intentionally vulnerable examples for local testing. State exists only in memory and is isolated by a session cookie.</p>
              <ul><li><a href="/reflected?q=hello">Reflected HTML</a></li><li><a href="/escaped?q=hello">Escaped HTML control</a></li><li><a href="/attribute?q=hello">HTML attribute</a></li><li><a href="/script?q=hello">Inline JavaScript</a></li><li><a href="/dom#hello">DOM fragment</a></li><li><a href="/dom-safe#hello">DOM text control</a></li><li><a href="/csp?q=hello">CSP control</a></li><li><a href="/form">Stored XSS form</a></li><li><a href="/stored">Stored value</a></li></ul>`));
          case '/reflected':
            return send(200, page('Reflected HTML', `<div id="result">${q}</div>`));
          case '/escaped':
            return send(200, page('Escaped HTML control', `<div id="result">${escapeHtml(q)}</div>`));
          case '/attribute':
            return send(200, page('HTML attribute', `<label>Value <input id="result" value="${q}"></label>`));
          case '/script':
            return send(200, page('Inline JavaScript', `<p>The query value is placed in a JavaScript string.</p><script>window.demoValue = '${q}';</script>`));
          case '/dom':
          case '/dom-safe': {
            const property = url.pathname === '/dom' ? 'innerHTML' : 'textContent';
            return send(200, page(property === 'innerHTML' ? 'DOM fragment' : 'DOM text control', `<div id="result"></div><script>
              function showFragment() {
                let value = location.hash.slice(1);
                try { value = decodeURIComponent(value); } catch {}
                document.getElementById('result').${property} = value;
              }
              addEventListener('hashchange', showFragment);
              showFragment();
            </script>`));
          }
          case '/csp':
            response.setHeader('content-security-policy', "default-src 'none'; script-src 'none'; base-uri 'none'; form-action 'self'");
            return send(200, page('CSP control', `<div id="result">${q}</div>`));
          case '/form':
            return send(200, page('Stored XSS form', '<form method="post" action="/stored"><label>Message <textarea name="message"></textarea></label><button type="submit">Save message</button></form>'));
          case '/stored':
            return send(200, page('Stored value', `<div id="result">${session.message}</div><p><a href="/form">Edit message</a></p>`));
          default:
            return send(404, page('Not found', '<p>Unknown test endpoint.</p>'));
        }
      }

      if (request.method === 'POST') {
        const contentType = (request.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
        if (url.pathname === '/stored') {
          if (contentType !== 'application/x-www-form-urlencoded') {
            return send(415, 'Expected application/x-www-form-urlencoded.', 'text/plain; charset=utf-8');
          }
          const body = await readBody(request);
          session.message = new URLSearchParams(body).get('message') ?? '';
          response.writeHead(303, { location: '/stored', 'cache-control': 'no-store' });
          return response.end();
        }
        if (url.pathname === '/api/echo' || url.pathname === '/json-html') {
          if (contentType !== 'application/json') {
            return send(415, 'Expected application/json.', 'text/plain; charset=utf-8');
          }
          let data;
          const body = await readBody(request);
          try {
            data = JSON.parse(body);
          } catch {
            return send(400, 'Invalid JSON.', 'text/plain; charset=utf-8');
          }
          if (!data || typeof data !== 'object' || Array.isArray(data)) {
            return send(400, 'Expected a JSON object.', 'text/plain; charset=utf-8');
          }
          const message = String(data.message ?? '');
          if (url.pathname === '/api/echo') {
            return send(200, JSON.stringify({ message }), 'application/json; charset=utf-8');
          }
          return send(200, page('JSON body reflected as HTML', `<div id="result">${message}</div>`));
        }
        return send(404, page('Not found', '<p>Unknown test endpoint.</p>'));
      }

      response.setHeader('allow', 'GET, POST');
      return send(405, 'Method not allowed.', 'text/plain; charset=utf-8');
    } catch (error) {
      return send(error.status ?? 500, error.status ? error.message : 'Demo server error.', 'text/plain; charset=utf-8');
    }
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.DEMO_PORT ?? 8765);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('DEMO_PORT must be an integer from 1 to 65535.');
    process.exitCode = 1;
  } else {
    const server = createDemoServer();
    server.on('error', (error) => {
      console.error(`Demo server could not start: ${error.message}`);
      process.exitCode = 1;
    });
    server.listen(port, '127.0.0.1', () => {
      console.log(`Intentionally vulnerable local demo: http://127.0.0.1:${port}/`);
      console.log('Stop with Ctrl+C. Stored messages disappear when this process stops.');
    });
  }
}
