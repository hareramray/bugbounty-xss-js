import { chromium, request as playwrightRequest } from 'playwright';
import { setTimeout as sleep } from 'node:timers/promises';
import { Scope } from './scope.js';
import { PAYLOADS, renderPayload, makeMarker } from './payloads.js';
import { buildRequest } from './requests.js';
import { formatError } from './errors.js';

const WRITING_TYPES = new Set(['form', 'json', 'browser-form']);
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

class RequestBudget {
  constructor(defaults) {
    this.defaults = defaults;
    this.count = 0;
    this.lastStart = 0;
    this.queue = Promise.resolve();
    this.stopReason = null;
  }
  async acquire(signal) {
    const job = this.queue.then(async () => {
      if (signal?.aborted) throw new Error('Browser context closed');
      if (this.stopReason) throw new Error(this.stopReason);
      if (this.count >= this.defaults.maxRequests) {
        this.stopReason = 'Request budget exhausted';
        throw new Error(this.stopReason);
      }
      await sleep(Math.max(0, this.defaults.delayMs - (Date.now() - this.lastStart)), undefined, { signal });
      if (signal?.aborted) throw new Error('Browser context closed');
      if (this.stopReason) throw new Error(this.stopReason);
      this.count += 1;
      this.lastStart = Date.now();
    });
    this.queue = job.catch(() => {});
    return job;
  }
  observe(status) {
    if (status === 429) this.stopReason = 'Received HTTP 429; stopped to respect rate limiting';
  }
}

function block(result, url, reason) {
  result.blockedRequestCount += 1;
  if (result.blockedRequests.length < 25) result.blockedRequests.push({ url, reason });
}

function inspectResponse(result, url, status, headers, body, step) {
  const text = body.toString('utf8');
  const index = text.indexOf(result.marker);
  const reflection = index >= 0;
  const info = {
    url, status, step, contentType: headers['content-type'] ?? '',
    csp: headers['content-security-policy'] ?? null,
    cspReportOnly: headers['content-security-policy-report-only'] ?? null,
    markerReflected: reflection,
    payloadReflectedVerbatim: text.includes(result.payload),
    snippet: reflection ? text.slice(Math.max(0, index - 140), index + result.marker.length + 180) : null,
  };
  if (reflection || result.responses.length < 20) result.responses.push(info);
}

async function readResponse(response, result, defaults, step) {
  const headers = response.headers();
  const length = Number(headers['content-length']);
  if (length > defaults.maxResponseBytes) {
    result.errors.push(`Response exceeds maxResponseBytes: ${response.url()}`);
    return null;
  }
  const body = await response.body();
  if (body.length > defaults.maxResponseBytes) {
    result.errors.push(`Response exceeds maxResponseBytes: ${response.url()}`);
    return null;
  }
  inspectResponse(result, response.url(), response.status(), headers, body, step);
  return body;
}

async function fetchScoped(api, request, scope, budget, result, defaults, step = 'submit') {
  let current = { ...request, headers: { ...request.headers } };
  const initialOrigin = new URL(request.url).origin;
  for (let hops = 0; ; hops += 1) {
    scope.assert(current.url);
    await budget.acquire();
    const response = await api.fetch(current.url, {
      method: current.method, headers: current.headers, data: current.body,
      maxRedirects: 0, maxRetries: 0, timeout: defaults.timeoutMs, failOnStatusCode: false,
    });
    try {
      const status = response.status();
      budget.observe(status);
      await readResponse(response, result, defaults, step);
      if (!REDIRECTS.has(status)) return;
      const location = response.headers().location;
      if (!location) return;
      const next = new URL(location, current.url).href;
      if (!scope.allows(next)) {
        block(result, next, 'Out-of-scope HTTP redirect');
        return;
      }
      if (hops >= defaults.maxRedirects) throw new Error('HTTP redirect limit reached');
      // Explicit headers are scoped to the original origin. Browser-style cookie
      // handling is provided by the API context's shared cookie jar.
      if (new URL(next).origin !== initialOrigin) current.headers = {};
      if (status === 303 || ((status === 301 || status === 302) && current.method === 'POST')) {
        current.method = 'GET';
        current.body = undefined;
        for (const key of Object.keys(current.headers)) {
          if (key.toLowerCase() === 'content-type') delete current.headers[key];
        }
      }
      current.url = next;
    } finally {
      await response.dispose();
    }
  }
}

async function browserProbe(browser, config, testCase, result, scope, budget, options) {
  const { defaults } = config;
  const context = await browser.newContext({
    storageState: config.storageState,
    serviceWorkers: 'block', acceptDownloads: false,
    ignoreHTTPSErrors: false,
  });
  context.setDefaultTimeout(defaults.timeoutMs);
  context.setDefaultNavigationTimeout(defaults.timeoutMs);
  let step = 'navigate';
  let closing = false;
  const contextAbort = new AbortController();
  const pendingRoutes = new Set();
  const customHeaders = { ...config.headers, ...testCase.headers };
  const errorText = error => formatError(error, Object.values(customHeaders));
  const targetOrigin = new URL(testCase.url).origin;
  const bindingName = `__xss_observe_${makeMarker().replace(/\W/g, '')}`;
  try {
    await context.exposeBinding(bindingName, async (source, event) => {
      const frameUrl = source.frame.url();
      const executionStep = step;
      if (event?.marker !== result.marker || !scope.allows(frameUrl)) return;
      if (event.origin !== new URL(frameUrl).origin || event.origin === 'null') return;
      let effectiveOrigin;
      try { effectiveOrigin = await source.frame.evaluate(() => globalThis.origin); }
      catch { return; }
      if (effectiveOrigin !== event.origin) return;
      result.executions.push({
        marker: event.marker, frameUrl, pageUrl: source.page.url(),
        origin: event.origin, step: executionStep, observedAt: new Date().toISOString(),
      });
    });
    await context.addInitScript(({ bindingName, marker }) => {
      const originalAlert = window.alert.bind(window);
      const observe = window[bindingName];
      const origin = window.origin;
      window.alert = function (value) {
        if (String(value) === marker) {
          void observe({ marker, origin }).catch(() => {});
        }
        return originalAlert(value);
      };
    }, { bindingName, marker: result.marker });
    context.on('dialog', dialog => { void dialog.dismiss().catch(() => {}); });
    await context.routeWebSocket('**/*', socket => {
      block(result, socket.url(), 'WebSockets are disabled during probes');
      socket.close();
    });
    await context.route('**/*', async route => {
      const request = route.request();
      const url = request.url();
      if (!scope.allows(url)) {
        block(result, url, 'Out-of-scope browser request');
        await route.abort('blockedbyclient').catch(() => {});
        return;
      }
      if (!options.allowWrites && !['GET', 'HEAD', 'OPTIONS'].includes(request.method())) {
        block(result, url, `Browser ${request.method()} needs --allow-writes`);
        await route.abort('blockedbyclient').catch(() => {});
        return;
      }
      let response;
      const pending = {};
      pendingRoutes.add(pending);
      try {
        await budget.acquire(contextAbort.signal);
        if (closing) throw new Error('Browser context closed');
        const headers = await request.allHeaders();
        if (new URL(url).origin === targetOrigin) Object.assign(headers, customHeaders);
        // route.continue() can follow redirects without invoking this handler on
        // each hop. Fetch exactly one hop and block 3xx rather than replaying a
        // final document at the wrong URL/origin and producing misleading proof.
        response = await route.fetch({
          headers, maxRedirects: 0, maxRetries: 0, timeout: defaults.timeoutMs,
        });
        budget.observe(response.status());
        if (response.status() >= 300 && response.status() < 400 && response.status() !== 304) {
          const location = response.headers().location;
          block(result, location ? new URL(location, url).href : url,
            'Browser redirects are blocked; configure the final URL or a verifyUrls entry');
          await route.abort('blockedbyclient');
          return;
        }
        const body = await readResponse(response, result, defaults, step);
        if (body === null) await route.abort('blockedbyclient');
        else await route.fulfill({ response, body });
      } catch (error) {
        if (!closing) result.errors.push(`Browser request: ${errorText(error)}`);
        await route.abort('failed').catch(() => {});
      } finally {
        if (response) await response.dispose().catch(() => {});
        pendingRoutes.delete(pending);
      }
    });
    const page = await context.newPage();
    const settle = async () => {
      await sleep(defaults.settleMs);
      const deadline = Date.now() + defaults.timeoutMs;
      while (pendingRoutes.size && Date.now() < deadline) await sleep(25);
      if (pendingRoutes.size) result.errors.push('Timed out waiting for pending browser requests');
      // Event handlers from the last response get their own observation window.
      await sleep(defaults.settleMs);
    };
    const navigate = async url => {
      try {
        await page.goto(url, { waitUntil: 'domcontentloaded' });
      } catch (error) {
        result.errors.push(`Navigation: ${errorText(error)}`);
      }
      await settle();
    };
    if (testCase.type === 'form' || testCase.type === 'json') {
      await fetchScoped(context.request, buildRequest(testCase, result.payload, config.headers),
        scope, budget, result, defaults);
    } else if (testCase.type === 'browser-form') {
      await navigate(testCase.url);
      for (const [selector, value] of Object.entries(testCase.fields ?? {})) {
        await page.locator(selector).fill(value);
      }
      await page.locator(testCase.field).fill(result.payload);
      step = 'submit';
      await page.locator(testCase.submit).click({ noWaitAfter: true });
      await settle();
    } else {
      await navigate(buildRequest(testCase, result.payload, config.headers).url);
    }
    for (const url of testCase.verifyUrls ?? []) {
      // A fresh page avoids attributing a late submit-page timer to read-back.
      for (const previousPage of context.pages()) await previousPage.close().catch(() => {});
      step = 'verify';
      const verificationPage = await context.newPage();
      try {
        await verificationPage.goto(url, { waitUntil: 'domcontentloaded' });
        await settle();
      } catch (error) {
        result.errors.push(`Verification: ${errorText(error)}`);
      } finally {
        await verificationPage.close().catch(() => {});
      }
    }
  } finally {
    closing = true;
    contextAbort.abort();
    await context.close();
  }
}

async function httpProbe(config, testCase, result, scope, budget) {
  const api = await playwrightRequest.newContext({ storageState: config.storageState });
  try {
    await fetchScoped(api, buildRequest(testCase, result.payload, config.headers),
      scope, budget, result, config.defaults);
    for (const url of testCase.verifyUrls ?? []) {
      await fetchScoped(api, { url, method: 'GET', headers: new URL(url).origin === new URL(testCase.url).origin
        ? { ...config.headers, ...testCase.headers } : {} }, scope, budget, result, config.defaults, 'verify');
    }
  } finally {
    await api.dispose();
  }
}

export function planScan(config, options = {}) {
  const payloads = PAYLOADS.filter(p => !config.payloadIds || config.payloadIds.includes(p.id));
  const items = config.cases.map(testCase => ({
    id: testCase.id, type: testCase.type, url: testCase.url,
    payloadCount: payloads.length,
    skippedReason: WRITING_TYPES.has(testCase.type) && !options.allowWrites
      ? 'Needs --allow-writes' : options.httpOnly && ['fragment', 'browser-form'].includes(testCase.type)
        ? 'Needs browser mode' : null,
  }));
  const requestedProbes = items.filter(item => !item.skippedReason).length * payloads.length;
  return { items, requestedProbes, plannedProbes: Math.min(requestedProbes, config.defaults.maxProbes),
    maxRequests: config.defaults.maxRequests, delayMs: config.defaults.delayMs };
}

export async function scan(config, options = {}) {
  const scope = new Scope(config.scope);
  const budget = new RequestBudget(config.defaults);
  const plan = planScan(config, options);
  const report = {
    schemaVersion: 1, startedAt: new Date().toISOString(),
    mode: options.httpOnly ? 'http-only' : 'chromium', scope: config.scope,
    options: { allowWrites: !!options.allowWrites, ...config.defaults },
    plan, results: [], stopReason: null,
    limitations: [
      'No observation does not prove absence of XSS. Coverage is limited to configured cases and payloads.',
      'Browser redirects, WebSockets, service workers and out-of-scope resources are blocked; this may change application behavior.',
      'Raw form/JSON responses are reflection evidence only. Use browser-form or verifyUrls to demonstrate execution.',
      'Alert is instrumented with a per-probe marker and originating-frame check. CSP remains enabled.',
      'Response size is checked after transport buffering; this is not a streaming download limit.',
    ],
  };
  let browser;
  let probes = 0;
  try {
    if (!options.httpOnly && plan.plannedProbes > 0) {
      browser = await chromium.launch({ headless: !options.headed });
    }
    outer: for (const testCase of config.cases) {
      const planned = plan.items.find(item => item.id === testCase.id);
      if (planned.skippedReason) {
        report.results.push({ caseId: testCase.id, caseType: testCase.type, status: 'skipped',
          reason: planned.skippedReason });
        continue;
      }
      for (const payload of PAYLOADS.filter(p => !config.payloadIds || config.payloadIds.includes(p.id))) {
        if (budget.stopReason || probes >= config.defaults.maxProbes) {
          report.stopReason = budget.stopReason ?? 'Probe budget exhausted';
          break outer;
        }
        probes += 1;
        const marker = makeMarker();
        const result = {
          caseId: testCase.id, caseType: testCase.type, payloadId: payload.id,
          payloadContext: payload.context, marker, payload: renderPayload(payload, marker),
          targetUrl: testCase.url, status: 'not_observed', responses: [], executions: [],
          blockedRequests: [], blockedRequestCount: 0, errors: [],
        };
        const built = buildRequest(testCase, result.payload, config.headers);
        result.reproduction = { url: built.url, method: built.method,
          parameter: testCase.param ?? null, field: testCase.field ?? null,
          verifyUrls: testCase.verifyUrls ?? [],
          note: 'Replay with the same case configuration and authentication; request headers and other body fields are omitted.' };
        try {
          if (options.httpOnly) await httpProbe(config, testCase, result, scope, budget);
          else await browserProbe(browser, config, testCase, result, scope, budget, options);
        } catch (error) {
          result.errors.push(formatError(error, Object.values({ ...config.headers, ...testCase.headers })));
        }
        result.status = result.executions.length ? 'confirmed'
          : result.responses.some(response => response.markerReflected) ? 'reflected'
            : result.errors.length || result.blockedRequestCount ? 'inconclusive' : 'not_observed';
        result.storedExecutionObserved = result.executions.some(event => event.step === 'verify');
        report.results.push(result);
        options.onProgress?.(result, probes, plan.plannedProbes);
      }
    }
  } finally {
    if (browser) await browser.close();
  }
  report.stopReason ??= budget.stopReason;
  report.finishedAt = new Date().toISOString();
  report.requestCount = budget.count;
  report.probeCount = probes;
  report.summary = Object.fromEntries(['confirmed', 'reflected', 'not_observed', 'inconclusive', 'skipped']
    .map(status => [status, report.results.filter(result => result.status === status).length]));
  return report;
}
