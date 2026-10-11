import { parseHttpUrl } from './scope.js';

function mergeHeaders(...sets) {
  return Object.fromEntries(sets.flatMap((headers) =>
    Object.entries(headers ?? {}).map(([key, value]) => [key.toLowerCase(), value])));
}

/** Payloads are encoded once by the selected transport, never pre-escaped. */
export function buildRequest(testCase, payload, globalHeaders = {}) {
  if (typeof payload !== 'string') throw new TypeError('payload must be a string');
  const url = parseHttpUrl(testCase.url, 'case URL');
  const headers = mergeHeaders(globalHeaders, testCase.headers);
  if (testCase.type === 'query') {
    url.searchParams.set(testCase.param, payload);
    return { url: url.href, method: 'GET', headers };
  }
  if (testCase.type === 'fragment') {
    const template = testCase.fragmentTemplate ?? '{payload}';
    url.hash = template.replace('{payload}', encodeURIComponent(payload));
    return { url: url.href, method: 'GET', headers };
  }
  if (testCase.type === 'form') {
    const data = { ...testCase.data, [testCase.param]: payload };
    const body = new URLSearchParams(Object.entries(data)
      .map(([key, value]) => [key, value === null ? '' : String(value)])).toString();
    headers['content-type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
    return { url: url.href, method: 'POST', headers, body };
  }
  if (testCase.type === 'json') {
    const body = JSON.stringify({ ...testCase.data, [testCase.param]: payload });
    headers['content-type'] = 'application/json';
    return { url: url.href, method: 'POST', headers, body };
  }
  if (testCase.type === 'browser-form') {
    return { url: url.href, method: 'GET', headers };
  }
  throw new TypeError(`Unsupported case type: ${testCase.type}`);
}
