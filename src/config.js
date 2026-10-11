import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { PAYLOADS } from './payloads.js';
import { Scope, parseHttpUrl } from './scope.js';

export const DEFAULTS = Object.freeze({
  delayMs: 750,
  timeoutMs: 10000,
  settleMs: 500,
  maxProbes: 100,
  maxResponseBytes: 2000000,
  maxRequests: 500,
  maxRedirects: 5,
});

const LIMITS = {
  delayMs: [0, 60000], timeoutMs: [1, 120000], settleMs: [0, 30000],
  maxProbes: [1, 10000], maxResponseBytes: [1, 50000000],
  maxRequests: [1, 50000], maxRedirects: [0, 20],
};
const CASE_TYPES = new Set(['query', 'fragment', 'form', 'json', 'browser-form']);
const UNSUPPORTED_HEADERS = new Set([
  'host', 'cookie', 'cookie2', 'content-length', 'connection', 'keep-alive',
  'transfer-encoding', 'te', 'trailer', 'upgrade', 'expect', 'accept-encoding',
  'content-encoding', 'access-control-request-headers', 'access-control-request-method',
]);

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function knownKeys(value, allowed, label) {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length) throw new TypeError(`${label} has unsupported option(s): ${unknown.join(', ')}`);
}

function nonemptyString(value, label, maxLength = 2048) {
  if (typeof value !== 'string' || !value.trim() || value.length > maxLength ||
      /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`${label} must be a nonempty string of at most ${maxLength} characters without control characters`);
  }
  return value;
}

export function validateHeaders(input = {}, label = 'headers') {
  object(input, label);
  const result = {};
  for (const [name, value] of Object.entries(input)) {
    const normalized = name.toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) ||
        UNSUPPORTED_HEADERS.has(normalized) || normalized.startsWith('proxy-') || normalized.startsWith('sec-')) {
      throw new TypeError(`${label}.${name} is a transport-managed or unsupported header; use storageState for cookies`);
    }
    if (typeof value !== 'string' || /[\u0000-\u001f\u007f]/u.test(value)) {
      throw new TypeError(`${label}.${name} must be a string without control characters`);
    }
    if (Object.hasOwn(result, normalized)) throw new TypeError(`${label} repeats header ${name} with different casing`);
    Object.defineProperty(result, normalized, { value, enumerable: true, configurable: true, writable: true });
  }
  return result;
}

function validateData(value, type, label) {
  object(value, label);
  const active = new WeakSet();
  function inspect(item, depth = 0) {
    if (depth > 30) throw new TypeError(`${label} must not be nested more than 30 levels`);
    if (item === null || ['string', 'boolean'].includes(typeof item)) return;
    if (typeof item === 'number' && Number.isFinite(item)) return;
    if (typeof item !== 'object') throw new TypeError(`${label} must contain finite JSON-serializable values`);
    if (!Array.isArray(item)) object(item, label);
    if (active.has(item)) throw new TypeError(`${label} must not contain circular references`);
    active.add(item);
    for (const child of Object.values(item)) inspect(child, depth + 1);
    active.delete(item);
  }
  inspect(value);
  let serialized;
  try { serialized = JSON.stringify(value); } catch {
    throw new TypeError(`${label} must contain JSON-serializable values`);
  }
  if (serialized.length > 1000000) throw new TypeError(`${label} must not exceed 1 MB of JSON`);
  for (const [key, item] of Object.entries(value)) {
    nonemptyString(key, `${label} field name`, 256);
    if (type === 'form' && item !== null && !['string', 'number', 'boolean'].includes(typeof item)) {
      throw new TypeError(`${label}.${key} must be a string, number, boolean, or null for form encoding`);
    }
    if (typeof item === 'number' && !Number.isFinite(item)) throw new TypeError(`${label}.${key} must be finite`);
    if (['undefined', 'function', 'symbol', 'bigint'].includes(typeof item)) {
      throw new TypeError(`${label}.${key} must contain JSON-serializable values`);
    }
  }
  return JSON.parse(serialized);
}

export function validateConfig(input, baseDir = process.cwd()) {
  object(input, 'config');
  knownKeys(input, ['scope', 'cases', 'defaults', 'storageState', 'headers', 'payloadIds'], 'config');
  if (!Array.isArray(input.scope) || input.scope.length > 100) throw new TypeError('scope must be an array of 1–100 URL prefixes');
  const scope = new Scope(input.scope);
  const defaultsInput = input.defaults === undefined ? {} : input.defaults;
  object(defaultsInput, 'defaults');
  knownKeys(defaultsInput, Object.keys(DEFAULTS), 'defaults');
  const defaults = { ...DEFAULTS, ...defaultsInput };
  for (const [key, [min, max]] of Object.entries(LIMITS)) {
    if (!Number.isSafeInteger(defaults[key]) || defaults[key] < min || defaults[key] > max) {
      throw new TypeError(`defaults.${key} must be an integer from ${min} to ${max}`);
    }
  }
  if (!Array.isArray(input.cases) || input.cases.length === 0 || input.cases.length > 1000) {
    throw new TypeError('cases must contain 1–1000 test cases');
  }
  const ids = new Set();
  const cases = input.cases.map((item, index) => {
    const label = `cases[${index}]`;
    object(item, label);
    knownKeys(item, ['id', 'type', 'url', 'param', 'data', 'headers', 'fragmentTemplate', 'field', 'submit', 'fields', 'verifyUrls'], label);
    const id = nonemptyString(item.id, `${label}.id`, 128);
    if (ids.has(id)) throw new TypeError(`${label}.id duplicates case id ${id}`);
    ids.add(id);
    if (!CASE_TYPES.has(item.type)) throw new TypeError(`${label}.type must be query, fragment, form, json, or browser-form`);
    const url = parseHttpUrl(item.url, `${label}.url`).href;
    scope.assert(url);
    const normalized = { id, type: item.type, url, headers: validateHeaders(item.headers, `${label}.headers`) };
    if (['query', 'form', 'json'].includes(item.type)) {
      normalized.param = nonemptyString(item.param, `${label}.param`, 256);
    } else if (item.param !== undefined) {
      throw new TypeError(`${label}.param is only supported for query, form, and json cases`);
    }
    if (['form', 'json'].includes(item.type)) {
      normalized.data = validateData(item.data === undefined ? {} : item.data, item.type, `${label}.data`);
    } else if (item.data !== undefined) {
      throw new TypeError(`${label}.data is only supported for POST form/json cases; GET request bodies are not supported`);
    }
    if (item.type === 'fragment') {
      const template = item.fragmentTemplate ?? '{payload}';
      nonemptyString(template, `${label}.fragmentTemplate`);
      if (template.split('{payload}').length !== 2) throw new TypeError(`${label}.fragmentTemplate must contain exactly one {payload} placeholder`);
      normalized.fragmentTemplate = template;
    } else if (item.fragmentTemplate !== undefined) {
      throw new TypeError(`${label}.fragmentTemplate is only supported for fragment cases`);
    }
    if (item.type === 'browser-form') {
      normalized.field = nonemptyString(item.field, `${label}.field`);
      normalized.submit = nonemptyString(item.submit, `${label}.submit`);
      const fields = item.fields === undefined ? {} : item.fields;
      object(fields, `${label}.fields`);
      normalized.fields = Object.fromEntries(Object.entries(fields).map(([selector, value]) => {
        nonemptyString(selector, `${label}.fields selector`);
        if (typeof value !== 'string') throw new TypeError(`${label}.fields[${selector}] must be a string`);
        if (selector === item.field) throw new TypeError(`${label}.fields must not include the payload field selector`);
        return [selector, value];
      }));
    } else if (item.field !== undefined || item.submit !== undefined || item.fields !== undefined) {
      throw new TypeError(`${label}.field, submit, and fields are only supported for browser-form cases`);
    }
    if (item.verifyUrls !== undefined) {
      if (!['form', 'json', 'browser-form'].includes(item.type)) throw new TypeError(`${label}.verifyUrls is only supported for form, json, or browser-form cases`);
      if (!Array.isArray(item.verifyUrls) || item.verifyUrls.length > 20) throw new TypeError(`${label}.verifyUrls must be an array of up to 20 URLs`);
      normalized.verifyUrls = item.verifyUrls.map((value, verifyIndex) => {
        const verifyUrl = parseHttpUrl(value, `${label}.verifyUrls[${verifyIndex}]`).href;
        scope.assert(verifyUrl);
        return verifyUrl;
      });
    } else normalized.verifyUrls = [];
    return normalized;
  });
  const payloadIds = input.payloadIds === undefined ? PAYLOADS.map((payload) => payload.id) : input.payloadIds;
  const supportedIds = new Set(PAYLOADS.map((payload) => payload.id));
  if (!Array.isArray(payloadIds) || payloadIds.length === 0 || payloadIds.length > PAYLOADS.length ||
      payloadIds.some((id) => !supportedIds.has(id)) || new Set(payloadIds).size !== payloadIds.length) {
    throw new TypeError(`payloadIds must be a nonempty list of unique supported ids: ${[...supportedIds].join(', ')}`);
  }
  const result = { scope: scope.entries.map((entry) => entry.url), cases, defaults,
    headers: validateHeaders(input.headers), payloadIds: [...payloadIds] };
  if (input.storageState !== undefined) {
    result.storageState = resolve(baseDir, nonemptyString(input.storageState, 'storageState', 4096));
  }
  return result;
}

export async function loadConfig(file) {
  const absolute = resolve(file);
  let input;
  try { input = JSON.parse((await readFile(absolute, 'utf8')).replace(/^\uFEFF/u, '')); } catch (error) {
    throw new Error(`Cannot read config ${absolute}: ${error.message}`, { cause: error });
  }
  return validateConfig(input, dirname(absolute));
}
