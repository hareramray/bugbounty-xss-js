/** Parse only unambiguous, absolute HTTP(S) URLs without embedded credentials. */
export function parseHttpUrl(value, label = 'URL') {
  if (typeof value !== 'string' || !value || value !== value.trim()) {
    throw new TypeError(`${label} must be a nonempty absolute HTTP(S) URL`);
  }
  if (/[\\\u0000-\u0020\u007f]/u.test(value) || !/^https?:\/\//iu.test(value)) {
    throw new TypeError(`${label} must be an absolute HTTP(S) URL without whitespace`);
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${label} is not a valid URL`);
  }
  const authority = value.slice(value.indexOf('://') + 3).split(/[/?#]/u)[0];
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname ||
      url.username || url.password || authority.includes('@') || authority.includes('\\')) {
    throw new TypeError(`${label} must use HTTP(S) and must not contain credentials`);
  }
  pathSegments(url, label);
  return url;
}

function pathSegments(url, label = 'URL') {
  const parts = url.pathname.split('/').slice(1);
  if (parts.at(-1) === '') parts.pop();
  return parts.map((part) => {
    let decoded;
    try {
      decoded = decodeURIComponent(part);
    } catch {
      throw new TypeError(`${label} contains an invalid percent-encoded path`);
    }
    // Reject ambiguous separators/traversal instead of guessing how a server decodes them.
    if (/[\\/\u0000-\u001f\u007f]/u.test(decoded) || decoded === '.' || decoded === '..' ||
        /%(?:2e|2f|5c|25)/iu.test(decoded)) {
      throw new TypeError(`${label} contains an ambiguous encoded path`);
    }
    return decoded;
  });
}

/** Exact origin plus a decoded path-segment prefix, never a hostname/string prefix. */
export class Scope {
  constructor(entries) {
    if (!Array.isArray(entries) || entries.length === 0) {
      throw new TypeError('scope must contain at least one absolute HTTP(S) URL prefix');
    }
    this.entries = entries.map((entry, index) => {
      const url = parseHttpUrl(entry, `scope[${index}]`);
      if (url.search || url.hash) {
        throw new TypeError(`scope[${index}] must not contain a query string or fragment`);
      }
      return { origin: url.origin, segments: pathSegments(url), url: url.href };
    });
  }

  allows(value) {
    try {
      const url = parseHttpUrl(value);
      const segments = pathSegments(url);
      return this.entries.some((entry) => entry.origin === url.origin &&
        entry.segments.length <= segments.length &&
        entry.segments.every((segment, index) => segment === segments[index]));
    } catch {
      return false;
    }
  }

  assert(value) {
    if (!this.allows(value)) throw new Error(`URL is outside the configured scope: ${value}`);
    return value;
  }
}
