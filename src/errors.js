/** Playwright's verbose call log can contain authorization headers and bodies. */
export function formatError(error, sensitiveValues = []) {
  let message = String(error?.message ?? error).split(/\r?\nCall log:/i)[0]
    .replace(/\u001b\[[0-9;]*m/g, '');
  for (const value of sensitiveValues) {
    if (typeof value === 'string' && value.length >= 4) message = message.replaceAll(value, '[redacted]');
  }
  return message.slice(0, 1800);
}
