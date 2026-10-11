# XSS in [feature / parameter]

**Affected URL:** [authorized URL]

**Type and execution origin:** [reflected / DOM / stored; effective origin]

**Account/role and prerequisites:** [test account role, authentication, necessary interaction]

## Reproduction

1. [Open the actual application flow.]
2. [Submit the exact harmless payload to the named parameter/field.]
3. [Visit the verification page or perform the required interaction.]
4. [Observe the unique marker executing in the affected origin.]

**Payload:** [copy the confirmed probe payload]

**Evidence:** [manual browser reproduction, relevant sanitized request/response excerpt, frame URL/origin and marker; attach only reviewed report excerpts]

## Impact

[Explain the demonstrated trust boundary: who controls the input, which authorized user encounters it, and what executes. Do not infer account compromise or assign severity solely from an alert.]

## Suggested remediation

[Apply context-appropriate output encoding, avoid unsafe DOM HTML insertion for plain text, or use a maintained HTML sanitizer where HTML is required. Mention CSP as an additional layer, if relevant to the demonstrated flow.]

**Cleanup:** [test data removed / remaining records and identifiers]

**Retest:** [date, exact cases rerun, execution no longer observed, application flow still functional]
