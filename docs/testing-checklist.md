# XSS testing checklist

Record the program, authorized origins/paths, account role, permitted request rate and tested date with your results. Create one case per input/endpoint combination. Run the local lab first to establish expected positive and negative results.

| Area | What to test | Evidence to collect |
| --- | --- | --- |
| Reflected query | Search, filters, preview text and error pages explicitly allowed by the program | Injected parameter, final browser URL, raw vs encoded response excerpt, exact execution marker |
| HTML text | Untrusted data inserted as markup | Executing element or script and affected page |
| HTML attributes | Double/single-quoted values and attribute boundaries | Surrounding response context and browser execution |
| JavaScript strings | Input included in inline strings or templates | Script context, syntax behavior, browser execution |
| DOM inputs | Query/hash used by client-side code | Actual source and sink; fragment execution can occur with no HTTP reflection |
| Form fields | Real form with hidden fields, CSRF and normal submission | Field selector, required interaction and resulting page |
| JSON endpoints | Response reflected as data vs consumed by a page | Real frontend flow that renders the response; JSON reflection alone is insufficient |
| Stored data | Test-account profile, draft or other permitted record | Submission and independent read-back pages, storage lifetime and cleanup |
| Permissions | Whether another authorized test account can encounter the data | A reproducible authorized two-account workflow; distinguish self-XSS |
| Controls | Escaped output, textContent and enforced CSP | No execution under the same conditions; CSP report-only is not enforcement |
| Timing | Deferred rendering, tabs and user-triggered actions | Exact steps and observation duration; increase settleMs only where needed |

For every candidate:

1. Inspect the actual input/output context. Do not classify a marker reflection as XSS.
2. Reproduce execution in an ordinary browser using the same account and application flow, with developer-console injection unnecessary.
3. Check whether execution occurs in the application origin rather than a sandboxed/opaque frame.
4. Review blocked requests, failed navigation, CSP and authentication failures. Repair the case configuration before treating missing evidence as a negative result.
5. Determine who can submit the input and who encounters it. Keep the demonstration to a harmless execution marker.
6. Remove test records when finished. Do not test unsuspecting accounts or submit blind payloads to operational inboxes without program authorization.
7. Deduplicate payload observations into the underlying input/sink issue and prepare a concise report.

Additional manual coverage may be needed for path/header/cookie inputs, message-event origin checks, client storage, rich text, file metadata, dynamic selectors, multi-step workflows and browser differences. These are not automatically covered by this toolkit.
