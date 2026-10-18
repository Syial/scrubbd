# Security policy

scrubbd is a **local-first** tool: logs are processed in the browser and never sent anywhere. This is the property that matters most, so reports about it get priority.

## Which channel?

**Detection problems → open a normal public issue.** A value that was not detected, a false positive, a wrong or inconsistent alias, a line that gets mangled: these are the everyday bugs of this project and a public issue helps everyone. Use the "Detection problem" template and follow its rules:

- **Never paste a real log.** Reduce the input to the smallest line(s) that reproduce the problem.
- Replace every identifying value with a lookalike of the same shape (same format, length and separators): `jean.dupont` → `anna.martin`, `185.199.108.153` → `203.0.113.7`, a real token → a made-up one with the same prefix. This includes values the tool did **not** flag: the output you are looking at is exactly what may still contain something.
- If you pasted something real by mistake, tell the maintainer right away so the issue can be deleted. Editing is not enough: GitHub keeps the edit history visible.

**Vulnerabilities in the tool itself → report privately**, using the repository's **Security** tab → **Report a vulnerability** (GitHub private vulnerability reporting). No email needed. Do not open a public issue for these:

- anything that makes data leave the page (network request, beacon, storage, telemetry, third-party resource);
- script injection through log content (XSS in the preview or the report), or a weakened CSP;
- a compromised dependency, build step or release artifact;
- an input that crashes or freezes the page in a way that looks exploitable (ReDoS, memory blow-up).

If you are not sure which side your report falls on, use the private channel; it can be made public afterwards.

## Supported versions

Pre-1.0: fixes ship on the latest `main` only. You should get an acknowledgement within a few days.

## Scope notes

- A successful redaction is **not** a guarantee of anonymity or GDPR compliance; human review is required before sharing logs. See "Known limits" in the README.
- Invented tokens and PII in `tests/corpus*` are fixtures, not real credentials. Secret scanners may still flag lookalikes: see `tests/README.md` for the `{{marker}}` convention.
