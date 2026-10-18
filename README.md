# scrubbd

Local-first security log redactor. Pseudonymises logs **in the browser** - no accounts, no cookies by default, no analytics, no server-side processing.

Keep code identifiers neutral (`redact`, `analyze`, `mapping`, `finding`) - brand only in UI copy, package name, and docs. UI is **English only for now** (a French catalogue is prepared for a later language switch). Code, comments, tests and docs are in English.

> Status: **v0.1, work in progress.** The analysis pipeline and the page work; see "Known limits" below for what is not done yet.

## What it does

Paste or drop a log (plain text, JSON/NDJSON, CSV, CEF/LEEF, syslog, Windows XML, ...). scrubbd detects personal data and secrets (IPs, emails, accounts, hostnames, person names, phones, cards, tokens and passwords, ...), lets you keep or replace each value, then produces a cleaned file and a report. Replacements are consistent: the same value gets the same alias everywhere in the file. Secrets are replaced by `[SECRET]`, never by a reversible alias. A final pass looks for original values left in the output.

## Stack

- TypeScript (strict) + Vite
- UI without framework
- Vitest + Playwright
- Apache-2.0
- Cloudflare Pages headers (`public/_headers`) for CSP

## Develop

```bash
npm install
npm run dev
npm run check          # type-check + unit/regression tests
npm run test:corpus    # the three log corpora (tests/corpus*)
npm run test:e2e       # Playwright: no network request after page load
```

## Layout

```
src/core        detection, mapping, apply and verify pipeline (no DOM)
src/rules       field-name classification rules
src/ui          page and event handling
src/i18n        UI copy (English default + French)
src/worker      reserved for the Web Worker (not implemented yet)
tests           unit, regression, e2e and log corpora (see tests/README.md)
docs            decisions, specification, known limits
```

## Principles

1. Zero network after page load
2. Structure before regex
3. Few precise detectors; low-precision ones opt-in
4. Transparent replacements; honest about limits

## Known limits

scrubbd pseudonymises obvious values; it does not guarantee anonymity or GDPR compliance, and a manual review before sharing is always needed. Main open points:

- Analysis runs on the main thread (roughly 0.5-2 s per MB depending on the content), so large inputs freeze the page until the Web Worker lands.
- Bare tokens in free text are only caught for a few formats (GitHub, AWS access key id, JWT, ...); Slack, GitLab, Google, npm, OpenAI keys and AWS secret keys are missed unless they follow a `key=` / `password:` style label. No national ID number detector yet.
- Re-running on an already pseudonymised log can alias the aliases.
- Very deeply nested JSON (thousands of levels) can overflow the stack.
- Names with no contextual cue (free text, URL paths, file names) are only partly detected.

The per-case list of open decisions lives in `docs/known-limits.md`. Fixed product choices are in `docs/decisions.md`; the original specification is `docs/specification.md`.

Contributing: see `CONTRIBUTING.md`; security reports: see `SECURITY.md`.
