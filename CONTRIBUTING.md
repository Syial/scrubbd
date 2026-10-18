# Contributing

Thanks for helping. The most useful contribution is a **detection case**: a value scrubbd misses, wrongly replaces, or aliases inconsistently.

## Before you start

- Never include real data (logs, names, IPs, tokens) in an issue, a PR or a test. Use invented lookalikes of the same shape.
- Vulnerabilities in the tool itself (data leaving the page, XSS, CSP) are reported privately: see `SECURITY.md`.
- Code, comments, tests and docs are in English. The UI defaults to English (`src/i18n/en.ts`); French is kept for a future language switch.

## Setup

```bash
npm ci
npm run check        # type-check + unit/regression tests
npm run test:corpus  # the three log corpora
npm run test:e2e     # Playwright (zero network after page load)
```

CI runs all three on every push and pull request.

## Add a corpus case

Corpora live in `tests/corpus*/` (see `tests/README.md` and each corpus `README.md`).

1. Add the line(s) to a log file, **at the end of the file**: expectations point at `file` + `line`, so inserting in the middle shifts every later entry. The redacted output must keep the same number of lines.
2. Add one entry per value to `expectations.json`: `{ "file", "line", "text", "cat", "note" }`, with `cat` one of `R` (must be replaced), `S` (secret: replaced by a marker), `K` (must stay identical, a false-positive trap) or `D` (no single right answer).
3. For "same entity, same alias" cases, add an entry to `links.json`.
4. A provider-shaped fake secret never goes in clear: write `{{ghp}}` instead of `ghp_`, etc. (table in `scripts/corpus-secrets.mjs`).
5. Run `npm run test:corpus`. For a new `D` case, also add a row to `docs/known-limits.md`.

## Change a detector

Detectors live in `src/core/detectors/` and are wired in `src/core/pipeline.ts`. Fix the bug, add a regression test in `tests/unit/regression/`, and make sure `npm run check` and `npm run test:corpus` stay green. A change that fixes a miss must not introduce a false positive in a `K` case: the corpora are there to catch exactly that.

Keep to the project principles (`README.md`): structure before regex, few precise detectors, honest about limits.
