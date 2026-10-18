# Tests

All automated checks live under `tests/`.

| Folder | What | Run |
|---|---|---|
| `unit/core/`, `unit/regression/`, `unit/rules/` | Vitest unit and regression tests | `npm test` |
| `e2e/` | Playwright: no network request after page load | `npm run test:e2e` |
| `fixtures/` | Small synthetic inputs used by the unit tests | - |
| `corpus/`, `corpus2/`, `corpus3/` | Synthetic log corpora with line-level expectations | `npm run test:corpus` |

All data is fictional. No real log belongs in this repository.

## Corpora

Each corpus holds log files, an `expectations.json` (one entry per value: file, line, text, category `R`/`S`/`K`/`D`, short note), an optional `links.json` (same entity ⇒ same alias), and a short `README.md`. See each README for the legend and the file index. Cases tagged `D` have no single right answer and are listed in `docs/known-limits.md`.

Shared checker: `scripts/check-corpus.mjs` (used by all three corpora).

```bash
npm run test:corpus          # redact + check corpora 1, 2, and 3
npm run test:corpus:1        # corpus 1 only
npm run test:corpus:redact   # redact only (defaults: tests/corpus → tmp/corpus-out)
npm run test:corpus:check    # check corpus 1 with --verbose
```

## Fake secrets and `{{marker}}`

Secret scanners (GitHub push protection, gitleaks, ...) flag strings shaped like real provider tokens even when they are invented. So corpus files never contain those prefixes in clear: `ghp_` is stored as `{{ghp}}`, `AKIA` as `{{AKIA}}`, `PRIVATE KEY` in a key header as `{{PRIVATE_KEY}}`, and so on. The full table is `scripts/corpus-secrets.mjs`.

`scripts/redact-corpus.ts` and `scripts/check-corpus.mjs` call `expandSecrets()` when they read a corpus file, `expectations.json` or `links.json`, so the redactor and the checker always work on the real strings.

When you add a case with a provider-shaped secret: write `{{ghp}}` instead of `ghp_` (or add a new prefix to `scripts/corpus-secrets.mjs`) and keep the rest of the token as is. Do not use the literal `{{` for anything else in a corpus file.
