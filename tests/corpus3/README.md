# Corpus 3

Synthetic security logs for regression. All data is fictional.

## Categories

| Tag | Meaning |
|---|---|
| **R** | Replace: value must no longer appear on the line |
| **S** | Secret: replace with an opaque marker (never a reversible alias) |
| **K** | Keep: value must stay identical (false-positive trap) |
| **D** | Decision / known limit: see `docs/known-limits.md` |

## Automatic checks (`scripts/check-corpus.mjs`)

- Same line count; valid JSON for `.ndjson` / `.json`
- JSON skeleton: same keys and types (number may become `null`)
- Same tab count per line (Zeek / TSV); same CSV field count
- XML tag sequence unchanged when the filename contains `xml`
- Collateral: timestamps and log levels never destroyed
- Sentinel `-` never replaced; IPv4 alias collisions; `links.json` SAME/DIFF

## Files

- `40-logging-variants.log`: fractional times, varied levels, names in messages
- `41-vendor-messages.log`: ordinary words after user; vendor auth messages
- `42-k8s-resources.ndjson`: varied Kubernetes resources and verbs
- `43-panos-apps.csv`: PAN-OS app ids and hyphenated rule/zone names
- `44-commands-windows.log`: PowerShell cmdlets, passwords in args
- `45-tls-http.ndjson`: public cert issuers, hyphenated headers, Basic b64
- `46-email-greetings.eml`: given names alone in body vs full names in headers
- `47-filenames-paths.log`: person names in filenames, UNC, URL, S3
- `48-cloud-errors.ndjson`: long cloud error messages must survive
- `49-user-at-host.log`: user@host, -l, -u, URL credentials
- `50-labels.log`: varied labels: only the value disappears
- `51-bulk-scale.log`: 1200 lines: alias pool / collision stress
- `52-ipv6-lookalikes.log`: IPv6 lookalikes
- `53-unicode-turkish.log`: Turkish İ length-fold
- `54-unicode-turkish.ndjson`: Turkish İ in NDJSON
- `55-punctuation.log`: punctuation glued to values; secret cited elsewhere
- `56-common-word-secrets.log`: secrets that are common words/numbers
- `57-repeated-secrets.log`: repeated secrets in the log
- `58-empty-values.log`: empty password= fields
- `59-secrets-with-equals.log`: secrets containing =
- `60-empty-field-date.log`: date/time after an empty field
- `61-date-passwords.log`: password that is a date

Run: `npm run test:corpus:3` (all three: `npm run test:corpus`). Add `-- --verbose` to list the `D` cases.
Fake provider-format secrets are stored with `{{marker}}` prefixes, see `tests/README.md`.
