# Corpus 1

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

- `01-nginx-access.log`: nginx combined format
- `02-auth-syslog.log`: syslog: sshd, sudo, UFW
- `03-wazuh-windows.ndjson`: Wazuh / Windows NDJSON
- `04-app-pii.log`: application free text
- `05-firewall-kv.log`: firewall key=value
- `06-edge-cases.log`: edge cases
- `07-stress.log`: performance / ReDoS

Run: `npm run test:corpus:1` (all three: `npm run test:corpus`). Add `-- --verbose` to list the `D` cases.
Fake provider-format secrets are stored with `{{marker}}` prefixes, see `tests/README.md`.
