# Corpus 2

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

- `10-apache-access.log`: Apache vhost_combined, ident, basic-auth, X-Forwarded-For
- `11-apache-error-php.log`: Apache error_log + PHP
- `12-iis-w3c.log`: IIS W3C extended (#Fields)
- `13-zeek-http.log`: Zeek http.log TSV
- `14-zeek-dns.log`: Zeek dns.log
- `15-suricata-eve.ndjson`: Suricata EVE
- `16-squid-access.log`: Squid native format
- `17-proxy-export.csv`: Proxy CSV export
- `18-vpn-sessions.csv`: VPN sessions CSV
- `19-cloudtrail.ndjson`: AWS CloudTrail
- `20-azure-signin.json`: Azure AD / Entra sign-in JSON
- `21-windows-events-xml.log`: Windows Security/Sysmon/PowerShell XML
- `22-cef-leef.log`: CEF and LEEF
- `23-linux-audit-auth.log`: auditd, sudo, su, PAM
- `24-mail-postfix-dovecot.log`: Postfix / Dovecot / SpamAssassin
- `25-email-message.eml`: Raw email with folded headers
- `26-sql-databases.log`: PostgreSQL + MySQL logged queries
- `27-docker-k8s.ndjson`: Docker json-file + Kubernetes audit
- `28-dns-servers.log`: BIND, dnsmasq, Windows DNS
- `29-panos-traffic.csv`: Palo Alto positional CSV
- `30-cisco-asa.log`: Cisco ASA messages
- `31-shell-history.log`: bash / PowerShell history
- `32-config-dump.log`: .env / YAML / Terraform dumps
- `33-crm-export.csv`: CRM semicolon CSV
- `34-java-stacktrace.log`: Multi-line Java stack traces
- `35-ldap-directory.ldif`: LDAP/AD LDIF
- `36-slack-export.ndjson`: Slack-like messaging export
- `37-network-syslog-misc.log`: RFC 5424 syslog, nginx error, Cisco IOS

Run: `npm run test:corpus:2` (all three: `npm run test:corpus`). Add `-- --verbose` to list the `D` cases.
Fake provider-format secrets are stored with `{{marker}}` prefixes, see `tests/README.md`.
