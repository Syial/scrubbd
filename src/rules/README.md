# Rule packs

- `fieldRules.ts`: table-driven field classification (normalize → path rules → leaf rules)
- Verdicts: `detect` | `ambiguous` | `protected`
- Phone / address / geo / secrets / IDs are primarily field-driven
- Packs to come: `wazuh`, `syslog`, …

Keep identifiers descriptive and brand-neutral (`redact`, `analyze`, `finding`).
