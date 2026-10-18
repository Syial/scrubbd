# Fixed decisions

| Topic | Choice |
|---|---|
| Product / repository name | **scrubbd** (from *scrubbed*) - UI, package, docs; **not** in code identifiers, CSS classes or i18n keys |
| UI title | "scrubbd" (i18n `appTitle`) |
| Language | Strict TypeScript |
| Build | Vite |
| UI | TypeScript, no framework |
| Tests | Vitest + Playwright (unit / regression / e2e) + corpora, all under `tests/` |
| Corpus docs | Short English `README.md` per corpus; open `D` cases in `docs/known-limits.md` |
| Licence | Apache-2.0 |
| Target hosting | Cloudflare Pages (`public/_headers` CSP) |
| Default IP alias | `preserveClass`: private → private, public/documentation → RFC 5737; `label` option gives `[IP-01]` |
| Non-IP alias style | Text identities as words (`personne-01`, `compte-01`, `email-01@…`); opaque literals as labels (`[TEL-01]`, `[ADR-01]`, `[SECRET]`) |
| Name ↔ email link | Not automatic; manual review (planned) |
| Language of the product | English default, French catalogue, i18n from the start; alias names stay French (`personne-01`, `compte-01`) |
| Language of the repository | English (code, comments, docs, tests, corpus notes); French only where it is data or UI copy |
