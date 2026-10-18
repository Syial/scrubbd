# Specification - scrubbd (100 % local log anonymiser)

> Project name: **scrubbd** (from *scrubbed*).
> Status: v0.1 draft of the specification, written before the code. Several points have since been settled
> (see `docs/decisions.md`): no UI framework, Apache-2.0, Cloudflare Pages, IP alias default, alias naming.
> Where this document and `docs/decisions.md` disagree, `docs/decisions.md` wins.
> Translated from the original French spec (`cahier des charges`).

---

## 1. Summary

A static site with no account, no cookie, no ads and no application server, that anonymises or pseudonymises **security logs** before they are shared (forum, vendor support, colleague, writeup). Everything happens in the browser: the file never leaves the computer.

The project does not sell itself on "it is local" (several tools already do that) but on **quality**: it understands the structure of logs, avoids false positives, keeps analytical value (consistent pseudonyms, IPs that keep their structure) and says exactly what it changed.

## 2. Context: what existing tools get wrong

A test on a single Wazuh JSON log file, with six comparable web tools. Findings:

- Phone numbers "found" in time zones (`+0000`).
- Birth dates "found" in plain dates.
- US postal codes and bank card numbers "found" **inside IP addresses**.
- Different results from one tool to the next, with different mistakes.
- Some tools give no summary of what was changed.
- Several sites add login, cookies, ads or commercial calls to action.

**Common cause:** regex detectors applied to raw text, with no understanding of structure, no priority between detectors, no validation.

## 3. Non-negotiable principles

1. **Zero network after the page has loaded.** No `fetch`, no external resource, no third-party call. Verifiable (Network tab, airplane mode) and tested automatically.
2. **Zero account, zero cookie, zero browser storage by default, zero analytics, zero ads.** No consent banner.
3. **Structure first, regex second.** Read the fields before guessing inside the text.
4. **Full transparency.** Every change is visible, counted and reversible before export.
5. **Honesty about limits.** The tool guarantees neither anonymity nor GDPR compliance. A manual review is always recommended.
6. **Few detectors, but precise ones.** Better to miss than to detect wrongly. Low-precision detectors are optional and off by default.
7. **Open source, auditable, no needless dependency.**

## 4. Target audience and use cases

- SOC analysts and students who publish a writeup or ask for help on a forum or Discord.
- Administrators who attach logs to a vendor support ticket.
- Anyone who has to share logs without exposing users, hosts, IPs or secrets.

Out of scope: bulk processing of terabytes (that is a server pipeline's job), certified regulatory compliance.

## 5. Scope

### 5.1 MVP (v0.1)

- Inputs: **JSON / JSONL** (including Wazuh `alerts.json` alerts) and **plain text** (`.log`, `.txt`, direct paste).
- Detectors: IPv4/IPv6, MAC, email, host and agent names, user names, Windows SIDs, secrets/tokens (very specific patterns), custom terms.
- **Consistent** pseudonymisation (same value → same alias, across the whole file).
- **Propagation**: a value found in a structured field is also replaced in free-text fields (`full_log`, messages).
- Preview with highlighting, table of replacements, "keep / replace" toggle per value.
- **Final check**: a second pass that looks for remaining original values in the output.
- Summary report (without the original values by default).
- Streaming processing in a Web Worker for large files.
- Downloadable single-file HTML version (offline use).

### 5.2 Explicitly out of scope

- No AI / language-model detection (readable, testable rules only).
- No server, account, synchronisation or link sharing.
- No PDF, images or OCR.
- No binary EVTX in v1 (export to JSON/XML first).
- No promise of GDPR compliance or of guaranteed irreversible anonymisation.

## 6. How it works

### 6.1 Pipeline

```
File ──► Format detection ──► PASS 1: analysis
                               ├─ traversal (JSON fields / lines)
                               ├─ detectors in priority order
                               ├─ validation
                               └─ build the mapping table
                                    │
        Preview + user choices ◄────┘  (keep / replace, custom terms)
                                    │
                               PASS 2: apply (re-read the file as a stream)
                                    │
                               CHECK: search for remaining original values
                                    │
                               Export: cleaned file + report
```

Two passes are mandatory: a value discovered late in the file must also replace its earlier occurrences. The file is re-read from disk (`File.stream()`), not kept in memory.

### 6.2 Detector priority order

Each text zone is assigned to **one** detector only (no overlap). Order:

1. **Field rules** (field name or JSON path): `srcip` is an IP, period.
2. **Value validators**: strictly parsed IP, MAC, SID, email.
3. **Specific secret patterns**: JWT, `Bearer …`, AWS keys (`AKIA…`), private key blocks, `password=`/`token=`/`secret=` pairs.
4. **Custom terms** from the user.
5. **Optional low-precision detectors** (off by default): phone, bank card (Luhn check **and** context), birth date.

A zone already identified (e.g. an IP) is never re-examined by a lower-ranked detector. This is what prevents "bank card inside an IP".

### 6.3 Rules by type

| Type | Detection | Default replacement | Notes |
|---|---|---|---|
| IPv4/IPv6 | Hand-written scanner + strict validation | Valid IP, structure preserved | Special addresses are never changed (see 6.4). Do not confuse with version numbers / OIDs (excluded by field name: `version`, `fileVersion`, etc.). |
| MAC | Scanner (6 octets, `:` `-` `.` separators) | Consistent fake MAC | Vendor OUI can optionally be kept. |
| Email | Scanner + validation | `user-01@domain-01.example` | Reserved domains (`.example`) to avoid collisions. |
| Host / agent | Known fields + dictionary + propagation | `host-01` | Public domains are untouched by default. |
| User | Known fields + paths `C:\Users\<name>\`, `/home/<name>/` + `DOMAIN\user` and `user@domain` forms | `user-01` | System accounts (`SYSTEM`, `root`, `LOCAL SERVICE`…) are kept. |
| SID | Pattern `S-1-5-21-…` | Consistent fake SID | "Well-known" SIDs (e.g. `S-1-5-18`) are kept. |
| Secrets/tokens | Specific patterns + key names | `[SECRET]` | **Never pseudonymised** (no mapping table). |
| Timestamps | ISO 8601 and syslog formats | Unchanged | Option: random global offset, gaps preserved. |
| File hashes | - | Kept | Analytical value (IOC), not personal. Option to mask. |

> Implementation note: the shipped alias names differ from this draft (`personne-01`, `compte-01`, `hote-01`,
> `email-01@…`, `[TEL-01]`…); see `docs/decisions.md`.

### 6.4 IP pseudonymisation

- **Special addresses never changed by default**: `0.0.0.0`, `127.0.0.0/8`, `255.255.255.255`, multicast, link-local (`169.254.0.0/16`, `fe80::/10`), `::1`.
- **Private ranges** (RFC 1918: `10/8`, `172.16/12`, `192.168/16`): the alias stays in the same private range (a private IP stays private).
- **"Structure preserved" mode** (default): deterministic HMAC-based transformation (WebCrypto) where two IPs sharing a prefix share the same prefix after transformation, Crypto-PAn style. To be documented: this mode **deliberately leaks subnet structure** and has known weaknesses if an attacker knows some mappings. An **unstructured random** mode is offered as an alternative.
- **"Documentation ranges" mode** (small files): aliases in `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) and `2001:db8::/32` (RFC 3849).
- **"Labels" mode**: `[IP-01]`.
- Random session key, in memory only. Option: passphrase to get the same aliases from one file to the next.

### 6.5 Propagation

When a value is identified in a structured field (e.g. `agent.name = "PC-DUPONT"`), all its occurrences in the rest of the document are replaced: free-text fields, `full_log`, paths, URLs. Take into account: case, Windows separators (`DOMAIN\user`), `user@domain` forms, compressed/expanded IPv6, URL encoding.

### 6.6 Final check

After applying, search the output for every original value (and its variants: case, IPv6, URL-encoded). Show "N original values found in the output" with their position. A warning, not a block: the user decides.

### 6.7 Report

- Summary by type (number of detections, number of unique values).
- Table original value → alias, **visible in the interface only**.
- Highlighted before/after preview.
- Report export **without the original values** by default.
- Mapping table export: explicit option, with a warning (the file contains the sensitive data).

## 7. Design and UX

### 7.1 Principles

- A single page for the tool, three visible steps: **Drop → Review → Download**.
- Light/dark theme following the system, system or self-hosted fonts.
- Sober tone. No modal, no banner, no popup, no account.
- A permanent line under the title: "No data leaves this page", with a link to "How to verify".
- French by default, texts externalised so English can follow.
- Accessibility: full keyboard navigation, sufficient contrast, visible focus, alternative text.

### 7.2 Main screen (sketch)

```
┌───────────────────────────────────────────────────────────┐
│ Short title                        No data is sent          │
├───────────────────────────────────────────────────────────┤
│ 1. Drop                                                   │
│    [ Drag a file ] or [ Paste text ]                      │
├───────────────────────────────────────────────────────────┤
│ 2. Review                                                 │
│    Summary: 124 IPs · 18 users · 6 hosts · 2 secrets      │
│    [Options] [My terms]                                   │
│    ┌─ Detected values ───────┐ ┌─ Before / after preview ┐│
│    │ ☑ 10.0.2.15 → 10.88.1.4 │ │ …highlighting…          ││
│    │ ☐ SYSTEM (kept)         │ │                         ││
│    └─────────────────────────┘ └─────────────────────────┘│
├───────────────────────────────────────────────────────────┤
│ 3. Download                                               │
│    ⚠ Check: 0 original values remaining                   │
│    [ Cleaned file ] [ Report ]                            │
└───────────────────────────────────────────────────────────┘
```

### 7.3 Pages

- **Home**: the tool.
- **How it works and limits**: how it works, what is not guaranteed, how to check that there is no network traffic.
- **Detection rules**: documentation generated automatically from the rule registry (transparency).
- **Contribute**: add a rule pack, report a false positive/negative.

## 8. Architecture and stack

### 8.1 Repository structure

```
/src
  /core        Pure TypeScript, no DOM: parsing, detectors, mapping, apply, check
  /rules       Rule packs (data + validators): generic, wazuh, syslog, web…
  /worker      Web Worker orchestration, streaming reads
  /ui          Interface
/tests
  /fixtures    Synthetic logs (never real data)
  /regression  One test per mistake observed in existing tools
/docs          Rule documentation, threat model
```

The core is independent of the interface: it can later power a Node CLI without a rewrite.

### 8.2 Proposed technical choices

| Area | Choice | Reason |
|---|---|---|
| Language | Strict TypeScript | Typed detection structures, easier contribution |
| Build | Vite | Fast; "single file" plugin for the offline version |
| UI | Svelte or Preact (or TS without a framework) | Small bundle; choose by familiarity |
| Unit tests | Vitest | Integrated with Vite |
| End-to-end tests | Playwright | Verify there are no network requests |
| Lint/format | ESLint + Prettier (or Biome) | Standard |
| Production dependencies | Ideally 0 or close | Smaller attack surface, trust |
| CI | GitHub Actions | Tests, build, publishing |

### 8.3 Performance and large files

- Reading: `File.stream()` + `TextDecoderStream`, line by line (JSONL) or by tokens.
- Processing in a **Web Worker** so the interface does not freeze.
- Two passes by re-reading the file, no full load into memory.
- Output: *File System Access* API (`showSaveFilePicker`) on Chromium; fallback by assembling `Blob`s elsewhere (more memory-hungry).
- Target to validate by measurement: smooth at ~100 MB; beyond that, "best effort", limit documented in the interface.
- Monolithic JSON (one big document) has to be loaded entirely: a limit to document, recommend JSONL.

### 8.4 Security of the tool itself

- **Logs = untrusted input** (they can contain XSS payloads). Render the preview **only through `textContent`**, never `innerHTML`.
- **ReDoS**: structured detectors (IP, MAC, SID, email) written as hand-written scanners, not regexes; remaining regexes without catastrophic backtracking patterns; analysed line length capped with a fallback; tests with adversarial strings.
- No `eval`, no external scripts, no CDN.
- Pseudonymisation key generated with `crypto.getRandomValues`, never persisted.

### 8.5 Hosting and CSP

- 100 % static site. Options: GitHub Pages (simple, **no custom HTTP headers** → CSP through a `<meta http-equiv>` tag, with a few unsupported directives) or Cloudflare Pages / Netlify (headers file). To be decided.
- Target CSP (to adjust to the Worker's needs):
  `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; worker-src 'self'; base-uri 'none'; form-action 'none'`
- Self-hosted fonts and scripts: no request to a third party.
- No `localStorage`, `sessionStorage` or cookie by default. Preferences and the personal dictionary can be exported/imported as a JSON file ("profile").
- To say honestly on the page: the host sees the page-load requests, not the content of the files.

## 9. Quality and tests

### 9.1 Regression tests from observed mistakes

| Case | Expected |
|---|---|
| `+0000` time zone in a timestamp | Never detected as a phone number |
| Plain date (`2025-01-02`) | Never detected as a birth date |
| IP `192.168.1.10` | Never split into a postal code or a card number |
| 16-digit run without a Luhn check | Never a card |
| Version number `10.0.19045.5555` | Never pseudonymised as an IP (excluded by field / context) |
| Plain text with no structure | A summary is still produced |

### 9.2 Other tests

- **Consistency**: same value → same alias, across the whole file and across files with the same passphrase.
- **Propagation**: a value found in `agent.name` is replaced in `full_log`.
- **Final check**: a deliberately mishandled file must trigger the warning.
- **No network request**: a Playwright test that fails if an outgoing request is made during processing.
- **ReDoS**: fuzzing with per-line time limits.
- **Fixtures**: synthetic logs written by hand or generated. **No real log in the repository.**

## 10. Trust and verifiability

- Public source code, clear licence.
- Reproducible build, "single HTML file" version published as a *release* with its SHA-256 hash.
- "How to verify" page: Network tab, airplane mode, offline via the downloaded file.
- Published threat model (see 12): what the tool protects, what it does not.

## 11. Milestones

| Milestone | Content | Exit criterion |
|---|---|---|
| **M0 - Foundations** | Repository, strict TypeScript, CI, core skeleton, fixtures, CSP and "zero network" test from the first commit | Green CI, network test in place |
| **M1 - Plain-text core** | IP/MAC/email scanners, mapping table, two passes, report | Regression tests (9.1) pass |
| **M2 - Wazuh JSON/JSONL** | Path-based traversal, field rules, propagation, list of fields to preserve | A real Wazuh export (from a lab, cleaned) processed with no known false positive |
| **M3 - Interface** | Three steps, preview, toggles, summary, download | Complete flow usable with the keyboard |
| **M4 - Large files and publishing** | Worker, streaming, single-file version, "limits" documentation | ~100 MB file processed without freezing; *release* + hash |
| **v0.2** | Exportable/importable personal dictionary, timestamp offset, IP modes | - |
| **v0.3** | Sysmon (XML), syslog, nginx/apache packs | - |
| **v1.0** | CLI on the same core, English interface | - |

MVP = M0 to M4.

## 12. Threat model (summary)

**Protects against:** accidental leak of obvious values (IPs, emails, names, secrets) when sharing logs.

**Does not protect against:**
- Information that can be inferred from context (working hours, internal software names, network structure).
- Re-identification by cross-referencing (the "structure preserved" mode deliberately leaks relations between IPs).
- Undetected data (free text, proper names in messages).
- Regulatory compliance: pseudonymised data generally remains personal data.

## 13. Risks and mitigations

| Risk | Mitigation |
|---|---|
| False negatives (leak) | Full preview, final check, personal dictionary, displayed limits |
| False positives | Priorities, validators, optional detectors off by default, regression tests |
| ReDoS / browser hang | Hand-written scanners, length cap, fuzzing |
| XSS through log content | `textContent` only, strict CSP |
| Memory on large files | Streaming, two passes, documented limits |
| Loss of trust ("what if it sent my data?") | Open source, automated zero-network test, offline version, CSP |
| Maintenance | Rules as data (packs), fixtures, one test per reported bug |
| Low visibility against well-ranked sites | "Security logs" positioning, presence in SOC communities, introductory writeup |

## 14. Open decisions

1. ~~**Project name**~~ → **scrubbd** (settled).
2. ~~**Licence**~~ → Apache-2.0 (settled; see `docs/decisions.md`).
3. ~~**UI framework**~~ → TypeScript without a framework (settled).
4. ~~**Hosting**~~ → Cloudflare Pages (settled).
5. ~~**Default IP alias style**~~ → `preserveClass` (settled).
6. ~~**Languages**~~ → French first, i18n catalogues from the start (settled).
7. **File size threshold** to guarantee (to be set after measurement).

## 15. Appendix - Wazuh fields (to validate against your real lab logs)

**To handle first (non-exhaustive list):**

- `agent.name`, `agent.ip`, `manager.name`, `predecoder.hostname`
- `data.srcip`, `data.dstip`, `data.srcuser`, `data.dstuser`
- `data.win.system.computer`
- `data.win.eventdata.*`: `ipAddress`, `targetUserName`, `subjectUserName`, `workstationName`, `user`, `commandLine`, `currentDirectory`, `parentCommandLine`
- `full_log` (propagation only)

**To preserve by default (analytical value):**

- `rule.*` (id, level, description, MITRE), `decoder.*`
- `timestamp`, `id`, `location`
- File hashes

## 16. MVP acceptance criteria

- [ ] No network request during or after processing (automated test).
- [ ] No cookie or browser storage by default.
- [ ] The 6 regression cases (9.1) pass.
- [ ] A lab Wazuh export (JSONL) is processed with correct propagation (`agent.name` also replaced in `full_log`).
- [ ] A summary is produced for JSON **and** plain text.
- [ ] The final check detects an original value deliberately left in.
- [ ] A file of about 100 MB is processed without freezing the interface.
- [ ] Complete flow usable with the keyboard alone.
- [ ] The "single HTML file" version works offline.
- [ ] The "How it works and limits" page exists and is honest about what is not guaranteed.
