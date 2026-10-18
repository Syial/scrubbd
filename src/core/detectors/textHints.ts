import { foldCase } from "../fold";
import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";
import { isKeptHostname, normalizeHostnameKey } from "../hostIdentity";
import { normalizePersonNameKey } from "../personName";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";
import {
  isAccountStopword,
  isHostnameStopword,
  isPersonNameStopword,
  looksLikePersonNamePhrase,
} from "../stopwords";

/** High-precision free-text PII hints (titles, mail headers, DOB, geo, …). */
export function findTextHints(text: string): Finding[] {
  return [
    ...findTitledNames(text),
    ...findMailHeaderNames(text),
    ...findUnquotedMailNames(text),
    ...findMimeEncodedNames(text),
    ...findClientLabels(text),
    ...findHolderNames(text),
    ...findQuotedUser(text),
    ...findBareUserLogin(text),
    ...findOnHostname(text),
    ...findStreetAddresses(text),
    ...findBirthLabels(text),
    ...findLatLon(text),
    ...findBillingAddresses(text),
    ...findLdapCn(text),
    ...findEmbeddedJsonNames(text),
    ...findEmbeddedJsonAccounts(text),
    ...findMachineTokens(text),
    ...findProsePersonNames(text),
  ];
}

/** `PC-SOBRIEN` / `srv-lmoreau-test` / `fw-edge-01` machine-shaped tokens. */
function findMachineTokens(text: string): Finding[] {
  const out: Finding[] = [];
  // No WEB- prefix: `web-browsing` is a PAN-OS app, not a host.
  const re =
    /\b((?:PC|SRV|HOST|VM|DB|FW|LAPTOP|DESKTOP)[-_][A-Za-z0-9][-A-Za-z0-9.]{1,48})\b/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    if (isKeptHostname(value) || isHostnameStopword(value)) continue;
    // Env var names: `DB_PASSWORD`, `DB_HOST` - not hostnames.
    if (value === value.toUpperCase() && value.includes("_")) continue;
    // Require a digit or hyphenated hostname shape (srv-web01, PC-SOBRIEN).
    if (!/\d/.test(value) && !/-/.test(value)) continue;
    out.push({
      kind: "hostname",
      value,
      key: normalizeHostnameKey(value),
      span: { start: m.index, end: m.index + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** Free-text person names after speech cues. */
function findProsePersonNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /\b(?:appeler|dossier\s+de|chez|pour|for|voir|contacter|demande[rm]?|bonjour|bonsoir|salut|hello|hi|cher|chère|madame|monsieur)[ \t]+([A-ZÀ-ÖØ-Ý][\p{L}'’-]*(?:[ \t]+[A-ZÀ-ÖØ-Ý][\p{L}'’-]*){0,3})/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!.trim();
    if (value.length < MIN_IDENTITY_LENGTH) continue;
    if (value.includes("\n")) continue;
    if (isPersonNameStopword(value)) continue;
    // Single token after Bonjour/Hello is OK (Léa, Nadia); skip technical CamelCase.
    if (isTechnicalToken(value.split(/\s+/)[0]!)) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  // Login after `for` / `opened for`: `for nadia.rousseau` / `for ines.carvalho`
  // Require a dot or underscore - a lone hyphen matches polkit `unix-session`.
  const reLogin =
    /\b(?:for|opened\s+for)\s+([a-z][a-z0-9._+-]{2,64})\b/g;
  while ((m = reLogin.exec(text)) !== null) {
    const value = m[1]!;
    if (isAccountStopword(value) || !isRedactableAccount(value)) continue;
    if (!/[._]/.test(value)) continue;
    if (/(?:^|-)session(?:-|$)/i.test(value)) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "account",
      value,
      key: value.toLowerCase(),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  // Also: standalone Proper-Case pairs with apostrophe/accent (Siobhán O'Brien).
  const re2 =
    /\b([A-ZÀ-ÖØ-Ý][\p{L}'’-]*[ \t]+[A-ZÀ-ÖØ-Ý][\p{L}'’-]*)\b/gu;
  while ((m = re2.exec(text)) !== null) {
    const value = m[1]!.trim();
    if (isPersonNameStopword(value)) continue;
    if (!/[àâäéèêëïîôùûüçáíóúń''']|O'/i.test(value) && !value.includes("-")) {
      // Require a cue of non-ASCII or hyphenated surname, else too noisy.
      if (!/[^\u0000-\u007f]/.test(value)) continue;
    }
    // Both tokens must look like name parts (rejects "Bonjour Léa", "Let's Encrypt").
    const parts = value.split(/\s+/);
    if (parts.length < 2) continue;
    if (parts.some((p) => isPersonNameStopword(p) || isTechnicalToken(p))) continue;
    const start = m.index;
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** CamelCase / API tokens: ComputerName, ScriptBlock, DisplayMessage… */
function isTechnicalToken(token: string): boolean {
  if (/^[A-Z][a-z]+[A-Z]/.test(token)) return true;
  if (/^(PC|SRV|HOST|VM|DB|FW)-/i.test(token)) return true;
  return false;
}

/** `CN=Mehdi El Amrani,OU=…` - replace CN value only (person names, not groups). */
function findLdapCn(text: string): Finding[] {
  const out: Finding[] = [];
  // Stop at DN separators AND JSON/string delimiters - never cross `"`, `}`, or EOL
  // (a CA CN without a following comma used to swallow the next NDJSON line).
  const re = /\bCN=([^,"}\n\r]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!.trim();
    // Groups like Comptabilite-RW have no space - leave them.
    if (value.length < MIN_IDENTITY_LENGTH || !/\s/.test(value)) continue;
    if (/^(Users|Computers|Builtin|Group)/i.test(value)) continue;
    // Public CA / TLS issuer CNs are not people.
    if (isTlsAuthorityCn(value)) continue;
    // Hostnames / wildcards in CN= (`*.acmecorp.fr`, `login.live.com`).
    if (value.includes("*") || value.includes(".") || /\d/.test(value)) continue;
    if (!looksLikePersonNamePhrase(value)) continue;
    const start = m.index + 3; // after CN=
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

function isTlsAuthorityCn(value: string): boolean {
  if (
    /DigiCert|GlobalSign|Microsoft|Let's Encrypt|ISRG|Amazon|GeoTrust|Sectigo|Comodo|GoDaddy|Verisign|Entrust|IdenTrust/i.test(
      value,
    )
  ) {
    return true;
  }
  // `… TLS … CA …`, `Issuing CA 03`, etc.
  if (/\b(?:TLS|SSL|RSA|SHA\d*|DV|OV|EV|CA)\b/i.test(value)) return true;
  return false;
}

function findTitledNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\b(?:Mme|M\.|Dr|Mr|Mrs|Ms)\s+([A-ZÀ-ÖØ-Ý][\p{L}'’-]*(?:\s+[A-ZÀ-ÖØ-Ý][\p{L}'’-]*){0,3})/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!.trim();
    if (value.length < MIN_IDENTITY_LENGTH) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** `From: "Élodie Fontaine" <efontaine@…>` */
function findMailHeaderNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /"([^"\n]{2,80})"\s*<[^>@\s]+@[^>]+>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!.trim();
    if (!/[A-Za-zÀ-ÖØ-öø-ÿ]/.test(value)) continue;
    const start = m.index + 1; // inside quotes
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** `Client: Rose Fontaine` / `par Pierre Martin` */
function findClientLabels(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /\b(?:Client|client|par|Par)\s*:\s*([A-ZÀ-ÖØ-Ý][\p{L}'’-]*(?:\s+[A-ZÀ-ÖØ-Ý][\p{L}'’-]*){0,3})|\bpar\s+([A-ZÀ-ÖØ-Ý][\p{L}'’-]*(?:\s+[A-ZÀ-ÖØ-Ý][\p{L}'’-]*){0,2})(?=\s*[\(,])/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = (m[1] ?? m[2] ?? "").trim();
    if (value.length < MIN_IDENTITY_LENGTH) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** `Mehdi El Amrani <mail@…>` - display name without quotes. */
function findUnquotedMailNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /(?:^|[\s,])([A-ZÀ-ÖØ-Ý][\p{L}'’-]*(?:\s+[A-ZÀ-ÖØ-Ý][\p{L}'’-]*){1,3})\s*<[^>@\s]+@[^>]+>/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!.trim();
    if (value.length < MIN_IDENTITY_LENGTH) continue;
    const start = m.index + m[0]!.indexOf(value);
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** `=?UTF-8?Q?L=C3=A9a_Moreau?=` - MIME encoded-word display names. */
function findMimeEncodedNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /=\?UTF-8\?[Qq]\?([^?]+)\?=/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const encoded = m[1]!;
    // Only treat as a person name when it looks like Name_Name / has =C3= accents.
    if (!/[A-Za-z]/.test(encoded) || (!encoded.includes("_") && !encoded.includes("="))) {
      continue;
    }
    const decoded = decodeMimeQ(encoded);
    const start = m.index + m[0]!.indexOf(encoded);
    out.push({
      kind: "person_name",
      value: encoded,
      key: normalizePersonNameKey(decoded),
      span: { start, end: start + encoded.length },
      decision: "replace",
    });
  }
  return out;
}

/** Q-encoding: `L=C3=A9a_Moreau` → `Léa Moreau`. */
function decodeMimeQ(encoded: string): string {
  const spaced = encoded.replace(/_/g, " ");
  try {
    // Percent-decode after turning =HH into %HH (UTF-8 sequences).
    return decodeURIComponent(spaced.replace(/=([0-9A-Fa-f]{2})/g, "%$1"));
  } catch {
    return spaced.replace(/=([0-9A-Fa-f]{2})/g, (_, h: string) =>
      String.fromCharCode(parseInt(h, 16)),
    );
  }
}

/** `holder Hugo Petit` / `for holder Alice Martin` */
function findHolderNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /\b(?:holder|titulaire|bénéficiaire|client)\s+([A-ZÀ-ÖØ-Ý][\p{L}'’-]*(?:\s+[A-ZÀ-ÖØ-Ý][\p{L}'’-]*){1,3})/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!.trim();
    if (value.length < MIN_IDENTITY_LENGTH) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** `user jb.delafontaine` / `Password for user X` - bare login after user. */
function findBareUserLogin(text: string): Finding[] {
  const out: Finding[] = [];
  // Lowercase keyword only - avoid `Login failed` / `User-Agent`.
  const re =
    /(?:^|[^A-Za-z])(?:user|utilisateur)\s+([A-Za-z][A-Za-z0-9._+-]{1,64})\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    if (/^(name|id|agent|agent_id|agentname)$/i.test(value)) continue;
    if (isAccountStopword(value)) continue;
    if (!isRedactableAccount(value)) continue;
    // Prefer login-shaped tokens (dot/underscore/hyphen) or lowercase.
    if (
      !/[._-]/.test(value) &&
      value === value.toUpperCase()
    ) {
      continue;
    }
    if (/^[A-Z]/.test(value) && !/[._-]/.test(value)) continue;
    // Bare English words after "user " (AAA user authentication) - skip
    // unless the token looks like a login (has . _ - or a digit) OR is
    // clearly a lowercase username (`icarvalho`, `yhaddad`).
    if (!/[._\d-]/.test(value) && value !== value.toLowerCase()) continue;
    if (
      !/[._\d-]/.test(value) &&
      value === value.toLowerCase() &&
      value.length < 5
    ) {
      continue;
    }
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "account",
      value,
      key: value.toLowerCase(),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** `on srv-web01 with PID` - only host-shaped tokens (digit or hyphen). */
function findOnHostname(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\bon\s+([A-Za-z0-9][A-Za-z0-9._-]{1,63})\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    if (
      /^(the|a|an|line|port|host|windows|linux|java|pid|exit|error|info|debug|interface|device)$/i.test(
        value,
      )
    ) {
      continue;
    }
    // Require hostname shape: contains a digit or a hyphen (srv-web01, pc-lmoreau).
    if (!/\d/.test(value) && !value.includes("-")) continue;
    if (value.length < MIN_IDENTITY_LENGTH || isKeptHostname(value)) continue;
    if (isHostnameStopword(value)) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "hostname",
      value,
      key: normalizeHostnameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** French-style street addresses in free text. */
function findStreetAddresses(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /\b(\d{1,4}\s+(?:rue|avenue|av\.?|bd|boulevard|impasse|place|chemin|allée|allee|quai|cours)\s+[^,;\n]{3,40},\s*\d{5}\s+[A-ZÀ-ÖØ-Ý][\p{L}'-]*)/giu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!.trim();
    const start = m.index;
    out.push({
      kind: "address",
      value,
      key: value.toLowerCase(),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** Embedded JSON fragments: `"firstName":"Zoë"` */
function findEmbeddedJsonNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /"(firstName|lastName|givenName|familyName|displayName|real_name|full_name)"\s*:\s*"([^"\\]{2,80})"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[2]!;
    const start = m.index + m[0]!.lastIndexOf(`"${value}"`) + 1;
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** Account fields inside embedded JSON in mixed/text blobs. */
function findEmbeddedJsonAccounts(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /"(username|user_name|userName|user|login|account|sAMAccountName|samaccountname|uid)"\s*:\s*"([^"\\]{2,64})"/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[2]!;
    if (isSentinelValue(value) || isAccountStopword(value)) continue;
    if (!isRedactableAccount(value)) continue;
    const start = m.index + m[0]!.lastIndexOf(`"${value}"`) + 1;
    out.push({
      kind: "account",
      value,
      key: value.toLowerCase(),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** `utilisateur 'camille.rousseau'` / `user "x"` */
function findQuotedUser(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /\b(?:utilisateur|username|user|login|account)\s+['"]([A-Za-z0-9._+-]{2,64})['"]/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    if (!isRedactableAccount(value)) continue;
    const start = m.index + m[0]!.indexOf(value);
    out.push({
      kind: "account",
      value,
      key: value.toLowerCase(),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

function findBirthLabels(text: string): Finding[] {
  const out: Finding[] = [];
  const patterns: RegExp[] = [
    /\b(?:né(?:e)?\s+le|date\s+de\s+naissance|birth(?:date|_date)?|dob)\s*[:=]?\s*(\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4})/gi,
    /\b(?:né(?:e)?\s+le|date\s+de\s+naissance|birth(?:date|_date)?|dob)\s*[:=]?\s*(\d{4}-\d{2}-\d{2})/gi,
    /\b(?:né(?:e)?\s+le|date\s+de\s+naissance|birth(?:date|_date)?|dob)\s*[:=]?\s*(\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})/gi,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const value = m[1]!;
      const start = m.index + m[0]!.lastIndexOf(value);
      out.push({
        kind: "birth_date",
        value,
        key: value,
        span: { start, end: start + value.length },
        decision: "replace",
      });
    }
  }
  return out;
}

function findLatLon(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\b(?:lat|latitude)\s*=\s*(-?\d+(?:\.\d+)?)(?:\s*[&,;]\s*|\s+)(?:lon|lng|longitude)\s*=\s*(-?\d+(?:\.\d+)?)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const full = m[0]!;
    // Replace each numeric token inside the match.
    const lat = m[1]!;
    const lon = m[2]!;
    const latAt = full.toLowerCase().indexOf(lat);
    const lonAt = full.toLowerCase().lastIndexOf(lon);
    if (latAt >= 0) {
      out.push({
        kind: "geo",
        value: lat,
        key: `lat:${lat}`,
        span: { start: m.index + latAt, end: m.index + latAt + lat.length },
        decision: "replace",
      });
    }
    if (lonAt >= 0) {
      out.push({
        kind: "geo",
        value: lon,
        key: `lon:${lon}`,
        span: { start: m.index + lonAt, end: m.index + lonAt + lon.length },
        decision: "replace",
      });
    }
  }
  return out;
}

/** Billing address label: span until | or ;. */
function findBillingAddresses(text: string): Finding[] {
  const out: Finding[] = [];
  const lower = foldCase(text);
  // Only explicit billing labels - bare `Address:` matches Windows Event Log
  // (`Source Network Address:`) and would swallow the rest of a JSON line.
  const labels = ["adresse de facturation:", "billing address:"];
  for (const label of labels) {
    let from = 0;
    while (from < text.length) {
      const idx = lower.indexOf(label, from);
      if (idx === -1) break;
      let i = idx + label.length;
      while (i < text.length && text.charCodeAt(i) === 32) i += 1;
      const start = i;
      // Read to `;` or EOL (not `|`) so `A | B | C` yields three addresses.
      while (
        i < text.length &&
        text.charCodeAt(i) !== 59 /* ; */ &&
        text.charCodeAt(i) !== 10 &&
        text.charCodeAt(i) !== 13
      ) {
        i += 1;
      }
      const chunk = text.slice(start, i);
      let segStart = start;
      for (const part of chunk.split("|")) {
        const trimmed = part.trim();
        if (trimmed.length >= 8 && /\d/.test(trimmed) && /[A-Za-zÀ-ÿ]/.test(trimmed)) {
          const local = part.indexOf(trimmed);
          const abs = segStart + local;
          out.push({
            kind: "address",
            value: trimmed,
            key: trimmed.toLowerCase(),
            span: { start: abs, end: abs + trimmed.length },
            decision: "replace",
          });
        }
        segStart += part.length + 1; // +1 for |
      }
      from = i + 1;
    }
  }
  return out;
}

void isSentinelValue;
