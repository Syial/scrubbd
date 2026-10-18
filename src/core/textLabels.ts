/** Extract key:value / key=value pairs from plain text logs. */

import { isBareDateOrTime, isBorrowedFieldValue } from "./secretValueGuards";

export interface TextLabel {
  fieldName: string;
  value: string;
  span: { start: number; end: number };
}

const LOG_LEVELS = new Set([
  "info",
  "warn",
  "warning",
  "error",
  "debug",
  "trace",
  "fatal",
  "notice",
]);

/** Labeled values and `user Jean Dupont (` speech patterns. */
export function findLabeledValues(text: string): TextLabel[] {
  const labels: TextLabel[] = [];
  const length = text.length;
  let i = 0;

  while (i < length) {
    if (!isIdentStart(text.charCodeAt(i))) {
      i += 1;
      continue;
    }
    if (i > 0 && isIdentContinue(text.charCodeAt(i - 1))) {
      i += 1;
      continue;
    }

    const keyStart = i;
    i = readIdent(text, i);
    const fieldName = text.slice(keyStart, i);
    const afterKey = i;

    // `/user:DOMAIN\u` is a CLI flag, not a labeled field.
    if (keyStart > 0 && text.charCodeAt(keyStart - 1) === 47 /* / */) {
      continue;
    }

    if (LOG_LEVELS.has(fieldName.toLowerCase())) {
      continue;
    }

    if (fieldName.toLowerCase() === "user") {
      const speech = readUserSpeechName(text, afterKey);
      if (speech) {
        labels.push({
          fieldName: "user",
          value: speech.value,
          span: speech.span,
        });
        i = speech.span.end;
        continue;
      }
    }

    i = skipSpaces(text, afterKey);
    const sep = text.charCodeAt(i);
    if (sep !== 58 /* : */ && sep !== 61 /* = */) {
      i = afterKey;
      continue;
    }
    i += 1;
    const afterSep = i;
    i = skipSpaces(text, i);
    const skippedSpaces = i > afterSep;
    if (i >= length) break;

    const parsed = readLabeledValue(text, i, fieldName, sep);
    if (parsed) {
      // Empty `token= status=200` / `normal: user=camille` - resume on the
      // nested field. Glued secrets (`secret=key=value123`) keep the value.
      if (skippedSpaces && isBorrowedFieldValue(parsed.value)) {
        i = parsed.span.start;
        continue;
      }
      // Spaced `password: 2026-10-15` - ambiguous empty field; leave the date.
      // Glued `password=1987-05-03` has no skipped spaces and stays a label.
      if (
        skippedSpaces &&
        isSecretishField(fieldName) &&
        isBareDateOrTime(parsed.value)
      ) {
        i = parsed.resumeAt;
        continue;
      }
      labels.push({
        fieldName,
        value: parsed.value,
        span: parsed.span,
      });
      i = parsed.resumeAt;
    }
  }

  return labels;
}

/** `user Jean Dupont (` speech: Proper-Case tokens only. */
function readUserSpeechName(
  text: string,
  afterUser: number,
): { value: string; span: { start: number; end: number } } | null {
  let i = skipSpaces(text, afterUser);
  const next = text.charCodeAt(i);
  if (next === 58 || next === 61) return null;
  if (!isUpperLetter(next)) return null;

  const start = i;
  let nameEnd = start;
  let tokens = 0;
  while (tokens < 4 && i < text.length) {
    if (tokens > 0) {
      if (!isSpace(text.charCodeAt(i))) break;
      i = skipSpaces(text, i);
      if (text.charCodeAt(i) === 40 /* ( */) break;
      if (!isUpperLetter(text.charCodeAt(i))) break;
    }
    const tokenStart = i;
    while (i < text.length && isNameChar(text.charCodeAt(i))) i += 1;
    if (i === tokenStart) break;
    nameEnd = i;
    tokens += 1;
  }

  if (tokens === 0) return null;
  i = skipSpaces(text, nameEnd);
  if (text.charCodeAt(i) !== 40 /* ( */) return null;

  const value = text.slice(start, nameEnd);
  if (value.length < 2) return null;
  return { value, span: { start, end: nameEnd } };
}

function readLabeledValue(
  text: string,
  start: number,
  fieldName: string,
  sep: number,
): { value: string; span: { start: number; end: number }; resumeAt: number } | null {
  const quote = text.charCodeAt(start);
  if (quote === 34 /* " */ || quote === 39 /* ' */) {
    let i = start + 1;
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === quote) {
        return {
          value: text.slice(start + 1, i),
          span: { start: start + 1, end: i },
          resumeAt: i + 1,
        };
      }
      if (c === 10 || c === 13) break;
      if (c === 92 && i + 1 < text.length) {
        i += 2;
        continue;
      }
      i += 1;
    }
    return null;
  }

  // `=` / `:` person fields: `user=Mehdi El Amrani` / `user_name: Yanis Haddad`.
  // Prefer Proper-Case phrase over single-token when it fits (avoids
  // `username: admin_test from IP` swallowing the rest of the sentence).
  if (
    (sep === 61 /* = */ || sep === 58 /* : */) &&
    allowsPersonNameEquals(fieldName)
  ) {
    const nameEnd = readProperCaseNamePhrase(text, start);
    if (nameEnd !== null) {
      return {
        value: text.slice(start, nameEnd),
        span: { start, end: nameEnd },
        resumeAt: nameEnd,
      };
    }
  }

  // `:` may allow spaces for User:/Address:/phone: (not login-shaped fields).
  const allowSpaces = sep === 58 && allowsEmbeddedSpaces(fieldName);
  // MySQL `User@Host: app_crm[app_crm] @ web01` - stop before `[`.
  const stopAtBracket =
    /^(host|hostname|user|username|user_name)$/i.test(fieldName);
  let i = start;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 10 || c === 13) break;
    // Closing delimiters of a surrounding quoted argv / JSON fragment.
    if (c === 34 /* " */ || c === 39 /* ' */) break;
    if (c === 41 /* ) */ || c === 93 /* ] */ || c === 40 /* ( */) break;
    if (stopAtBracket && c === 91 /* [ */) break;
    if (c === 59 /* ; */) break; // sudo … USER=root ; COMMAND=…
    if (c === 38 /* & */) break; // query string: api_key=…&limit=10
    if (c === 9 /* tab */) break; // TSV / Zeek columns
    if (c === 32 && looksLikeDashLabeledField(text, i)) break;
    if (c === 32 && !allowSpaces) break;
    if (c === 44 /* , */ && looksLikeLabeledField(text, i + 1)) break;
    i += 1;
  }

  let end = i;
  while (end > start && isSpace(text.charCodeAt(end - 1))) end -= 1;
  // Keep PHP truncation artefacts (`db-p...`) intact - do not strip `...`.
  if (!(end - start >= 3 && text.slice(end - 3, end) === "...")) {
    while (end > start && isTrailingPunct(text.charCodeAt(end - 1))) end -= 1;
  }
  if (end <= start) return null;

  return {
    value: text.slice(start, end),
    span: { start, end },
    resumeAt: i,
  };
}

/** `user=` / `cn=` may carry `Mehdi El Amrani` (Proper-Case, ≥2 tokens). */
function allowsPersonNameEquals(fieldName: string): boolean {
  const n = fieldName.toLowerCase().replace(/-/g, "_");
  return (
    n === "user" ||
    n === "username" ||
    n === "user_name" ||
    n === "name" ||
    n === "cn" ||
    n === "sn" ||
    n === "givenname" ||
    n === "displayname" ||
    n === "display_name" ||
    n === "full_name" ||
    n === "fullname"
  );
}

function isSecretishField(fieldName: string): boolean {
  const n = fieldName.toLowerCase().replace(/-/g, "_");
  return (
    n === "password" ||
    n === "passwd" ||
    n === "pwd" ||
    n === "secret" ||
    n === "token" ||
    n === "api_key" ||
    n === "apikey" ||
    n === "access_token" ||
    n === "refresh_token" ||
    n === "client_secret" ||
    n === "private_key" ||
    n === "passphrase"
  );
}

/** Multi-word Proper-Case name until next key= / EOL (≥2 tokens). */
function readProperCaseNamePhrase(text: string, start: number): number | null {
  if (!isUpperLetter(text.charCodeAt(start))) return null;
  let i = start;
  let tokens = 0;
  let end = start;
  while (tokens < 4 && i < text.length) {
    if (tokens > 0) {
      if (!isSpace(text.charCodeAt(i))) break;
      const after = skipSpaces(text, i);
      if (after >= text.length) break;
      if (looksLikeLabeledField(text, after)) break;
      // Particles: El / De / Van / Von / Di / Da / Le / La (Proper-Case).
      if (!isUpperLetter(text.charCodeAt(after))) break;
      i = after;
    }
    const tokenStart = i;
    while (i < text.length && isNameChar(text.charCodeAt(i))) i += 1;
    if (i === tokenStart) break;
    end = i;
    tokens += 1;
  }
  if (tokens < 2) return null;
  return end;
}

function allowsEmbeddedSpaces(fieldName: string): boolean {
  const n = fieldName.toLowerCase().replace(/-/g, "_");
  // Display / person labels may embed spaces. Login fields (`username`) stay
  // single-token unless readProperCaseNamePhrase already matched.
  if (
    n === "user" ||
    n === "name" ||
    n === "cn" ||
    n === "sn" ||
    n === "givenname" ||
    n === "displayname" ||
    n === "display_name" ||
    n === "full_name" ||
    n === "fullname"
  ) {
    return true;
  }
  if (n === "authorization" || n === "www_authenticate") return true;
  if (
    n.includes("phone") ||
    n.includes("mobile") ||
    n.includes("tel") ||
    n.includes("fixe") ||
    n === "msisdn" ||
    n === "fax"
  ) {
    return true;
  }
  if (
    n.includes("address") ||
    n.includes("adresse") ||
    n === "street" ||
    n === "rue"
  ) {
    return true;
  }
  if (
    n.includes("full_name") ||
    n.includes("display_name") ||
    n.includes("customer_name") ||
    n.includes("first_name") ||
    n.includes("last_name")
  ) {
    return true;
  }
  return false;
}

function looksLikeDashLabeledField(text: string, spaceIndex: number): boolean {
  if (text.charCodeAt(spaceIndex) !== 32) return false;
  if (text.charCodeAt(spaceIndex + 1) !== 45 /* - */) return false;
  if (text.charCodeAt(spaceIndex + 2) !== 32) return false;
  let i = spaceIndex + 3;
  if (!isIdentStart(text.charCodeAt(i))) return false;
  i = readIdent(text, i);
  i = skipSpaces(text, i);
  return text.charCodeAt(i) === 58 || text.charCodeAt(i) === 61;
}

function looksLikeLabeledField(text: string, from: number): boolean {
  let i = skipSpaces(text, from);
  if (!isIdentStart(text.charCodeAt(i))) return false;
  i = readIdent(text, i);
  i = skipSpaces(text, i);
  return text.charCodeAt(i) === 58 || text.charCodeAt(i) === 61;
}

function readIdent(text: string, start: number): number {
  let i = start;
  while (i < text.length && isIdentContinue(text.charCodeAt(i))) i += 1;
  return i;
}

function skipSpaces(text: string, start: number): number {
  let i = start;
  while (i < text.length && isSpace(text.charCodeAt(i))) i += 1;
  return i;
}

function isIdentStart(code: number): boolean {
  return isLetter(code) || code === 95 /* _ */;
}

function isIdentContinue(code: number): boolean {
  return (
    isIdentStart(code) ||
    (code >= 48 && code <= 57) ||
    code === 45 /* - */ ||
    code === 46 /* . */
  );
}

function isNameChar(code: number): boolean {
  return isLetter(code) || code === 45 /* - */ || code === 39 /* ' */;
}

function isLetter(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 192 && code <= 255)
  );
}

function isUpperLetter(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 192 && code <= 223)
  );
}

function isSpace(code: number): boolean {
  return code === 32 || code === 9;
}

function isTrailingPunct(code: number): boolean {
  return (
    code === 46 /* . */ ||
    code === 44 /* , */ ||
    code === 59 /* ; */ ||
    code === 34 /* " */ ||
    code === 39 /* ' */
  );
}
