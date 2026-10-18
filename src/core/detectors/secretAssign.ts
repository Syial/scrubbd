import { foldCase } from "../fold";
import { shouldRejectSecretValue } from "../secretValueGuards";
import type { Finding } from "../types";

/** password=/secret: assigns, including nested kv1=password=…. */
const SECRET_KEYS = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "api_key",
  "apikey",
  "token",
  "access_token",
  "refresh_token",
  "client_secret",
  "private_key",
];

export function findSecretAssignments(text: string): Finding[] {
  const findings: Finding[] = [];
  const lower = foldCase(text);

  for (const key of SECRET_KEYS) {
    let from = 0;
    while (from < text.length) {
      const idx = lower.indexOf(key, from);
      if (idx === -1) break;

      const prev = idx > 0 ? text.charCodeAt(idx - 1) : -1;
      if (isIdentChar(prev)) {
        from = idx + key.length;
        continue;
      }
      let i = idx + key.length;
      // optional spaces then : or =
      while (i < text.length && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) i += 1;
      const sep = text.charCodeAt(i);
      if (sep !== 61 /* = */ && sep !== 58 /* : */) {
        from = idx + key.length;
        continue;
      }
      i += 1;
      const afterSep = i;
      while (i < text.length && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) i += 1;
      const skippedSpaces = i > afterSep;

      const parsed = readSecretValue(text, i);
      if (!parsed) {
        from = idx + key.length;
        continue;
      }

      // Empty field → next token (`password= from=…`); glued `Summer=2026!` stays.
      if (shouldRejectSecretValue(parsed.value, skippedSpaces)) {
        from = idx + key.length;
        continue;
      }
      // Skip filesystem paths (PWD=/home/…).
      if (looksLikePath(parsed.value)) {
        from = parsed.end;
        continue;
      }

      findings.push({
        kind: "secret",
        value: parsed.value,
        key: `assign:${idx}:${parsed.value}`,
        span: { start: parsed.start, end: parsed.end },
        decision: "replace",
      });
      from = parsed.end;
    }
  }

  return findings;
}

function readSecretValue(
  text: string,
  start: number,
): { start: number; end: number; value: string } | null {
  if (start >= text.length) return null;
  const quote = text.charCodeAt(start);
  if (quote === 34 || quote === 39) {
    let i = start + 1;
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === quote) {
        return {
          start: start + 1,
          end: i,
          value: text.slice(start + 1, i),
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

  let i = start;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 32 || c === 9 || c === 10 || c === 13) break;
    // CSV / JSON string closers - never swallow the surrounding quote.
    if (c === 34 /* " */ || c === 39 /* ' */) break;
    // Query-string / CSV / argv delimiters.
    if (
      c === 59 /* ; */ ||
      c === 44 /* , */ ||
      c === 41 ||
      c === 93 ||
      c === 38 /* & */ ||
      c === 63 /* ? */
    ) {
      break;
    }
    i += 1;
  }
  if (i <= start) return null;
  return { start, end: i, value: text.slice(start, i) };
}

function looksLikePath(value: string): boolean {
  if (value.startsWith("/") || value.startsWith("~")) return true;
  if (/^[A-Za-z]:[\\/]/.test(value)) return true;
  if (value.startsWith("\\\\")) return true;
  return false;
}

function isIdentChar(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 95 ||
    code === 45
  );
}
