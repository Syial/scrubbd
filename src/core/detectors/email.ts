import { foldCase } from "../fold";
import type { Finding } from "../types";

/** Whole-string e-mail check (field values, exact tokens). */
export function isValidEmail(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed !== value) return false;
  return parseEmail(value) !== null;
}

/** Manual e-mail scanner: locate `@`, expand local/domain, validate. */
export function findEmails(
  text: string,
  options?: { fieldPath?: string },
): Finding[] {
  const findings: Finding[] = [];
  const length = text.length;
  let i = 0;

  while (i < length) {
    if (text.charCodeAt(i) !== 64 /* @ */) {
      i += 1;
      continue;
    }

    const local = readLocalPart(text, i);
    if (!local) {
      i += 1;
      continue;
    }

    const domain = readDomain(text, i + 1);
    if (!domain) {
      i += 1;
      continue;
    }

    const start = local.start;
    const end = domain.end;
    const value = text.slice(start, end);

    // URL userinfo (`user:pass@host`) - not an email.
    const prev = start > 0 ? text.charCodeAt(start - 1) : -1;
    if (prev === 58 /* : */) {
      i += 1;
      continue;
    }
    // `git@github.com:org/repo` - SCP-like, not an email.
    // But `user@host:2222` is user@host + port - still an email/mailbox.
    if (end < length && text.charCodeAt(end) === 58 /* : */) {
      const after = text.charCodeAt(end + 1);
      const isPort = after >= 48 && after <= 57; // digit
      if (!isPort) {
        i += 1;
        continue;
      }
    }
    const localPart = value.slice(0, value.indexOf("@"));
    // Generic VCS accounts: `git@gitlab.com`, `git@github.com` (keep readable).
    if (isKeptVcsMailbox(localPart, value.slice(value.indexOf("@") + 1))) {
      i = end;
      continue;
    }
    if (looksLikeSecretLocal(localPart)) {
      i += 1;
      continue;
    }
    // Message-ID bodies: `20261014080112.4F2A1B2C3D@mail…` - not a mailbox.
    if (looksLikeMessageIdLocal(localPart)) {
      i += 1;
      continue;
    }

    if (parseEmail(value)) {
      findings.push({
        kind: "email",
        value,
        key: value.toLowerCase(),
        span: { start, end },
        decision: "replace",
        ...(options?.fieldPath !== undefined ? { fieldPath: options.fieldPath } : {}),
      });
      i = end;
      continue;
    }

    // `a@a@a@a@…` stress: jump past a run of failed short @-tokens.
    i = skipFailedAtRun(text, i, start);
  }

  findings.push(...findPercentEncodedEmails(text, options));
  findings.push(...findObfuscatedEmails(text, options));
  return findings;
}

function skipFailedAtRun(text: string, atIndex: number, localStart: number): number {
  // If local was a single char and domain didn't parse, skip `x@x@x@…`.
  if (atIndex - localStart <= 1) {
    let i = atIndex + 1;
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 64 /* @ */) {
        i += 1;
        continue;
      }
      if (isLocalChar(c) && (i + 1 >= text.length || text.charCodeAt(i + 1) === 64)) {
        i += 1;
        continue;
      }
      break;
    }
    return Math.max(i, atIndex + 1);
  }
  return atIndex + 1;
}

/** Obfuscated emails ([dot]/[at], &#64;, zero-width). */
function findObfuscatedEmails(
  text: string,
  options?: { fieldPath?: string },
): Finding[] {
  const out: Finding[] = [];
  // Fast reject - never run ReDoS-prone patterns on `a@a@a@…` stress lines.
  const lower = foldCase(text);
  const hasBracketAt = lower.includes("[at]") || lower.includes("(at)");
  const hasBracketDot = lower.includes("[dot]") || lower.includes("(dot)");
  const hasEntity = lower.includes("&#64;") || lower.includes("&#x40;");
  const hasZw = /[\u200b\u200c\u200d\ufeff]/.test(text);
  if (!hasBracketAt && !hasBracketDot && !hasEntity && !hasZw) return out;

  let m: RegExpExecArray | null;

  if (hasBracketAt || hasBracketDot) {
    // Linear-ish: require literal [at]/(at) anchor, expand outward.
    const atRe = /\[\s*at\s*\]|\(\s*at\s*\)/gi;
    while ((m = atRe.exec(text)) !== null) {
      const span = expandObfuscatedAroundAt(text, m.index, m[0]!.length);
      if (!span) continue;
      const raw = text.slice(span.start, span.end);
      const decoded = decodeObfuscatedEmail(raw);
      if (!decoded || !parseEmail(decoded)) continue;
      out.push({
        kind: "email",
        value: raw,
        key: decoded.toLowerCase(),
        span,
        decision: "replace",
        ...(options?.fieldPath !== undefined ? { fieldPath: options.fieldPath } : {}),
      });
    }
  }

  if (hasEntity) {
    const entity = /\b([A-Za-z0-9._+-]+)&#(?:x0*40|64);([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/gi;
    while ((m = entity.exec(text)) !== null) {
      const raw = m[0]!;
      const decoded = `${m[1]}@${m[2]}`.toLowerCase();
      if (!parseEmail(decoded)) continue;
      out.push({
        kind: "email",
        value: raw,
        key: decoded,
        span: { start: m.index, end: m.index + raw.length },
        decision: "replace",
        ...(options?.fieldPath !== undefined ? { fieldPath: options.fieldPath } : {}),
      });
    }
  }

  if (hasZw) {
    const zw = /\b([A-Za-z0-9._+-]+@[A-Za-z0-9.\u200b\u200c\u200d\ufeff-]+\.[A-Za-z]{2,})\b/g;
    while ((m = zw.exec(text)) !== null) {
      const raw = m[1]!;
      if (!/[\u200b\u200c\u200d\ufeff]/.test(raw)) continue;
      const decoded = raw.replace(/[\u200b\u200c\u200d\ufeff]/g, "");
      if (!parseEmail(decoded)) continue;
      const start = m.index;
      out.push({
        kind: "email",
        value: raw,
        key: decoded.toLowerCase(),
        span: { start, end: start + raw.length },
        decision: "replace",
        ...(options?.fieldPath !== undefined ? { fieldPath: options.fieldPath } : {}),
      });
    }
  }

  return out;
}

/** Expand `… [dot] … [at] … [dot] …` around a found `[at]` token. */
function expandObfuscatedAroundAt(
  text: string,
  atIndex: number,
  atLen: number,
): { start: number; end: number } | null {
  const isPart = (c: number) =>
    (c >= 65 && c <= 90) ||
    (c >= 97 && c <= 122) ||
    (c >= 48 && c <= 57) ||
    c === 46 ||
    c === 95 ||
    c === 43 ||
    c === 45 ||
    c === 32 ||
    c === 91 ||
    c === 93 ||
    c === 40 ||
    c === 41;

  let start = atIndex;
  while (start > 0 && isPart(text.charCodeAt(start - 1))) start -= 1;
  let end = atIndex + atLen;
  while (end < text.length && isPart(text.charCodeAt(end))) end += 1;
  if (end - start < 5) return null;
  return { start, end };
}

function decodeObfuscatedEmail(raw: string): string | null {
  let s = raw.toLowerCase();
  s = s.replace(/\s*[\[(]?\s*at\s*[\])]?\s*/gi, "@");
  s = s.replace(/\s*[\[(]?\s*dot\s*[\])]?\s*/gi, ".");
  s = s.replace(/\s+/g, "");
  if (!s.includes("@")) return null;
  return s;
}

function looksLikeSecretLocal(local: string): boolean {
  const lower = local.toLowerCase();
  return (
    lower.startsWith("ghp_") ||
    lower.startsWith("gho_") ||
    lower.startsWith("ghu_") ||
    lower.startsWith("ghs_") ||
    lower.startsWith("ghr_") ||
    lower.startsWith("sk_test_") ||
    lower.startsWith("sk_live_") ||
    lower.startsWith("rk_test_") ||
    lower.startsWith("akia") ||
    lower.startsWith("asia")
  );
}

/** RFC 5322 Message-ID local parts, not mailboxes. */
function looksLikeMessageIdLocal(local: string): boolean {
  // `20261014080112.4F2A1B2C3D` / `CA+abc=def@`
  if (/^\d{10,}\.[A-Fa-f0-9]{6,}$/.test(local)) return true;
  if (/^[A-Za-z0-9+/=_-]{20,}$/.test(local) && /\d/.test(local) && /[A-F]/.test(local)) {
    return true;
  }
  return false;
}

function findPercentEncodedEmails(
  text: string,
  options?: { fieldPath?: string },
): Finding[] {
  const out: Finding[] = [];
  let from = 0;
  const lower = foldCase(text);
  while (from < text.length) {
    const idx = lower.indexOf("%40", from);
    if (idx === -1) break;

    const local = readLocalPart(text, idx);
    if (!local) {
      from = idx + 3;
      continue;
    }
    const domain = readDomain(text, idx + 3);
    if (!domain) {
      from = idx + 3;
      continue;
    }

    const start = local.start;
    const end = domain.end;
    const decoded = `${text.slice(start, idx)}@${text.slice(idx + 3, end)}`;
    if (!parseEmail(decoded)) {
      from = idx + 3;
      continue;
    }
    const prev = start > 0 ? text.charCodeAt(start - 1) : -1;
    if (prev === 58 /* : */) {
      from = idx + 3;
      continue;
    }

    out.push({
      kind: "email",
      value: text.slice(start, end),
      key: decoded.toLowerCase(),
      span: { start, end },
      decision: "replace",
      ...(options?.fieldPath !== undefined ? { fieldPath: options.fieldPath } : {}),
    });
    from = end;
  }
  return out;
}

function parseEmail(value: string): string | null {
  const at = value.indexOf("@");
  if (at <= 0 || at !== value.lastIndexOf("@")) return null;
  if (value.length > 254) return null;

  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (!isLocalPart(local) || !isDomain(domain)) return null;
  return value;
}

const VCS_LOCALS = new Set(["git", "svn", "hg", "cvs"]);
const VCS_HOSTS = [
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "codeberg.org",
  "gitea.com",
];

function isKeptVcsMailbox(local: string, domain: string): boolean {
  if (!VCS_LOCALS.has(local.toLowerCase())) return false;
  const d = domain.toLowerCase();
  return VCS_HOSTS.some((h) => d === h || d.endsWith(`.` + h));
}

function readLocalPart(
  text: string,
  atIndex: number,
): { start: number } | null {
  let i = atIndex - 1;
  if (i < 0) return null;

  while (i >= 0 && isLocalChar(text.charCodeAt(i))) {
    i -= 1;
  }
  const start = i + 1;
  if (start >= atIndex) return null;
  if (!isLocalPart(text.slice(start, atIndex))) return null;
  return { start };
}

function readDomain(
  text: string,
  start: number,
): { end: number } | null {
  let i = start;
  while (i < text.length && isDomainChar(text.charCodeAt(i))) {
    i += 1;
  }
  // Trim a trailing dot if we over-consumed punctuation wrongly - domains shouldn't end with '.'
  while (i > start && text.charCodeAt(i - 1) === 46 /* . */) {
    i -= 1;
  }
  if (i <= start) return null;
  if (!isDomain(text.slice(start, i))) return null;
  return { end: i };
}

function isLocalPart(local: string): boolean {
  if (local.length === 0 || local.length > 64) return false;
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
    return false;
  }
  for (let i = 0; i < local.length; i += 1) {
    if (!isLocalChar(local.charCodeAt(i))) return false;
  }
  return true;
}

function isDomain(domain: string): boolean {
  if (domain.length < 3 || domain.length > 253) return false;
  if (domain.startsWith(".") || domain.endsWith(".") || domain.includes("..")) {
    return false;
  }
  const labels = domain.split(".");
  if (labels.length < 2) return false;

  // Retina / asset suffixes: `logo@2x.png`, `icon@3x.webp` - not emails.
  if (/^\d+x$/i.test(labels[0]!)) return false;

  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
    for (let i = 0; i < label.length; i += 1) {
      const code = label.charCodeAt(i);
      if (!isAlphaNum(code) && code !== 45 /* - */) return false;
    }
  }

  const tld = labels[labels.length - 1]!;
  // Require a textual TLD (rejects hostnames like a.b if we want - actually a.b is ok for internal;
  // require at least one letter in TLD to avoid "user@123.456" style nonsense from IPs).
  let hasLetter = false;
  for (let i = 0; i < tld.length; i += 1) {
    if (isLetter(tld.charCodeAt(i))) {
      hasLetter = true;
      break;
    }
  }
  return hasLetter && tld.length >= 2;
}

function isLocalChar(code: number): boolean {
  return (
    isAlphaNum(code) ||
    code === 46 /* . */ ||
    code === 95 /* _ */ ||
    code === 37 /* % */ ||
    code === 43 /* + */ ||
    code === 45 /* - */
  );
}

function isDomainChar(code: number): boolean {
  return isAlphaNum(code) || code === 46 /* . */ || code === 45 /* - */;
}

function isAlphaNum(code: number): boolean {
  return isLetter(code) || (code >= 48 && code <= 57);
}

function isLetter(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    // Latin-1 supplement (élodie, café.fr) - common in FR logs.
    (code >= 192 && code <= 255 && code !== 215 && code !== 247)
  );
}
