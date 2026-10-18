import { foldCase } from "../fold";
import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";

/** High-precision account grammars in auth logs (sshd, Windows, DOMAIN\\user). */
export function findAuthAccounts(text: string): Finding[] {
  return [
    ...findSshdForUser(text),
    ...findWindowsAccountName(text),
    ...findDomainUser(text),
    ...findCronUser(text),
    ...findSudoUser(text),
    ...findSuUser(text),
    ...findAuthenticatingUser(text),
    ...findCliUserFlags(text),
    ...findArnUsers(text),
  ];
}

/** CRON[991]: (yhaddad) CMD (…) */
function findCronUser(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\bCRON\[\d+\]:\s*\(([A-Za-z][A-Za-z0-9._+-]{1,64})\)/g;
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

/** `sudo: t.marchand : TTY=…` */
function findSudoUser(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\bsudo:\s+([A-Za-z][A-Za-z0-9._+-]{1,64})\s+:/g;
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

/** `su: (to root) icarvalho on pts/0` */
function findSuUser(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\bsu:\s+\(to\s+\w+\)\s+([A-Za-z][A-Za-z0-9._+-]{1,64})\s+on\b/g;
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

/** `authenticating user icarvalho` */
function findAuthenticatingUser(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\bauthenticating\s+user\s+([A-Za-z][A-Za-z0-9._+-]{1,64})\b/gi;
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

/** `ssh -l icarvalho`, `mysql -u yhaddad`, `psql -U nrousseau` */
function findCliUserFlags(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /(?:^|[\s])-(?:l|u|U)\s+([A-Za-z][A-Za-z0-9._+-]{1,64})\b/g;
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
  // PowerShell / AD: `-Identity icarvalho`
  const idRe = /(?:^|[\s])-Identity\s+([A-Za-z][A-Za-z0-9._+-]{1,64})\b/gi;
  while ((m = idRe.exec(text)) !== null) {
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

/** ARN / STS: `user/nrousseau`, `assumed-role/Admin/thibault.marchand` */
function findArnUsers(text: string): Finding[] {
  const out: Finding[] = [];
  const patterns = [
    /:user\/([A-Za-z][A-Za-z0-9._+-]{1,64})\b/g,
    // AWS audit prose: `by user/nrousseau` (no leading colon).
    /\bby\s+user\/([A-Za-z][A-Za-z0-9._+-]{1,64})\b/gi,
    /:assumed-role\/[^/\s]+\/([A-Za-z][A-Za-z0-9._+-]{1,64})\b/g,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const value = m[1]!;
      if (!isRedactableAccount(value)) continue;
      const start = m.index + m[0]!.lastIndexOf(value);
      out.push({
        kind: "account",
        value,
        key: value.toLowerCase(),
        span: { start, end: start + value.length },
        decision: "replace",
      });
    }
  }
  return out;
}

/** Windows Event Log: `Account Name:\t\tefontaine` (works on decoded text). */
function findWindowsAccountName(text: string): Finding[] {
  const out: Finding[] = [];
  const lower = foldCase(text);
  const needle = "account name:";
  let from = 0;
  while (from < text.length) {
    const idx = lower.indexOf(needle, from);
    if (idx === -1) break;
    let i = idx + needle.length;
    while (i < text.length && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) {
      i += 1;
    }
    const start = i;
    while (i < text.length && isAccountChar(text.charCodeAt(i))) i += 1;
    if (i > start) {
      const value = text.slice(start, i);
      if (isRedactableAccount(value)) {
        out.push({
          kind: "account",
          value,
          key: value.toLowerCase(),
          span: { start, end: i },
          decision: "replace",
        });
      }
    }
    from = Math.max(i, idx + needle.length);
  }
  return out;
}

function findSshdForUser(text: string): Finding[] {
  const out: Finding[] = [];
  const lower = foldCase(text);
  const needles = [
    "failed password for ",
    "accepted publickey for ",
    "accepted password for ",
    "accepted keyboard-interactive/pam for ",
    "of user ",
    "for user ",
    "session for ",
    "changed for ",
    "login ok for ",
    "opened for ",
    "session opened for ",
  ];

  for (const needle of needles) {
    let from = 0;
    while (from < text.length) {
      const idx = lower.indexOf(needle, from);
      if (idx === -1) break;
      let i = idx + needle.length;
      if (lower.startsWith("invalid user ", i)) i += "invalid user ".length;
      // Optional quotes around the account
      const q = text.charCodeAt(i);
      if (q === 34 || q === 39) i += 1;
      const start = i;
      // DOMAIN\user - take the user part only.
      let domainEnd = -1;
      while (i < text.length && isAccountChar(text.charCodeAt(i))) {
        // Don't swallow a sentence-final `.` after `lea.moreau.`
        if (text.charCodeAt(i) === 46 /* . */) {
          const next = i + 1 < text.length ? text.charCodeAt(i + 1) : -1;
          if (!isAlphaNumAccount(next)) break;
        }
        i += 1;
      }
      if (i < text.length && text.charCodeAt(i) === 92 /* \ */) {
        domainEnd = i;
        i += 1;
        const userStart = i;
        while (i < text.length && isAccountChar(text.charCodeAt(i))) i += 1;
        if (i > userStart) {
          const value = text.slice(userStart, i);
          if (isRedactableAccount(value)) {
            out.push({
              kind: "account",
              value,
              key: value.toLowerCase(),
              span: { start: userStart, end: i },
              decision: "replace",
            });
          }
          from = Math.max(i, idx + needle.length);
          continue;
        }
        i = domainEnd;
      }
      if (i > start && domainEnd === -1) {
        const value = text.slice(start, i);
        // `of user via MFA` - require login shape for the vague "of user " cue.
        if (
          needle === "of user " &&
          !/[._\d-]/.test(value) &&
          value === value.toLowerCase()
        ) {
          from = Math.max(i, idx + needle.length);
          continue;
        }
        if (isRedactableAccount(value)) {
          out.push({
            kind: "account",
            value,
            key: value.toLowerCase(),
            span: { start, end: i },
            decision: "replace",
          });
        }
      }
      from = Math.max(i, idx + needle.length);
    }
  }
  return out;
}

function findDomainUser(text: string): Finding[] {
  const out: Finding[] = [];
  let i = 0;
  while (i < text.length) {
    if (text.charCodeAt(i) !== 92 /* \ */) {
      i += 1;
      continue;
    }
    const sep = i;
    let left = sep - 1;
    while (left >= 0 && isAccountChar(text.charCodeAt(left))) left -= 1;
    const domainStart = left + 1;
    if (domainStart >= sep) {
      i += 1;
      continue;
    }
    let right = sep + 1;
    while (right < text.length && isAccountChar(text.charCodeAt(right))) right += 1;
    if (right <= sep + 1) {
      i += 1;
      continue;
    }

    const domain = text.slice(domainStart, sep);
    const user = text.slice(sep + 1, right);
    if (/^u[0-9a-fA-F]{4}/.test(user)) {
      i = sep + 1;
      continue;
    }
    if (!looksLikeAdDomain(domain, text, domainStart, right)) {
      i = right;
      continue;
    }
    if (!isRedactableAccount(user)) {
      i = right;
      continue;
    }

    out.push({
      kind: "account",
      value: user,
      key: user.toLowerCase(),
      span: { start: sep + 1, end: right },
      decision: "replace",
    });
    i = right;
  }
  return out;
}

/** NetBIOS / DNS-style AD domain - not a filesystem path segment. */
function looksLikeAdDomain(
  domain: string,
  text: string,
  domainStart: number,
  userEnd: number,
): boolean {
  if (domain.length < 2) return false;
  const d = domain.toLowerCase();
  if (PATH_SEGMENTS.has(d)) return false;
  // Drive letter context `C:`
  if (domainStart >= 2 && text.charCodeAt(domainStart - 1) === 58) return false;
  // Continuation of a path `...\something\user`
  if (domainStart >= 1 && (text.charCodeAt(domainStart - 1) === 92 || text.charCodeAt(domainStart - 1) === 47)) {
    return false;
  }
  // PHP / C++ namespaces: `App\Db::connect`, `Illuminate\Cache::get`
  if (userEnd + 1 < text.length && text.charCodeAt(userEnd) === 58 && text.charCodeAt(userEnd + 1) === 58) {
    return false;
  }
  // NetBIOS-ish or DNS-ish
  if (!/^[A-Za-z][A-Za-z0-9._-]*$/.test(domain)) return false;
  // Bare PascalCase `App` / `Illuminate` are code, not AD NetBIOS (ALLCAPS / DNS).
  if (!domain.includes(".") && domain !== domain.toUpperCase()) return false;
  return true;
}

const PATH_SEGMENTS = new Set(
  [
    "home",
    "users",
    "homes",
    "documents",
    "desktop",
    "windows",
    "system32",
    "system",
    "program",
    "files",
    "program files",
    "program files (x86)",
    "programdata",
    "appdata",
    "roaming",
    "local",
    "temp",
    "tmp",
    "mozilla",
    "firefox",
    "chrome",
    "google",
    "microsoft",
    "common files",
    "inetpub",
    "wwwroot",
  ].map((s) => s.toLowerCase()),
);

function isAccountChar(code: number): boolean {
  return (
    isAlphaNumAccount(code) ||
    code === 46 /* . */ ||
    code === 95 /* _ */ ||
    code === 45 /* - */ ||
    (code >= 192 && code <= 255)
  );
}

function isAlphaNumAccount(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    (code >= 192 && code <= 255)
  );
}
