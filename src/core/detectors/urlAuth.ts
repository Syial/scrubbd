import { foldCase } from "../fold";
import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";

/** URL userinfo / CLI credentials; password → secret. */
export function findUrlAuth(text: string): Finding[] {
  return [
    ...findSchemeUserinfo(text),
    ...findCliCredentials(text),
    ...findUserAtIpv4(text),
  ];
}

/** scp/ssh login@host (IPv4 or hostname), not mailbox emails. */
function findUserAtIpv4(text: string): Finding[] {
  const findings: Finding[] = [];
  const re =
    /\b([A-Za-z][A-Za-z0-9._+-]{1,63})@(\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9][A-Za-z0-9.-]{1,80})\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const user = m[1]!;
    const host = m[2]!;
    if (!isRedactableAccount(user)) continue;
    // `exampleSDID@32473` - structured-data ID, not user@host.
    if (/^\d+$/.test(host)) continue;
    // Leave real emails to the email detector (has a dotted TLD of letters).
    if (/\.[A-Za-z]{2,}$/.test(host) && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
      continue;
    }
    findings.push({
      kind: "account",
      value: user,
      key: user.toLowerCase(),
      span: { start: m.index, end: m.index + user.length },
      decision: "replace",
    });
  }
  return findings;
}

function findSchemeUserinfo(text: string): Finding[] {
  const findings: Finding[] = [];
  let from = 0;

  while (from < text.length) {
    const scheme = text.indexOf("://", from);
    if (scheme === -1) break;

    let i = scheme + 3;
    const userinfoStart = i;
    let at = -1;
    let colon = -1;

    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 64 /* @ */) {
        at = i;
        break;
      }
      if (c === 58 /* : */ && colon === -1) colon = i;
      if (
        c === 47 /* / */ ||
        c === 63 /* ? */ ||
        c === 35 /* # */ ||
        c === 32 ||
        c === 10 ||
        c === 13
      ) {
        break;
      }
      i += 1;
    }

    if (at === -1 || colon === -1 || colon >= at || colon < userinfoStart) {
      from = scheme + 3;
      continue;
    }

    const user = text.slice(userinfoStart, colon);
    if (isRedactableAccount(user)) {
      findings.push({
        kind: "account",
        value: user,
        key: user.toLowerCase(),
        span: { start: userinfoStart, end: colon },
        decision: "replace",
      });
    }

    const passwordStart = colon + 1;
    const passwordEnd = at;
    if (passwordEnd > passwordStart) {
      const value = text.slice(passwordStart, passwordEnd);
      findings.push({
        kind: "secret",
        value,
        key: `urlpass:${passwordStart}:${value}`,
        span: { start: passwordStart, end: passwordEnd },
        decision: "replace",
      });
    }

    from = at + 1;
  }

  return findings;
}

/** `curl -u user:pass` / `--user user:pass` / `net use … /user:DOM\u Winter2026!`. */
function findCliCredentials(text: string): Finding[] {
  const findings: Finding[] = [];
  const lower = foldCase(text);
  let i = 0;

  while (i < text.length) {
    let matched = 0;
    let mode: "colon-pair" | "next-token" | null = null;

    if (
      (i === 0 || isBoundary(text.charCodeAt(i - 1))) &&
      (lower.startsWith("-u", i) || lower.startsWith("--user", i))
    ) {
      const isLong = lower.startsWith("--user", i);
      const flagLen = isLong ? 6 : 2;
      if (!isLong && isAlphaNum(text.charCodeAt(i + 2))) {
        i += 1;
        continue;
      }
      if (isLong && i + 6 < text.length && isAlphaNum(text.charCodeAt(i + 6))) {
        i += 1;
        continue;
      }
      const after = i + flagLen;
      if (after < text.length && (text.charCodeAt(after) === 32 || text.charCodeAt(after) === 61)) {
        matched = after + 1;
        while (matched < text.length && text.charCodeAt(matched) === 32) matched += 1;
        mode = "colon-pair";
      }
    } else if (lower.startsWith("/user:", i)) {
      // Must not match inside `://user:` - require whitespace (or start) before `/`.
      const prev = i > 0 ? text.charCodeAt(i - 1) : -1;
      if (i === 0 || isBoundary(prev)) {
        matched = i + 6;
        mode = "next-token";
      }
    }

    if (!mode || matched === 0) {
      i += 1;
      continue;
    }

    if (mode === "colon-pair") {
      let j = matched;
      while (j < text.length && !isSpace(text.charCodeAt(j)) && text.charCodeAt(j) !== 34) {
        j += 1;
      }
      const colon = text.indexOf(":", matched);
      if (colon !== -1 && colon < j) {
        const user = text.slice(matched, colon);
        if (isRedactableAccount(user)) {
          findings.push({
            kind: "account",
            value: user,
            key: user.toLowerCase(),
            span: { start: matched, end: colon },
            decision: "replace",
          });
        }
        const value = text.slice(colon + 1, j);
        if (value.length > 0) {
          findings.push({
            kind: "secret",
            value,
            key: `clipass:${colon + 1}:${value}`,
            span: { start: colon + 1, end: j },
            decision: "replace",
          });
        }
      }
      i = Math.max(j, matched);
      continue;
    }

    // /user:DOMAIN\account <password> - one account token, then password token.
    let j = matched;
    const userStart = j;
    while (j < text.length && !isCliTokenEnd(text.charCodeAt(j))) j += 1;
    const userToken = text.slice(userStart, j);
    // Prefer the user part after DOMAIN\ for alias coherence with bare usernames.
    const slash = userToken.lastIndexOf("\\");
    const user =
      slash >= 0 ? userToken.slice(slash + 1) : userToken;
    if (isRedactableAccount(user)) {
      const start = slash >= 0 ? userStart + slash + 1 : userStart;
      findings.push({
        kind: "account",
        value: user,
        key: user.toLowerCase(),
        span: { start, end: userStart + userToken.length },
        decision: "replace",
      });
    }

    j = skipSpaces(text, j);
    const passStart = j;
    while (j < text.length && !isCliTokenEnd(text.charCodeAt(j))) j += 1;
    if (j > passStart) {
      const value = text.slice(passStart, j);
      if (
        value.length >= 4 &&
        value.length <= 128 &&
        !value.startsWith("/") &&
        !value.startsWith("-") &&
        looksLikePassword(value)
      ) {
        findings.push({
          kind: "secret",
          value,
          key: `clipass:${passStart}:${value}`,
          span: { start: passStart, end: j },
          decision: "replace",
        });
      }
    }
    i = Math.max(j, matched);
  }

  return findings;
}

function looksLikePassword(value: string): boolean {
  let hasLetter = false;
  let hasDigitOrSpecial = false;
  for (let k = 0; k < value.length; k += 1) {
    const c = value.charCodeAt(k);
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) hasLetter = true;
    else hasDigitOrSpecial = true;
  }
  return hasLetter && hasDigitOrSpecial;
}

function isBoundary(code: number): boolean {
  return code === 32 || code === 9 || code === 10 || code === 13;
}

function isSpace(code: number): boolean {
  return code === 32 || code === 9;
}

/** End of a CLI argv token - also stop at JSON/string delimiters when scanning raw logs. */
function isCliTokenEnd(code: number): boolean {
  return (
    code === 32 ||
    code === 9 ||
    code === 10 ||
    code === 13 ||
    code === 34 /* " */ ||
    code === 39 /* ' */ ||
    code === 44 /* , */ ||
    code === 125 /* } */ ||
    code === 93 /* ] */ ||
    code === 60 /* < */ ||
    code === 62 /* > */
  );
}

function isAlphaNum(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57)
  );
}

function skipSpaces(text: string, start: number): number {
  let i = start;
  while (i < text.length && isSpace(text.charCodeAt(i))) i += 1;
  return i;
}
