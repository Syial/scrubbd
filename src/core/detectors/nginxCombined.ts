import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";
import { isAccountStopword } from "../stopwords";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";

/** Nginx/Apache combined remote_user; require a real access-log [timestamp]. */
export function findNginxCombinedUsers(text: string): Finding[] {
  const findings: Finding[] = [];
  let lineStart = 0;

  while (lineStart <= text.length) {
    let lineEnd = text.indexOf("\n", lineStart);
    if (lineEnd === -1) lineEnd = text.length;
    const line = text.slice(lineStart, lineEnd);
    for (const hit of parseCombinedUsers(line)) {
      findings.push({
        kind: "account",
        value: hit.value,
        key: hit.value.toLowerCase(),
        span: {
          start: lineStart + hit.start,
          end: lineStart + hit.end,
        },
        decision: "replace",
      });
    }
    if (lineEnd >= text.length) break;
    lineStart = lineEnd + 1;
  }

  return findings;
}

function parseCombinedUsers(
  line: string,
): Array<{ value: string; start: number; end: number }> {
  const client = matchClientToken(line);
  if (!client) return [];
  // Client itself must look like an address/host - not a calendar date.
  if (!looksLikeClientAddr(client.value) && !isVhostToken(client.value)) {
    return [];
  }

  let i = client.end;
  while (i < line.length && line.charCodeAt(i) === 32) i += 1;

  // Form A: ` - user [` or ` - - [`
  if (line.startsWith("- ", i) || (line.charCodeAt(i) === 45 && line.charCodeAt(i + 1) === 32)) {
    if (line.charCodeAt(i) === 45) {
      i += 1;
      while (i < line.length && line.charCodeAt(i) === 32) i += 1;
    }
    return oneUserBeforeBracket(line, i);
  }

  // Form B: common log `ident user [`
  const ident = readToken(line, i);
  if (!ident) return [];
  i = ident.end;
  while (i < line.length && line.charCodeAt(i) === 32) i += 1;
  const user = readToken(line, i);
  if (!user) return [];
  i = user.end;
  while (i < line.length && line.charCodeAt(i) === 32) i += 1;
  if (line.charCodeAt(i) !== 91 /* [ */) return [];
  if (!looksLikeAccessLogTime(line, i)) return [];

  const out: Array<{ value: string; start: number; end: number }> = [];
  pushAccount(out, line, ident);
  pushAccount(out, line, user);
  return out;
}

function oneUserBeforeBracket(
  line: string,
  userStart: number,
): Array<{ value: string; start: number; end: number }> {
  let userEnd = userStart;
  while (
    userEnd < line.length &&
    line.charCodeAt(userEnd) !== 32 &&
    line.charCodeAt(userEnd) !== 91 /* [ */
  ) {
    userEnd += 1;
  }
  if (userEnd <= userStart) return [];
  let i = userEnd;
  while (i < line.length && line.charCodeAt(i) === 32) i += 1;
  if (line.charCodeAt(i) !== 91 /* [ */) return [];
  if (!looksLikeAccessLogTime(line, i)) return [];
  const out: Array<{ value: string; start: number; end: number }> = [];
  pushAccount(out, line, { start: userStart, end: userEnd });
  return out;
}

/** `[14/Oct/2026:08:01:02 +0200]` or `[Tue Oct 14 08:01:12.123456 2026]` */
function looksLikeAccessLogTime(line: string, bracketIdx: number): boolean {
  const slice = line.slice(bracketIdx, bracketIdx + 40);
  if (/^\[\d{1,2}\/[A-Za-z]{3}\/\d{4}:/.test(slice)) return true;
  if (/^\[\d{4}-\d{2}-\d{2}[T ]/.test(slice)) return true;
  if (/^\[[A-Za-z]{3} [A-Za-z]{3} +\d{1,2} /.test(slice)) return true;
  return false;
}

function matchClientToken(
  line: string,
): { start: number; end: number; value: string } | null {
  const first = readToken(line, 0);
  if (!first) return null;
  let j = first.end;
  while (j < line.length && line.charCodeAt(j) === 32) j += 1;
  const second = readToken(line, j);
  if (second && isVhostToken(first.value) && looksLikeClientAddr(second.value)) {
    return second;
  }
  return first;
}

function isVhostToken(value: string): boolean {
  return /^[A-Za-z0-9._-]+:\d+$/.test(value);
}

function looksLikeClientAddr(value: string): boolean {
  if (value === "::1") return true;
  if (
    value.startsWith("::ffff:") ||
    (/^[0-9a-fA-F:]+$/.test(value) && value.includes(":"))
  ) {
    return true;
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return true;
  // Reject ISO dates mistaken for hosts: `2026-10-14`
  if (/^\d{4}-\d{2}-\d{2}/.test(value)) return false;
  return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value) && /[A-Za-z]/.test(value);
}

function readToken(
  line: string,
  start: number,
): { value: string; start: number; end: number } | null {
  if (start >= line.length || line.charCodeAt(start) === 32) return null;
  let end = start;
  while (end < line.length && line.charCodeAt(end) !== 32) end += 1;
  if (end <= start) return null;
  return { value: line.slice(start, end), start, end };
}

function pushAccount(
  out: Array<{ value: string; start: number; end: number }>,
  line: string,
  tok: { start: number; end: number },
): void {
  const user = line.slice(tok.start, tok.end);
  if (user === "-" || isSentinelValue(user)) return;
  if (user.length < MIN_IDENTITY_LENGTH) return;
  if (user.includes("@") || /\s/.test(user)) return;
  if (user.includes(":") || isAccountStopword(user)) return;
  if (!isRedactableAccount(user) && !looksLikeLogin(user)) return;
  out.push({ value: user, start: tok.start, end: tok.end });
}

function looksLikeLogin(value: string): boolean {
  return /^[A-Za-z0-9._+-]+$/.test(value) && /[A-Za-z]/.test(value);
}
