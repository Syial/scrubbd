import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";

/** Squid access.log user field (between URL and HIER_/NONE_ codes). */
export function findSquidAccessUsers(text: string): Finding[] {
  const findings: Finding[] = [];
  let lineStart = 0;

  while (lineStart <= text.length) {
    let lineEnd = text.indexOf("\n", lineStart);
    if (lineEnd === -1) lineEnd = text.length;
    const line = text.slice(lineStart, lineEnd);
    const hit = parseSquidUser(line);
    if (hit) {
      findings.push({
        kind: "account",
        value: hit.value,
        key: normalizeSquidUserKey(hit.value),
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

function parseSquidUser(
  line: string,
): { value: string; start: number; end: number } | null {
  // Hierarchy token is the reliable anchor.
  const hier = /\s(HIER_[A-Z_]+|NONE_[A-Z_]+)(?:\/\S*)?(?:\s|$)/.exec(line);
  if (!hier || hier.index === undefined) return null;

  // Walk back one whitespace-separated token - that's the user field.
  let end = hier.index;
  while (end > 0 && line.charCodeAt(end - 1) === 32) end -= 1;
  let start = end;
  while (start > 0 && line.charCodeAt(start - 1) !== 32) start -= 1;
  if (end <= start) return null;

  const user = line.slice(start, end);
  if (user === "-" || isSentinelValue(user)) return null;
  if (user.length < MIN_IDENTITY_LENGTH) return null;
  // Skip method verbs accidentally captured
  if (/^(GET|POST|PUT|DELETE|CONNECT|HEAD|OPTIONS|PATCH)$/i.test(user)) return null;
  if (user.includes("://")) return null;
  // Client IP landed in the user slot when the hierarchy anchor matched early
  // (`NONE_NONE/…` before the real `HIER_*` and `-` user).
  if (looksLikeIpLiteral(user)) return null;

  const decoded = user.replace(/%5[Cc]/g, "\\").replace(/%20/g, " ");
  const account = decoded.includes("\\")
    ? decoded.slice(decoded.lastIndexOf("\\") + 1)
    : decoded;
  if (!isRedactableAccount(account) && !looksLikeLogin(account)) return null;

  return { value: user, start, end };
}

function normalizeSquidUserKey(value: string): string {
  const decoded = value.replace(/%5[Cc]/gi, "\\");
  const account = decoded.includes("\\")
    ? decoded.slice(decoded.lastIndexOf("\\") + 1)
    : decoded;
  return account.toLowerCase();
}

function looksLikeLogin(value: string): boolean {
  return /^[A-Za-z0-9._+%\\-]+$/.test(value) && /[A-Za-z]/.test(value);
}

function looksLikeIpLiteral(value: string): boolean {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return true;
  // IPv6 (compressed or full) - never an account.
  if (value.includes(":") && /^[0-9a-fA-F:]+$/.test(value)) return true;
  return false;
}
