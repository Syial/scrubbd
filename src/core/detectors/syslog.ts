import type { Finding } from "../types";
import { isKeptHostname, normalizeHostnameKey } from "../hostIdentity";

const MONTHS = new Set([
  "jan",
  "feb",
  "mar",
  "apr",
  "may",
  "jun",
  "jul",
  "aug",
  "sep",
  "oct",
  "nov",
  "dec",
]);

/** Classic syslog positional hostname. */
export function findSyslogHosts(text: string): Finding[] {
  const findings: Finding[] = [];
  let lineStart = 0;

  while (lineStart <= text.length) {
    let lineEnd = text.indexOf("\n", lineStart);
    if (lineEnd === -1) lineEnd = text.length;
    const line = text.slice(lineStart, lineEnd);
    const host = readSyslogHost(line);
    if (host) {
      const value = host.value;
      if (!isKeptHostname(value)) {
        findings.push({
          kind: "hostname",
          value,
          key: normalizeHostnameKey(value),
          span: {
            start: lineStart + host.start,
            end: lineStart + host.end,
          },
          decision: "replace",
        });
      }
    }
    if (lineEnd >= text.length) break;
    lineStart = lineEnd + 1;
  }

  return findings;
}

function readSyslogHost(
  line: string,
): { start: number; end: number; value: string } | null {
  // Optional leading spaces
  let i = 0;
  while (i < line.length && (line.charCodeAt(i) === 32 || line.charCodeAt(i) === 9)) {
    i += 1;
  }
  // Month (3 letters)
  if (i + 3 > line.length) return null;
  const month = line.slice(i, i + 3).toLowerCase();
  if (!MONTHS.has(month)) return null;
  i += 3;
  if (line.charCodeAt(i) !== 32) return null;
  i += 1;
  // Day (1–2 digits, space-padded)
  while (i < line.length && line.charCodeAt(i) === 32) i += 1;
  if (!isDigit(line.charCodeAt(i))) return null;
  while (i < line.length && isDigit(line.charCodeAt(i))) i += 1;
  if (line.charCodeAt(i) !== 32) return null;
  i += 1;
  // Optional year: `Oct 14 2026 08:01:12` (Cisco ASA)
  if (
    isDigit(line.charCodeAt(i)) &&
    isDigit(line.charCodeAt(i + 1)) &&
    isDigit(line.charCodeAt(i + 2)) &&
    isDigit(line.charCodeAt(i + 3)) &&
    line.charCodeAt(i + 4) === 32
  ) {
    i += 5;
  }
  // hh:mm:ss
  if (!isDigit(line.charCodeAt(i)) || !isDigit(line.charCodeAt(i + 1))) return null;
  if (line.charCodeAt(i + 2) !== 58) return null;
  if (!isDigit(line.charCodeAt(i + 3)) || !isDigit(line.charCodeAt(i + 4))) return null;
  if (line.charCodeAt(i + 5) !== 58) return null;
  if (!isDigit(line.charCodeAt(i + 6)) || !isDigit(line.charCodeAt(i + 7))) return null;
  i += 8;
  if (line.charCodeAt(i) !== 32) return null;
  i += 1;
  const start = i;
  while (i < line.length && isHostChar(line.charCodeAt(i))) i += 1;
  if (i <= start) return null;
  // Next should be space then tag
  if (i < line.length && line.charCodeAt(i) !== 32) return null;
  return { start, end: i, value: line.slice(start, i) };
}

function isHostChar(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 45 ||
    code === 46 ||
    code === 95
  );
}

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}
