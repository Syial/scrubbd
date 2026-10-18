import type { Finding } from "../types";

/** Whole-string MAC check. Separators `:`, `-`, `.` (pairs) or Cisco `xxxx.xxxx.xxxx`. */
export function isValidMac(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed !== value) return false;
  return parseMac(trimmed) !== null;
}

/** Scan free text for MAC addresses (including glued MAC=dst:src:etype runs). */
export function findMac(text: string): Finding[] {
  const findings: Finding[] = [];
  const length = text.length;
  let i = 0;

  while (i < length) {
    const code = text.charCodeAt(i);
    if (!isHex(code)) {
      i += 1;
      continue;
    }
    const prev = i > 0 ? text.charCodeAt(i - 1) : -1;
    if (isHex(prev)) {
      i += 1;
      continue;
    }

    const ciscoSlice = text.slice(i, i + 14);
    if (ciscoSlice.length === 14) {
      const key = parseCiscoMac(ciscoSlice);
      if (key) {
        findings.push({
          kind: "mac",
          value: ciscoSlice,
          key,
          span: { start: i, end: i + 14 },
          decision: "replace",
        });
        i += 14;
        continue;
      }
    }

    const run = readHexPairRun(text, i);
    if (!run) {
      i += 1;
      continue;
    }

    // Plain MAC: exactly 6 pairs.
    if (run.octets.length === 6) {
      findings.push({
        kind: "mac",
        value: text.slice(i, run.end),
        key: run.octets.join(":"),
        span: { start: i, end: run.end },
        decision: "replace",
      });
      i = run.end;
      continue;
    }

    // UFW glued `MAC=dst:src:etype` - 14 pairs (6 + 6 + 2 EtherType).
    if (run.octets.length === 14) {
      const sep = String.fromCharCode(run.sep);
      const dst = run.octets.slice(0, 6).join(sep);
      const src = run.octets.slice(6, 12).join(sep);
      const dstEnd = i + 6 * 2 + 5; // 6 pairs, 5 seps
      const srcStart = dstEnd + 1;
      const srcEnd = srcStart + 6 * 2 + 5;
      findings.push({
        kind: "mac",
        value: dst,
        key: run.octets.slice(0, 6).join(":"),
        span: { start: i, end: dstEnd },
        decision: "replace",
      });
      findings.push({
        kind: "mac",
        value: src,
        key: run.octets.slice(6, 12).join(":"),
        span: { start: srcStart, end: srcEnd },
        decision: "replace",
      });
      // Skip past EtherType too so IPv6 does not claim `08:00`.
      i = run.end;
      continue;
    }

    i += 1;
  }

  return findings;
}

function parseMac(value: string): string | null {
  const cisco = parseCiscoMac(value);
  if (cisco) return cisco;
  const run = readHexPairRun(value, 0);
  if (!run || run.end !== value.length || run.octets.length !== 6) return null;
  return run.octets.join(":");
}

function parseCiscoMac(value: string): string | null {
  if (value.length !== 14) return null;
  if (value.charCodeAt(4) !== 46 || value.charCodeAt(9) !== 46) return null;
  const parts = [value.slice(0, 4), value.slice(5, 9), value.slice(10, 14)];
  for (const part of parts) {
    for (let i = 0; i < 4; i += 1) {
      if (!isHex(part.charCodeAt(i))) return null;
    }
  }
  const hex = (parts[0]! + parts[1]! + parts[2]!).toLowerCase();
  return `${hex.slice(0, 2)}:${hex.slice(2, 4)}:${hex.slice(4, 6)}:${hex.slice(6, 8)}:${hex.slice(8, 10)}:${hex.slice(10, 12)}`;
}

/** Read a maximal run of `xx:xx:…` (or `-` / `.`) hex pairs. */
function readHexPairRun(
  text: string,
  start: number,
): { end: number; sep: number; octets: string[] } | null {
  let i = start;
  let sep: number | null = null;
  const octets: string[] = [];

  for (let n = 0; n < 16; n += 1) {
    if (n > 0) {
      if (i >= text.length) break;
      const c = text.charCodeAt(i);
      if (c !== 58 && c !== 45 && c !== 46) break;
      if (sep === null) sep = c;
      else if (c !== sep) break;
      i += 1;
    }
    if (i + 1 >= text.length) break;
    if (!isHex(text.charCodeAt(i)) || !isHex(text.charCodeAt(i + 1))) break;
    // Exactly 2 hex digits per octet.
    if (
      i + 2 < text.length &&
      isHex(text.charCodeAt(i + 2)) &&
      (n === 0 || text.charCodeAt(i + 2) !== sep)
    ) {
      if (n === 0) return null;
      break;
    }
    octets.push(text.slice(i, i + 2).toLowerCase());
    i += 2;
  }

  if (sep === null || octets.length < 6) return null;
  // Reject if this run is a suffix of a longer colon-hex sequence.
  if (
    start >= 3 &&
    text.charCodeAt(start - 1) === sep &&
    isHex(text.charCodeAt(start - 2)) &&
    isHex(text.charCodeAt(start - 3))
  ) {
    return null;
  }
  // Accept plain MAC (6) or UFW dst+src+etype (14). Other lengths are noise.
  if (octets.length !== 6 && octets.length !== 14) return null;
  return { end: i, sep, octets };
}

function isHex(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 70) ||
    (code >= 97 && code <= 102)
  );
}
