import type { Finding } from "../types";

const SPECIAL_KEEP = new Set([
  "0.0.0.0",
  "255.255.255.255",
  "127.0.0.1",
]);

/** Coarse IPv4 class used to keep private / public / doc ranges distinguishable. */
export type Ipv4Class =
  | "loopback"
  | "link_local"
  | "multicast"
  | "private_10"
  | "private_172"
  | "private_192"
  | "documentation"
  | "public"
  | "other";

/** True when the whole string is exactly one IPv4 address. */
export function isValidIpv4(value: string): boolean {
  const parsed = readIpv4(value, 0);
  return parsed !== null && parsed.end === value.length;
}

/** Classify an IPv4 for aliasing (RFC 1918 / 5737 / specials). */
export function classifyIpv4(value: string): Ipv4Class {
  const parsed = readIpv4(value, 0);
  if (!parsed || parsed.end !== value.length) return "other";
  const octets = parsed.value.split(".").map(Number) as [number, number, number, number];
  const [a, b] = octets;

  if (a === 127) return "loopback";
  if (a === 169 && b === 254) return "link_local";
  if (a >= 224 && a <= 239) return "multicast";
  if (a === 10) return "private_10";
  if (a === 172 && b >= 16 && b <= 31) return "private_172";
  if (a === 192 && b === 168) return "private_192";
  // RFC 5737 documentation / test nets
  if (
    (a === 192 && b === 0 && octets[2] === 2) ||
    (a === 198 && b === 51 && octets[2] === 100) ||
    (a === 203 && b === 0 && octets[2] === 113)
  ) {
    return "documentation";
  }
  if (a === 0 || (a === 255 && b === 255 && octets[2] === 255 && octets[3] === 255)) {
    return "other";
  }
  return "public";
}

/** Manual IPv4 scanner: no regex, digit/dot only, strict 0–255 octets. */
export function findIpv4(
  text: string,
  options?: { fieldPath?: string; excluded?: boolean },
): Finding[] {
  if (options?.excluded) return [];

  const findings: Finding[] = [];
  const length = text.length;
  let i = 0;

  while (i < length) {
    if (!isDigit(text.charCodeAt(i))) {
      i += 1;
      continue;
    }

    // Candidate must not be preceded by a digit or dot (avoid versions mid-token badly),
    // but versions like 10.0.19045.5555 are rejected by octet validation / trailing junk.
    const prev = i > 0 ? text.charCodeAt(i - 1) : -1;
    if (isDigit(prev) || prev === 46 /* . */) {
      i += 1;
      continue;
    }

    const start = i;
    // v1.2.3.4 / openjdk 17.0.9.1 - not addresses.
    if (isVersionContext(text, start)) {
      i += 1;
      continue;
    }

    const parsed = readIpv4(text, i);
    if (!parsed) {
      i += 1;
      continue;
    }

    const { end, value } = parsed;
    const next = end < length ? text.charCodeAt(end) : -1;
    // More address digits → reject. A trailing `.` is OK when it is sentence
    // punctuation / ellipsis (`153.` / `153...`), not a longer dotted token
    // (`10.0.0.1.5` or `1.2.3.4.foo`).
    if (isDigit(next)) {
      i = end;
      continue;
    }
    if (next === 46 /* . */) {
      const afterDot = end + 1 < length ? text.charCodeAt(end + 1) : -1;
      if (isDigit(afterDot) || isAlpha(afterDot)) {
        i = end;
        continue;
      }
    }
    // CIDR / range labels: `10.0.0.0-10.255.255.255` or `10.0.0.0/8`
    if (next === 45 /* - */ && end + 1 < length && isDigit(text.charCodeAt(end + 1))) {
      i = end;
      continue;
    }
    if (prev === 45 /* - */ && start >= 2 && isDigit(text.charCodeAt(start - 2))) {
      i = end;
      continue;
    }
    // CSV structural probe: `;;;;45.33.32.156;` (three empty fields).
    if (start >= 4 && text.slice(start - 4, start) === ";;;;") {
      i = end;
      continue;
    }

    const decision = shouldKeepIpv4(value) ? "keep" : "replace";
    findings.push({
      kind: "ipv4",
      value,
      key: value,
      span: { start, end },
      decision,
      ...(options?.fieldPath !== undefined ? { fieldPath: options.fieldPath } : {}),
    });
    i = end;
  }

  return findings;
}

function readIpv4(
  text: string,
  start: number,
): { end: number; value: string } | null {
  let i = start;
  const octets: number[] = [];

  for (let part = 0; part < 4; part += 1) {
    if (part > 0) {
      if (text.charCodeAt(i) !== 46 /* . */) return null;
      i += 1;
    }

    if (i >= text.length || !isDigit(text.charCodeAt(i))) return null;

    let value = 0;
    let digits = 0;
    // Disallow leading zeros except a single 0.
    const leading = text.charCodeAt(i);
    while (i < text.length && isDigit(text.charCodeAt(i)) && digits < 3) {
      value = value * 10 + (text.charCodeAt(i) - 48);
      digits += 1;
      i += 1;
    }

    if (digits === 0 || value > 255) return null;
    if (digits > 1 && leading === 48 /* 0 */) return null;
    octets.push(value);
  }

  return {
    end: i,
    value: octets.join("."),
  };
}

function shouldKeepIpv4(value: string): boolean {
  if (SPECIAL_KEEP.has(value)) return true;
  if (value.startsWith("127.")) return true;
  if (value.startsWith("169.254.")) return true;
  // Subnet masks (`255.255.255.0`) - not host addresses.
  if (value.startsWith("255.")) return true;
  const first = Number(value.slice(0, value.indexOf(".")));
  // Multicast 224–239
  if (first >= 224 && first <= 239) return true;
  return false;
}

/** Reject `v1.2.3.4`, `jdk 17.0.9.1`, `kernel=5.15.0.1`-style matches. */
function isVersionContext(text: string, start: number): boolean {
  const prev = start > 0 ? text.charCodeAt(start - 1) : -1;
  // Attached letter: v1.2.3.4, jdk17.0.0.1
  if (isAlpha(prev)) return true;

  // Image tags / semver after colon: `crm:3.12.4.1` (not `::ffff:10.1.2.3`).
  if (prev === 58 /* : */ && start >= 2) {
    const beforeColon = text.charCodeAt(start - 2);
    if (isAlphaNum(beforeColon) && !isHexOnlyRunBefore(text, start - 1)) {
      return true;
    }
  }

  // UA products: MacOutlook/16.78.0.230, Chrome/118 - not HIER_DIRECT/1.2.3.4
  if (prev === 47 /* / */ && isUaProductSlash(text, start)) return true;

  // Previous word: openjdk 17.0.9.1 / version 1.2.3.4 / APP_VERSION=
  let i = start - 1;
  while (i >= 0 && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) i -= 1;
  if (i < 0) return false;
  // Skip `=` so `APP_VERSION=3.12.4.1` resolves the key word.
  if (text.charCodeAt(i) === 61 /* = */) {
    i -= 1;
    while (i >= 0 && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) i -= 1;
  }
  if (i < 0) return false;
  const wordEnd = i + 1;
  while (i >= 0 && (isAlpha(text.charCodeAt(i)) || text.charCodeAt(i) === 95 /* _ */)) {
    i -= 1;
  }
  const word = text.slice(i + 1, wordEnd).toLowerCase();

  return (
    word === "v" ||
    word === "ver" ||
    word === "version" ||
    word.endsWith("_version") ||
    word.endsWith("version") ||
    word === "jdk" ||
    word === "openjdk" ||
    word === "java" ||
    word === "kernel" ||
    word === "chrome" ||
    word === "firefox" ||
    word === "windows" ||
    word === "nt"
  );
}

/** `MacOutlook/16…` - product token without `_` immediately before `/`. */
function isUaProductSlash(text: string, ipStart: number): boolean {
  let k = ipStart - 2;
  while (k >= 0 && isIdentChar(text.charCodeAt(k))) k -= 1;
  const word = text.slice(k + 1, ipStart - 1);
  if (word.length < 2 || word.includes("_")) return false;
  return /^[A-Za-z][A-Za-z0-9.-]*$/.test(word);
}

/** True when the run before `:` is 1–4 hex digits (`ffff` in `::ffff:a.b.c.d`). */
function isHexOnlyRunBefore(text: string, colonIdx: number): boolean {
  let k = colonIdx - 1;
  while (k >= 0 && isHex(text.charCodeAt(k))) k -= 1;
  const run = text.slice(k + 1, colonIdx);
  return /^[0-9a-fA-F]{1,4}$/.test(run);
}

function isAlphaNum(code: number): boolean {
  return isAlpha(code) || isDigit(code);
}

function isIdentChar(code: number): boolean {
  return isAlphaNum(code) || code === 95 /* _ */ || code === 45 /* - */ || code === 46 /* . */;
}

function isHex(code: number): boolean {
  return (
    isDigit(code) ||
    (code >= 65 && code <= 70) ||
    (code >= 97 && code <= 102)
  );
}

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

function isAlpha(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}
