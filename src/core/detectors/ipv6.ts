import type { Finding } from "../types";
import { findIpv4 } from "./ipv4";

/** IPv6 scan + normalize (::, zone id, [addr]:port, ::ffff:IPv4). Rejects MACs. */
export function findIpv6(text: string): Finding[] {
  const findings: Finding[] = [];
  const length = text.length;
  let i = 0;

  while (i < length) {
    // Bracketed form [2001:db8::1]:443
    if (text.charCodeAt(i) === 91 /* [ */) {
      const close = text.indexOf("]", i + 1);
      if (close !== -1) {
        const inner = text.slice(i + 1, close);
        if (!looksLikeMacRun(inner)) {
          const mapped = asMappedIpv4Finding(inner, i + 1, close);
          if (mapped) {
            findings.push(mapped);
            i = close + 1;
            continue;
          }
          const norm = normalizeIpv6(inner);
          if (norm) {
            findings.push({
              kind: "ipv6",
              value: inner,
              key: norm,
              span: { start: i + 1, end: close },
              decision: shouldKeepIpv6(norm) ? "keep" : "replace",
            });
            i = close + 1;
            continue;
          }
        }
      }
    }

    if (!isIpv6Start(text, i)) {
      i += 1;
      continue;
    }

    // Skip MAC= glued runs (UFW: dst:src:etype).
    if (hasMacFieldPrefix(text, i)) {
      i += 1;
      continue;
    }

    const parsed = readIpv6At(text, i);
    if (!parsed) {
      // Avoid O(n²) on `ab:ab:ab:…` - jump past a failed hex:colon run.
      const skipTo = skipHexColonRun(text, i);
      i = skipTo > i + 1 ? skipTo : i + 1;
      continue;
    }

    if (looksLikeMacRun(parsed.value)) {
      i = parsed.end;
      continue;
    }

    // Strict edges: `arn:aws:s3:::acmecorp` / `Time::HiRes` / `::acmecorp`.
    if (!hasStrictIpv6Boundaries(text, i, parsed.end, parsed.value)) {
      i = parsed.end > i + 1 ? parsed.end : i + 1;
      continue;
    }

    const mapped = asMappedIpv4Finding(parsed.value, i, parsed.end);
    if (mapped) {
      findings.push(mapped);
      i = parsed.end;
      continue;
    }

    findings.push({
      kind: "ipv6",
      value: parsed.value,
      key: parsed.key,
      span: { start: i, end: parsed.end },
      decision: shouldKeepIpv6(parsed.key) ? "keep" : "replace",
    });
    i = parsed.end;
  }

  return findings;
}

function skipHexColonRun(text: string, start: number): number {
  let i = start;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (isHex(c) || c === 58 /* : */ || c === 46 /* . */) {
      i += 1;
      continue;
    }
    break;
  }
  return i;
}

/** `::ffff:a.b.c.d` shares the IPv4 alias key. */
function asMappedIpv4Finding(
  value: string,
  start: number,
  end: number,
): Finding | null {
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value.trim());
  if (!m) return null;
  const v4 = m[1]!;
  const hit = findIpv4(v4)[0];
  if (!hit) return null;
  return {
    kind: "ipv4",
    value,
    key: v4,
    span: { start, end },
    decision: hit.decision,
  };
}

/** 6 octets (MAC) or 8 (MAC + EtherType 08:00) - all groups exactly 2 hex digits. */
function looksLikeMacRun(value: string): boolean {
  const parts = value.split(":");
  if (parts.length !== 6 && parts.length !== 8) return false;
  return parts.every((p) => /^[0-9a-fA-F]{2}$/.test(p));
}

function hasMacFieldPrefix(text: string, index: number): boolean {
  // Look back for `MAC=` within a short window (UFW glued form).
  const from = Math.max(0, index - 8);
  const prefix = text.slice(from, index).toLowerCase();
  return /mac=$/.test(prefix) || /mac=[0-9a-f:]*$/.test(prefix);
}

export function normalizeIpv6(raw: string): string | null {
  let s = raw.trim().toLowerCase();
  if (!s) return null;
  // Drop zone id
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);

  // IPv4-mapped ::ffff:a.b.c.d
  const v4mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  if (v4mapped) {
    const octets = v4mapped[1]!.split(".").map(Number);
    if (octets.length !== 4 || octets.some((n) => n > 255)) return null;
    const hi = ((octets[0]! << 8) | octets[1]!).toString(16);
    const lo = ((octets[2]! << 8) | octets[3]!).toString(16);
    s = `::ffff:${hi}:${lo}`;
  }

  if (!s.includes(":")) return null;
  // Must look like hex/colons (and optional already-handled v4)
  if (!/^[0-9a-f:]+$/.test(s)) return null;

  const sides = s.split("::");
  if (sides.length > 2) return null;

  const left = sides[0] ? sides[0].split(":").filter(Boolean) : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(":").filter(Boolean) : [];

  if (sides.length === 1) {
    if (left.length !== 8) return null;
  } else {
    const missing = 8 - left.length - right.length;
    if (missing < 1 && left.length + right.length !== 8) return null;
    if (missing < 0) return null;
  }

  for (const part of [...left, ...right]) {
    if (part.length === 0 || part.length > 4 || !/^[0-9a-f]+$/.test(part)) return null;
  }

  let groups: string[];
  if (sides.length === 1) {
    groups = left;
  } else {
    const missing = 8 - left.length - right.length;
    groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  }

  if (groups.length !== 8) return null;
  return groups.map((g) => g.replace(/^0+(?=\w)/, "") || "0").join(":");
}

function readIpv6At(
  text: string,
  start: number,
): { end: number; value: string; key: string } | null {
  let i = start;
  // Consume hex, colons, optional single zone or dotted v4 tail
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (isHex(c) || c === 58 /* : */) {
      i += 1;
      continue;
    }
    // IPv4 tail in mapped form
    if (c === 46 /* . */) {
      i += 1;
      continue;
    }
    if (c === 37 /* % */) {
      i += 1;
      while (i < text.length && isZoneChar(text.charCodeAt(i))) i += 1;
      break;
    }
    break;
  }

  // Trim trailing colon if we over-consumed (e.g. before port in rare forms)
  while (i > start + 1 && text.charCodeAt(i - 1) === 58 && text.charCodeAt(i - 2) !== 58) {
    // keep :: intact; only strip a single trailing :
    const slice = text.slice(start, i);
    if (slice.endsWith("::")) break;
    // If next char is digit (port without brackets), don't include trailing junk
    break;
  }

  const value = text.slice(start, i);
  // Need at least two colons to be plausibly IPv6 (or ::)
  if (!value.includes(":")) return null;
  const colonCount = (value.match(/:/g) || []).length;
  if (colonCount < 2) return null;

  const key = normalizeIpv6(value);
  if (!key) return null;

  // Reject if glued to more hex (version-like) - already bounded by read loop
  return { end: i, value, key };
}

function shouldKeepIpv6(normalized: string): boolean {
  // loopback
  if (normalized === "0:0:0:0:0:0:0:1" || normalized === "0:0:0:0:0:0:0:0") return true;
  const first = parseInt(normalized.split(":")[0]!, 16);
  // link-local fe80::/10 - redact concrete addresses (they embed MAC / host id);
  // keep only the bare router form fe80::1.
  if ((first & 0xffc0) === 0xfe80) {
    return normalized === "fe80:0:0:0:0:0:0:1";
  }
  // unique local fc00::/7
  if ((first & 0xfe00) === 0xfc00) return true;
  // multicast ff00::/8
  if ((first & 0xff00) === 0xff00) return true;
  // documentation 2001:db8::/32
  if (normalized.startsWith("2001:db8:")) return true;
  return false;
}

function isIpv6Start(text: string, i: number): boolean {
  const c = text.charCodeAt(i);
  // Never start mid-token: `objectSid::` must not yield `d::`.
  if (i > 0) {
    const prev = text.charCodeAt(i - 1);
    if (isHex(prev) || isAlpha(prev) || prev === 95 /* _ */) return false;
    // `arn:aws:s3:::bucket` - a third colon is not the start of `::`.
    if (prev === 58 /* : */) return false;
  }
  if (c === 58 /* : */) {
    // ::xxxx
    return i + 1 < text.length && text.charCodeAt(i + 1) === 58;
  }
  if (!isHex(c)) return false;
  // Look ahead for a colon soon
  for (let j = i; j < Math.min(i + 5, text.length); j += 1) {
    if (text.charCodeAt(j) === 58) return true;
    if (!isHex(text.charCodeAt(j))) return false;
  }
  return false;
}

/** Reject IPv6 lookalikes glued into identifiers (ARN, objectSid, …). */
function hasStrictIpv6Boundaries(
  text: string,
  start: number,
  end: number,
  value: string,
): boolean {
  if (start > 0) {
    const prev = text.charCodeAt(start - 1);
    if (isAlpha(prev) || isHex(prev) || prev === 95 || prev === 58) return false;
  }
  if (end < text.length) {
    const next = text.charCodeAt(end);
    // Allow zone (`%eth0`), closing bracket, CIDR `/64`, and trailing punctuation.
    if (
      next !== 37 /* % */ &&
      next !== 93 /* ] */ &&
      next !== 47 /* / */ &&
      next !== 44 /* , */ &&
      next !== 59 /* ; */ &&
      next !== 41 /* ) */
    ) {
      if (isAlpha(next) || next === 95 /* _ */) return false;
    }
  }
  // `::` + hex-word longer than 4 digits (even if we only captured 4).
  const compressed = value.indexOf("::");
  if (compressed >= 0) {
    let j = start + compressed + 2;
    let hexRun = 0;
    while (j < text.length && isHex(text.charCodeAt(j))) {
      hexRun += 1;
      if (hexRun > 4) return false;
      j += 1;
    }
  }
  return true;
}

function isAlpha(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122)
  );
}

function isHex(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 70) ||
    (code >= 97 && code <= 102)
  );
}

function isZoneChar(code: number): boolean {
  return (
    isHex(code) ||
    (code >= 71 && code <= 90) ||
    (code >= 103 && code <= 122) ||
    code === 45 ||
    code === 95
  );
}
