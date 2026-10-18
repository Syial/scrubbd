import { foldCase } from "../fold";
import type { Finding } from "../types";
import { isKeptHostname, normalizeHostnameKey } from "../hostIdentity";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";

const INTERNAL_SUFFIXES = [".local", ".lan", ".internal", ".corp", ".intranet"];

/** Hostnames in UNC/URLs/FQDNs → hote-NN (same key as agent.name). */
export function findHostsInText(text: string): Finding[] {
  return [
    ...findUncHosts(text),
    ...findUrlHosts(text),
    ...findInternalFqdn(text),
    ...findAwsEc2Hosts(text),
  ];
}

/** EC2 public DNS embeds IPv4 as hyphenated octets; redact the whole label. */
function findAwsEc2Hosts(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /\bec2-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\.[a-z0-9-]+\.compute\.amazonaws\.com\b/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[0]!;
    pushHost(out, value, m.index, m.index + value.length);
  }
  return out;
}

/** `\\srv-compta-01\partage` or JSON-escaped `\\\\srv-compta-01\\partage` */
function findUncHosts(text: string): Finding[] {
  const out: Finding[] = [];
  let i = 0;
  while (i < text.length - 1) {
    // Raw UNC \\host\ or encoded \\\\host\\
    const enc = text.startsWith("\\\\\\\\", i);
    const raw = !enc && text.startsWith("\\\\", i);
    if (!raw && !enc) {
      i += 1;
      continue;
    }
    // Reject Windows drive paths: `C:\Program` / JSON `C:\\Program`
    if (isDrivePathPrefix(text, i)) {
      i += 1;
      continue;
    }
    // UNC must sit at a token boundary (start, whitespace, quote, `=`).
    if (i > 0 && !isUncBoundary(text.charCodeAt(i - 1))) {
      i += 1;
      continue;
    }
    const prefixLen = enc ? 4 : 2;
    const hostStart = i + prefixLen;
    let j = hostStart;
    while (j < text.length && isHostChar(text.charCodeAt(j))) j += 1;
    if (j > hostStart) {
      const value = text.slice(hostStart, j);
      pushHost(out, value, hostStart, j);
    }
    i = Math.max(j, i + 1);
  }
  return out;
}

function isDrivePathPrefix(text: string, uncIndex: number): boolean {
  // `X:` immediately before the backslashes
  if (uncIndex >= 2) {
    const c0 = text.charCodeAt(uncIndex - 2);
    const c1 = text.charCodeAt(uncIndex - 1);
    if (c1 === 58 /* : */ && isLetter(c0)) return true;
  }
  return false;
}

function isUncBoundary(code: number): boolean {
  return (
    code === 32 ||
    code === 9 ||
    code === 10 ||
    code === 13 ||
    code === 34 /* " */ ||
    code === 39 /* ' */ ||
    code === 61 /* = */ ||
    code === 58 /* : */ || // `Z: \\host` after space is handled; bare `:` rare
    code === 44 /* , */
  );
}

function isLetter(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

/** `https://intranet.fakecorp.local/api` - host after :// (skip userinfo). */
function findUrlHosts(text: string): Finding[] {
  const out: Finding[] = [];
  let from = 0;
  while (from < text.length) {
    const scheme = text.indexOf("://", from);
    if (scheme === -1) break;
    let i = scheme + 3;
    // Skip userinfo
    const slash = text.indexOf("/", i);
    const lim = slash === -1 ? text.length : slash;
    const at = text.indexOf("@", i);
    if (at !== -1 && at < lim) i = at + 1;

    // Optional [ipv6]
    if (text.charCodeAt(i) === 91 /* [ */) {
      from = scheme + 3;
      continue;
    }

    const hostStart = i;
    while (i < text.length && isHostChar(text.charCodeAt(i))) i += 1;
    if (i > hostStart) {
      const host = text.slice(hostStart, i);
      // Only internal hosts - never rewrite public URLs (github.com, fortinet.com, …).
      if (isInternalHostname(host)) {
        pushHost(out, host, hostStart, i);
      }
    }
    from = Math.max(i, scheme + 3);
  }
  return out;
}

/** Bare internal FQDNs with known suffixes. */
function findInternalFqdn(text: string): Finding[] {
  const out: Finding[] = [];
  const lower = foldCase(text);
  for (const suffix of INTERNAL_SUFFIXES) {
    let from = 0;
    while (from < text.length) {
      const idx = lower.indexOf(suffix, from);
      if (idx === -1) break;
      // Expand left to start of hostname
      let start = idx;
      while (start > 0 && isHostChar(text.charCodeAt(start - 1))) start -= 1;
      const end = idx + suffix.length;
      // Must not be glued to more hostname chars on the right
      if (end < text.length && isHostChar(text.charCodeAt(end))) {
        from = end;
        continue;
      }
      if (start < idx) {
        const value = text.slice(start, end);
        // Avoid double-counting URL/UNC hits: still OK - mergeNonOverlapping dedupes.
        pushHost(out, value, start, end);
      }
      from = end;
    }
  }
  return out;
}

function pushHost(
  out: Finding[],
  value: string,
  start: number,
  end: number,
): void {
  if (value.length < MIN_IDENTITY_LENGTH) return;
  if (isSentinelValue(value)) return;
  if (isKeptHostname(value)) return;
  // Skip pure IPv4
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return;
  // DNS SRV / underscore service labels: `_ldap._tcp.dc._msdcs…`
  if (value.startsWith("_") || value.includes("._")) return;
  // Public eTLD hosts (github.com, etc.) - only internal FQDNs from this path,
  // except AWS EC2 public DNS which embeds a public IP in the label.
  const lower = value.toLowerCase();
  if (
    !isInternalHostname(value) &&
    value.includes(".") &&
    !lower.includes(".compute.amazonaws.com")
  ) {
    return;
  }
  out.push({
    kind: "hostname",
    value,
    key: normalizeHostnameKey(value),
    span: { start, end },
    decision: "replace",
  });
}

function isInternalHostname(host: string): boolean {
  const lower = host.toLowerCase();
  return INTERNAL_SUFFIXES.some((s) => lower.endsWith(s));
}

function isHostChar(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 45 /* - */ ||
    code === 46 /* . */ ||
    code === 95 /* _ */
  );
}
