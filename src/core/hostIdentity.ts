import { isSentinelValue, MIN_IDENTITY_LENGTH } from "./sentinels";

/** Normalize host / machine-account tokens for coherent aliasing. */
export function normalizeHostnameKey(value: string): string {
  let v = value.trim().toLowerCase();
  if (v.endsWith("$")) v = v.slice(0, -1);
  const dot = v.indexOf(".");
  if (dot > 0) v = v.slice(0, dot);
  return v;
}

/** Windows machine account: `PC-COMPTA-07$`. */
export function isMachineAccount(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 3 || !trimmed.endsWith("$")) return false;
  const body = trimmed.slice(0, -1);
  if (isSentinelValue(body) || body.length < MIN_IDENTITY_LENGTH) return false;
  // Must look like a hostname body, not a person (no spaces).
  return !/\s/.test(body) && /^[A-Za-z0-9._-]+$/.test(body);
}

const INTERNAL_SUFFIXES = [".local", ".lan", ".internal", ".corp", ".intranet"];

/** Well-known public registrable labels (github.com, www.google.com, …). */
const PUBLIC_APEX = new Set([
  "github",
  "google",
  "googleapis",
  "gstatic",
  "microsoft",
  "live",
  "office",
  "office365",
  "microsoftonline",
  "windows",
  "windowsupdate",
  "amazonaws",
  "aws",
  "azure",
  "cloudflare",
  "fastly",
  "akamai",
  "example",
  "slack",
  "facebook",
  "apple",
  "icloud",
]);

const MONTH_HOSTS = new Set([
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

const WINDOWS_AUTHORITY = new Set(
  [
    "nt authority",
    "nt service",
    "font driver host",
    "window manager",
    "iis apppool",
    "builtin",
  ].map((s) => s.toLowerCase()),
);

export function isKeptHostname(value: string): boolean {
  const trimmed = value.trim();
  const n = normalizeHostnameKey(value);
  if (
    n === "localhost" ||
    n === "localhost.localdomain" ||
    n === "ip6-localhost" ||
    n === "ip6-loopback"
  ) {
    return true;
  }
  // Windows well-known authorities / built-in domains - never hosts.
  if (WINDOWS_AUTHORITY.has(trimmed.toLowerCase())) return true;
  if (WINDOWS_AUTHORITY.has(n)) return true;
  // AD NetBIOS domain (`FAKECORP`, `CONTOSO`) - org label, not a machine.
  // Keep so DOMAIN\user stays coherent and matches CEF `domain=FAKECORP`.
  if (/^[A-Z][A-Z0-9]{2,15}$/.test(trimmed) && !/\d/.test(trimmed)) {
    return true;
  }
  // Never treat calendar month abbreviations as hostnames.
  if (MONTH_HOSTS.has(n)) return true;
  // EC2 public DNS embeds the IPv4 as hyphenated octets - must be redacted.
  if (isAwsEc2IpHostname(value)) return false;
  return isPublicInternetHostname(value);
}

/** EC2 public DNS embeds IPv4 as hyphenated octets; redact the label. */
export function isAwsEc2IpHostname(value: string): boolean {
  return /^ec2-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.[a-z0-9.-]+\.compute\.amazonaws\.com$/i.test(
    value.trim(),
  );
}

/** True for well-known public internet hosts that must stay readable. */
export function isPublicInternetHostname(value: string): boolean {
  const lower = value.trim().toLowerCase();
  if (!lower.includes(".")) return false;
  if (INTERNAL_SUFFIXES.some((s) => lower.endsWith(s))) return false;
  if (isAwsEc2IpHostname(lower)) return false;
  const parts = lower.split(".").filter(Boolean);
  if (parts.length < 2) return false;
  // github.com / www.google.com → registrable label is second-to-last for
  // common single-part TLDs (com/org/net/…).
  const apex = parts.length === 2 ? parts[0]! : parts[parts.length - 2]!;
  return PUBLIC_APEX.has(apex);
}

/** Group / role CN without a person name shape: `Comptabilite-RW`. */
export function isGroupLikeCn(value: string): boolean {
  const trimmed = value.trim();
  if (/\s/.test(trimmed)) return false;
  if (/-(?:RW|RO|R|W|ALL|USERS|ADMINS?|GROUP)$/i.test(trimmed)) return true;
  if (/^(Users|Computers|Builtin|Group|Domain Controllers)$/i.test(trimmed)) {
    return true;
  }
  return false;
}
