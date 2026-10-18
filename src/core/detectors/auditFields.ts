import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";
import { normalizeHostnameKey, isKeptHostname } from "../hostIdentity";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";
import { findAuthAccounts } from "./authGrammar";
import { findCliSecrets } from "./cliSecrets";
import { isValidIpv4 } from "./ipv4";
import { findUrlAuth } from "./urlAuth";

/** Linux audit/PAM fields inside msg='…' and proctitle= hex blobs. */
export function findAuditFields(text: string): Finding[] {
  return [...findAcct(text), ...findHostnameAssign(text), ...findProctitleHex(text)];
}

/** auditd proctitle=<hex>: redact blob when it embeds credentials. */
function findProctitleHex(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\bproctitle=([0-9A-Fa-f]{20,})\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const hex = m[1]!;
    const decoded = decodeHexBytes(hex);
    if (!decoded) continue;
    const hits = [
      ...findCliSecrets(decoded),
      ...findUrlAuth(decoded),
      ...findAuthAccounts(decoded),
    ];
    if (!hits.some((h) => h.decision === "replace" && (h.kind === "secret" || h.kind === "account"))) {
      continue;
    }
    const start = m.index + m[0]!.indexOf(hex);
    out.push({
      kind: "secret",
      value: hex,
      key: `proctitle:${start}`,
      span: { start, end: start + hex.length },
      decision: "replace",
    });
  }
  return out;
}

function decodeHexBytes(hex: string): string | null {
  if (hex.length % 2 !== 0) return null;
  try {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

function findAcct(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\bacct=(?:"([^"]+)"|'([^']+)'|([^\s'"=]+))/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = (m[1] ?? m[2] ?? m[3])!;
    if (!isRedactableAccount(value)) continue;
    // Prefer exact surface without quotes
    const rel = text.indexOf(value, m.index);
    if (rel < 0) continue;
    out.push({
      kind: "account",
      value,
      key: value.toLowerCase(),
      span: { start: rel, end: rel + value.length },
      decision: "replace",
    });
  }
  return out;
}

function findHostnameAssign(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /\bhostname=(?:"([^"]+)"|'([^']+)'|([^\s'"=]+))/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = (m[1] ?? m[2] ?? m[3])!;
    if (isSentinelValue(value) || value.length < MIN_IDENTITY_LENGTH) continue;
    if (isKeptHostname(value) || isValidIpv4(value)) continue;
    // Audit often puts the client IP in hostname= - leave IPs to findIpv4.
    if (/^\d/.test(value) || value.includes(":")) continue;
    const rel = text.indexOf(value, m.index);
    if (rel < 0) continue;
    out.push({
      kind: "hostname",
      value,
      key: normalizeHostnameKey(value),
      span: { start: rel, end: rel + value.length },
      decision: "replace",
    });
  }
  return out;
}
