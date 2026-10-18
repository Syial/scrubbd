import type { Finding } from "../types";
import {
  normalizeHostnameKey,
  isKeptHostname,
  isPublicInternetHostname,
} from "../hostIdentity";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";

/** DHCP/DNS hostnames at end of line or in length-prefixed DNS labels. */
export function findDhcpHosts(text: string): Finding[] {
  return [...findDhcpAckNames(text), ...findDnsLengthLabels(text)];
}

function findDhcpAckNames(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /\bDHCP(?:ACK|OFFER|REQUEST)\([^)]*\)\s+\S+\s+\S+(?:\s+(\S+))?/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1];
    if (!value || isSentinelValue(value) || isKeptHostname(value)) continue;
    if (value.length < MIN_IDENTITY_LENGTH) continue;
    if (/^\d/.test(value) || value.includes(":") && !value.includes(".")) continue;
    // MAC addresses look like aa:bb:…
    if (/^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/.test(value)) continue;
    const start = m.index + m[0]!.length - value.length;
    out.push({
      kind: "hostname",
      value,
      key: normalizeHostnameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }
  return out;
}

/** Windows DNS packet dump: `(11)lmoreau-pc(8)fakecorp(5)local(0)` */
function findDnsLengthLabels(text: string): Finding[] {
  const out: Finding[] = [];
  // Collect consecutive length-prefixed labels on one line, then decide.
  const lineRe = /(?:\(\d+\)[A-Za-z0-9][A-Za-z0-9_-]*){2,}/g;
  let block: RegExpExecArray | null;
  while ((block = lineRe.exec(text)) !== null) {
    const chunk = block[0]!;
    const labels: Array<{ value: string; start: number }> = [];
    const partRe = /\((\d+)\)([A-Za-z0-9][A-Za-z0-9_-]*)/g;
    let m: RegExpExecArray | null;
    while ((m = partRe.exec(chunk)) !== null) {
      const len = Number(m[1]);
      const value = m[2]!;
      // Some dumps mis-count by 1; accept exact or ±1 when bounded by `(`.
      if (Math.abs(value.length - len) > 1) continue;
      labels.push({
        value,
        start: block.index + m.index + m[0]!.length - value.length,
      });
    }
    if (labels.length < 2) continue;
    // Rebuild FQDN to detect public hosts: github.com / www.google.com
    const fqdn = labels.map((l) => l.value).join(".");
    if (isPublicInternetHostname(fqdn) || /\.(com|net|org|io)$/i.test(fqdn)) {
      continue;
    }
    for (const lab of labels) {
      if (lab.value.length < MIN_IDENTITY_LENGTH) continue;
      if (/^(com|net|org|local|arpa|in-addr)$/i.test(lab.value)) continue;
      if (isKeptHostname(lab.value)) continue;
      out.push({
        kind: "hostname",
        value: lab.value,
        key: normalizeHostnameKey(lab.value),
        span: { start: lab.start, end: lab.start + lab.value.length },
        decision: "replace",
      });
    }
  }
  return out;
}
