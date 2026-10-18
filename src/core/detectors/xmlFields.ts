import type { Finding } from "../types";
import { classifyField, type FieldKind } from "../../rules/fieldRules";
import { isRedactableAccount } from "../accounts";
import {
  isKeptHostname,
  isMachineAccount,
  normalizeHostnameKey,
} from "../hostIdentity";
import { normalizePersonNameKey } from "../personName";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";
import { isValidEmail } from "./email";
import { findIpv4, isValidIpv4 } from "./ipv4";
import { normalizeIpv6 } from "./ipv6";

/** Windows Event XML: Computer tags and Data Name="X" fields. */
export function findXmlFields(text: string): Finding[] {
  if (!/<[A-Za-z]/.test(text) || !text.includes("</")) return [];
  const out: Finding[] = [];

  // <Computer>fqdn</Computer>
  const computer = /<Computer>([^<]+)<\/Computer>/gi;
  let m: RegExpExecArray | null;
  while ((m = computer.exec(text)) !== null) {
    const value = m[1]!.trim();
    if (!value || isSentinelValue(value) || isKeptHostname(value)) continue;
    const start = m.index + m[0]!.indexOf(value);
    out.push({
      kind: "hostname",
      value,
      key: normalizeHostnameKey(value),
      span: { start, end: start + value.length },
      decision: "replace",
    });
  }

  // <Data Name="Field">value</Data>
  const data = /<Data\s+Name="([^"]+)">([^<]*)<\/Data>/gi;
  while ((m = data.exec(text)) !== null) {
    const field = m[1]!;
    const value = m[2]!;
    if (!value || isSentinelValue(value)) continue;
    const verdict = classifyField([field]);
    if (!verdict || verdict.type === "protected") continue;
    const kind =
      verdict.type === "detect"
        ? verdict.kind
        : verdict.type === "ambiguous"
          ? verdict.fallback
          : null;
    if (!kind) continue;
    const start = m.index + m[0]!.lastIndexOf(value);
    const hit = resolveXmlValue(kind, value, start);
    if (hit) out.push(hit);
  }

  // Bare machine accounts HOST$ anywhere in XML text
  const mach = /\b([A-Za-z0-9][A-Za-z0-9._-]{1,62}\$)\b/g;
  while ((m = mach.exec(text)) !== null) {
    const value = m[1]!;
    if (!isMachineAccount(value)) continue;
    out.push({
      kind: "hostname",
      value,
      key: normalizeHostnameKey(value),
      span: { start: m.index, end: m.index + value.length },
      decision: "replace",
    });
  }

  return out;
}

function resolveXmlValue(
  kind: FieldKind,
  value: string,
  start: number,
): Finding | null {
  const end = start + value.length;
  if (isMachineAccount(value)) {
    return {
      kind: "hostname",
      value,
      key: normalizeHostnameKey(value),
      span: { start, end },
      decision: "replace",
    };
  }
  switch (kind) {
    case "account": {
      // DOMAIN\user → same alias key as the bare login.
      const slash = value.lastIndexOf("\\");
      let account = slash >= 0 ? value.slice(slash + 1) : value;
      // UPN `user@realm` → email (shares compte-NN with bare login via alias factory).
      if (isValidEmail(account)) {
        return {
          kind: "email",
          value: account,
          key: account.toLowerCase(),
          span: {
            start: slash >= 0 ? start + slash + 1 : start,
            end,
          },
          decision: "replace",
        };
      }
      const at = account.indexOf("@");
      if (at > 0) account = account.slice(0, at);
      if (!isRedactableAccount(account)) return null;
      return {
        kind: "account",
        value: account,
        key: account.toLowerCase(),
        span: {
          start: slash >= 0 ? start + slash + 1 : start,
          end: slash >= 0 ? end : start + account.length,
        },
        decision: "replace",
      };
    }
    case "person_name":
      if (value.length < MIN_IDENTITY_LENGTH) return null;
      return {
        kind: "person_name",
        value,
        key: normalizePersonNameKey(value),
        span: { start, end },
        decision: "replace",
      };
    case "hostname":
      if (isKeptHostname(value)) return null;
      return {
        kind: "hostname",
        value,
        key: normalizeHostnameKey(value),
        span: { start, end },
        decision: "replace",
      };
    case "ip":
      if (isValidIpv4(value)) {
        const d = findIpv4(value)[0]?.decision ?? "replace";
        return { kind: "ipv4", value, key: value, span: { start, end }, decision: d };
      }
      {
        const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
        if (mapped) {
          return {
            kind: "ipv4",
            value,
            key: mapped[1]!,
            span: { start, end },
            decision: "replace",
          };
        }
      }
      if (normalizeIpv6(value)) {
        return {
          kind: "ipv6",
          value,
          key: normalizeIpv6(value)!,
          span: { start, end },
          decision: "replace",
        };
      }
      return null;
    case "email":
      if (!isValidEmail(value)) return null;
      return {
        kind: "email",
        value,
        key: value.toLowerCase(),
        span: { start, end },
        decision: "replace",
      };
    default:
      return null;
  }
}
