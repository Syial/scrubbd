import { classifyField } from "../../rules/fieldRules";
import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";
import { normalizeHostnameKey, isKeptHostname } from "../hostIdentity";
import { normalizePersonNameKey } from "../personName";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";
import { isHostnameStopword, isPersonNameStopword } from "../stopwords";
import { isValidEmail } from "./email";
import { findIpv4, isValidIpv4 } from "./ipv4";
import { isPhoneValue } from "./phone";

/** CEF/LEEF key=value extensions; parse per line (values may hold spaces). */
export function findCefFields(text: string): Finding[] {
  if (!/\b(?:CEF:|LEEF:)/i.test(text) && !/\bsuser=/.test(text)) return [];
  const out: Finding[] = [];
  let lineStart = 0;
  while (lineStart <= text.length) {
    let lineEnd = text.indexOf("\n", lineStart);
    if (lineEnd === -1) lineEnd = text.length;
    out.push(...findCefFieldsInLine(text, lineStart, lineEnd));
    if (lineEnd >= text.length) break;
    lineStart = lineEnd + 1;
  }
  return out;
}

function findCefFieldsInLine(
  text: string,
  lineStart: number,
  lineEnd: number,
): Finding[] {
  const out: Finding[] = [];
  const line = text.slice(lineStart, lineEnd);
  if (!line.includes("=")) return out;

  const keyRe = /(?:^|[\s|^])([A-Za-z][A-Za-z0-9_.]*)=/g;
  const keys: Array<{ field: string; valueStart: number; keyIdx: number }> = [];
  let km: RegExpExecArray | null;
  while ((km = keyRe.exec(line)) !== null) {
    keys.push({
      field: km[1]!,
      valueStart: km.index + km[0]!.length,
      keyIdx: km.index + km[0]!.length - km[1]!.length - 1,
    });
  }

  for (let i = 0; i < keys.length; i += 1) {
    const { field, valueStart: localStart } = keys[i]!;
    const localEnd =
      i + 1 < keys.length
        ? boundaryBeforeKey(line, keys[i + 1]!.keyIdx)
        : line.length;
    let surface = line.slice(localStart, localEnd).replace(/[\s^]+$/u, "");
    const raw = surface.replace(/\\=/g, "=");
    if (!raw || isSentinelValue(raw)) continue;

    const valueStart = lineStart + localStart;
    const verdict = classifyField([field]);
    if (verdict && verdict.type !== "protected") {
      const kind =
        verdict.type === "detect"
          ? verdict.kind
          : verdict.type === "ambiguous"
            ? verdict.fallback
            : null;
      if (kind) {
        const hit = toFinding(
          kind,
          raw,
          surface,
          valueStart,
          valueStart + surface.length,
        );
        if (hit) out.push(hit);
      }
    }

    // LEEF `resource=srv-files01` (not K8s objectRef.resource types).
    if (/^resource$/i.test(field) && looksLikeHostToken(raw)) {
      const hit = toFinding(
        "hostname",
        raw,
        surface,
        valueStart,
        valueStart + surface.length,
      );
      if (hit) out.push(hit);
    }

    // Free-text person names / hosts inside msg= (even when msg has no field rule).
    if (/^(msg|reason|message)$/i.test(field)) {
      out.push(...findNamesInProse(raw, surface, valueStart));
      out.push(...findHostsInProse(raw, surface, valueStart));
    }

    // Embedded `pass=…` / `password=…` / `pass\=…` inside extension values.
    const pass = /(?:pass|password)\\?=([^\s|^\\]+)/i.exec(raw);
    if (pass) {
      const secretVal = pass[1]!;
      const rel = surface.toLowerCase().lastIndexOf(secretVal.toLowerCase());
      if (rel >= 0) {
        out.push({
          kind: "secret",
          value: surface.slice(rel, rel + secretVal.length),
          key: `cefpass:${secretVal}`,
          span: {
            start: valueStart + rel,
            end: valueStart + rel + secretVal.length,
          },
          decision: "replace",
        });
      }
    }

    // GPS pair in any custom field value.
    if (/^-?\d{1,3}\.\d+,-?\d{1,3}\.\d+$/.test(raw.trim())) {
      const trimmed = surface.trim();
      const rel = surface.indexOf(trimmed);
      out.push({
        kind: "geo",
        value: trimmed,
        key: raw.trim(),
        span: {
          start: valueStart + rel,
          end: valueStart + rel + trimmed.length,
        },
        decision: "replace",
      });
    }
  }
  return out;
}

function boundaryBeforeKey(text: string, keyIdx: number): number {
  // keyIdx points at first letter of next key; walk back over separators.
  let i = keyIdx;
  while (i > 0 && (text.charCodeAt(i - 1) === 32 || text.charCodeAt(i - 1) === 94 /* ^ */)) {
    i -= 1;
  }
  return i;
}

function findNamesInProse(raw: string, surface: string, valueStart: number): Finding[] {
  const out: Finding[] = [];
  // `user Léa Moreau from` / `for Léa Moreau`
  const re =
    /\b(?:user|utilisateur|for|par)\s+([A-ZÀ-ÖØ-Ý][\p{L}'-]*(?:\s+[A-ZÀ-ÖØ-Ý][\p{L}']*)+)/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    const value = m[1]!;
    const rel = surface.indexOf(value);
    if (rel < 0) continue;
    out.push({
      kind: "person_name",
      value,
      key: normalizePersonNameKey(value),
      span: { start: valueStart + rel, end: valueStart + rel + value.length },
      decision: "replace",
    });
  }
  return out;
}

function findHostsInProse(raw: string, surface: string, valueStart: number): Finding[] {
  const out: Finding[] = [];
  // `from workstation PC-LMOREAU` - capture the host, never the word "workstation".
  const re =
    /\b(?:workstation|host|server)\s+([A-Za-z0-9][A-Za-z0-9._-]{1,63})/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    const value = m[1]!;
    if (!looksLikeHostToken(value)) continue;
    if (isKeptHostname(value) || isSentinelValue(value)) continue;
    const rel = surface.indexOf(value);
    if (rel < 0) continue;
    out.push({
      kind: "hostname",
      value,
      key: normalizeHostnameKey(value),
      span: { start: valueStart + rel, end: valueStart + rel + value.length },
      decision: "replace",
    });
  }
  return out;
}

function looksLikeHostToken(value: string): boolean {
  if (value.length < 3) return false;
  if (/^(workstation|host|server|from|the|a|an)$/i.test(value)) return false;
  // Prefer machine-shaped tokens (digit or hyphen), not bare English words.
  return /\d/.test(value) || value.includes("-") || value.includes(".");
}

function toFinding(
  kind: string,
  decoded: string,
  surface: string,
  start: number,
  end: number,
): Finding | null {
  switch (kind) {
    case "account":
      if (!isRedactableAccount(decoded)) return null;
      return {
        kind: "account",
        value: surface,
        key: decoded.toLowerCase(),
        span: { start, end },
        decision: "replace",
      };
    case "person_name":
      if (decoded.length < MIN_IDENTITY_LENGTH) return null;
      if (isPersonNameStopword(decoded)) return null;
      return {
        kind: "person_name",
        value: surface,
        key: normalizePersonNameKey(decoded),
        span: { start, end },
        decision: "replace",
      };
    case "email":
      if (!isValidEmail(decoded)) return null;
      return {
        kind: "email",
        value: surface,
        key: decoded.toLowerCase(),
        span: { start, end },
        decision: "replace",
      };
    case "ip":
      if (!isValidIpv4(decoded)) return null;
      return {
        kind: "ipv4",
        value: surface,
        key: decoded,
        span: { start, end },
        decision: findIpv4(decoded)[0]?.decision ?? "replace",
      };
    case "phone":
      if (!isPhoneValue(decoded)) return null;
      return {
        kind: "phone",
        value: surface,
        key: decoded.replace(/\D/g, ""),
        span: { start, end },
        decision: "replace",
      };
    case "hostname":
      if (isKeptHostname(decoded) || decoded.length < MIN_IDENTITY_LENGTH) return null;
      if (isHostnameStopword(decoded)) return null;
      return {
        kind: "hostname",
        value: surface,
        key: normalizeHostnameKey(decoded),
        span: { start, end },
        decision: "replace",
      };
    case "geo":
      return {
        kind: "geo",
        value: surface,
        key: decoded,
        span: { start, end },
        decision: "replace",
      };
    case "secret":
      return {
        kind: "secret",
        value: surface,
        key: `cef:${decoded}`,
        span: { start, end },
        decision: "replace",
      };
    default:
      return null;
  }
}
