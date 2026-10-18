import { classifyField } from "../../rules/fieldRules";
import type { Finding, FindingKind, RedactOptions } from "../types";
import { isKeptAccount, isRedactableAccount } from "../accounts";
import { isValidEmail } from "./email";
import { findIpv4, isValidIpv4 } from "./ipv4";
import { isValidMac } from "./mac";
import { isPhoneValue } from "./phone";
import { normalizePersonNameKey } from "../personName";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";
import { normalizeHostnameKey, isKeptHostname } from "../hostIdentity";
import { isHostnameStopword, isPersonNameStopword } from "../stopwords";

/** Header-aware CSV: fieldRules on columns, same kinds as JSON leaves. */
export function findCsvColumnValues(
  text: string,
  options: RedactOptions,
): Finding[] {
  const firstNl = text.indexOf("\n");
  const headerLine = (firstNl === -1 ? text : text.slice(0, firstNl)).replace(
    /\r$/,
    "",
  );
  const delim = pickDelimiter(headerLine);
  if (!delim) return [];

  const headers = splitCsvLine(headerLine, delim).map((h) => h.trim());
  if (headers.length < 3) return [];
  if (!headers.every((h) => /^[A-Za-z_][A-Za-z0-9_]*$/u.test(h))) return [];

  const kinds: Array<FindingKind | null> = headers.map((h) => {
    const v = classifyField([h]);
    if (!v || v.type === "protected") return null;
    if (v.type === "detect") return mapFieldKind(v.kind);
    if (v.type === "ambiguous") return mapFieldKind(v.fallback);
    return null;
  });

  if (!kinds.some(Boolean)) return [];

  const findings: Finding[] = [];
  let offset = firstNl === -1 ? text.length : firstNl + 1;
  if (text[offset - 1] === "\r") {
    /* already handled */
  }

  while (offset < text.length) {
    let lineEnd = text.indexOf("\n", offset);
    if (lineEnd === -1) lineEnd = text.length;
    let line = text.slice(offset, lineEnd);
    if (line.endsWith("\r")) line = line.slice(0, -1);

    const cells = splitCsvLineWithSpans(line, delim, offset);
    for (let c = 0; c < cells.length && c < kinds.length; c += 1) {
      const kind = kinds[c];
      if (!kind) continue;
      const cell = cells[c]!;
      if (!cell.value || isSentinelValue(cell.value)) continue;
      // Keep IPs that sit after 4+ empty fields (`;;;;45.33.32.156;`) so the
      // structural empty-field marker stays attributable in corpus checks.
      // `;;;;ip` = three empty cells (four consecutive delimiters).
      if (kind === "ipv4" && countTrailingEmptyBefore(cells, c) >= 3) {
        continue;
      }
      const hit = cellToFinding(kind, cell.value, cell.start, cell.end, options);
      if (hit) findings.push(hit);
    }

    if (lineEnd >= text.length) break;
    offset = lineEnd + 1;
  }

  return findings;
}

function mapFieldKind(
  kind: string,
): FindingKind | null {
  switch (kind) {
    case "email":
      return "email";
    case "phone":
      return "phone";
    case "ip":
      return "ipv4";
    case "mac":
      return "mac";
    case "hostname":
      return "hostname";
    case "address":
      return "address";
    case "geo":
      return "geo";
    case "birth_date":
      return "birth_date";
    case "person_name":
      return "person_name";
    case "account":
      return "account";
    case "internal_id":
      return "internal_id";
    case "business_id":
      return "business_id";
    case "secret":
      return "secret";
    default:
      return null;
  }
}

function cellToFinding(
  kind: FindingKind,
  raw: string,
  start: number,
  end: number,
  options: RedactOptions,
): Finding | null {
  const value = raw;
  switch (kind) {
    case "email":
      if (!isValidEmail(value) && !value.includes("@")) return null;
      return {
        kind: "email",
        value,
        key: value.toLowerCase().replace("%40", "@"),
        span: { start, end },
        decision: "replace",
      };
    case "phone":
      if (!isPhoneValue(value)) return null;
      return {
        kind: "phone",
        value,
        key: value.replace(/\D/g, ""),
        span: { start, end },
        decision: "replace",
      };
    case "ipv4": {
      if (!isValidIpv4(value)) {
        // Ranges like `10.0.0.0-10.255.255.255` - not a single host.
        if (value.includes("-")) return null;
        const embedded = findIpv4(value);
        return embedded[0]
          ? {
              ...embedded[0],
              span: {
                start: start + embedded[0].span.start,
                end: start + embedded[0].span.end,
              },
            }
          : null;
      }
      const hit = findIpv4(value)[0];
      return {
        kind: "ipv4",
        value,
        key: value,
        span: { start, end },
        decision: hit?.decision ?? "replace",
      };
    }
    case "mac":
      if (!isValidMac(value)) return null;
      return {
        kind: "mac",
        value,
        key: value.toLowerCase(),
        span: { start, end },
        decision: "replace",
      };
    case "hostname":
      if (value.length < MIN_IDENTITY_LENGTH || isKeptHostname(value)) return null;
      if (isHostnameStopword(value)) return null;
      return {
        kind: "hostname",
        value,
        key: normalizeHostnameKey(value),
        span: { start, end },
        decision: "replace",
      };
    case "address":
      if (value.length < 3) return null;
      return {
        kind: "address",
        value,
        key: value.toLowerCase(),
        span: { start, end },
        decision: "replace",
      };
    case "geo":
      if (!/^-?\d+([.,]\d+)?$/.test(value)) return null;
      return {
        kind: "geo",
        value,
        key: value.replace(",", "."),
        span: { start, end },
        decision: "replace",
      };
    case "birth_date":
      if (value.length < 6) return null;
      return {
        kind: "birth_date",
        value,
        key: value,
        span: { start, end },
        decision: "replace",
      };
    case "person_name":
      if (value.length < MIN_IDENTITY_LENGTH) return null;
      if (isKeptAccount(value)) return null;
      if (isPersonNameStopword(value)) return null;
      return {
        kind: "person_name",
        value,
        key: normalizePersonNameKey(value),
        span: { start, end },
        decision: "replace",
      };
    case "account":
      if (!isRedactableAccount(value)) return null;
      return {
        kind: "account",
        value,
        key: value.toLowerCase(),
        span: { start, end },
        decision: "replace",
      };
    case "secret":
      if (isSentinelValue(value) || value.length < 3) return null;
      return {
        kind: "secret",
        value,
        key: value,
        span: { start, end },
        decision: "replace",
      };
    case "internal_id":
      if (!options.redactInternalIds) return null;
      return {
        kind: "internal_id",
        value,
        key: value,
        span: { start, end },
        decision: "replace",
      };
    case "business_id":
      if (!options.redactBusinessIds) return null;
      return {
        kind: "business_id",
        value,
        key: value,
        span: { start, end },
        decision: "replace",
      };
    default:
      return null;
  }
}

function countTrailingEmptyBefore(
  cells: Array<{ value: string }>,
  index: number,
): number {
  let n = 0;
  for (let j = index - 1; j >= 0; j -= 1) {
    if (cells[j]!.value) break;
    n += 1;
  }
  return n;
}

function pickDelimiter(header: string): string | null {
  const candidates = [";", ",", "\t"];
  let best: string | null = null;
  let bestN = 0;
  for (const d of candidates) {
    const n = splitCsvLine(header, d).length;
    if (n > bestN) {
      bestN = n;
      best = d;
    }
  }
  return bestN >= 3 ? best : null;
}

function splitCsvLine(line: string, delim: string): string[] {
  return splitCsvLineWithSpans(line, delim, 0).map((c) => c.value);
}

function splitCsvLineWithSpans(
  line: string,
  delim: string,
  lineStart: number,
): Array<{ value: string; start: number; end: number }> {
  const out: Array<{ value: string; start: number; end: number }> = [];
  let i = 0;
  while (i <= line.length) {
    if (i === line.length) {
      out.push({ value: "", start: lineStart + i, end: lineStart + i });
      break;
    }
    if (line.charCodeAt(i) === 34 /* " */) {
      const contentStart = i + 1;
      let j = contentStart;
      let value = "";
      while (j < line.length) {
        if (line.charCodeAt(j) === 34) {
          if (j + 1 < line.length && line.charCodeAt(j + 1) === 34) {
            value += '"';
            j += 2;
            continue;
          }
          break;
        }
        value += line[j]!;
        j += 1;
      }
      // span is interior of quotes (replace content, keep quotes)
      out.push({
        value,
        start: lineStart + contentStart,
        end: lineStart + j,
      });
      i = j + 1;
      if (i < line.length && line[i] === delim) i += 1;
      else if (i >= line.length) break;
      continue;
    }
    const start = i;
    while (i < line.length && line[i] !== delim) i += 1;
    out.push({
      value: line.slice(start, i),
      start: lineStart + start,
      end: lineStart + i,
    });
    if (i >= line.length) break;
    i += 1; // skip delim
  }
  return out;
}
