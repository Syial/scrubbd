import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";
import { normalizeHostnameKey, isKeptHostname } from "../hostIdentity";
import { normalizePersonNameKey } from "../personName";
import { MIN_IDENTITY_LENGTH } from "../sentinels";

/** SQL patterns: User@Host lines and INSERT VALUES aligned to columns. */
export function findSqlValues(text: string): Finding[] {
  return [...findMysqlUserHost(text), ...findInsertNameValues(text)];
}

/** `User@Host: app_crm[app_crm] @ web01 [10.30.4.5]` */
function findMysqlUserHost(text: string): Finding[] {
  const out: Finding[] = [];
  const re = /@\s+([A-Za-z0-9][A-Za-z0-9._-]{1,63})\s+\[/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const value = m[1]!;
    if (isKeptHostname(value) || value.length < MIN_IDENTITY_LENGTH) continue;
    const start = m.index + m[0]!.indexOf(value);
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

/** Redact INSERT VALUES that align with person/address columns. */
function findInsertNameValues(text: string): Finding[] {
  const out: Finding[] = [];
  const re =
    /INSERT\s+INTO\s+\w+\s*\(([^)]+)\)\s*VALUES\s*\(([^)]*)\)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const cols = m[1]!.split(",").map((c) => c.trim().toLowerCase());
    const valuesSql = m[2]!;
    const valueStartBase = m.index + m[0]!.lastIndexOf(valuesSql);
    const values = splitSqlValues(valuesSql);
    for (let i = 0; i < cols.length && i < values.length; i += 1) {
      const col = cols[i]!;
      const cell = values[i]!;
      if (!cell.quoted) continue;
      const kind = columnKind(col);
      if (!kind) continue;
      const absStart = valueStartBase + cell.start;
      if (kind === "person_name") {
        out.push({
          kind: "person_name",
          value: cell.value,
          key: normalizePersonNameKey(cell.value),
          span: { start: absStart, end: absStart + cell.value.length },
          decision: "replace",
        });
      } else if (kind === "address") {
        out.push({
          kind: "address",
          value: cell.value,
          key: cell.value.toLowerCase(),
          span: { start: absStart, end: absStart + cell.value.length },
          decision: "replace",
        });
      } else if (kind === "account" && isRedactableAccount(cell.value)) {
        out.push({
          kind: "account",
          value: cell.value,
          key: cell.value.toLowerCase(),
          span: { start: absStart, end: absStart + cell.value.length },
          decision: "replace",
        });
      }
    }
  }
  return out;
}

function columnKind(
  col: string,
): "person_name" | "address" | "account" | null {
  if (
    /^(nom|prenom|prénom|name|firstname|lastname|surname|givenname)$/.test(col)
  ) {
    return "person_name";
  }
  if (/^(adresse|address|street|rue)$/.test(col)) return "address";
  if (/^(user|username|login|utilisateur)$/.test(col)) return "account";
  return null;
}

function splitSqlValues(
  sql: string,
): Array<{ value: string; start: number; quoted: boolean }> {
  const out: Array<{ value: string; start: number; quoted: boolean }> = [];
  let i = 0;
  while (i < sql.length) {
    while (i < sql.length && (sql.charCodeAt(i) === 32 || sql.charCodeAt(i) === 44)) {
      i += 1;
    }
    if (i >= sql.length) break;
    const q = sql.charCodeAt(i);
    if (q === 39 || q === 34) {
      const start = i + 1;
      let j = start;
      while (j < sql.length && sql.charCodeAt(j) !== q) j += 1;
      out.push({ value: sql.slice(start, j), start, quoted: true });
      i = j + 1;
    } else {
      const start = i;
      while (i < sql.length && sql.charCodeAt(i) !== 44) i += 1;
      out.push({ value: sql.slice(start, i).trim(), start, quoted: false });
    }
  }
  return out;
}
