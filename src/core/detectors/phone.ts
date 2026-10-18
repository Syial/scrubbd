import type { Finding } from "../types";

/** Field-driven phone check; free-text is stricter (findPhones). */
export function isPhoneValue(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed || trimmed !== value) return false;
  return classifyPhone(trimmed, { fieldLabeled: true }) !== null;
}

/** Free-text phones: compact 10 digits only for FR mobiles 06/07. */
export function findPhones(text: string): Finding[] {
  const findings: Finding[] = [];
  const length = text.length;
  let i = 0;

  while (i < length) {
    const code = text.charCodeAt(i);
    if (
      code !== 43 /* + */ &&
      code !== 40 /* ( */ &&
      !(code >= 48 && code <= 57)
    ) {
      i += 1;
      continue;
    }
    const prev = i > 0 ? text.charCodeAt(i - 1) : -1;
    if (isDigit(prev)) {
      i += 1;
      continue;
    }

    const parsed = readPhoneAt(text, i);
    if (!parsed) {
      i += 1;
      continue;
    }

    const next = parsed.end < length ? text.charCodeAt(parsed.end) : -1;
    if (isDigit(next)) {
      i = parsed.end;
      continue;
    }

    findings.push({
      kind: "phone",
      value: parsed.value,
      key: parsed.key,
      span: { start: i, end: parsed.end },
      decision: "replace",
    });
    i = parsed.end;
  }

  return findings;
}

function classifyPhone(
  value: string,
  options: { fieldLabeled: boolean },
): string | null {
  if (value.charCodeAt(0) === 43) {
    let digits = "";
    for (let i = 1; i < value.length; i += 1) {
      const c = value.charCodeAt(i);
      if (c >= 48 && c <= 57) digits += value[i]!;
      else if (c === 32 || c === 45 || c === 46 || c === 40 || c === 41) continue;
      else return null;
    }
    if (digits.length < 10 || digits.length > 15) return null;
    if (digits[0] === "0") return null;
    return digits;
  }

  const fr = matchFrenchNational(value, options.fieldLabeled);
  if (fr) return fr;

  if (options.fieldLabeled) {
    let digits = "";
    for (let i = 0; i < value.length; i += 1) {
      const c = value.charCodeAt(i);
      if (c >= 48 && c <= 57) digits += value[i]!;
      else if (c === 32 || c === 45 || c === 46 || c === 40 || c === 41 || c === 47) {
        continue;
      } else return null;
    }
    if (digits.length < 8 || digits.length > 15) return null;
    return digits;
  }

  return null;
}

function matchFrenchNational(value: string, fieldLabeled: boolean): string | null {
  let digits = "";
  let hasSep = false;
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c >= 48 && c <= 57) digits += value[i]!;
    else if (c === 32 || c === 46 || c === 45) {
      hasSep = true;
      continue;
    } else return null;
  }

  if (digits.startsWith("0033") && digits.length === 13) {
    return `0${digits.slice(4)}`;
  }
  if (digits.length !== 10) return null;
  if (digits[0] !== "0") return null;
  const second = digits[1]!;
  if (second < "1" || second > "9") return null;

  // Compact (no separators): free-text only 06/07 mobiles. Field-labeled: any 0X.
  if (!hasSep) {
    if (fieldLabeled) return digits;
    if (second === "6" || second === "7") return digits;
    return null;
  }

  return digits;
}

function readPhoneAt(
  text: string,
  start: number,
): { end: number; value: string; key: string } | null {
  if (text.charCodeAt(start) === 43) {
    let i = start + 1;
    let digits = 0;
    let sawTrunkZero = false;
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c >= 48 && c <= 57) {
        digits += 1;
        i += 1;
        continue;
      }
      if (c === 32 || c === 45 || c === 46) {
        i += 1;
        continue;
      }
      // French trunk prefix in intl form: `+33 (0)4 72 …`
      if (c === 40 /* ( */ && text.charCodeAt(i + 1) === 48 /* 0 */ && text.charCodeAt(i + 2) === 41 /* ) */) {
        sawTrunkZero = true;
        i += 3;
        continue;
      }
      break;
    }
    // Trunk `(0)` is not part of the E.164 digit count.
    const minDigits = sawTrunkZero ? 10 : 10;
    if (digits < minDigits || digits > 15) return null;
    const value = text.slice(start, i).trimEnd();
    // Build key ignoring the trunk `(0)`.
    const keyDigits = value.replace(/\D/g, "").replace(/^33(0?)/, (_, z) => (z ? "33" : "33"));
    let key = keyDigits;
    if (key.startsWith("33") && key.length >= 11) {
      key = `0${key.slice(2)}`;
      // Drop the trunk 0 if present: 3304… → 04…
      if (key.startsWith("00")) key = `0${key.slice(2)}`;
    }
    if (key.length < 10) return null;
    return { end: start + value.length, value, key };
  }

  if (text.startsWith("0033", start)) {
    const intl = tryReadIntl0033(text, start);
    if (intl) return intl;
  }

  if (text.charCodeAt(start) === 40 /* ( */) {
    const us = tryReadUsParen(text, start);
    if (us) return us;
  }

  if (text.charCodeAt(start) !== 48 /* 0 */) return null;
  const second = text.charCodeAt(start + 1);
  if (second < 49 || second > 57) return null;

  const grouped = tryReadGroupedFr(text, start);
  if (grouped) return grouped;

  // Compact 10 digits - mobiles 06/07 only (avoids Fortinet logid=0316013056 etc.).
  if (second !== 54 /* 6 */ && second !== 55 /* 7 */) return null;

  let i = start;
  let digits = 0;
  while (i < text.length && isDigit(text.charCodeAt(i)) && digits < 10) {
    digits += 1;
    i += 1;
  }
  if (digits !== 10) return null;
  const value = text.slice(start, i);
  return { end: i, value, key: value };
}

function tryReadIntl0033(
  text: string,
  start: number,
): { end: number; value: string; key: string } | null {
  let i = start + 4;
  let digits = "";
  while (i < text.length && digits.length < 9) {
    const c = text.charCodeAt(i);
    if (c >= 48 && c <= 57) {
      digits += text[i]!;
      i += 1;
      continue;
    }
    if (c === 32 || c === 46 || c === 45) {
      i += 1;
      continue;
    }
    break;
  }
  if (digits.length !== 9) return null;
  const value = text.slice(start, i).trimEnd();
  return { end: start + value.length, value, key: `0${digits}` };
}

function tryReadUsParen(
  text: string,
  start: number,
): { end: number; value: string; key: string } | null {
  const re = /^\(\d{3}\)\s?\d{3}[- ]?\d{4}/;
  const m = re.exec(text.slice(start, start + 14));
  if (!m) return null;
  const value = m[0]!;
  let digits = "";
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c >= 48 && c <= 57) digits += value[i]!;
  }
  if (digits.length !== 10) return null;
  return { end: start + value.length, value, key: digits };
}

function tryReadGroupedFr(
  text: string,
  start: number,
): { end: number; value: string; key: string } | null {
  const re = /^0[1-9](?:[ .\-]\d{2}){4}/;
  const slice = text.slice(start, start + 14);
  const m = re.exec(slice);
  if (!m) return null;
  const value = m[0]!;
  const key = matchFrenchNational(value, false);
  if (!key) return null;
  return { end: start + value.length, value, key };
}

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}
