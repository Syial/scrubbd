import type { Finding } from "../types";

/** Payment cards (Luhn) and IBAN (mod-97). */
export function findPaymentIds(text: string): Finding[] {
  return [...findCards(text), ...findIbans(text)];
}

function findCards(text: string): Finding[] {
  const out: Finding[] = [];
  let i = 0;
  while (i < text.length) {
    if (!isDigit(text.charCodeAt(i))) {
      i += 1;
      continue;
    }
    const prev = i > 0 ? text.charCodeAt(i - 1) : -1;
    if (isDigit(prev)) {
      i += 1;
      continue;
    }

    const parsed = readCardAt(text, i);
    if (!parsed) {
      i += 1;
      continue;
    }
    out.push({
      kind: "secret",
      value: parsed.value,
      key: `card:${parsed.key}`,
      span: { start: i, end: parsed.end },
      decision: "replace",
    });
    i = parsed.end;
  }
  return out;
}

function readCardAt(
  text: string,
  start: number,
): { end: number; value: string; key: string } | null {
  let i = start;
  let digits = "";
  let lastDigitEnd = start;
  while (i < text.length && digits.length < 19) {
    const c = text.charCodeAt(i);
    if (isDigit(c)) {
      digits += text[i]!;
      i += 1;
      lastDigitEnd = i;
      continue;
    }
    if ((c === 32 || c === 45) && digits.length > 0 && digits.length < 19) {
      i += 1;
      continue;
    }
    break;
  }
  if (digits.length < 13 || digits.length > 19) return null;
  if (!isKnownCardPrefix(digits)) return null;
  if (!luhnOk(digits)) return null;

  const next = lastDigitEnd < text.length ? text.charCodeAt(lastDigitEnd) : -1;
  if (isDigit(next)) return null;

  const raw = text.slice(start, lastDigitEnd);
  // Bare digit runs (no space/dash) collide with session IDs / JSON numbers
  // that pass Luhn by chance (e.g. Suricata smb.session_id). Require
  // separators, except for well-formed 15–16 digit PANs.
  const hasSep = /[\s-]/.test(raw);
  if (!hasSep && digits.length < 15) return null;

  return {
    end: lastDigitEnd,
    value: raw,
    key: digits,
  };
}

function isKnownCardPrefix(digits: string): boolean {
  // Visa 4…, Mastercard 51–55 / 2221–2720, Amex 34/37
  if (digits.startsWith("4") && (digits.length === 13 || digits.length === 16 || digits.length === 19)) {
    return true;
  }
  if (digits.length === 16) {
    const two = Number(digits.slice(0, 2));
    if (two >= 51 && two <= 55) return true;
    const four = Number(digits.slice(0, 4));
    if (four >= 2221 && four <= 2720) return true;
  }
  if (digits.length === 15 && (digits.startsWith("34") || digits.startsWith("37"))) {
    return true;
  }
  return false;
}

function luhnOk(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function findIbans(text: string): Finding[] {
  const out: Finding[] = [];
  let i = 0;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (!isLetter(c)) {
      i += 1;
      continue;
    }
    const prev = i > 0 ? text.charCodeAt(i - 1) : -1;
    if (isLetter(prev) || isDigit(prev)) {
      i += 1;
      continue;
    }

    const parsed = readIbanAt(text, i);
    if (!parsed) {
      i += 1;
      continue;
    }
    out.push({
      kind: "secret",
      value: parsed.value,
      key: `iban:${parsed.key}`,
      span: { start: i, end: parsed.end },
      decision: "replace",
    });
    i = parsed.end;
  }
  return out;
}

/** ISO 13616 IBAN lengths (subset of common EU/EEA + a few others). */
const IBAN_LENGTHS: Record<string, number> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22,
  BR: 29, CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20,
  ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27,
  GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30,
  KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21, LT: 20, LU: 20, LV: 21, MC: 27,
  MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24,
  PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SE: 24, SI: 19,
  SK: 24, SM: 27, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20,
};

function readIbanAt(
  text: string,
  start: number,
): { end: number; value: string; key: string } | null {
  if (!isLetter(text.charCodeAt(start)) || !isLetter(text.charCodeAt(start + 1))) {
    return null;
  }
  const country = text.slice(start, start + 2).toUpperCase();
  const expected = IBAN_LENGTHS[country];
  if (!expected) return null;

  let i = start;
  let compact = "";
  let end = start;
  while (i < text.length && compact.length < expected) {
    const c = text.charCodeAt(i);
    if (isLetter(c) || isDigit(c)) {
      compact += text[i]!.toUpperCase();
      i += 1;
      end = i;
      continue;
    }
    if (c === 32 && compact.length >= 4) {
      i += 1;
      continue;
    }
    break;
  }
  if (compact.length !== expected) return null;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(compact)) return null;
  if (!ibanMod97(compact)) return null;

  const next = end < text.length ? text.charCodeAt(end) : -1;
  if (isLetter(next) || isDigit(next)) return null;

  return {
    end,
    value: text.slice(start, end).trimEnd(),
    key: compact,
  };
}

function ibanMod97(iban: string): boolean {
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let expanded = "";
  for (let i = 0; i < rearranged.length; i += 1) {
    const c = rearranged.charCodeAt(i);
    if (c >= 65 && c <= 90) expanded += String(c - 55);
    else expanded += rearranged[i]!;
  }
  let remainder = 0;
  for (let i = 0; i < expanded.length; i += 1) {
    remainder = (remainder * 10 + (expanded.charCodeAt(i) - 48)) % 97;
  }
  return remainder === 1;
}

function isDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

function isLetter(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}
