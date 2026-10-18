import { foldCase } from "../fold";
import type { Finding } from "../types";
import { normalizePersonNameKey } from "../personName";
import { findEmails } from "./email";

/** Derive person-name variants from email local parts for shared aliases. */
export function findEmailDerivedNames(text: string): Finding[] {
  // Skip pathological stress lines (`a@a@a@…`) - no real domain to derive names from.
  if (text.length > 8000 && !/@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(text)) {
    return [];
  }
  const emails = findEmails(text);
  if (emails.length === 0) return outEmpty();

  // needle(lower) → person key (first writer wins; same local parts share a key)
  const needles = new Map<string, { display: string; key: string }>();
  for (const email of emails) {
    const at = email.key.indexOf("@");
    if (at <= 0) continue;
    const local = email.key.slice(0, at);
    const parts = local.split(/[._+-]+/).filter((p) => p.length >= 2);
    if (parts.length < 2) continue;

    const key = normalizePersonNameKey(parts.join(" "));
    for (const variant of buildNameVariants(parts)) {
      const lower = variant.toLowerCase();
      if (!needles.has(lower)) {
        needles.set(lower, { display: variant, key });
      }
    }
  }
  if (needles.size === 0) return outEmpty();

  const lowerText = foldCase(text);
  const out: Finding[] = [];
  const seenSpans = new Set<string>();

  for (const [lowerNeedle, meta] of needles) {
    let from = 0;
    while (from < text.length) {
      const idx = lowerText.indexOf(lowerNeedle, from);
      if (idx === -1) break;
      const end = idx + lowerNeedle.length;
      if (isWordChar(text, idx - 1) || isWordChar(text, end)) {
        from = idx + 1;
        continue;
      }
      const spanKey = `${idx}:${end}`;
      if (!seenSpans.has(spanKey)) {
        seenSpans.add(spanKey);
        out.push({
          kind: "person_name",
          value: text.slice(idx, end),
          key: meta.key,
          span: { start: idx, end },
          decision: "replace",
        });
      }
      from = end;
    }
  }

  return out;
}

function outEmpty(): Finding[] {
  return [];
}

function buildNameVariants(parts: string[]): string[] {
  const titled = parts.map(titleCase);
  const upper = parts.map((p) => p.toUpperCase());
  const first = titled[0]!;
  const last = titled[titled.length - 1]!;
  const variants = new Set<string>();

  variants.add(titled.join(" "));
  variants.add(`${last}, ${first}`);
  variants.add(`${last}, ${titled.slice(0, -1).join(" ")}`);
  variants.add(upper.join(" "));
  variants.add(`${last.toUpperCase()}, ${first.toUpperCase()}`);
  if (parts.length === 2) {
    variants.add(`${titled[1]} ${titled[0]}`);
  }
  for (const v of [...variants]) {
    const plain = stripAccents(v);
    if (plain !== v) variants.add(plain);
  }
  return [...variants].filter((v) => v.length >= 3);
}

function isWordChar(text: string, index: number): boolean {
  if (index < 0 || index >= text.length) return false;
  const c = text.charCodeAt(index);
  return (
    (c >= 65 && c <= 90) ||
    (c >= 97 && c <= 122) ||
    (c >= 48 && c <= 57) ||
    (c >= 192 && c <= 255) ||
    c === 95
  );
}

function titleCase(s: string): string {
  if (!s) return s;
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

function stripAccents(s: string): string {
  return s.normalize("NFD").replace(/\p{M}+/gu, "");
}
