import { MIN_IDENTITY_LENGTH } from "./sentinels";

/** Person-name key: case/accent-insensitive, order-independent. */
export function normalizePersonNameKey(value: string): string {
  const stripped = stripAccents(value)
    .toLowerCase()
    .replace(/,/g, " ")
    .replace(/['']/g, "");
  const parts = stripped.split(/[^a-z0-9]+/).filter((p) => p.length > 0);
  if (parts.length === 0) return stripped.trim();
  parts.sort();
  return parts.join(" ");
}

export function isPersonNameValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed !== value || trimmed.length < MIN_IDENTITY_LENGTH) return false;
  return normalizePersonNameKey(trimmed).length >= 2;
}

function stripAccents(s: string): string {
  return s.normalize("NFD").replace(/\p{M}+/gu, "");
}
