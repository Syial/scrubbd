/** Placeholder values that must never be redacted (case-insensitive). */
const SENTINELS = new Set(
  [
    "-",
    "--",
    "---",
    "",
    "*",
    "?",
    "n/a",
    "na",
    "none",
    "null",
    "nil",
    "undefined",
    "unknown",
    "not available",
    "not applicable",
    "(null)",
    "(none)",
    "(empty)",
    "empty",
  ].map((s) => s.toLowerCase()),
);

/** True when the value is a sentinel that must stay as-is. */
export function isSentinelValue(value: string): boolean {
  const trimmed = value.trim();
  if (SENTINELS.has(trimmed.toLowerCase())) return true;
  // Bare punctuation / whitespace-only
  if (trimmed.length === 0) return true;
  if (trimmed.length === 1 && !/[A-Za-z0-9]/.test(trimmed)) return true;
  return false;
}

/** Minimum length for accounts / hostnames / person names before replace. */
export const MIN_IDENTITY_LENGTH = 2;
