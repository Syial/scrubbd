/** Lowercase without changing string length (U+0130 is the only length-changing case). */
export function foldCase(s: string): string {
  return s.replace(/İ/g, "i").toLowerCase();
}
