import type { Finding } from "../types";
import { isRedactableAccount } from "../accounts";
import { isSentinelValue, MIN_IDENTITY_LENGTH } from "../sentinels";

/** Zeek TSV with #fields: redact username / password columns. */
export function findZeekColumnValues(text: string): Finding[] {
  if (!text.includes("#fields")) return [];
  const lines = text.split("\n");
  let fields: string[] | null = null;
  let offset = 0;
  const out: Finding[] = [];

  for (const line of lines) {
    const lineStart = offset;
    offset += line.length + 1;
    if (line.startsWith("#fields")) {
      fields = line.split("\t").slice(1);
      continue;
    }
    if (!fields || line.startsWith("#") || !line.includes("\t")) continue;

    const cols = line.split("\t");
    let colOffset = lineStart;
    for (let c = 0; c < cols.length && c < fields.length; c += 1) {
      const name = fields[c]!;
      const value = cols[c]!;
      const start = colOffset;
      const end = start + value.length;
      colOffset = end + 1; // + tab

      if (!value || value === "-" || isSentinelValue(value) || value === "(empty)") {
        continue;
      }

      if (name === "username" || name === "user" || name === "id.orig_h") {
        if (name !== "id.orig_h" && isRedactableAccount(value) && value.length >= MIN_IDENTITY_LENGTH) {
          out.push({
            kind: "account",
            value,
            key: value.toLowerCase(),
            span: { start, end },
            decision: "replace",
          });
        }
      }
      if (name === "password" || name === "passwd") {
        out.push({
          kind: "secret",
          value,
          key: `zeek:${value}`,
          span: { start, end },
          decision: "replace",
        });
      }
    }
  }
  return out;
}
