import type { InputFormat } from "./types";

/** Best-effort format sniff for the first chunk of input. */
export function detectFormat(sample: string): InputFormat {
  const trimmed = sample.trimStart();
  if (!trimmed) return "text";

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    const lines = sample.split(/\r?\n/).filter((line) => line.trim().length > 0);
    if (lines.length >= 2) {
      const jsonlLike = lines
        .slice(0, Math.min(lines.length, 8))
        .every((line) => {
          const t = line.trim();
          return t.startsWith("{") && t.endsWith("}");
        });
      if (jsonlLike) return "jsonl";
    }
    return "json";
  }

  const firstLines = sample
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .slice(0, 8);
  if (
    firstLines.length >= 2 &&
    firstLines.every((line) => {
      const t = line.trim();
      return t.startsWith("{") && t.endsWith("}");
    })
  ) {
    return "jsonl";
  }

  return "text";
}
